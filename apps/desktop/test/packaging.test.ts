import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const check = require("../../scripts/sj-binary-check.cjs");

const repoRoot = path.resolve(__dirname, "../../../..");

function tmp(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sj-pack-"));
}

function elf(machine: number): Buffer {
  const b = Buffer.alloc(64);
  b.write("\x7fELF", 0, "latin1");
  b[4] = 2; // 64-bit
  b[5] = 1; // little endian
  b.writeUInt16LE(machine, 18);
  return b;
}

function machoThin(cpu: number): Buffer {
  const b = Buffer.alloc(64);
  b.writeUInt32LE(0xfeedfacf, 0);
  b.writeUInt32LE(cpu, 4);
  return b;
}

function machoFat(cpus: number[]): Buffer {
  const b = Buffer.alloc(8 + 20 * cpus.length + 16);
  b.writeUInt32BE(0xcafebabe, 0);
  b.writeUInt32BE(cpus.length, 4);
  cpus.forEach((cpu, i) => b.writeUInt32BE(cpu, 8 + 20 * i));
  return b;
}

function pe(machine: number): Buffer {
  const b = Buffer.alloc(256);
  b.write("MZ", 0, "latin1");
  b.writeUInt32LE(128, 0x3c);
  b.write("PE\0\0", 128, "latin1");
  b.writeUInt16LE(machine, 132);
  return b;
}

const X64 = 0x01000007;
const ARM64 = 0x0100000c;

test("packaging: header inspection recognises ELF, Mach-O (thin and fat) and PE architectures", () => {
  assert.deepEqual(check.inspectBinaryBuffer(elf(0x3e)), { format: "elf", archs: ["x64"] });
  assert.deepEqual(check.inspectBinaryBuffer(elf(0xb7)), { format: "elf", archs: ["arm64"] });
  assert.deepEqual(check.inspectBinaryBuffer(machoThin(ARM64)), { format: "macho", archs: ["arm64"] });
  assert.deepEqual(check.inspectBinaryBuffer(machoFat([X64, ARM64])), { format: "macho", archs: ["x64", "arm64"] });
  assert.deepEqual(check.inspectBinaryBuffer(pe(0x8664)), { format: "pe", archs: ["x64"] });
  assert.deepEqual(check.inspectBinaryBuffer(pe(0xaa64)), { format: "pe", archs: ["arm64"] });
  assert.equal(check.inspectBinaryBuffer(Buffer.from("#!/bin/sh\necho hi\n")), null);
});

test("packaging: assertSjBinary accepts only the right platform/arch, an existing file, and the exec bit", () => {
  const dir = tmp();
  try {
    const bin = (name: string, buf: Buffer, mode = 0o755) => {
      const p = path.join(dir, name);
      fs.writeFileSync(p, buf, { mode });
      fs.chmodSync(p, mode);
      return p;
    };
    assert.doesNotThrow(() => check.assertSjBinary(bin("l64", elf(0x3e)), "linux", "x64"));
    assert.doesNotThrow(() => check.assertSjBinary(bin("la", elf(0xb7)), "linux", "arm64"));
    assert.doesNotThrow(() => check.assertSjBinary(bin("m", machoFat([X64, ARM64])), "darwin", "universal"));
    assert.doesNotThrow(() => check.assertSjBinary(bin("m2", machoFat([X64, ARM64])), "darwin", "arm64"));
    assert.doesNotThrow(() => check.assertSjBinary(bin("w.exe", pe(0x8664), 0o644), "win32", "x64"));
    assert.doesNotThrow(() => check.assertSjBinary(bin("wa.exe", pe(0xaa64), 0o644), "win32", "arm64"));

    assert.throws(() => check.assertSjBinary(path.join(dir, "missing"), "linux", "x64"), /missing/);
    assert.throws(() => check.assertSjBinary(bin("wrongarch", elf(0xb7)), "linux", "x64"), /arch/);
    assert.throws(() => check.assertSjBinary(bin("wrongfmt", pe(0x8664)), "linux", "x64"), /format/);
    assert.throws(() => check.assertSjBinary(bin("thinmac", machoThin(ARM64)), "darwin", "universal"), /universal/);
    assert.throws(() => check.assertSjBinary(bin("script", Buffer.from("#!/bin/sh\n")), "linux", "x64"), /not a/);
    if (process.platform !== "win32") {
      assert.throws(() => check.assertSjBinary(bin("noexec", elf(0x3e), 0o644), "linux", "x64"), /executable/);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("packaging: the pack check rejects symlinked, group/world-writable and directory sj", () => {
  if (process.platform === "win32") return;
  const dir = tmp();
  try {
    const good = path.join(dir, "good");
    fs.writeFileSync(good, elf(0x3e), { mode: 0o755 });
    fs.chmodSync(good, 0o755);
    assert.doesNotThrow(() => check.assertSjBinary(good, "linux", "x64"));
    const link = path.join(dir, "link");
    fs.symlinkSync(good, link);
    assert.throws(() => check.assertSjBinary(link, "linux", "x64"), /symlink/);
    for (const mode of [0o777, 0o775, 0o757]) {
      const p = path.join(dir, `m${mode.toString(8)}`);
      fs.writeFileSync(p, elf(0x3e));
      fs.chmodSync(p, mode);
      assert.throws(() => check.assertSjBinary(p, "linux", "x64"), /writable/, mode.toString(8));
    }
    const d = path.join(dir, "adir");
    fs.mkdirSync(d, { mode: 0o755 });
    assert.throws(() => check.assertSjBinary(d, "linux", "x64"), /regular file/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("packaging: electron-builder bundles resources/bin and refuses to pack without a verified sj", () => {
  const cfg = fs.readFileSync(path.join(repoRoot, "apps/desktop/electron-builder.yml"), "utf8");
  assert.match(cfg, /extraResources:\s*\n\s*- from: resources\/bin\s*\n\s*to: bin/);
  assert.match(cfg, /beforePack:\s*scripts\/before-pack\.cjs/);
  assert.equal(fs.existsSync(path.join(repoRoot, "apps/desktop/scripts/before-pack.cjs")), true);
});

test("packaging: release.yml verifies the bundled sj of every desktop target after packing", () => {
  const wf = fs.readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8");
  const matrix = wf.slice(wf.indexOf("desktop-installer-matrix:"), wf.indexOf("publish-release:"));
  const targets = [...matrix.matchAll(/- label: (\S+)/g)].map((m) => m[1]);
  assert.deepEqual(targets.sort(), ["linux-arm64", "linux-x64", "macos-universal", "windows-arm64", "windows-x64"]);
  for (const key of ["sj_platform:", "sj_arch:"]) {
    assert.equal((matrix.match(new RegExp(key, "g")) || []).length, targets.length, `${key} per target`);
  }
  assert.match(matrix, /verify-packaged-sj\.cjs --platform \$\{\{ matrix\.sj_platform \}\} --arch \$\{\{ matrix\.sj_arch \}\}/);
  assert.ok(matrix.indexOf("verify-packaged-sj.cjs") > matrix.indexOf("electron-builder --config"), "verify runs after packing");
});

test("packaging: linux/win targets carry no arch lists, so each CI job packs only the arch its flag selects", () => {
  const cfg = fs.readFileSync(path.join(repoRoot, "apps/desktop/electron-builder.yml"), "utf8");
  const section = (name: string): string => {
    const m = cfg.match(new RegExp(`^${name}:\\n((?:[ \\t].*\\n?|\\n)*)`, "m"));
    assert.ok(m, `${name} section present`);
    return m[1];
  };
  for (const name of ["linux", "win"]) {
    assert.doesNotMatch(section(name), /^\s*arch:/m, `${name}: arch lists in config override the --x64/--arm64 CLI flag`);
  }
  // macOS keeps its explicit universal target (the lipo'd sj is staged for it).
  assert.match(section("mac"), /- universal/);
});

test("packaging: linux executableName is a safe path component (not the scoped npm package name)", () => {
  const cfg = fs.readFileSync(path.join(repoRoot, "apps/desktop/electron-builder.yml"), "utf8");
  assert.match(cfg, /^linux:\n(?:[ \t].*\n)*?[ \t]+executableName:\s*spacejanitor\s*$/m);
});

test("packaging: .deb metadata (homepage + maintainer) is configured so the deb target can build", () => {
  const cfg = fs.readFileSync(path.join(repoRoot, "apps/desktop/electron-builder.yml"), "utf8");
  assert.match(cfg, /^linux:\n(?:[ \t].*\n)*?[ \t]+maintainer:\s*\S.*<\S+@\S+>/m);
  const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, "apps/desktop/package.json"), "utf8"));
  assert.match(pkg.homepage, /^https:\/\//);
});
