"use strict";
/**
 * Packaging guard for the bundled Rust `sj` gate. The desktop app refuses every destructive action
 * without it, so a build that ships a missing, non-executable or wrong-architecture sj must fail.
 * Pure header inspection (no execution), so it works when cross-packaging (e.g. win32-arm64 on x64).
 */
const fs = require("node:fs");
const path = require("node:path");

const MACHO_CPU = { 0x01000007: "x64", 0x0100000c: "arm64" };
const ELF_MACHINE = { 0x3e: "x64", 0xb7: "arm64" };
const PE_MACHINE = { 0x8664: "x64", 0xaa64: "arm64" };
const FORMAT_FOR_PLATFORM = { darwin: "macho", linux: "elf", win32: "pe" };

function inspectBinaryBuffer(b) {
  if (b.length >= 20 && b.readUInt32BE(0) === 0x7f454c46) {
    const le = b[5] !== 2;
    const machine = le ? b.readUInt16LE(18) : b.readUInt16BE(18);
    return { format: "elf", archs: ELF_MACHINE[machine] ? [ELF_MACHINE[machine]] : [] };
  }
  if (b.length >= 8 && b.readUInt32LE(0) === 0xfeedfacf) {
    const cpu = MACHO_CPU[b.readUInt32LE(4)];
    return { format: "macho", archs: cpu ? [cpu] : [] };
  }
  if (b.length >= 8 && (b.readUInt32BE(0) === 0xcafebabe || b.readUInt32BE(0) === 0xcafebabf)) {
    const is64 = b.readUInt32BE(0) === 0xcafebabf;
    const entry = is64 ? 32 : 20;
    const n = b.readUInt32BE(4);
    if (n > 8) return null; // a Java class file shares this magic; fat Mach-O has 2-3 slices
    const archs = [];
    for (let i = 0; i < n && 8 + entry * i + 4 <= b.length; i += 1) {
      const cpu = MACHO_CPU[b.readUInt32BE(8 + entry * i)];
      if (cpu && !archs.includes(cpu)) archs.push(cpu);
    }
    return { format: "macho", archs };
  }
  if (b.length >= 0x40 && b[0] === 0x4d && b[1] === 0x5a) {
    const off = b.readUInt32LE(0x3c);
    if (off + 6 <= b.length && b.toString("latin1", off, off + 4) === "PE\0\0") {
      const m = PE_MACHINE[b.readUInt16LE(off + 4)];
      return { format: "pe", archs: m ? [m] : [] };
    }
  }
  return null;
}

function readHeader(file) {
  const fd = fs.openSync(file, "r");
  try {
    const buf = Buffer.alloc(4096);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    return buf.subarray(0, n);
  } finally {
    fs.closeSync(fd);
  }
}

/** Throws a descriptive Error unless `file` is a runnable sj for `platform` (darwin|linux|win32) and `arch` (x64|arm64|universal). */
function assertSjBinary(file, platform, arch) {
  let st;
  try {
    st = fs.lstatSync(file);
  } catch {
    throw new Error(`bundled sj is missing: ${file}`);
  }
  if (st.isSymbolicLink()) throw new Error(`bundled sj must not be a symlink: ${file}`);
  if (!st.isFile() || st.size === 0) throw new Error(`bundled sj is not a regular file: ${file}`);
  if (platform !== "win32") {
    if ((st.mode & 0o111) === 0) throw new Error(`bundled sj is not executable: ${file}`);
    if ((st.mode & 0o022) !== 0) throw new Error(`bundled sj is writable by group or others: ${file}`);
  }
  const info = inspectBinaryBuffer(readHeader(file));
  if (!info) throw new Error(`bundled sj is not a native executable (unrecognised header): ${file}`);
  const wantFormat = FORMAT_FOR_PLATFORM[platform];
  if (info.format !== wantFormat) throw new Error(`bundled sj has the wrong format ${info.format}, expected ${wantFormat} for ${platform}: ${file}`);
  const wanted = arch === "universal" ? ["x64", "arm64"] : [arch];
  if (arch === "universal" && platform !== "darwin") throw new Error("universal is only valid for darwin");
  for (const a of wanted) {
    if (!info.archs.includes(a)) {
      throw new Error(`bundled sj has the wrong arch [${info.archs.join(",")}], need ${arch === "universal" ? "universal (x64+arm64)" : a} for ${platform}: ${file}`);
    }
  }
}

const ARCH_NAMES = { 1: "x64", 3: "arm64", 4: "universal" };

function exeName(platform) {
  return platform === "win32" ? "sj.exe" : "sj";
}

module.exports = { inspectBinaryBuffer, assertSjBinary, ARCH_NAMES, exeName };
