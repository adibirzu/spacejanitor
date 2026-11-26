import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  SCHEMA_VERSIONS,
  activeSjBinary,
  collectBlockers,
  collectDisk,
  collectLinuxAudit,
  collectMemory,
  formatToon,
  parseLinuxMeminfo,
  parseLinuxProcessStates,
  parseProcMounts,
  parseProcStatusVmSwap,
  parseSystemctlUnits,
} from "../src/index.mjs";

test("parseProcMounts handles overlay, tmpfs, and AppImage mounts cleanly without false alerts", () => {
  const raw = [
    "/dev/nvme0n1p2 / ext4 rw,relatime 0 0",
    "tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0",
    "overlay /var/lib/docker/overlay2/layer1/merged overlay rw,relatime 0 0",
    "Orca-1.2.3.AppImage /tmp/.mount_Orca-aaaaaa fuse.Orca-1.2.3.AppImage ro,nosuid,nodev 0 0",
    "Orca-1.2.4.AppImage /tmp/.mount_Orca-bbbbbb fuse.AppImage ro,nosuid,nodev 0 0",
    "proc /proc proc rw,nosuid,nodev 0 0",
  ].join("\n");

  const mounts = parseProcMounts(raw);
  assert.equal(mounts.length, 6);
  assert.equal(mounts[0].kind, "physical");
  assert.equal(mounts[0].alertEligible, true);
  assert.equal(mounts[1].kind, "tmpfs");
  assert.equal(mounts[1].alertEligible, false);
  assert.equal(mounts[2].kind, "overlay");
  assert.equal(mounts[2].alertEligible, false);
  assert.equal(mounts[3].kind, "appimage");
  assert.equal(mounts[3].alertEligible, false);
  assert.equal(mounts[5].kind, "virtual");
  assert.equal(mounts[5].alertEligible, false);
});

test("parseLinuxMeminfo computes MemAvailable and swap accurately", () => {
  const meminfo = [
    "MemTotal:       131072000 kB",
    "MemFree:         2000000 kB",
    "MemAvailable:   64000000 kB",
    "SwapTotal:       8388608 kB",
    "SwapFree:        4194304 kB",
  ].join("\n");
  const parsed = parseLinuxMeminfo(meminfo);
  assert.equal(parsed.totalBytes, 131072000 * 1024);
  assert.equal(parsed.availableBytes, 64000000 * 1024);
  assert.equal(parsed.swapTotalBytes, 8388608 * 1024);
  assert.equal(parsed.swapUsedBytes, 4194304 * 1024);

  assert.equal(parseProcStatusVmSwap("Name:\tnode\nVmRSS:\t1000 kB\nVmSwap:\t512 kB\n"), 512 * 1024);
});

test("collectBlockers detects Linux systemd failed units, broken user services, podman healthcheck units, and D/Z processes", async () => {
  const sysOut = "project-status.service loaded failed failed Project status updater\npaperclip-backup.service loaded failed failed Backup service\n";
  const userOut = "no-mistakes-daemon.service loaded failed failed Daemon\npodman-999-healthcheck.service loaded failed failed Podman healthcheck\n";
  const psStat = "S 100 bash\nD 201 sync-io\nZ 202 defunct-child\nD 203 nvme-flush\nD 204 dockerd\n";

  const sysUnits = parseSystemctlUnits(sysOut, "system");
  assert.equal(sysUnits.length, 2);
  const userUnits = parseSystemctlUnits(userOut, "user");
  assert.equal(userUnits.length, 2);
  assert.equal(userUnits[1].isPodmanHealthcheck, true);

  const states = parseLinuxProcessStates(psStat);
  assert.equal(states.dStateCount, 3);
  assert.equal(states.zombieCount, 1);

  const report = await collectBlockers({
    platformOverride: "linux",
    procFiles: {
      "/proc/sys/fs/file-nr": "4096\t0\t1048576\n",
      "/proc/sys/fs/inotify/max_user_watches": "524288\n",
      "/proc/sys/fs/inotify/max_user_instances": "1024\n",
    },
    execFn: async (cmd, args) => {
      if (cmd === "ps") return { ok: true, stdout: psStat };
      if (cmd === "systemctl" && args.includes("--user") && args.includes("--failed")) return { ok: true, stdout: userOut };
      if (cmd === "systemctl" && args.includes("--user") && args.includes("--all")) return { ok: true, stdout: userOut };
      if (cmd === "systemctl" && args.includes("--failed")) return { ok: true, stdout: sysOut };
      return { ok: false, stdout: "" };
    },
  });

  assert.equal(report.schema, SCHEMA_VERSIONS.blockers);
  assert.ok(report.status === "WARN" || report.status === "CRITICAL");
  assert.equal(report.systemd.systemFailed.length, 2);
  assert.equal(report.systemd.userFailed.length, 2);
  assert.equal(report.systemd.podmanHealthcheckIssues.length, 1);
  assert.ok(report.counters.some((c) => c.name === "systemd.system_failed" && c.current === 2));
  assert.ok(report.counters.some((c) => c.name === "podman.healthcheck_failed" && c.current === 1));

  const toon = formatToon(report);
  assert.ok(toon.includes("project-status.service"));
  assert.ok(toon.includes("podman-999-healthcheck.service"));
});

test("collectLinuxAudit probes Docker, Podman, journald, apt, AppImage mounts, HF caches, and old backups in dry-run", async () => {
  // Windows runner temp files live under the protected user profile.
  const fixtureRoot = process.platform === "win32" ? process.cwd() : os.tmpdir();
  const tmp = fs.realpathSync(fs.mkdtempSync(path.join(fixtureRoot, "sj-linux-audit-")));
  try {
    const home = path.join(tmp, "home");
    const tmpDir = path.join(tmp, "tmp");
    const aptDir = path.join(tmp, "apt-archives");
    const hfDir = path.join(home, ".cache", "huggingface", "hub");
    const pipDir = path.join(home, ".cache", "pip");
    const backupDir = path.join(home, "backups");
    const staleMount = path.join(tmpDir, ".mount_Orca-old");

    for (const d of [hfDir, pipDir, backupDir, staleMount, aptDir]) {
      fs.mkdirSync(d, { recursive: true });
    }
    fs.writeFileSync(path.join(hfDir, "model.safetensors"), "weights");
    fs.writeFileSync(path.join(pipDir, "pkg.whl"), "wheel");
    fs.writeFileSync(path.join(backupDir, "snap-old.tar.gz"), "backup");
    fs.writeFileSync(path.join(staleMount, "AppRun"), "old");
    fs.writeFileSync(path.join(aptDir, "pkg_1.0_amd64.deb"), "debpkg");

    const audit = await collectLinuxAudit({
      platformOverride: "linux",
      homeDir: home,
      tmpDir,
      aptArchivesDir: aptDir,
      staleAgeMs: 0,
      mountsRaw: [
        "/dev/nvme0n1p1 / ext4 rw 0 0",
        "overlay /var/lib/docker/overlay2/x/merged overlay rw 0 0",
        "Orca-1.0.AppImage /tmp/.mount_Orca-live1 fuse.AppImage ro 0 0",
        "Orca-1.1.AppImage /tmp/.mount_Orca-live2 fuse.AppImage ro 0 0",
      ].join("\n"),
      execFn: async (cmd, args) => {
        if (cmd === "docker" && args[0] === "system") {
          return {
            ok: true,
            stdout: [
              JSON.stringify({ Type: "Images", TotalCount: "10", Active: "2", Size: "94GB", Reclaimable: "80GB (85%)" }),
              JSON.stringify({ Type: "Build Cache", TotalCount: "20", Active: "0", Size: "22.8GB", Reclaimable: "22.8GB" }),
            ].join("\n"),
          };
        }
        if (cmd === "docker" && args[0] === "ps") {
          return {
            ok: true,
            stdout: [
              JSON.stringify({ ID: "c1", Names: "exited-vllm", Image: "vllm:latest", Status: "Exited (0) 2d ago", State: "exited", Size: "1GB" }),
              JSON.stringify({ ID: "c2", Names: "cadvisor", Image: "cadvisor:latest", Status: "Up 2d (unhealthy)", State: "running", Size: "0B" }),
            ].join("\n"),
          };
        }
        if (cmd === "docker" && args[0] === "images") {
          return { ok: true, stdout: JSON.stringify({ ID: "img1", Repository: "<none>", Tag: "<none>", Size: "2.5GB" }) };
        }
        if (cmd === "podman" && args[0] === "ps") {
          return { ok: true, stdout: JSON.stringify([{ Id: "p1", Names: ["old-pod"], State: "exited", Status: "Exited (0) 5d ago" }]) };
        }
        if (cmd === "podman" && args[0] === "system") {
          return { ok: true, stdout: JSON.stringify([{ Type: "Images", Reclaimable: "1.2GB" }]) };
        }
        if (cmd === "journalctl") {
          return { ok: true, stdout: "Archived and active journals take up 1.5G in the file system." };
        }
        return { ok: false, stdout: "" };
      },
    });

    assert.equal(audit.schema, SCHEMA_VERSIONS.linuxAudit);
    assert.equal(audit.docker.exitedContainers.length, 1);
    assert.equal(audit.docker.unhealthyContainers.length, 1);
    assert.equal(audit.docker.danglingImages.length, 1);
    assert.ok(audit.docker.buildCacheReclaimableBytes > 20e9);
    assert.equal(audit.podman.exitedContainers.length, 1);
    assert.ok(audit.journald.bytes > 1e9);
    assert.ok(audit.packageCaches.aptArchivesBytes > 0);
    assert.equal(audit.appimageMounts.length, 2);
    if (activeSjBinary()) {
      assert.equal(audit.staleTmpEntries.length, 1);
    } else {
      assert.equal(audit.staleTmpEntries.length, 0);
    }
    assert.ok(audit.modelCaches.some((m) => m.path.includes("huggingface") && m.manualReviewOnly === true));
    assert.ok(audit.oldBackups.some((b) => b.path.includes("backups") && b.manualReviewOnly === true));

    const toon = formatToon(audit);
    assert.ok(toon.includes("spacejanitor.linux_audit.v1"));
    assert.ok(toon.includes("docker_build_cache"));
    assert.ok(toon.includes("docker: exited=1 unhealthy=1 dangling_imgs=1"));
    assert.ok(!toon.includes("docker_build_cache_gib=0.00"));
    assert.ok(toon.includes("podman: exited=1 unhealthy=0"));
    assert.ok(toon.includes("appimage_mounts: 2"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("formatToon and normalizeReportEnvelope preserve Docker/Podman stats across double normalization of Rust snake_case JSON", async () => {
  const { normalizeReportEnvelope } = await import("../src/index.mjs");
  const rustJson = {
    schema: SCHEMA_VERSIONS.linuxAudit,
    os: "linux",
    arch: "aarch64",
    mounts: [],
    appimage_mounts: [{ mount_point: "/tmp/.mount_Orca-1", source: "Orca.AppImage" }],
    docker: {
      available: true,
      df: {
        available: true,
        images_reclaimable_bytes: 2 * 1024 ** 3,
        build_cache_reclaimable_bytes: 1024 ** 3,
      },
      exited_containers: [{ id: "abc123", name: "old-vllm" }],
      unhealthy_containers: [{ id: "def456", name: "cadvisor" }],
      dangling_images: [{ id: "sha256:999" }],
    },
    podman: {
      available: true,
      df: {
        available: true,
        images_reclaimable_bytes: 512 * 1024 ** 2,
        volumes_reclaimable_bytes: 0,
      },
      exited_containers: [{ id: "pod1", name: "stale-pod" }],
      unhealthy_containers: [],
      dangling_images: [],
    },
    journald: { bytes: 100 * 1024 ** 2 },
    package_caches: {
      apt_archives_path: "/var/cache/apt/archives",
      apt_archives_bytes: 50 * 1024 ** 2,
      user_caches: [],
    },
    stale_tmp_entries: [],
    model_caches: [],
    old_backups: [],
  };

  const norm1 = normalizeReportEnvelope(rustJson);
  const norm2 = normalizeReportEnvelope(norm1);
  assert.deepEqual(norm2.docker, norm1.docker);
  assert.deepEqual(norm2.podman, norm1.podman);

  const toon = formatToon(norm1);
  assert.ok(toon.includes("docker: exited=1 unhealthy=1 dangling_imgs=1 img_reclaim_gib=2.00 docker_build_cache_gib=1.00"), toon);
  assert.ok(toon.includes("podman: exited=1 unhealthy=0"), toon);
});

test("collectDisk evaluates percentage thresholds cleanly for both 96 GiB and 3.7 TB disks", async () => {
  const smallHealthy = await collectDisk({
    targetPath: process.cwd(),
    statfsOverride: { bavail: 60 * 1024 ** 2, bsize: 1024, blocks: 96 * 1024 ** 2 },
  });
  assert.equal(smallHealthy.status, "OK");

  const smallCritical = await collectDisk({
    targetPath: process.cwd(),
    statfsOverride: { bavail: 1.6 * 1024 ** 2, bsize: 1024, blocks: 96 * 1024 ** 2 },
  });
  assert.equal(smallCritical.status, "CRITICAL");

  const huge97Pct = await collectDisk({
    targetPath: process.cwd(),
    statfsOverride: { bavail: 123 * 1024 ** 2, bsize: 1024, blocks: 3700 * 1024 ** 2 },
  });
  assert.equal(huge97Pct.status, "CRITICAL");
});

test("collectLinuxAudit never flags a /tmp directory as stale when a descendant file was recently modified", async () => {
  const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sj-tmp-desc-")));
  try {
    const home = path.join(tmp, "home");
    const tmpDir = path.join(tmp, "tmp");
    const appDir = path.join(tmpDir, ".mount_App-old-parent");
    const deepDir = path.join(appDir, "a", "b", "c", "d", "e", "f", "g");
    fs.mkdirSync(home, { recursive: true });
    fs.mkdirSync(deepDir, { recursive: true });
    const activeChild = path.join(deepDir, "active.sock.log");
    fs.writeFileSync(activeChild, "active");
    const oldTime = new Date(Date.now() - 10 * 86_400_000);
    let cur = appDir;
    for (const seg of ["a", "b", "c", "d", "e", "f", "g"]) {
      fs.utimesSync(cur, oldTime, oldTime);
      cur = path.join(cur, seg);
    }
    fs.utimesSync(deepDir, oldTime, oldTime);

    const audit = await collectLinuxAudit({
      platformOverride: "linux",
      homeDir: home,
      tmpDir,
      staleAgeMs: 24 * 3600 * 1000,
      execFn: async () => ({ ok: false, stdout: "" }),
    });
    assert.deepEqual(audit.staleTmpEntries, []);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
