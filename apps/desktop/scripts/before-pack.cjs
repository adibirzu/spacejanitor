"use strict";
/**
 * electron-builder beforePack hook: refuse to build an installer that would ship without a working,
 * correct-architecture Rust sj gate in resources/bin (the app then fails closed on every cleanup).
 * The release workflow stages the matching binary there before packaging.
 */
const path = require("node:path");
const { ARCH_NAMES, assertSjBinary, exeName } = require("./sj-binary-check.cjs");

exports.default = async function beforePack(context) {
  const platform = context.electronPlatformName;
  const arch = ARCH_NAMES[context.arch];
  if (!arch) throw new Error(`unsupported electron-builder arch id ${context.arch} for the bundled sj check`);
  // The darwin universal build packs x64 and arm64 apps first; both consume the staged fat binary.
  const file = path.join(context.packager.projectDir, "resources", "bin", exeName(platform));
  assertSjBinary(file, platform, arch === "universal" ? "universal" : arch);
};
