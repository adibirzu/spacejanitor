#!/usr/bin/env node
/**
 * Programmatic icon generator for SpaceJanitor Electron packaging (macOS, Linux, Windows).
 * Produces build/icon.svg, build/icon.png (512x512), build/trayTemplate.png (22x22),
 * and build/trayTemplate@2x.png (44x44) using pure Node zlib (zero native dependencies).
 */
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BUILD_DIR = path.resolve(__dirname, "../build");

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) {
    c ^= buf[i];
    for (let k = 0; k < 8; k += 1) {
      c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
    }
  }
  return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, "ascii");
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crcBuf]);
}

function encodePng(width, height, rgba) {
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const stride = width * 4 + 1;
  const raw = Buffer.alloc(stride * height);
  for (let y = 0; y < height; y += 1) {
    raw[y * stride] = 0; // filter none
    rgba.copy(raw, y * stride + 1, y * width * 4, (y + 1) * width * 4);
  }
  const compressed = zlib.deflateSync(raw, { level: 9 });
  return Buffer.concat([
    sig,
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", compressed),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

function renderAppIcon(size) {
  const buf = Buffer.alloc(size * size * 4);
  const cx = size / 2;
  const cy = size / 2;
  const rOuter = size * 0.44;
  const rInner = size * 0.28;
  const rHole = size * 0.14;

  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const dx = x - cx;
      const dy = y - cy;
      const dist = Math.hypot(dx, dy);
      const idx = (y * size + x) * 4;

      if (dist <= rOuter) {
        // Rounded dark slate badge with teal-emerald telemetry ring
        const isRing = dist <= rInner && dist >= rHole;
        if (isRing) {
          buf[idx] = 20;
          buf[idx + 1] = 184;
          buf[idx + 2] = 166;
          buf[idx + 3] = 255;
        } else {
          buf[idx] = 15;
          buf[idx + 1] = 23;
          buf[idx + 2] = 42;
          buf[idx + 3] = 255;
        }
      } else {
        buf[idx] = 0;
        buf[idx + 1] = 0;
        buf[idx + 2] = 0;
        buf[idx + 3] = 0;
      }
    }
  }
  return encodePng(size, size, buf);
}

function renderTrayTemplate(size) {
  const buf = Buffer.alloc(size * size * 4);
  const cx = size / 2;
  const cy = size / 2;
  const rOuter = size * 0.42;
  const rInner = size * 0.22;

  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const dist = Math.hypot(x - cx, y - cy);
      const idx = (y * size + x) * 4;
      if (dist <= rOuter && dist >= rInner) {
        buf[idx] = 0;
        buf[idx + 1] = 0;
        buf[idx + 2] = 0;
        buf[idx + 3] = 255;
      }
    }
  }
  return encodePng(size, size, buf);
}

const SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <rect width="512" height="512" rx="112" fill="#0f172a"/>
  <circle cx="256" cy="256" r="140" fill="none" stroke="#14b8a6" stroke-width="44"/>
  <circle cx="256" cy="256" r="56" fill="#38bdf8"/>
</svg>
`;

fs.mkdirSync(BUILD_DIR, { recursive: true });
fs.writeFileSync(path.join(BUILD_DIR, "icon.svg"), SVG, "utf8");
fs.writeFileSync(path.join(BUILD_DIR, "icon.png"), renderAppIcon(512));
fs.writeFileSync(path.join(BUILD_DIR, "trayTemplate.png"), renderTrayTemplate(22));
fs.writeFileSync(path.join(BUILD_DIR, "trayTemplate@2x.png"), renderTrayTemplate(44));
console.log("Generated desktop icons in", BUILD_DIR);
