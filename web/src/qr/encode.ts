// A QR Code encoder (ISO/IEC 18004), written for this app: byte mode, error correction
// level M, versions 1 to 40, the mask with the lowest penalty. It turns a pairing code into
// the matrix `QrCode` draws; tests/unit/qr.test.ts decodes every version with the scanner's
// decoder. "QR Code" is a registered trademark of DENSO WAVE INCORPORATED.

/** Error correction codewords per block at level M, by version (index 0 unused). */
// deno-fmt-ignore
const ECC_PER_BLOCK = [
  -1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
  26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
];
/** Number of error correction blocks at level M, by version. */
// deno-fmt-ignore
const BLOCKS = [
  -1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
  17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49,
];
/** The two format bits of level M. */
const FORMAT_LEVEL_M = 0;

export interface QrMatrix {
  /** Modules per side. */
  size: number;
  version: number;
  /** Row by row; true is a dark module. */
  modules: boolean[][];
}

/** Data and error correction modules of a version (everything but the function patterns). */
function rawDataModules(version: number): number {
  let result = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const align = Math.floor(version / 7) + 2;
    result -= (25 * align - 10) * align - 55;
    if (version >= 7) result -= 36;
  }
  return result;
}

function dataCodewords(version: number): number {
  return Math.floor(rawDataModules(version) / 8) - ECC_PER_BLOCK[version] * BLOCKS[version];
}

/** How many bytes a version holds in byte mode at level M. */
export function capacity(version: number): number {
  const header = 4 + (version < 10 ? 8 : 16);
  return Math.floor((dataCodewords(version) * 8 - header) / 8);
}

// GF(256) with the QR polynomial x^8 + x^4 + x^3 + x^2 + 1.
function multiply(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}

/** The Reed-Solomon generator polynomial of a degree (without its leading 1). */
function divisor(degree: number): number[] {
  const result = new Array<number>(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = multiply(result[j], root);
      if (j + 1 < degree) result[j] ^= result[j + 1];
    }
    root = multiply(root, 2);
  }
  return result;
}

function remainder(data: readonly number[], generator: readonly number[]): number[] {
  const result = generator.map(() => 0);
  for (const byte of data) {
    const factor = byte ^ result.shift()!;
    result.push(0);
    generator.forEach((coefficient, i) => (result[i] ^= multiply(coefficient, factor)));
  }
  return result;
}

/** The data codewords: mode, length, the bytes, terminator and padding. */
function codewords(bytes: Uint8Array, version: number): number[] {
  const bits: number[] = [];
  const push = (value: number, length: number) => {
    for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  push(0b0100, 4);
  push(bytes.length, version < 10 ? 8 : 16);
  for (const byte of bytes) push(byte, 8);
  const total = dataCodewords(version) * 8;
  push(0, Math.min(4, total - bits.length));
  push(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < total; pad ^= 0xec ^ 0x11) push(pad, 8);
  const out: number[] = [];
  for (let i = 0; i < bits.length; i += 8) {
    out.push(bits.slice(i, i + 8).reduce((byte, bit) => (byte << 1) | bit, 0));
  }
  return out;
}

/** Split into blocks, add each block's error correction, and interleave. */
function interleave(data: readonly number[], version: number): number[] {
  const blocks = BLOCKS[version];
  const eccLength = ECC_PER_BLOCK[version];
  const raw = Math.floor(rawDataModules(version) / 8);
  const shortBlocks = blocks - (raw % blocks);
  const shortLength = Math.floor(raw / blocks) - eccLength;
  const generator = divisor(eccLength);
  const dataBlocks: number[][] = [];
  const eccBlocks: number[][] = [];
  for (let i = 0, at = 0; i < blocks; i++) {
    const length = shortLength + (i < shortBlocks ? 0 : 1);
    const block = data.slice(at, at + length);
    at += length;
    dataBlocks.push(block);
    eccBlocks.push(remainder(block, generator));
  }
  const out: number[] = [];
  for (let i = 0; i <= shortLength; i++) {
    for (const block of dataBlocks) if (i < block.length) out.push(block[i]);
  }
  for (let i = 0; i < eccLength; i++) {
    for (const block of eccBlocks) out.push(block[i]);
  }
  return out;
}

function alignmentPositions(version: number): number[] {
  if (version === 1) return [];
  const count = Math.floor(version / 7) + 2;
  const step = Math.floor((version * 8 + count * 3 + 5) / (count * 4 - 4)) * 2;
  const result = [6];
  for (let position = version * 4 + 10; result.length < count; position -= step) {
    result.splice(1, 0, position);
  }
  return result;
}

const MASKS: Array<(x: number, y: number) => boolean> = [
  (x, y) => (x + y) % 2 === 0,
  (_x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

/** The standard's penalty score: lower is easier to scan. */
function penalty(modules: boolean[][]): number {
  const size = modules.length;
  let result = 0;
  const lines = [
    ...modules,
    ...modules.map((_, x) => modules.map((row) => row[x])),
  ];
  for (const line of lines) {
    // Runs of five or more of one colour.
    for (let i = 0, run = 1; i < size; i++, run++) {
      if (i + 1 === size || line[i + 1] !== line[i]) {
        if (run >= 5) result += run - 2;
        run = 0;
      }
    }
    // Finder-like patterns: 1011101 with four light modules on either side.
    const text = line.map((dark) => (dark ? "1" : "0")).join("");
    for (const pattern of ["10111010000", "00001011101"]) {
      for (let at = text.indexOf(pattern); at >= 0; at = text.indexOf(pattern, at + 1)) {
        result += 40;
      }
    }
  }
  let dark = 0;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (modules[y][x]) dark++;
      // 2x2 blocks of one colour.
      if (
        x + 1 < size && y + 1 < size && modules[y][x] === modules[y][x + 1] &&
        modules[y][x] === modules[y + 1][x] && modules[y][x] === modules[y + 1][x + 1]
      ) result += 3;
    }
  }
  // The share of dark modules, in steps of 5% away from half.
  result += Math.floor(Math.abs((dark * 20) / (size * size) - 10)) * 10;
  return result;
}

/** Encode bytes as a QR Code at error correction level M, in the smallest version that fits. */
export function encodeQr(bytes: Uint8Array): QrMatrix {
  let version = 1;
  while (capacity(version) < bytes.length) {
    if (++version > 40) throw new RangeError("too long for a QR code");
  }
  const size = version * 4 + 17;
  const modules = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const reserved = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const set = (x: number, y: number, dark: boolean) => {
    modules[y][x] = dark;
    reserved[y][x] = true;
  };

  // Timing patterns.
  for (let i = 0; i < size; i++) {
    set(6, i, i % 2 === 0);
    set(i, 6, i % 2 === 0);
  }
  // Finder patterns with their separators.
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx;
        const y = cy + dy;
        const distance = Math.max(Math.abs(dx), Math.abs(dy));
        if (x >= 0 && x < size && y >= 0 && y < size) set(x, y, distance !== 2 && distance !== 4);
      }
    }
  }
  // Alignment patterns, except where the finders are.
  const positions = alignmentPositions(version);
  const last = positions.length - 1;
  positions.forEach((cy, i) =>
    positions.forEach((cx, j) => {
      if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) return;
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) {
          set(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
        }
      }
    })
  );

  const drawFormat = (mask: number) => {
    const data = (FORMAT_LEVEL_M << 3) | mask;
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const bits = ((data << 10) | rem) ^ 0x5412;
    const bit = (i: number) => ((bits >>> i) & 1) !== 0;
    for (let i = 0; i <= 5; i++) set(8, i, bit(i));
    set(8, 7, bit(6));
    set(8, 8, bit(7));
    set(7, 8, bit(8));
    for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
    for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));
    set(8, size - 8, true);
  };
  drawFormat(0);
  if (version >= 7) {
    let rem = version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) !== 0;
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      set(a, b, dark);
      set(b, a, dark);
    }
  }

  // The codewords, in the zigzag from the bottom right corner.
  const stream = interleave(codewords(bytes, version), version);
  let index = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let step = 0; step < size; step++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - step : step;
        if (reserved[y][x] || index >= stream.length * 8) continue;
        modules[y][x] = ((stream[index >>> 3] >>> (7 - (index & 7))) & 1) !== 0;
        index++;
      }
    }
  }

  const applyMask = (mask: number) => {
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        if (!reserved[y][x] && MASKS[mask](x, y)) modules[y][x] = !modules[y][x];
      }
    }
  };
  let best = 0;
  let lowest = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    applyMask(mask);
    drawFormat(mask);
    const score = penalty(modules);
    if (score < lowest) {
      lowest = score;
      best = mask;
    }
    applyMask(mask); // XOR again: undone.
  }
  applyMask(best);
  drawFormat(best);
  return { size, version, modules };
}

/** The dark modules as one SVG path, with `quiet` light modules around them. */
export function qrPath(matrix: QrMatrix, quiet = 4): { d: string; viewBox: string } {
  const parts: string[] = [];
  matrix.modules.forEach((row, y) => {
    for (let x = 0; x < matrix.size; x++) {
      if (!row[x]) continue;
      let run = 1;
      while (x + run < matrix.size && row[x + run]) run++;
      parts.push(`M${x + quiet} ${y + quiet}h${run}v1h-${run}z`);
      x += run;
    }
  });
  const side = matrix.size + 2 * quiet;
  return { d: parts.join(""), viewBox: `0 0 ${side} ${side}` };
}
