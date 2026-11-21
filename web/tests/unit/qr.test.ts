import { assert, assertEquals, assertThrows } from "@std/assert";
import { capacity, encodeQr, type QrMatrix, qrPath } from "../../src/qr/encode.ts";

type JsQr = (
  data: Uint8ClampedArray,
  width: number,
  height: number,
  options?: { inversionAttempts?: string },
) => { data: string; binaryData: number[]; version: number } | null;

/** The decoder the scanner falls back to (public/vendor/jsqr.js, a UMD file). */
async function jsQr(): Promise<JsQr> {
  await import("../../public/vendor/jsqr.js");
  return (globalThis as unknown as { jsQR: JsQr }).jsQR;
}

/** The matrix as an image: `scale` pixels per module, four light modules around it. */
function rasterise(matrix: QrMatrix, scale: number): { data: Uint8ClampedArray; side: number } {
  const quiet = 4;
  const side = (matrix.size + 2 * quiet) * scale;
  const data = new Uint8ClampedArray(side * side * 4).fill(255);
  for (let y = 0; y < matrix.size; y++) {
    for (let x = 0; x < matrix.size; x++) {
      if (!matrix.modules[y][x]) continue;
      for (let dy = 0; dy < scale; dy++) {
        for (let dx = 0; dx < scale; dx++) {
          const at = (((y + quiet) * scale + dy) * side + (x + quiet) * scale + dx) * 4;
          data[at] = data[at + 1] = data[at + 2] = 0;
        }
      }
    }
  }
  return { data, side };
}

function hex(length: number, seed: number): string {
  let state = seed;
  let out = "";
  while (out.length < length) {
    state = (state * 1103515245 + 12345) >>> 0;
    out += (state >>> 16).toString(16).padStart(4, "0");
  }
  return out.slice(0, length);
}

Deno.test("qr: a pairing code survives encoding and the scanner's decoder", async () => {
  const decode = await jsQr();
  // A pairing code is a couple of hundred hex characters.
  for (const length of [1, 64, 180, 220, 300]) {
    const text = hex(length, length);
    const matrix = encodeQr(new TextEncoder().encode(text));
    const image = rasterise(matrix, 4);
    assertEquals(decode(image.data, image.side, image.side)?.data, text, `${length} characters`);
  }
});

Deno.test("qr: a real-length pairing code, at the size a phone shows it, decodes", async () => {
  const decode = await jsQr();
  // About 170 bytes as hex (the longest, with a relay address in it). The screen draws the
  // code 17rem (272px) wide with its quiet zone.
  const text = hex(344, 7);
  const matrix = encodeQr(new TextEncoder().encode(text));
  const pixelsPerModule = 272 / (matrix.size + 2 * 4);
  assert(pixelsPerModule >= 3, `${pixelsPerModule.toFixed(2)}px per module`);
  const image = rasterise(matrix, 3);
  assertEquals(decode(image.data, image.side, image.side)?.data, text);
});

Deno.test("qr: every version, filled to capacity, decodes", async () => {
  const decode = await jsQr();
  for (let version = 1; version <= 40; version++) {
    const text = hex(capacity(version), version);
    const matrix = encodeQr(new TextEncoder().encode(text));
    assertEquals(matrix.version, version);
    assertEquals(matrix.size, version * 4 + 17);
    const image = rasterise(matrix, 4);
    const result = decode(image.data, image.side, image.side, { inversionAttempts: "dontInvert" });
    assertEquals(result?.data, text, `version ${version}`);
    assertEquals(result?.version, version);
  }
});

Deno.test("qr: one byte over a version's capacity moves to the next version", () => {
  assertEquals(capacity(1), 14);
  assertEquals(capacity(10), 213);
  assertEquals(capacity(40), 2331);
  assertEquals(encodeQr(new Uint8Array(14)).version, 1);
  assertEquals(encodeQr(new Uint8Array(15)).version, 2);
  assertThrows(() => encodeQr(new Uint8Array(2332)), RangeError);
});

Deno.test("qr: arbitrary bytes round-trip", async () => {
  const decode = await jsQr();
  const bytes = Uint8Array.from({ length: 200 }, (_, i) => (i * 37 + 11) & 0xff);
  const image = rasterise(encodeQr(bytes), 4);
  assertEquals(decode(image.data, image.side, image.side)?.binaryData, [...bytes]);
});

Deno.test("qr: the path draws exactly the dark modules, inside a quiet zone", () => {
  const matrix = encodeQr(new TextEncoder().encode("parolnet"));
  const { d, viewBox } = qrPath(matrix);
  assertEquals(viewBox, `0 0 ${matrix.size + 8} ${matrix.size + 8}`);
  let drawn = 0;
  for (const [, x, y, run] of d.matchAll(/M(\d+) (\d+)h(\d+)v1h-\d+z/g)) {
    assert(Number(x) >= 4 && Number(y) >= 4);
    drawn += Number(run);
  }
  assertEquals(drawn, matrix.modules.flat().filter(Boolean).length);
});
