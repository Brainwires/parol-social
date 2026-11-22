// Received files at rest (src/engine/sealed-files.ts): what a store is given is ciphertext,
// what comes back is what went in, and anything changed, cut short, reordered or moved is
// refused. Real WebCrypto, the in-memory store.
import { assert, assertEquals, assertNotEquals, assertRejects } from "@std/assert";
import { MemoryFileStore } from "../../src/engine/files.ts";
import {
  chunkRange,
  FILE_FORMAT,
  FILE_KEY_BYTES,
  type FileCrypto,
  FileSealError,
  openChunk,
  sealChunk,
  SealedFiles,
  SEGMENT_HEADER_BYTES,
  segmentKey,
} from "../../src/engine/sealed-files.ts";

/** Small chunks: the tests are about the form, not about 64 KiB. */
const CHUNK = 1000;
const TAG = 16;
const ID = "0123456789abcdef0123456789abcdef";
const OTHER_ID = "fedcba9876543210fedcba9876543210";

const cryptoOf = (): FileCrypto => ({
  subtle: crypto.subtle,
  random: (n) => crypto.getRandomValues(new Uint8Array(n)),
});

function bytes(size: number, seed = 1): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(size);
  let x = (0x9e3779b9 ^ seed) >>> 0;
  for (let i = 0; i < size; i++) {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    out[i] = x & 0xff;
  }
  return out;
}

function sealed(store = new MemoryFileStore()): { files: SealedFiles; store: MemoryFileStore } {
  return { files: new SealedFiles(store, cryptoOf(), () => CHUNK), store };
}

/** Write `data` as segment `index`, one chunk per `write`. */
async function writeSegment(
  files: SealedFiles,
  id: string,
  index: number,
  key: Uint8Array,
  data: Uint8Array,
): Promise<void> {
  const writer = await files.writer(id, index, key);
  for (let at = 0; at < data.length; at += CHUNK) {
    await writer.write(data.subarray(at, Math.min(data.length, at + CHUNK)));
  }
  await writer.close();
}

/** Put `stored` in place of segment `index`, as someone with the disk would. */
async function replaceRaw(
  store: MemoryFileStore,
  id: string,
  index: number,
  stored: Uint8Array,
): Promise<void> {
  const writer = await store.writer(id, index);
  await writer.write(stored);
  await writer.close();
}

function includes(haystack: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

async function refused(run: () => Promise<unknown>): Promise<void> {
  await assertRejects(run, FileSealError);
}

Deno.test("sealed files: a segment comes back as written, and the store holds ciphertext", async () => {
  const { files, store } = sealed();
  const key = files.newKey();
  assertEquals(key.length, FILE_KEY_BYTES);
  for (const size of [1, CHUNK - 1, CHUNK, CHUNK + 1, 5 * CHUNK, 5 * CHUNK + 321]) {
    const data = bytes(size, size);
    await writeSegment(files, ID, 0, key, data);
    assertEquals(await files.readSegment(ID, 0, key), data, `${size} bytes`);
    const stored = await store.readSegment(ID, 0);
    const chunks = Math.ceil(size / CHUNK);
    assertEquals(stored.length, SEGMENT_HEADER_BYTES + size + chunks * TAG);
    assertEquals(stored[0], FILE_FORMAT);
    // Nothing of the file is in what is stored.
    for (let at = 0; at + 16 <= size; at += 97) {
      assert(!includes(stored, data.subarray(at, at + 16)), `plaintext at ${at}`);
    }
  }
  // The one record of an empty file: a chunk that is a tag and nothing else.
  const writer = await files.writer(OTHER_ID, 0, key);
  await writer.write(new Uint8Array(0));
  await writer.close();
  assertEquals((await store.readSegment(OTHER_ID, 0)).length, SEGMENT_HEADER_BYTES + TAG);
  assertEquals((await files.readSegment(OTHER_ID, 0, key)).length, 0);
  assertEquals((await files.blob(OTHER_ID, 1, "", key)).size, 0);
});

Deno.test("sealed files: the same bytes written twice are stored differently", async () => {
  const { files, store } = sealed();
  const key = files.newKey();
  const data = bytes(3 * CHUNK);
  await writeSegment(files, ID, 0, key, data);
  const first = await store.readSegment(ID, 0);
  await writeSegment(files, ID, 0, key, data);
  const second = await store.readSegment(ID, 0);
  // A new salt, so a new key: no key and nonce is ever used for two writes.
  assertNotEquals(first.slice(1, SEGMENT_HEADER_BYTES), second.slice(1, SEGMENT_HEADER_BYTES));
  assertNotEquals(first.slice(SEGMENT_HEADER_BYTES), second.slice(SEGMENT_HEADER_BYTES));
  assertEquals(await files.readSegment(ID, 0, key), data);
});

Deno.test("sealed files: a changed byte anywhere is refused", async () => {
  const { files, store } = sealed();
  const key = files.newKey();
  const data = bytes(3 * CHUNK + 10);
  await writeSegment(files, ID, 0, key, data);
  const good = await store.readSegment(ID, 0);
  // The format byte, the salt, a chunk's body, a chunk's tag, the last byte.
  for (const at of [0, 1, 16, SEGMENT_HEADER_BYTES, 500, CHUNK + 20, good.length - 1]) {
    const bad = good.slice();
    bad[at] ^= 0x01;
    await replaceRaw(store, ID, 0, bad);
    await refused(() => files.readSegment(ID, 0, key));
  }
  await replaceRaw(store, ID, 0, good);
  assertEquals(await files.readSegment(ID, 0, key), data);
});

Deno.test("sealed files: a segment cut short or continued is refused", async () => {
  const { files, store } = sealed();
  const key = files.newKey();
  const data = bytes(4 * CHUNK);
  await writeSegment(files, ID, 0, key, data);
  const good = await store.readSegment(ID, 0);
  const frame = CHUNK + TAG;
  // Cut at a chunk boundary (the chunks that remain are genuine), inside a chunk, down to
  // the header, and to nothing.
  for (
    const length of [
      SEGMENT_HEADER_BYTES + 3 * frame,
      SEGMENT_HEADER_BYTES + frame,
      SEGMENT_HEADER_BYTES + 3 * frame + 40,
      good.length - 1,
      SEGMENT_HEADER_BYTES,
      1,
    ]
  ) {
    await replaceRaw(store, ID, 0, good.slice(0, length));
    await refused(() => files.readSegment(ID, 0, key));
  }
  // Continued: a genuine chunk of the same segment appended after its last one.
  const longer = new Uint8Array(good.length + frame);
  longer.set(good);
  longer.set(good.subarray(SEGMENT_HEADER_BYTES, SEGMENT_HEADER_BYTES + frame), good.length);
  await replaceRaw(store, ID, 0, longer);
  await refused(() => files.readSegment(ID, 0, key));
});

Deno.test("sealed files: chunks in another order, or of another place, are refused", async () => {
  const { files, store } = sealed();
  const key = files.newKey();
  const data = bytes(4 * CHUNK);
  await writeSegment(files, ID, 0, key, data);
  const good = await store.readSegment(ID, 0);
  const frame = CHUNK + TAG;
  const first = chunkRange(CHUNK, 0);
  const second = chunkRange(CHUNK, 1);
  assertEquals([first.start, first.end, second.start], [
    SEGMENT_HEADER_BYTES,
    SEGMENT_HEADER_BYTES + frame,
    SEGMENT_HEADER_BYTES + frame,
  ]);
  // Chunks 0 and 1 swapped.
  const swapped = good.slice();
  swapped.set(good.subarray(second.start, second.end), first.start);
  swapped.set(good.subarray(first.start, first.end), second.start);
  await replaceRaw(store, ID, 0, swapped);
  await refused(() => files.readSegment(ID, 0, key));

  // The whole segment at another index, in another transfer, or under another key.
  await replaceRaw(store, ID, 0, good);
  await replaceRaw(store, ID, 1, good);
  assertEquals(await files.readSegment(ID, 0, key), data);
  await refused(() => files.readSegment(ID, 1, key));
  await replaceRaw(store, OTHER_ID, 0, good);
  await refused(() => files.readSegment(OTHER_ID, 0, key));
  await refused(() => files.readSegment(ID, 0, files.newKey()));
});

Deno.test("sealed files: a chunk opens only at its own index, and can be read on its own", async () => {
  const { files, store } = sealed();
  const key = files.newKey();
  const data = bytes(3 * CHUNK + 77);
  await writeSegment(files, ID, 0, key, bytes(CHUNK, 8));
  await writeSegment(files, ID, 1, key, bytes(CHUNK, 9));
  await writeSegment(files, ID, 2, key, data);
  const stored = await store.readSegment(ID, 2);
  const subtle = crypto.subtle;
  const segKey = await segmentKey(subtle, key, ID, 2, stored.subarray(1, SEGMENT_HEADER_BYTES));

  // Random access: chunk 2 without the chunks before it.
  const at = chunkRange(CHUNK, 2);
  const chunk = stored.subarray(at.start, at.end);
  assertEquals(
    await openChunk(subtle, segKey, 2, chunk, false),
    data.subarray(2 * CHUNK, 3 * CHUNK),
  );
  // The wrong index, and the wrong claim about being the last.
  await refused(() => openChunk(subtle, segKey, 1, chunk, false));
  await refused(() => openChunk(subtle, segKey, 3, chunk, false));
  await refused(() => openChunk(subtle, segKey, 2, chunk, true));
  // The last chunk is short, and is the last.
  const tail = chunkRange(CHUNK, 3);
  const lastChunk = stored.subarray(tail.start, Math.min(tail.end, stored.length));
  assertEquals(lastChunk.length, 77 + TAG);
  assertEquals(await openChunk(subtle, segKey, 3, lastChunk, true), data.subarray(3 * CHUNK));
  await refused(() => openChunk(subtle, segKey, 3, lastChunk, false));
  // The key of another segment, or of another transfer, opens nothing.
  const salt = stored.subarray(1, SEGMENT_HEADER_BYTES);
  for (
    const other of [
      await segmentKey(subtle, key, ID, 1, salt),
      await segmentKey(subtle, key, OTHER_ID, 2, salt),
    ]
  ) {
    await refused(() => openChunk(subtle, other, 2, chunk, false));
  }
  // And sealing is the inverse.
  const again = await sealChunk(subtle, segKey, 2, data.subarray(2 * CHUNK, 3 * CHUNK), false);
  assertEquals(again, chunk);
});

Deno.test("sealed files: resume after a part that did not finish", async () => {
  const { files, store } = sealed();
  const key = files.newKey();
  const first = bytes(4 * CHUNK, 1);
  const second = bytes(2 * CHUNK + 5, 2);
  await writeSegment(files, ID, 0, key, first);

  // The second segment is under way when the page goes: two chunks written, never closed.
  const lost = await files.writer(ID, 1, key);
  await lost.write(second.subarray(0, CHUNK));
  await lost.write(second.subarray(CHUNK, 2 * CHUNK));
  assertEquals(await files.segments(ID), 1, "an unfinished segment is not stored");

  // After the reload: a new view of the same store, the key from the transfer's row.
  const later = sealed(store).files;
  assertEquals(await later.segments(ID), 1);
  assertEquals(await later.readSegment(ID, 0, key), first);
  await writeSegment(later, ID, 1, key, second);
  assertEquals(await later.segments(ID), 2);
  assertEquals(await later.readSegment(ID, 1, key), second);

  const whole = new Uint8Array(await (await later.blob(ID, 2, "text/plain", key)).arrayBuffer());
  const expected = new Uint8Array(first.length + second.length);
  expected.set(first);
  expected.set(second, first.length);
  assertEquals(whole, expected);
  assertEquals((await later.blob(ID, 2, "text/plain", key)).type, "text/plain");
  // More segments than are stored, or one that was changed: no file.
  await refused(() => later.blob(ID, 3, "", key));
  const stored = await store.readSegment(ID, 1);
  stored[40] ^= 0x80;
  await replaceRaw(store, ID, 1, stored);
  await refused(() => later.blob(ID, 2, "", key));
  assertEquals(await later.readSegment(ID, 0, key), first, "the other segment still opens");
});

Deno.test("sealed files: a segment written again from an index drops what followed", async () => {
  const { files } = sealed();
  const key = files.newKey();
  await writeSegment(files, ID, 0, key, bytes(CHUNK, 1));
  await writeSegment(files, ID, 1, key, bytes(CHUNK, 2));
  await writeSegment(files, ID, 2, key, bytes(CHUNK, 3));
  const again = bytes(2 * CHUNK, 4);
  await writeSegment(files, ID, 1, key, again);
  assertEquals(await files.segments(ID), 2);
  assertEquals(await files.readSegment(ID, 1, key), again);
  await files.remove(ID);
  assertEquals(await files.segments(ID), 0);
});

Deno.test("sealed files: what a writer refuses", async () => {
  const { files, store } = sealed();
  const key = files.newKey();
  // A short chunk (an empty one too) may only be the last; an oversized one is never written.
  const writer = await files.writer(ID, 0, key);
  await refused(() => writer.write(new Uint8Array(CHUNK + 1)));
  await writer.write(bytes(CHUNK - 1));
  await refused(() => writer.write(bytes(CHUNK)));
  await writer.abort();
  assertEquals(await files.segments(ID), 0);
  const afterEmpty = await files.writer(ID, 0, key);
  await afterEmpty.write(new Uint8Array(0));
  await refused(() => afterEmpty.write(bytes(1)));
  await afterEmpty.abort();
  assertEquals(await files.segments(ID), 0);
  // A segment without a chunk is not a segment.
  const empty = await files.writer(ID, 0, key);
  await refused(() => empty.close());
  assertEquals(await files.segments(ID), 0);
  // Closed is closed.
  const done = await files.writer(ID, 0, key);
  await done.write(bytes(10));
  await done.close();
  await refused(() => done.write(bytes(10)));
  // Keys and ids of the wrong form.
  await refused(() => files.writer(ID, 0, new Uint8Array(16)));
  await refused(() => files.writer("../x", 0, key));
  await refused(() => files.readSegment(ID, 0, new Uint8Array(31)));
  // A failing store fails the write (a full disk), and nothing is counted.
  const full = await files.writer(OTHER_ID, 0, key);
  await full.write(bytes(CHUNK));
  store.failNextWrite = true;
  await assertRejects(() => full.write(bytes(CHUNK)));
  await full.abort();
  assertEquals(await files.segments(OTHER_ID), 0);
});
