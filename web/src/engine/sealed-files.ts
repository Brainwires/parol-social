// Received files, encrypted at rest (docs/web-port/at-rest.md, "Received files"). The
// engine's transfers write and read through `SealedFiles`; the `FileStore` underneath (OPFS,
// or memory where the browser has no writable OPFS) only ever sees ciphertext.
//
// Each transfer has a key of its own: 32 random bytes kept in the transfer's row, which is
// sealed like every other row (./vault.ts). So a file is readable exactly when the database
// is: not while the app is locked, and a change of the storage keys carries the file keys
// along with the rows without touching the files.
//
// A stored segment is
//
//   0x01 | salt (16 bytes) | chunk 0 | chunk 1 | … | chunk n-1
//
// - The segment's key is HKDF-SHA-256(file key, salt, info) as an AES-256-GCM key, where
//   info = "parolnet-web-file" ‖ 0x00 ‖ format ‖ transfer id (32 hex digits) ‖ segment index
//   (4 bytes, big-endian). The salt is new every time a segment is written, so a segment that
//   is written again (an attempt that did not finish, a file started over) never reuses a
//   key and nonce pair, whatever the sender sends the second time.
// - Chunk j is AES-256-GCM of one record's plaintext: nonce = 4 zero bytes ‖ j (8 bytes,
//   big-endian), associated data = one byte, 1 for the last chunk of the segment and 0 for
//   every other. Every chunk but the last holds exactly `chunkSize` bytes, so chunk j starts
//   at byte 17 + j × (chunkSize + 16) and can be read without the ones before it. (The one
//   record of an empty file is an empty chunk: a tag and nothing else.)
//
// What is detected: a changed byte (the tag); chunks in another order or a chunk of another
// segment or transfer (the nonce and the key); a segment cut short or continued (the last
// chunk's flag); segments in another order (the key). How many segments a file has, and how
// many records each holds, is in the transfer's sealed row.
import { utf8 } from "./bytes.ts";
import type { FileStore, SegmentWriter } from "./platform.ts";

/** The format of a stored segment (its first byte). */
export const FILE_FORMAT = 1;
/** A transfer's storage key: this many random bytes. */
export const FILE_KEY_BYTES = 32;
const SALT_BYTES = 16;
const TAG_BYTES = 16;
/** Format byte and salt. */
export const SEGMENT_HEADER_BYTES = 1 + SALT_BYTES;

/** WebCrypto and randomness, as the platform gives them. */
export interface FileCrypto {
  subtle: SubtleCrypto;
  /** Cryptographically strong bytes. */
  random(n: number): Uint8Array;
}

/** A stored segment that cannot be read: changed, cut short, moved, or of another format. */
export class FileSealError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FileSealError";
  }
}

// The buffer type WebCrypto wants (`BufferSource` over an `ArrayBuffer`).
const buf = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => bytes as Uint8Array<ArrayBuffer>;

function checkId(id: string): void {
  if (!/^[0-9a-f]{32}$/.test(id)) throw new FileSealError("bad transfer id");
}

/** Where chunk `index` of a segment lies in its stored bytes (the last chunk may end earlier). */
export function chunkRange(chunkSize: number, index: number): { start: number; end: number } {
  const start = SEGMENT_HEADER_BYTES + index * (chunkSize + TAG_BYTES);
  return { start, end: start + chunkSize + TAG_BYTES };
}

/**
 * The key of one written segment: HKDF-SHA-256 over the transfer's storage key with the
 * segment's salt, bound to the format, the transfer and the segment's place in it.
 */
export async function segmentKey(
  subtle: SubtleCrypto,
  fileKey: Uint8Array,
  id: string,
  segment: number,
  salt: Uint8Array,
): Promise<CryptoKey> {
  checkId(id);
  if (fileKey.length !== FILE_KEY_BYTES || salt.length !== SALT_BYTES) {
    throw new FileSealError("bad key or salt");
  }
  if (!Number.isInteger(segment) || segment < 0 || segment > 0xffff_ffff) {
    throw new FileSealError("bad segment index");
  }
  const label = utf8("parolnet-web-file");
  const info = new Uint8Array(label.length + 2 + 32 + 4);
  info.set(label);
  info[label.length] = 0;
  info[label.length + 1] = FILE_FORMAT;
  info.set(utf8(id), label.length + 2);
  new DataView(info.buffer).setUint32(label.length + 2 + 32, segment);
  const base = await subtle.importKey("raw", buf(fileKey), "HKDF", false, ["deriveKey"]);
  return await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: buf(salt), info: buf(info) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function chunkParams(index: number, last: boolean): AesGcmParams {
  if (!Number.isInteger(index) || index < 0 || index > 0xffff_ffff) {
    throw new FileSealError("bad chunk index");
  }
  const nonce = new Uint8Array(12);
  new DataView(nonce.buffer).setUint32(8, index);
  return { name: "AES-GCM", iv: nonce, additionalData: new Uint8Array([last ? 1 : 0]) };
}

/** Chunk `index` of a segment, sealed. `last`: no chunk follows it in the segment. */
export async function sealChunk(
  subtle: SubtleCrypto,
  key: CryptoKey,
  index: number,
  plain: Uint8Array,
  last: boolean,
): Promise<Uint8Array> {
  return new Uint8Array(await subtle.encrypt(chunkParams(index, last), key, buf(plain)));
}

/** The plaintext of chunk `index`. Rejects with `FileSealError` when it is not that chunk. */
export async function openChunk(
  subtle: SubtleCrypto,
  key: CryptoKey,
  index: number,
  sealed: Uint8Array,
  last: boolean,
): Promise<Uint8Array> {
  if (sealed.length < TAG_BYTES) throw new FileSealError("a stored chunk is cut short");
  try {
    return new Uint8Array(await subtle.decrypt(chunkParams(index, last), key, buf(sealed)));
  } catch {
    throw new FileSealError("a stored chunk does not decrypt");
  }
}

/**
 * The transfers' view of a `FileStore`: the same segments, sealed under each transfer's
 * storage key. `chunkSize` is the size of every chunk but a segment's last (a PNP-010
 * record's plaintext).
 */
export class SealedFiles {
  constructor(
    private readonly raw: FileStore,
    private readonly crypto: FileCrypto,
    private readonly chunkSize: () => number,
  ) {}

  /** Stored parts survive a reload (OPFS), or not (memory). */
  get persistent(): boolean {
    return this.raw.persistent;
  }

  /** A storage key for a new transfer. It belongs in the transfer's (sealed) row. */
  newKey(): Uint8Array {
    const key = this.crypto.random(FILE_KEY_BYTES);
    if (key.length !== FILE_KEY_BYTES) throw new FileSealError("no randomness");
    return key;
  }

  /** How many segments 0..n-1 are stored for a transfer. */
  segments(id: string): Promise<number> {
    return this.raw.segments(id);
  }

  /**
   * Start segment `index` (dropping any stored segment from `index` on). Each `write` is one
   * chunk: exactly `chunkSize` bytes, except the last before `close`, which may be shorter
   * (and empty, as the one record of an empty file is). A chunk is sealed when
   * the next one (or `close`) says whether it is the last, so a segment is stored, and
   * readable, only once it is closed.
   */
  async writer(id: string, index: number, fileKey: Uint8Array): Promise<SegmentWriter> {
    const { subtle } = this.crypto;
    const size = this.chunkSize();
    const salt = this.crypto.random(SALT_BYTES);
    const key = await segmentKey(subtle, fileKey, id, index, salt);
    const out = await this.raw.writer(id, index);
    const header = new Uint8Array(SEGMENT_HEADER_BYTES);
    header[0] = FILE_FORMAT;
    header.set(salt, 1);
    let headerWritten = false;
    let held: Uint8Array | null = null;
    let chunks = 0;
    let over = false;
    const flush = async (last: boolean): Promise<void> => {
      if (!held) return;
      const plain = held;
      held = null;
      try {
        if (!headerWritten) {
          await out.write(header);
          headerWritten = true;
        }
        await out.write(await sealChunk(subtle, key, chunks++, plain, last));
      } finally {
        plain.fill(0);
      }
    };
    return {
      write: async (chunk: Uint8Array): Promise<void> => {
        if (over) throw new FileSealError("the segment is closed");
        if (chunk.length > size) {
          throw new FileSealError("a chunk of the wrong size");
        }
        // Only a segment's last chunk may be short: the one held is not the last.
        if (held && held.length !== size) throw new FileSealError("a short chunk mid-segment");
        // The chunk is a view the caller may reuse: keep a copy until it is sealed.
        const copy = new Uint8Array(chunk);
        await flush(false);
        held = copy;
      },
      close: async (): Promise<void> => {
        if (over) throw new FileSealError("the segment is closed");
        over = true;
        if (!held) {
          await out.abort();
          throw new FileSealError("an empty segment");
        }
        await flush(true);
        await out.close();
      },
      abort: async (): Promise<void> => {
        over = true;
        held?.fill(0);
        held = null;
        await out.abort();
      },
    };
  }

  /**
   * The plaintext of segment `index`, every chunk verified. Rejects with `FileSealError`
   * when the segment was changed, cut short, continued, or belongs elsewhere.
   */
  async readSegment(id: string, index: number, fileKey: Uint8Array): Promise<Uint8Array> {
    const { subtle } = this.crypto;
    const size = this.chunkSize();
    const stored = await this.raw.readSegment(id, index);
    if (stored.length < SEGMENT_HEADER_BYTES + TAG_BYTES || stored[0] !== FILE_FORMAT) {
      throw new FileSealError("a stored segment is not in a form this app knows");
    }
    const key = await segmentKey(subtle, fileKey, id, index, stored.subarray(1, 1 + SALT_BYTES));
    const frame = size + TAG_BYTES;
    const body = stored.length - SEGMENT_HEADER_BYTES;
    const count = Math.ceil(body / frame);
    const out = new Uint8Array(body - count * TAG_BYTES);
    let at = 0;
    try {
      for (let j = 0; j < count; j++) {
        const { start, end } = chunkRange(size, j);
        const last = j === count - 1;
        const plain = await openChunk(
          subtle,
          key,
          j,
          stored.subarray(start, Math.min(end, stored.length)),
          last,
        );
        out.set(plain, at);
        at += plain.length;
        plain.fill(0);
      }
    } catch (error) {
      out.fill(0);
      throw error;
    }
    return out;
  }

  /**
   * Segments 0..count-1 decrypted into one Blob of the given MIME type, for the person to
   * save. The Blob is plaintext in the browser's hands for as long as it lives.
   */
  async blob(id: string, count: number, type: string, fileKey: Uint8Array): Promise<Blob> {
    if ((await this.raw.segments(id)) < count) throw new FileSealError("segments are missing");
    const parts: Blob[] = [];
    for (let n = 0; n < count; n++) {
      const plain = await this.readSegment(id, n, fileKey);
      // The Blob takes a copy; ours is wiped.
      parts.push(new Blob([buf(plain)]));
      plain.fill(0);
    }
    return new Blob(parts, { type });
  }

  remove(id: string): Promise<void> {
    return this.raw.remove(id);
  }

  /** Remove every stored part ("delete all data on this device"). */
  clear(): Promise<void> {
    return this.raw.clear();
  }
}
