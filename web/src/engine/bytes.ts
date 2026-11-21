// Hex, UTF-8 and the little CBOR the engine has to read itself: the pairing code's public
// fields (PNP-003) and an envelope's cleartext `source_hint` (PNP-001 §3.2). Everything
// secret stays inside wasm; nothing here handles key material.

const HEX = "0123456789abcdef";

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += HEX[b >> 4] + HEX[b & 15];
  return out;
}

export function isHex(s: string): boolean {
  return s.length % 2 === 0 && /^[0-9a-fA-F]*$/.test(s);
}

/** Decode hex; `null` when it is not hex. */
export function fromHex(s: string): Uint8Array | null {
  if (!isHex(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: false });

export function utf8(s: string): Uint8Array {
  return encoder.encode(s);
}

/** Lossy, like the native core's `from_utf8_lossy`. */
export function fromUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

/** Overwrite a buffer we own. Strings cannot be wiped in JavaScript. */
export function wipe(bytes: Uint8Array | null | undefined): void {
  bytes?.fill(0);
}

// ── CBOR (decode only; the subset ciborium emits for these structures) ──

export type Cbor =
  | number
  | bigint
  | string
  | Uint8Array
  | boolean
  | null
  | Cbor[]
  | Map<Cbor, Cbor>;

class Reader {
  at = 0;
  constructor(readonly buf: Uint8Array, readonly maxDepth = 8) {}

  private byte(): number {
    if (this.at >= this.buf.length) throw new Error("truncated");
    return this.buf[this.at++];
  }

  private arg(info: number): number {
    if (info < 24) return info;
    if (info === 24) return this.byte();
    let n = 0;
    const len = info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : -1;
    if (len < 0) throw new Error("unsupported length");
    for (let i = 0; i < len; i++) n = n * 256 + this.byte();
    if (!Number.isSafeInteger(n)) throw new Error("integer too large");
    return n;
  }

  item(depth = 0): Cbor {
    if (depth > this.maxDepth) throw new Error("too deep");
    const head = this.byte();
    const major = head >> 5;
    const info = head & 31;
    switch (major) {
      case 0:
        return this.arg(info);
      case 1:
        return -1 - this.arg(info);
      case 2:
      case 3: {
        const len = this.arg(info);
        if (this.at + len > this.buf.length) throw new Error("truncated");
        const slice = this.buf.subarray(this.at, this.at + len);
        this.at += len;
        return major === 2 ? slice.slice() : fromUtf8(slice);
      }
      case 4: {
        const len = this.arg(info);
        if (len > this.buf.length) throw new Error("truncated");
        const out: Cbor[] = [];
        for (let i = 0; i < len; i++) out.push(this.item(depth + 1));
        return out;
      }
      case 5: {
        const len = this.arg(info);
        if (len > this.buf.length) throw new Error("truncated");
        const out = new Map<Cbor, Cbor>();
        for (let i = 0; i < len; i++) {
          const k = this.item(depth + 1);
          out.set(k, this.item(depth + 1));
        }
        return out;
      }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22 || info === 23) return null;
        throw new Error("unsupported simple value");
      default:
        throw new Error("unsupported major type");
    }
  }
}

/** Decode the first CBOR item of `bytes`. Throws on anything outside the subset. */
export function cborDecode(bytes: Uint8Array): Cbor {
  return new Reader(bytes).item();
}

/** The public fields of a PNP-003 pairing code. */
export interface PairingPayload {
  /** The presenter's Ed25519 identity key, hex. */
  identityKey: string;
  /** Seconds since the epoch, floored to 300 s by the presenter. */
  ts: number;
}

/** A pairing code is valid for this long after its `ts` (parolnet-core `QR_MAX_AGE_SECS`). */
export const PAIRING_CODE_LIFETIME_SECS = 1800;

/**
 * Read the public fields of a pairing code (`{v:1, ik, seed, rk, relay, ts, net}`). `null`
 * when it is not one. The seed is read past, never kept.
 */
export function parsePairingCode(codeHex: string): PairingPayload | null {
  const bytes = fromHex(codeHex);
  if (!bytes) return null;
  try {
    const v = cborDecode(bytes);
    if (!(v instanceof Map)) return null;
    const ik = v.get("ik");
    const ts = v.get("ts");
    if (v.get("v") !== 1 || !(ik instanceof Uint8Array) || ik.length !== 32) {
      return null;
    }
    if (typeof ts !== "number" || ts < 0) return null;
    return { identityKey: toHex(ik), ts };
  } catch {
    return null;
  } finally {
    wipe(bytes);
  }
}

/**
 * The cleartext `source_hint` of an envelope (hex), or `null` when it has none or is
 * malformed. An envelope is the CBOR array `[cleartext_header, ratchet_header, ciphertext,
 * padding]`; the header is `[version, msg_type, dest, message_id, timestamp, ttl_hops,
 * source_hint | null]`. On the scanner's bootstrap envelope the hint is its Ed25519 identity
 * key (PNP-001-MUST-063).
 */
export function envelopeSourceHint(envelopeHex: string): string | null {
  // The header sits in the first few hundred bytes; never decode the whole padded frame.
  const head = fromHex(envelopeHex.slice(0, 1024));
  if (!head || head.length < 4 || head[0] !== 0x84) return null;
  try {
    const reader = new Reader(head.subarray(1));
    const header = reader.item();
    if (!Array.isArray(header) || header.length !== 7) return null;
    const hint = header[6];
    return hint instanceof Uint8Array && hint.length === 32 ? toHex(hint) : null;
  } catch {
    return null;
  }
}
