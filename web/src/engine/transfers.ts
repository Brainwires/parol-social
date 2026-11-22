// File transfer (PNP-010) for the web engine. The protocol's rules and all cryptography are
// in parolnet-wasm (crates/parolnet-transfer through crates/parolnet-wasm/src/transfer.rs);
// this file keeps the transfers, stores what must survive a reload, talks to the data
// channel and reads or writes the file. crates/parolnet-app/src/engine/transfers.rs and
// transfer.rs are the reference: the names and the flow are the same.
//
// - The offer and the accept / decline / cancel / complete messages are FILE_TRANSFER (0x15)
//   envelopes on the contact's verified channel. One this device cannot send yet waits in
//   the transfer's row (`pending`) and goes out when the channel verifies.
// - The file flows as sealed 64 KiB records on its own data channel `pn-file/<id>`, opened
//   by the receiver. The sender reads the picked `File` slice by slice and pauses on the
//   channel's `bufferedAmount`; the receiver writes segments to a `FileStore` (OPFS where the
//   browser allows it) and never holds the file in memory. What it stores is sealed under a
//   key of the transfer's own, kept in its row (./sealed-files.ts; docs/web-port/at-rest.md).
// - After a lost connection the receiver opens a new channel and names the next record it
//   needs. After a reload a received part in OPFS is read back into the hash and continued;
//   a file being sent is gone with the page (a web page keeps no file handle), so that
//   transfer is cancelled with reason "unavailable" (PNP-010-MAY-001).
//
// Everything runs in the engine's mailbox except the sender's read-and-send loop, which
// re-enters it through `host.internal` for anything that changes a transfer.
import { fromHex, toHex } from "./bytes.ts";
import { MemoryFileStore } from "./files.ts";
import { SealedFiles } from "./sealed-files.ts";
import type {
  DataChannel,
  FileSource,
  Platform,
  SegmentWriter,
  TransferControl,
  TransferLimits,
  WasmOfferLimiter,
  WasmTransferReceiver,
  WasmTransferSender,
  WriteOp,
} from "./platform.ts";
import type { SettingRow } from "./storage.ts";
import {
  type AppEvent,
  type CancelReason,
  EngineError,
  shortId,
  type TransferInfo,
  type TransferState,
} from "./types.ts";

/** Records per stored segment: 16 MiB. Also how often a received part is made durable. */
export const SEGMENT_RECORDS = 256;
/** Records read from the file at once when sending (1 MiB). */
const READ_RECORDS = 16;
/** The file is hashed for the offer in pieces of this size. */
const HASH_PIECE = 4 << 20;
const PROGRESS_MS = 200;
/** The receiver's wait before another channel after an attempt that moved nothing. */
export const TRANSFER_RETRY_BASE_MS = 500;
export const TRANSFER_RETRY_MAX_MS = 30_000;
/** A channel we asked for must open within this long. */
export const TRANSFER_OPEN_TIMEOUT_MS = 15_000;
/** The sender's wait for RESUME on a new channel. */
export const TRANSFER_RESUME_TIMEOUT_MS = 120_000;
/** Finished transfers kept for the conversation. */
const FINISHED_MAX = 200;
/** Rows live in the `settings` store under this key prefix. */
const ROW_PREFIX = "transfer:";

type Phase = "offered" | "accepted" | "complete" | "declined" | "cancelled";
type Pending =
  | { t: "offer" }
  | { t: "accept" }
  | { t: "decline" }
  | { t: "cancel"; reason: number }
  | { t: "complete" };

/** What is stored about a transfer (store `settings`, key `transfer:<id>`). */
export interface TransferRow {
  id: string;
  peerId: string;
  outgoing: boolean;
  phase: Phase;
  /** As offered; shown and used only through `pnp010_sanitize_file_name`. */
  name: string;
  size: number;
  mime: string;
  sha256: string;
  /** The file key (hex). Secret; null once the transfer is over. Never logged. */
  key: string | null;
  /**
   * Receiver: the key what is stored of the file is sealed with (hex; ./sealed-files.ts).
   * Not the file key of the transfer. Secret; kept for as long as the file is, never logged.
   */
  storeKey?: string | null;
  /** Receiver: how many records each stored segment holds, in order. */
  segs: number[];
  pending: Pending | null;
  cancelled: { byPeer: boolean; reason: number } | null;
  createdMs: number;
  updatedMs: number;
}

const REASONS: readonly CancelReason[] = ["User", "Unavailable", "Integrity", "Storage", "Limit"];

function reasonName(code: number): CancelReason {
  return REASONS[code] ?? "Other";
}

function isFinal(phase: Phase): boolean {
  return phase === "complete" || phase === "declined" || phase === "cancelled";
}

export interface TransferHost {
  platform: Platform;
  isContact(peer: string): boolean;
  hasSession(peer: string): boolean;
  /** The contact's verified connection as an opaque token, or null. */
  verified(peer: string): object | null;
  /** Open a reliable, ordered channel on that connection. */
  openChannel(peer: string, label: string): DataChannel | null;
  /** Seal `body` as FILE_TRANSFER and send it on the verified channel; false when it could not go. */
  sendControl(peer: string, body: Uint8Array): Promise<boolean>;
  /** Ask for a direct path. */
  connect(peer: string): void;
  /** An offer arrived: the conversation has something new. */
  noteIncoming(peer: string): Promise<void>;
  save(ops: readonly WriteOp[]): Promise<void>;
  emit(ev: AppEvent): void;
  after(ms: number, fn: () => Promise<void> | void): unknown;
  cancel(handle: unknown): void;
  /** Run inside the engine's mailbox. */
  internal(fn: () => Promise<void> | void): void;
  /** Offers above this size are declined without asking (PNP-010 §8). */
  maxAcceptSize?: number;
}

/** One attempt: the life of one channel. */
interface Attempt {
  /** The connection it runs on. */
  conn: object;
  dc: DataChannel;
  closed: boolean;
  /** At least one record moved. */
  progressed: boolean;
  timer: unknown;
  /** Receiver: the segment being written, and how many records it holds so far. */
  writer: SegmentWriter | null;
  segRecords: number;
  /** Sender: wakes the send loop when the channel's buffer has drained. */
  wake: (() => void) | null;
}

/** What the engine keeps about a transfer while it runs. */
interface Run {
  attempt: Attempt | null;
  receiver: WasmTransferReceiver | null;
  sender: WasmTransferSender | null;
  bytes: number | null;
  /** Attempts in a row that moved nothing. */
  idle: number;
  retry: unknown;
  lastEmit: number;
}

export class TransferManager {
  private readonly rows = new Map<string, TransferRow>();
  private readonly runs = new Map<string, Run>();
  /** The files being sent (lost on reload). */
  private readonly sources = new Map<string, FileSource>();
  private readonly limiters = new Map<string, WasmOfferLimiter>();
  private readonly files: SealedFiles;
  private limitsCache: TransferLimits | null = null;
  private stopped = false;

  constructor(private readonly host: TransferHost) {
    const { platform } = host;
    // Whatever keeps the segments (OPFS, memory) is given ciphertext only.
    this.files = new SealedFiles(
      platform.files ?? new MemoryFileStore(),
      { subtle: platform.subtle, random: (n) => platform.random.bytes(n) },
      () => this.limits.chunkSize,
    );
  }

  private get wasm() {
    return this.host.platform.wasm;
  }

  /** A received part survives a reload of the page (the store is OPFS, not memory). */
  get persistent(): boolean {
    return this.files.persistent;
  }

  private get limits(): TransferLimits {
    return this.limitsCache ??= this.wasm.pnp010_limits();
  }

  private now(): number {
    return this.host.platform.clock.now();
  }

  private run(id: string): Run {
    let r = this.runs.get(id);
    if (!r) {
      this.runs.set(
        id,
        r = {
          attempt: null,
          receiver: null,
          sender: null,
          bytes: null,
          idle: 0,
          retry: null,
          lastEmit: 0,
        },
      );
    }
    return r;
  }

  private rowOp(row: TransferRow): WriteOp {
    row.updatedMs = this.now();
    const value: SettingRow = { key: ROW_PREFIX + row.id, value: { ...row, segs: [...row.segs] } };
    return { op: "put", store: "settings", value };
  }

  private async saveRow(row: TransferRow): Promise<void> {
    await this.host.save([this.rowOp(row)]);
  }

  /** The key the transfer's stored segments are sealed with; made when first needed. */
  private storeKey(row: TransferRow): Uint8Array {
    if (typeof row.storeKey !== "string") row.storeKey = toHex(this.files.newKey());
    const key = fromHex(row.storeKey);
    if (!key) throw new Error("the transfer's storage key is unreadable");
    return key;
  }

  private stored(row: TransferRow): number {
    const records = row.segs.reduce((a, b) => a + b, 0);
    return Math.min(row.size, records * this.limits.chunkSize);
  }

  /** How many bytes of the file stored segment `index` holds, by the row's count of records. */
  private segmentBytes(row: TransferRow, index: number): number {
    const { chunkSize } = this.limits;
    let before = 0;
    for (let i = 0; i < index; i++) before += row.segs[i];
    const start = Math.min(row.size, before * chunkSize);
    const end = Math.min(row.size, (before + row.segs[index]) * chunkSize);
    return end - start;
  }

  info(row: TransferRow): TransferInfo {
    const run = this.runs.get(row.id);
    let state: TransferState;
    switch (row.phase) {
      case "offered":
        state = { kind: "Offered" };
        break;
      case "accepted":
        state = run?.attempt && !run.attempt.closed && run.attempt.dc.readyState === "open"
          ? { kind: "Active" }
          : { kind: "Waiting" };
        break;
      case "complete":
        state = { kind: "Complete" };
        break;
      case "declined":
        state = { kind: "Declined" };
        break;
      default:
        state = {
          kind: "Cancelled",
          byPeer: row.cancelled?.byPeer ?? false,
          reason: reasonName(row.cancelled?.reason ?? 0),
        };
    }
    const done = row.phase === "complete"
      ? row.size
      : Math.min(row.size, run?.bytes ?? (row.outgoing ? 0 : this.stored(row)));
    return Object.freeze({
      id: row.id,
      peerId: row.peerId,
      direction: row.outgoing ? "Sent" : "Received",
      name: this.wasm.pnp010_sanitize_file_name(row.name),
      size: row.size,
      mime: row.mime,
      state: Object.freeze(state),
      bytesDone: done,
      pending: row.pending !== null,
      createdMs: row.createdMs,
      available: !row.outgoing && row.phase === "complete" && row.segs.length > 0,
    });
  }

  private emit(row: TransferRow): void {
    this.host.emit({ kind: "Transfer", transfer: this.info(row) });
  }

  /** Progress, at most a few times a second. */
  private emitProgress(row: TransferRow, run: Run): void {
    const now = this.now();
    if (now - run.lastEmit < PROGRESS_MS) return;
    run.lastEmit = now;
    this.emit(row);
  }

  // ── Start, stop ────────────────────────────────────────────────

  /** Read the stored transfers. What cannot go on after a reload is settled here. */
  async load(): Promise<void> {
    const { storage } = this.host.platform;
    const ops: WriteOp[] = [];
    for (const s of await storage.getAll<SettingRow>("settings")) {
      if (typeof s.key !== "string" || !s.key.startsWith(ROW_PREFIX)) continue;
      const row = s.value as TransferRow;
      if (!row || typeof row.id !== "string" || !Array.isArray(row.segs)) continue;
      this.rows.set(row.id, row);
    }
    for (const row of this.rows.values()) {
      if (isFinal(row.phase)) continue;
      if (this.now() - row.updatedMs > this.limits.transferMaxAgeMs) {
        // PNP-010-SHOULD-003.
        ops.push(...await this.settle(row, false, 4));
      } else if (row.outgoing) {
        // The page that held the file is gone.
        ops.push(...await this.settle(row, false, 1));
      } else if (row.phase === "accepted") {
        // Only what the store really holds counts.
        const have = await this.files.segments(row.id).catch(() => 0);
        if (have < row.segs.length) {
          row.segs.length = have;
          ops.push(this.rowOp(row));
        }
      }
    }
    if (ops.length > 0) await storage.write(ops);
  }

  /** Stop every attempt (the engine is shutting down). Stored parts stay. */
  async shutdown(): Promise<void> {
    this.stopped = true;
    for (const row of this.rows.values()) {
      const run = this.runs.get(row.id);
      if (run?.attempt) await this.closeAttempt(row, run, run.attempt, false);
      if (run) this.host.cancel(run.retry);
      this.freeRun(row.id);
    }
  }

  /** "Delete all data on this device". */
  async clear(): Promise<void> {
    this.rows.clear();
    this.sources.clear();
    for (const id of [...this.runs.keys()]) this.freeRun(id);
    try {
      await this.files.clear();
    } catch { /* nothing more can be done */ }
  }

  private freeRun(id: string): void {
    const run = this.runs.get(id);
    if (!run) return;
    this.host.cancel(run.retry);
    try {
      run.receiver?.free();
    } catch { /* already freed */ }
    try {
      run.sender?.free();
    } catch { /* already freed */ }
    this.runs.delete(id);
  }

  /** Something waits on this device for a verified connection to the contact. */
  wants(peer: string): boolean {
    for (const row of this.rows.values()) {
      if (row.peerId === peer && (row.pending !== null || row.phase === "accepted")) return true;
    }
    return false;
  }

  list(peer?: string): TransferInfo[] {
    return [...this.rows.values()]
      .filter((r) => peer === undefined || r.peerId === peer)
      .sort((a, b) => a.createdMs - b.createdMs)
      .map((r) => this.info(r));
  }

  // ── Commands ───────────────────────────────────────────────────

  /** SHA-256 (hex) of the file, read in pieces (PNP-010-MUST-005). Runs outside the mailbox. */
  async hash(file: FileSource): Promise<string> {
    const hasher = new this.wasm.TransferHasher();
    try {
      for (let at = 0; at < file.size; at += HASH_PIECE) {
        const end = Math.min(file.size, at + HASH_PIECE);
        const piece = new Uint8Array(await file.slice(at, end).arrayBuffer());
        if (piece.length !== end - at) throw new Error("short read");
        hasher.update(piece);
      }
    } catch {
      throw new EngineError("Transfer", "the file could not be read");
    }
    return hasher.finalize();
  }

  async offer(peer: string, file: FileSource, sha256: string): Promise<TransferInfo> {
    if (!this.host.isContact(peer)) {
      throw new EngineError("UnknownContact", `unknown contact ${shortId(peer)}`);
    }
    if (!this.host.hasSession(peer)) {
      throw new EngineError("NoSession", `no secure session with ${shortId(peer)}`);
    }
    let o: TransferControl;
    try {
      o = this.wasm.pnp010_new_offer(file.name || "file", file.size, file.type ?? "", sha256);
    } catch {
      throw new EngineError("Transfer", "this file cannot be offered (its size or name)");
    }
    const now = this.now();
    const row: TransferRow = {
      id: o.id,
      peerId: peer,
      outgoing: true,
      phase: "offered",
      name: o.name ?? "file",
      size: file.size,
      mime: o.mime ?? "",
      sha256,
      key: o.key ?? null,
      segs: [],
      pending: { t: "offer" },
      cancelled: null,
      createdMs: now,
      updatedMs: now,
    };
    await this.host.save([this.rowOp(row), ...this.pruneOps()]);
    this.rows.set(row.id, row);
    this.sources.set(row.id, file);
    this.emit(row);
    await this.flushControls(peer);
    if (!this.host.verified(peer)) this.host.connect(peer);
    return this.info(row);
  }

  private mine(id: string, incomingOffered: boolean): TransferRow {
    const row = this.rows.get(id);
    const ok = row &&
      (incomingOffered ? !row.outgoing && row.phase === "offered" : !isFinal(row.phase));
    if (!row || !ok) throw new EngineError("UnknownTransfer", "no such transfer to act on");
    return row;
  }

  async accept(id: string): Promise<TransferInfo> {
    const row = this.mine(id, true);
    row.phase = "accepted";
    row.pending = { t: "accept" };
    // The key for what will be stored is in the row before the first segment is.
    this.storeKey(row).fill(0);
    await this.saveRow(row);
    this.emit(row);
    // The accept goes first, then the channel (PNP-010-MUST-010).
    await this.flushControls(row.peerId);
    await this.pump(row.peerId);
    if (!this.host.verified(row.peerId)) this.host.connect(row.peerId);
    return this.info(row);
  }

  async decline(id: string): Promise<TransferInfo> {
    const row = this.mine(id, true);
    row.phase = "declined";
    row.key = null;
    row.pending = { t: "decline" };
    await this.saveRow(row);
    this.emit(row);
    await this.flushControls(row.peerId);
    return this.info(row);
  }

  async cancelTransfer(id: string): Promise<TransferInfo> {
    const row = this.mine(id, false);
    await this.end(row, false, 0);
    return this.info(row);
  }

  /** The received file, once complete, as a Blob over what is stored. */
  async file(id: string): Promise<Blob | null> {
    const row = this.rows.get(id);
    if (!row || row.outgoing || row.phase !== "complete" || row.segs.length === 0) return null;
    if (typeof row.storeKey !== "string") return null;
    let key: Uint8Array | null = null;
    try {
      key = this.storeKey(row);
      const blob = await this.files.blob(id, row.segs.length, row.mime, key);
      // Every segment opened; together they are the file that was verified, or nothing.
      return blob.size === row.size ? blob : null;
    } catch {
      // Missing, or not what was stored (changed or cut short at rest).
      return null;
    } finally {
      key?.fill(0);
    }
  }

  /** Take a finished transfer out of the conversation and delete its stored file. */
  async remove(id: string): Promise<void> {
    const row = this.rows.get(id);
    if (!row || !isFinal(row.phase)) {
      throw new EngineError("UnknownTransfer", "only a finished transfer can be removed");
    }
    await this.host.save([{ op: "delete", store: "settings", key: ROW_PREFIX + id }]);
    this.rows.delete(id);
    this.sources.delete(id);
    this.freeRun(id);
    await this.files.remove(id).catch(() => {});
    this.host.emit({ kind: "TransferRemoved", peerId: row.peerId, id });
  }

  /** The contact was removed: nothing of its transfers stays. */
  async forgetPeer(peer: string): Promise<WriteOp[]> {
    const ops: WriteOp[] = [];
    for (const row of [...this.rows.values()]) {
      if (row.peerId !== peer) continue;
      const run = this.runs.get(row.id);
      if (run?.attempt) await this.closeAttempt(row, run, run.attempt, true);
      this.freeRun(row.id);
      this.rows.delete(row.id);
      this.sources.delete(row.id);
      await this.files.remove(row.id).catch(() => {});
      ops.push({ op: "delete", store: "settings", key: ROW_PREFIX + row.id });
    }
    this.limiters.delete(peer);
    return ops;
  }

  /** The oldest finished transfers beyond the cap leave the list (and their files). */
  private pruneOps(): WriteOp[] {
    const finished = [...this.rows.values()]
      .filter((r) => isFinal(r.phase) && r.pending === null)
      .sort((a, b) => a.updatedMs - b.updatedMs);
    const ops: WriteOp[] = [];
    for (const row of finished.slice(0, Math.max(0, finished.length - FINISHED_MAX))) {
      this.rows.delete(row.id);
      this.freeRun(row.id);
      void this.files.remove(row.id).catch(() => {});
      ops.push({ op: "delete", store: "settings", key: ROW_PREFIX + row.id });
    }
    return ops;
  }

  /**
   * Make a transfer that is not over cancelled: the key is erased, what was received is
   * removed, its attempt ends (PNP-010-MUST-009, -035). Returns the write; `end` also
   * saves, announces and tells the contact.
   */
  private async settle(row: TransferRow, byPeer: boolean, reason: number): Promise<WriteOp[]> {
    if (isFinal(row.phase)) return [];
    const run = this.runs.get(row.id);
    if (run?.attempt) await this.closeAttempt(row, run, run.attempt, true);
    this.freeRun(row.id);
    this.sources.delete(row.id);
    row.phase = "cancelled";
    row.key = null;
    row.cancelled = { byPeer, reason };
    row.pending = byPeer ? null : { t: "cancel", reason };
    if (!row.outgoing) {
      row.segs = [];
      row.storeKey = null;
      await this.files.remove(row.id).catch(() => {});
    }
    return [this.rowOp(row)];
  }

  private async end(row: TransferRow, byPeer: boolean, reason: number): Promise<void> {
    const ops = await this.settle(row, byPeer, reason);
    if (ops.length === 0) return;
    await this.host.save(ops);
    this.emit(row);
    await this.flushControls(row.peerId);
    // A slot may be free for another accepted transfer.
    await this.pump(row.peerId);
  }

  // ── Control messages ───────────────────────────────────────────

  /** Send what this device still owes the contact (PNP-010-MUST-006). */
  async flushControls(peer: string): Promise<void> {
    for (const row of [...this.rows.values()]) {
      if (row.peerId !== peer || row.pending === null) continue;
      if (!this.host.verified(peer)) return;
      const pending = row.pending;
      let body: Uint8Array;
      try {
        if (pending.t === "offer") {
          if (row.key === null) {
            // Over before it was ever delivered: there is nothing to offer.
            row.pending = null;
            await this.saveRow(row);
            continue;
          }
          body = this.wasm.pnp010_encode_offer(
            row.id,
            row.name,
            row.size,
            row.mime,
            row.sha256,
            row.key,
          );
        } else {
          body = this.wasm.pnp010_encode_control(
            pending.t,
            row.id,
            pending.t === "cancel" ? pending.reason : 0,
          );
        }
      } catch {
        row.pending = null;
        await this.saveRow(row);
        continue;
      }
      const sent = await this.host.sendControl(peer, body);
      body.fill(0);
      if (!sent) return;
      // Still the message that was sent (nothing replaced it while it was sealed)?
      if (row.pending === pending) {
        row.pending = null;
        await this.saveRow(row);
        if (this.rows.has(row.id)) this.emit(row);
      }
    }
  }

  /** A FILE_TRANSFER envelope from the contact, on its verified channel. */
  async onControl(peer: string, body: Uint8Array): Promise<void> {
    let c: TransferControl;
    try {
      c = this.wasm.pnp010_decode_control(body);
    } catch {
      // PNP-010-MUST-001: what does not decode is ignored.
      return;
    }
    const existing = this.rows.get(c.id);
    const row = existing && existing.peerId === peer ? existing : undefined;
    const next = this.wasm.pnp010_on_control(
      row ? (row.outgoing ? "sender" : "receiver") : undefined,
      row?.phase,
      c.t,
    );
    if (next === "ignore") return;
    if (next === "new") {
      // An id this device already uses with anyone names that transfer and no other.
      if (!existing) await this.onOffer(peer, c);
      return;
    }
    if (!row) return;
    if (next === "accepted") {
      row.phase = "accepted";
      await this.saveRow(row);
      this.emit(row);
    } else if (next === "declined") {
      row.phase = "declined";
      row.key = null;
      row.pending = null;
      this.sources.delete(row.id);
      await this.saveRow(row);
      this.emit(row);
    } else if (next === "complete") {
      const run = this.runs.get(row.id);
      if (run?.attempt) await this.closeAttempt(row, run, run.attempt, false);
      this.freeRun(row.id);
      this.sources.delete(row.id);
      row.phase = "complete";
      row.key = null;
      row.pending = null;
      await this.saveRow(row);
      this.emit(row);
    } else if (next === "cancelled") {
      await this.end(row, true, c.reason ?? 0);
    }
  }

  private async onOffer(peer: string, c: TransferControl): Promise<void> {
    if (!this.host.isContact(peer) || c.t !== "offer") return;
    const now = this.now();
    let limiter = this.limiters.get(peer);
    if (!limiter) this.limiters.set(peer, limiter = new this.wasm.TransferOfferLimiter(now));
    const withinRate = limiter.allow(now);
    let waiting = 0;
    for (const r of this.rows.values()) {
      if (r.peerId === peer && !r.outgoing && r.phase === "offered") waiting++;
    }
    const max = this.host.maxAcceptSize ?? this.limits.defaultMaxAcceptSize;
    if (!this.wasm.pnp010_admit_offer(c.size ?? -1, max, waiting, withinRate)) {
      // PNP-010 §8: declined without asking the user; the sender is told.
      try {
        await this.host.sendControl(peer, this.wasm.pnp010_encode_control("decline", c.id, 0));
      } catch { /* the sender's offer simply stays unanswered */ }
      return;
    }
    const row: TransferRow = {
      id: c.id,
      peerId: peer,
      outgoing: false,
      phase: "offered",
      name: c.name ?? "file",
      size: c.size ?? 0,
      mime: c.mime ?? "",
      sha256: c.sha256 ?? "",
      key: c.key ?? null,
      segs: [],
      pending: null,
      cancelled: null,
      createdMs: now,
      updatedMs: now,
    };
    await this.host.save([this.rowOp(row), ...this.pruneOps()]);
    this.rows.set(row.id, row);
    this.emit(row);
    await this.host.noteIncoming(peer);
  }

  // ── Channels ───────────────────────────────────────────────────

  /** The contact's connection verified: send what is owed, open channels (PNP-010-MUST-024). */
  async onVerified(peer: string): Promise<void> {
    await this.flushControls(peer);
    await this.pump(peer);
  }

  /** The contact's connection is gone: its attempts are over. */
  async onConnGone(peer: string): Promise<void> {
    for (const row of this.rows.values()) {
      if (row.peerId !== peer) continue;
      const run = this.runs.get(row.id);
      if (run?.attempt) await this.attemptEnded(row, run, run.attempt);
    }
  }

  private openCount(peer: string, conn: object, outgoing: boolean, except?: string): number {
    let n = 0;
    for (const row of this.rows.values()) {
      if (row.peerId !== peer || row.outgoing !== outgoing || row.id === except) continue;
      const a = this.runs.get(row.id)?.attempt;
      if (a && !a.closed && a.conn === conn) n++;
    }
    return n;
  }

  /**
   * Open channels for the accepted transfers this device receives from `peer`, at most
   * four at once (PNP-010-MUST-033).
   */
  async pump(peer: string): Promise<void> {
    if (this.stopped) return;
    const wanted = [...this.rows.values()]
      .filter((r) => r.peerId === peer && !r.outgoing && r.phase === "accepted")
      // The accept must have left before the channel is opened.
      .filter((r) => r.pending === null)
      .sort((a, b) => a.createdMs - b.createdMs);
    for (const row of wanted) {
      const conn = this.host.verified(peer);
      if (!conn) return;
      const run = this.run(row.id);
      if (run.attempt && !run.attempt.closed) continue;
      if (this.openCount(peer, conn, false) >= this.limits.maxConcurrent) return;
      if (!(await this.ensureReceiver(row, run))) continue;
      if (this.host.verified(peer) !== conn || row.phase !== "accepted") continue;
      if (run.receiver?.is_complete()) {
        await this.finish(row, run);
        continue;
      }
      let dc: DataChannel | null = null;
      try {
        dc = this.host.openChannel(peer, this.wasm.pnp010_label(row.id));
      } catch {
        dc = null;
      }
      if (!dc) continue;
      this.receiveOn(row, run, conn, dc);
    }
  }

  /** The receiver's state machine, with what is stored read back into its hash. */
  private async ensureReceiver(row: TransferRow, run: Run): Promise<boolean> {
    if (run.receiver) return true;
    if (row.key === null) {
      await this.end(row, false, 3);
      return false;
    }
    try {
      const records = row.segs.reduce((a, b) => a + b, 0);
      const receiver = new this.wasm.TransferReceiver(
        row.id,
        row.size,
        row.sha256,
        row.key,
        records,
      );
      // PNP-010-MUST-025: the stored plaintext goes into the final hash. A segment that
      // was changed, cut short or moved at rest does not open, and throws here.
      if (row.segs.length > 0) {
        if (typeof row.storeKey !== "string") throw new Error("stored without a key");
        const key = this.storeKey(row);
        try {
          for (let i = 0; i < row.segs.length; i++) {
            const plain = await this.files.readSegment(row.id, i, key);
            try {
              if (plain.length !== this.segmentBytes(row, i)) throw new Error("a short segment");
              receiver.absorb_stored(plain);
            } finally {
              plain.fill(0);
            }
          }
        } finally {
          key.fill(0);
        }
      }
      run.receiver = receiver;
      run.bytes = receiver.stored_bytes();
      return true;
    } catch {
      // What is stored cannot be used: start over rather than give up.
      row.segs = [];
      await this.files.remove(row.id).catch(() => {});
      await this.saveRow(row);
      try {
        run.receiver = new this.wasm.TransferReceiver(row.id, row.size, row.sha256, row.key, 0);
        run.bytes = 0;
        return true;
      } catch {
        await this.end(row, false, 3);
        return false;
      }
    }
  }

  private newAttempt(conn: object, dc: DataChannel): Attempt {
    return {
      conn,
      dc,
      closed: false,
      progressed: false,
      timer: null,
      writer: null,
      segRecords: 0,
      wake: null,
    };
  }

  private receiveOn(row: TransferRow, run: Run, conn: object, dc: DataChannel): void {
    const attempt = this.newAttempt(conn, dc);
    run.attempt = attempt;
    dc.binaryType = "arraybuffer";
    const begin = () =>
      this.host.internal(async () => {
        if (attempt.closed || run.attempt !== attempt || !run.receiver) return;
        this.host.cancel(attempt.timer);
        attempt.timer = null;
        try {
          dc.send(run.receiver.begin());
        } catch {
          await this.attemptEnded(row, run, attempt);
          return;
        }
        this.emit(row);
      });
    dc.onopen = begin;
    dc.onmessage = (ev) => {
      const data = ev.data;
      this.host.internal(() => this.onRecord(row, run, attempt, data));
    };
    dc.onclose = () => this.host.internal(() => this.attemptEnded(row, run, attempt));
    attempt.timer = this.host.after(TRANSFER_OPEN_TIMEOUT_MS, () => {
      if (dc.readyState !== "open") return this.attemptEnded(row, run, attempt);
    });
    if (dc.readyState === "open") begin();
  }

  private bytesOf(data: unknown): Uint8Array | null {
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data)) {
      return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    }
    return null;
  }

  private async onRecord(
    row: TransferRow,
    run: Run,
    attempt: Attempt,
    data: unknown,
  ): Promise<void> {
    const receiver = run.receiver;
    if (attempt.closed || run.attempt !== attempt || !receiver || row.phase !== "accepted") return;
    const message = this.bytesOf(data);
    let chunk: Uint8Array | undefined;
    try {
      // A text message, a malformed frame, a frame out of place, a record that does not
      // verify: nothing of it is stored and the attempt is over (PNP-010-MUST-013, -019, -020).
      if (!message) throw new Error("not binary");
      chunk = receiver.on_message(message);
    } catch {
      await this.attemptEnded(row, run, attempt);
      return;
    }
    if (chunk === undefined) return; // START
    try {
      if (!attempt.writer) {
        const key = this.storeKey(row);
        try {
          attempt.writer = await this.files.writer(row.id, row.segs.length, key);
        } finally {
          key.fill(0);
        }
      }
      await attempt.writer.write(chunk);
      attempt.segRecords++;
      attempt.progressed = true;
      run.bytes = receiver.stored_bytes();
      if (receiver.is_complete() || attempt.segRecords >= SEGMENT_RECORDS) {
        await this.closeSegment(row, attempt);
      }
    } catch {
      await this.end(row, false, 3);
      this.host.emit({
        kind: "Notice",
        code: "Storage",
        peerId: row.peerId,
        text: "A file could not be stored on this device; the transfer was stopped.",
      });
      return;
    }
    if (receiver.is_complete()) {
      await this.finish(row, run);
    } else {
      this.emitProgress(row, run);
    }
  }

  /** Finish the segment being written: from here on its records count as stored. */
  private async closeSegment(row: TransferRow, attempt: Attempt): Promise<void> {
    const writer = attempt.writer;
    if (!writer) return;
    attempt.writer = null;
    const records = attempt.segRecords;
    attempt.segRecords = 0;
    if (records === 0) {
      await writer.abort();
      return;
    }
    // PNP-010-SHOULD-002: stored first, then counted.
    await writer.close();
    row.segs.push(records);
    await this.saveRow(row);
  }

  /** Every record is stored: the final check (PNP-010-MUST-022), then `complete`. */
  private async finish(row: TransferRow, run: Run): Promise<void> {
    const receiver = run.receiver;
    if (!receiver || row.phase !== "accepted") return;
    const ok = receiver.finish();
    const attempt = run.attempt;
    if (!ok) {
      if (attempt) await this.closeAttempt(row, run, attempt, true);
      this.freeRun(row.id);
      this.host.emit({
        kind: "Notice",
        code: "Transfer",
        peerId: row.peerId,
        text: "A received file did not match what was offered; it was discarded.",
      });
      await this.end(row, false, 2);
      return;
    }
    row.phase = "complete";
    row.key = null;
    // PNP-010-MUST-023: only now; it waits here if it cannot go out.
    row.pending = { t: "complete" };
    await this.saveRow(row);
    this.emit(row);
    // The sender hears `complete` before it sees the channel close.
    await this.flushControls(row.peerId);
    if (attempt) await this.closeAttempt(row, run, attempt, false);
    this.freeRun(row.id);
    await this.pump(row.peerId);
  }

  /**
   * Close an attempt's channel and what it holds. `discard`: the transfer is over without a
   * file, so the segment being written is dropped instead of kept.
   */
  private async closeAttempt(
    row: TransferRow,
    run: Run,
    attempt: Attempt,
    discard: boolean,
  ): Promise<void> {
    if (attempt.closed) return;
    attempt.closed = true;
    this.host.cancel(attempt.timer);
    const dc = attempt.dc;
    dc.onopen = dc.onmessage = dc.onclose = null;
    if (dc.onbufferedamountlow !== undefined) dc.onbufferedamountlow = null;
    try {
      dc.close();
    } catch { /* already closed */ }
    attempt.wake?.();
    if (run.attempt === attempt) run.attempt = null;
    try {
      if (discard) await attempt.writer?.abort();
      else await this.closeSegment(row, attempt);
    } catch { /* what was not stored is asked for again */ }
    attempt.writer = null;
    try {
      run.receiver?.end_attempt();
      run.sender?.end_attempt();
    } catch { /* freed */ }
  }

  /** An attempt's channel closed or failed: keep what arrived and, as receiver, try again. */
  private async attemptEnded(row: TransferRow, run: Run, attempt: Attempt): Promise<void> {
    if (attempt.closed) return;
    await this.closeAttempt(row, run, attempt, false);
    if (this.stopped || row.phase !== "accepted" || !this.rows.has(row.id)) return;
    this.emit(row);
    if (row.outgoing) return;
    if ((run.receiver?.record_failures() ?? 0) >= this.limits.maxRecordFailures) {
      // PNP-010-SHOULD-005.
      this.host.emit({
        kind: "Notice",
        code: "Transfer",
        peerId: row.peerId,
        text: "A file kept arriving damaged; the transfer was stopped.",
      });
      await this.end(row, false, 2);
      return;
    }
    let wait = 100;
    if (attempt.progressed) {
      run.idle = 0;
    } else {
      wait = Math.min(TRANSFER_RETRY_MAX_MS, TRANSFER_RETRY_BASE_MS * 2 ** Math.min(run.idle, 8));
      run.idle++;
    }
    this.host.cancel(run.retry);
    run.retry = this.host.after(wait, () => this.pump(row.peerId));
  }

  /**
   * Take a channel the contact opened, in the very task that announced it: a message can
   * follow at once, before the mailbox has decided about the channel. Returns what arrives
   * until `onRemoteChannel` takes over.
   */
  adopt(dc: DataChannel): unknown[] {
    const early: unknown[] = [];
    dc.binaryType = "arraybuffer";
    // One RESUME is all a well-behaved receiver sends; more is not kept.
    dc.onmessage = (ev) => {
      if (early.length < 2) early.push(ev.data);
    };
    return early;
  }

  /**
   * A data channel the contact opened under `pn-` (PNP-010 §5.1). Admitted only for an
   * accepted transfer this device sends, on a verified connection, at most four at once;
   * anything else is closed. `early`: what `adopt` collected in the meantime.
   */
  async onRemoteChannel(
    peer: string,
    conn: object | null,
    dc: DataChannel,
    early: unknown[] = [],
  ): Promise<void> {
    const close = () => {
      dc.onmessage = null;
      try {
        dc.close();
      } catch { /* already closed */ }
    };
    const id = this.wasm.pnp010_label_id(dc.label);
    const candidate = id === undefined ? undefined : this.rows.get(id);
    const row = candidate && candidate.peerId === peer ? candidate : undefined;
    const verified = conn !== null;
    const admitted = this.wasm.pnp010_admit_channel(
      dc.label,
      verified,
      conn && row ? this.openCount(peer, conn, true, row.id) : 0,
      row ? (row.outgoing ? "sender" : "receiver") : undefined,
      row?.phase,
    );
    if (!row || !conn || admitted !== row.id) {
      close();
      return;
    }
    const source = this.sources.get(row.id);
    if (!source || row.key === null) {
      close();
      await this.end(row, false, 1);
      return;
    }
    const run = this.run(row.id);
    // A newer channel for the same transfer supersedes the older one.
    if (run.attempt) await this.closeAttempt(row, run, run.attempt, false);
    try {
      run.sender ??= new this.wasm.TransferSender(row.id, row.size, row.key);
    } catch {
      close();
      await this.end(row, false, 1);
      return;
    }
    const attempt = this.newAttempt(conn, dc);
    run.attempt = attempt;
    dc.binaryType = "arraybuffer";
    dc.bufferedAmountLowThreshold = this.limits.bufferLow;
    dc.onbufferedamountlow = () => attempt.wake?.();
    dc.onclose = () => this.host.internal(() => this.attemptEnded(row, run, attempt));
    let started = false;
    const onMessage = (data: unknown) => {
      this.host.internal(async () => {
        if (attempt.closed || run.attempt !== attempt) return;
        const message = this.bytesOf(data);
        let start: Uint8Array | null = null;
        // The receiver speaks once: RESUME. Anything else, or anything more, is out of
        // place (PNP-010-MUST-015, -020).
        if (!started && message && run.sender) {
          try {
            start = run.sender.begin(message);
          } catch {
            start = null;
          }
        }
        if (!start) {
          await this.attemptEnded(row, run, attempt);
          return;
        }
        started = true;
        this.host.cancel(attempt.timer);
        attempt.timer = null;
        try {
          dc.send(start);
        } catch {
          await this.attemptEnded(row, run, attempt);
          return;
        }
        // Where the receiver is: what it has stored, not what an earlier attempt had sent.
        run.bytes = run.sender?.sent_bytes() ?? null;
        this.emit(row);
        void this.sendLoop(row, run, attempt, source);
      });
    };
    dc.onmessage = (ev) => onMessage(ev.data);
    for (const data of early.splice(0)) onMessage(data);
    attempt.timer = this.host.after(TRANSFER_RESUME_TIMEOUT_MS, () => {
      if (!started) return this.attemptEnded(row, run, attempt);
    });
  }

  /** Resolves when the channel's buffer has drained to the low mark (or the attempt ended). */
  private drained(attempt: Attempt): Promise<void> {
    const { clock } = this.host.platform;
    return new Promise((resolve) => {
      let poll: unknown = null;
      const done = () => {
        if (attempt.wake !== done) return;
        attempt.wake = null;
        clock.clearTimeout(poll);
        resolve();
      };
      attempt.wake = done;
      // The event may not come (or may have come already): the amount is also looked at.
      const look = () => {
        if (attempt.closed || attempt.dc.bufferedAmount <= this.limits.bufferLow) done();
        else poll = clock.setTimeout(look, 50);
      };
      look();
    });
  }

  /**
   * Read the file a block at a time, seal each record and send it, pausing on the channel's
   * buffer (PNP-010-SHOULD-001). Runs outside the mailbox; it touches only its attempt.
   */
  private async sendLoop(
    row: TransferRow,
    run: Run,
    attempt: Attempt,
    source: FileSource,
  ): Promise<void> {
    const sender = run.sender;
    if (!sender) return;
    const { chunkSize, bufferHigh } = this.limits;
    const fail = (reason: number | null) =>
      this.host.internal(async () => {
        if (reason === null) await this.attemptEnded(row, run, attempt);
        else if (!isFinal(row.phase)) await this.end(row, false, reason);
      });
    try {
      while (!attempt.closed) {
        const offset = sender.next_offset();
        if (offset < 0) break;
        const end = Math.min(row.size, offset + READ_RECORDS * chunkSize);
        let block: Uint8Array;
        try {
          block = new Uint8Array(await source.slice(offset, end).arrayBuffer());
        } catch {
          return fail(1);
        }
        // PNP-010-SHOULD-004: a file that is no longer what was offered is not sent.
        if (block.length !== end - offset || source.size !== row.size) return fail(1);
        let at = 0;
        do {
          if (attempt.closed) return;
          const len = sender.next_len();
          const record = sender.seal(block.subarray(at, at + len));
          attempt.dc.send(record);
          attempt.progressed = true;
          at += len;
          if (attempt.dc.bufferedAmount > bufferHigh) await this.drained(attempt);
        } while (at < block.length);
        run.bytes = sender.sent_bytes();
        const now = this.now();
        if (now - run.lastEmit >= PROGRESS_MS) {
          run.lastEmit = now;
          this.host.internal(() => {
            if (!attempt.closed && this.rows.has(row.id)) this.emit(row);
          });
        }
      }
    } catch {
      // The channel refused a send, or the attempt's state is gone.
      return fail(null);
    }
    // Everything is on its way. The transfer is complete when the receiver says so
    // (PNP-010-MUST-023); the channel stays open until then.
    run.bytes = sender.sent_bytes();
    this.host.internal(() => {
      if (!attempt.closed && this.rows.has(row.id)) this.emit(row);
    });
  }
}
