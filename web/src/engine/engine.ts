// The engine: one serial mailbox owns the identity, sessions, contacts, outbox and every
// contact connection. Commands from the UI, relay frames, WebRTC callbacks and timers all
// become mailbox tasks, so the logic reads like the native actor it mirrors
// (crates/parolnet-app/src/engine.rs). No DOM, no framework: everything comes in through
// `Platform`.
import {
  envelopeSourceHint,
  fromHex,
  fromUtf8,
  parsePairingCode,
  toHex,
  utf8,
  wipe,
} from "./bytes.ts";
import { PAIRING_CODE_LIFETIME_SECS } from "./bytes.ts";
import { CallManager } from "./calls.ts";
import { fetchStun, hasCandidates, peerConfig, validateTurn } from "./ice.ts";
import type {
  DataChannel,
  IceCandidateInit,
  IceServer,
  MediaStreamLike,
  PeerConfig,
  PeerConnection,
  Platform,
  WriteOp,
} from "./platform.ts";
import { DEFAULT_RECONNECT, ProbeSchedule, type ReconnectConfig } from "./reconnect.ts";
import { RelayClient } from "./relay.ts";
import type {
  ContactRow,
  ContactStateRow,
  IdentityRow,
  MessageRow,
  OutboxRow,
  SessionsRow,
  SettingRow,
} from "./storage.ts";
import {
  type AppEvent,
  type CallInfo,
  type ChatMessage,
  type Contact,
  type ContactView,
  type DeliveryState,
  EngineError,
  type PairingCode,
  type PathState,
  type RelayState,
  shortId,
  type Snapshot,
  type TurnSettings,
  type Verification,
} from "./types.ts";
import {
  type CallSignal,
  callSignalJson,
  chatFrame,
  DATA_CHANNEL_LABEL,
  ICE_PAYLOAD_MAX,
  identityFrame,
  isPeerId,
  MsgType,
  parseCallSignal,
  parseDcFrame,
  parseIcePayload,
  parseSdpPayload,
  SDP_PAYLOAD_MAX,
  type ServerFrame,
  shouldInitiate,
  type SignalKind,
  WATCH_MAX,
} from "./wire.ts";

// ── Timing and limits (the native core's values unless noted) ────

/** The initiator's wait for an answer. */
export const ANSWER_TIMEOUT_MS = 20_000;
/** From starting a connection to an open data channel. */
export const CONNECT_TIMEOUT_MS = 45_000;
/** The non-initiator waits this long (plus up to 2 s) for the initiator's offer. */
export const OFFER_FALLBACK_MS = 10_000;
export const OFFER_FALLBACK_JITTER_MS = 2_000;
/** A disconnected ICE connection gets this long to recover. */
export const DISCONNECT_GRACE_MS = 5_000;
export const RETRY_BASE_MS = 5_000;
export const RETRY_MAX_MS = 5 * 60_000;
export const RETRY_MAX_ATTEMPTS = 8;
/** New offers: at most 3 per 10 s. */
export const OFFERS_PER_WINDOW = 3;
export const OFFER_WINDOW_MS = 10_000;
export const TICK_MS = 15_000;
const PENDING_ICE_MAX = 32;
/** Late candidates sent as `rtc_ice` per attempt. */
const LATE_ICE_MAX = 4;
/** Non-trickle: wait this long for ICE gathering before sending the description. */
export const GATHER_CAP_MS = 3_000;
/** PNP-001-MUST-081. */
export const BINDING_TIMEOUT_MS = 20_000;
/** `rate_limited`: pause offers 60 s × 2^hits (exponent capped at 4), at most 10 min. */
export const RATE_LIMIT_BASE_MS = 60_000;
export const RATE_LIMIT_MAX_MS = 600_000;
/** How long after `registered` the first connections wait for the relay's STUN list. */
const STUN_WAIT_MS = 3_000;

/** The sender-side queue (crates/parolnet-app/src/store.rs). */
export const QUEUE_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;
export const QUEUE_MAX_PER_PEER = 500;
export const QUEUE_MAX_ENTRIES = 2000;
/** Longest text accepted, in UTF-8 bytes (the largest envelope bucket is 16384 bytes). */
export const MAX_TEXT_BYTES = 15_000;
const FLUSH_CHUNK = 16;
const SEND_BUFFER_HIGH = 1 << 20;

export interface EngineConfig {
  /** The home relay's WebSocket URL, e.g. `wss://example.org/ws`. */
  relayUrl: string;
  /**
   * STUN servers. Omitted: taken from the relay's own `/turn-credentials` (`stun:` URIs
   * only). `[]`: host candidates only (tests, one network).
   */
  stunServers?: string[];
  reconnect?: ReconnectConfig;
  /** Name given to new contacts (default: the first 8 hex digits of the PeerId). */
  defaultContactName?: string;
}

type FailReason =
  | "Timeout"
  | "IceFailed"
  | "Closed"
  | "Error"
  | "Binding"
  | "NoRelay";

interface Conn {
  readonly pc: PeerConnection;
  readonly initiator: boolean;
  remoteSet: boolean;
  pendingIce: IceCandidateInit[];
  dc: DataChannel | null;
  /** The data channel opened. */
  open: boolean;
  /** Our CHANNEL_BINDING went out on this connection. */
  bindingSent: boolean;
  /** The peer's CHANNEL_BINDING verified: only now is the path direct. */
  verified: boolean;
  descriptionSent: boolean;
  lateIce: number;
  timers: unknown[];
}

interface PeerState {
  /** Presence: true online, false offline, null unknown. */
  online: boolean | null;
  /** `online === false` came from a `peer_offline` answer: soft, re-probed with backoff. */
  offlineByError: boolean;
  /** The user asked to connect and no verified channel has come of it yet. */
  wanted: boolean;
  /** The next attempt is a background probe: the path stays `Offline` unless answered. */
  quietProbe: boolean;
  conn: Conn | null;
  attempt: number;
  failures: number;
  path: PathState;
  fallbackArmed: boolean;
  retryArmed: boolean;
  offerWaiting: boolean;
}

function newPeerState(): PeerState {
  return {
    online: null,
    offlineByError: false,
    wanted: false,
    quietProbe: false,
    conn: null,
    attempt: 0,
    failures: 0,
    path: "Unknown",
    fallbackArmed: false,
    retryArmed: false,
    offerWaiting: false,
  };
}

function toContact(row: ContactRow): Contact {
  return Object.freeze({ ...row });
}

function toMessage(row: MessageRow): ChatMessage {
  return Object.freeze({ ...row });
}

export class Engine {
  readonly peerId: string;
  readonly publicKey: string;

  private readonly p: Platform;
  private readonly cfg: EngineConfig;
  private readonly relay: RelayClient;
  private readonly calls: CallManager;
  private readonly listeners = new Set<(ev: AppEvent) => void>();
  private tail: Promise<unknown> = Promise.resolve();
  private stopped = false;
  private readonly timers = new Set<unknown>();

  private relayState: RelayState = { kind: "Connecting" };
  private registered = false;
  private registerGen = 0;
  private readonly contacts = new Map<string, ContactRow>();
  private readonly contactState = new Map<string, ContactStateRow>();
  private outbox: OutboxRow[] = [];
  private readonly peers = new Map<string, PeerState>();
  private pairing: (PairingCode & { timer: unknown }) | null = null;
  private stun: string[] = [];
  private turn: TurnSettings | null = null;
  private nextMessageId = 1;
  private nextOutboxId = 1;
  private offerHistory: number[] = [];
  private signalingBackoffUntil = 0;
  private rateLimitHits = 0;
  private readonly probes: ProbeSchedule;
  private probeWakeAt: number | null = null;
  private turnNoticeAt: number | null = null;
  /** The sessions as last saved: what a failed decrypt is rolled back to. Secret. */
  private sessionsJson = "";

  private constructor(
    platform: Platform,
    cfg: EngineConfig,
    peerId: string,
    publicKey: string,
  ) {
    this.p = platform;
    this.cfg = cfg;
    this.peerId = peerId;
    this.publicKey = publicKey;
    this.probes = new ProbeSchedule(
      cfg.reconnect ?? DEFAULT_RECONNECT,
      platform.clock.now(),
    );
    this.relay = new RelayClient({
      url: cfg.relayUrl,
      peerId,
      publicKey,
      sign: (nonceHex) => platform.wasm.sign_bytes(nonceHex),
      sockets: platform.sockets,
      clock: platform.clock,
      random: platform.random,
      log: platform.log,
    }, {
      onState: (state) => void this.internal(() => this.onRelayState(state)),
      onFrame: (frame) => void this.internal(() => this.onFrame(frame)),
    });
    this.calls = new CallManager({
      platform,
      me: peerId,
      isContact: (peer) => this.contacts.has(peer),
      isVerified: (peer) => this.verifiedConn(peer) !== null,
      connect: (peer) => this.dial(peer, true),
      sendSignal: (peer, sig) => this.sendCallSignal(peer, sig),
      peerConfig: () => this.rtcConfig(),
      emit: (ev) => this.emit(ev),
      after: (ms, fn) => this.after(ms, fn),
      cancel: (h) => this.cancel(h),
      internal: (fn) => void this.internal(fn),
    });
  }

  /**
   * Start the engine: load or create the identity, restore sessions and state, connect to
   * the relay. Throws `EngineError("Config")` for a bad relay URL and `EngineError("Busy")`
   * when another instance already uses the database.
   */
  static async start(platform: Platform, cfg: EngineConfig): Promise<Engine> {
    if (!/^wss?:\/\//.test(cfg.relayUrl)) {
      throw new EngineError("Config", "the relay URL must be ws:// or wss://");
    }
    if (platform.lock && !(await platform.lock.acquire())) {
      throw new EngineError("Busy", "ParolNet is already open in another tab");
    }
    const { wasm, storage } = platform;
    try {
      // 1. Identity.
      const stored = await storage.get<IdentityRow>("identity", "self");
      let peerId: string;
      if (stored && typeof stored.secretHex === "string") {
        try {
          peerId = wasm.initialize_from_key(stored.secretHex);
        } catch {
          throw new EngineError("Storage", "the stored identity is unreadable");
        }
      } else {
        peerId = wasm.initialize();
        // Persist before anything can use it: an identity that exists only in memory would
        // strand every pairing made with it.
        await storage.write([{
          op: "put",
          store: "identity",
          value: {
            id: "self",
            secretHex: wasm.export_secret_key(),
          } satisfies IdentityRow,
        }]);
      }
      const engine = new Engine(
        platform,
        cfg,
        peerId.toLowerCase(),
        wasm.get_public_key().toLowerCase(),
      );
      await engine.load();
      engine.relay.start();
      engine.armTick();
      return engine;
    } catch (e) {
      platform.lock?.release();
      throw e instanceof EngineError
        ? e
        : new EngineError("Storage", "could not open the local database");
    }
  }

  private async load(): Promise<void> {
    const { wasm, storage, clock } = this.p;
    const sessions = await storage.get<SessionsRow>("sessions", "blob");
    if (sessions && sessions.json) {
      try {
        wasm.import_sessions(sessions.json);
        this.sessionsJson = sessions.json;
      } catch {
        this.p.log.warn(
          "[Engine] stored sessions are unreadable; contacts must pair again",
        );
      }
    }
    for (const c of await storage.getAll<ContactRow>("contacts")) {
      if (isPeerId(c.peerId)) this.contacts.set(c.peerId, c);
    }
    for (const s of await storage.getAll<ContactStateRow>("contactState")) {
      this.contactState.set(s.peerId, s);
    }
    this.outbox = await storage.getAll<OutboxRow>("outbox");
    this.nextMessageId = (await storage.maxKey("messages")) + 1;
    this.nextOutboxId = (await storage.maxKey("outbox")) + 1;
    const turn = await storage.get<SettingRow>("settings", "turn");
    if (turn && turn.value) {
      try {
        this.turn = validateTurn(turn.value as TurnSettings);
      } catch {
        this.turn = null;
      }
    }
    if (this.cfg.stunServers) this.stun = [...this.cfg.stunServers];
    // Entries that outlived the queue's age limit while the app was closed.
    const ops = await this.dropOps(this.expired(clock.now()));
    if (ops.length > 0) await storage.write(ops);
  }

  // ── Mailbox, timers, events ──────────────────────────────────────

  /** Run `fn` after everything already queued. Rejects with what `fn` throws. */
  private post<T>(fn: () => Promise<T> | T): Promise<T> {
    const run = this.tail.then(() => {
      if (this.stopped) {
        throw new EngineError("Stopped", "the engine has stopped");
      }
      return fn();
    });
    this.tail = run.catch(() => {});
    return run;
  }

  /** A task nobody awaits (a frame, a timer, a WebRTC callback): failures are logged. */
  private internal(fn: () => Promise<void> | void): Promise<void> {
    return this.post(fn).catch((e) => {
      if (e instanceof EngineError && e.code === "Stopped") return;
      // Only the error's class: its message could quote data.
      this.p.log.warn(
        "[Engine] internal task failed:",
        e instanceof EngineError ? e.code : (e as Error)?.name,
      );
      if (e instanceof EngineError && e.code === "Storage") {
        this.emit({
          kind: "Notice",
          text: "Could not save to this device's storage.",
        });
      }
    });
  }

  /** Resolves when the mailbox is empty (tests). */
  async idle(): Promise<void> {
    let seen: Promise<unknown>;
    do {
      seen = this.tail;
      await seen;
    } while (seen !== this.tail);
  }

  private after(ms: number, fn: () => Promise<void> | void): unknown {
    const handle = this.p.clock.setTimeout(() => {
      this.timers.delete(handle);
      void this.internal(fn);
    }, Math.max(0, ms));
    this.timers.add(handle);
    return handle;
  }

  private cancel(handle: unknown): void {
    if (handle === null || handle === undefined) return;
    this.timers.delete(handle);
    this.p.clock.clearTimeout(handle);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => this.p.clock.setTimeout(resolve, ms));
  }

  /** Subscribe to events. Returns the unsubscribe function. */
  subscribe(listener: (ev: AppEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private emit(ev: AppEvent): void {
    for (const l of [...this.listeners]) {
      try {
        l(ev);
      } catch { /* a listener's problem */ }
    }
  }

  private async save(ops: readonly WriteOp[]): Promise<void> {
    if (ops.length === 0) return;
    try {
      await this.p.storage.write(ops);
    } catch {
      throw new EngineError(
        "Storage",
        "could not save to this device's storage",
      );
    }
  }

  /** Ratchet state changes on every encrypt and decrypt: this writes it. */
  private sessionsOp(): WriteOp {
    this.sessionsJson = this.p.wasm.export_sessions();
    const row: SessionsRow = { id: "blob", json: this.sessionsJson };
    return { op: "put", store: "sessions", value: row };
  }

  /**
   * Put the sessions back as they were last saved, except `keep`'s. The core's ratchet
   * advances before it authenticates (a failed decrypt leaves the session stepped onto the
   * sender's bogus key), so without this one undecryptable envelope would end a session for
   * good, and a trial decrypt would do that to every other contact's session.
   */
  private rollbackSessions(keep: string | null = null): void {
    if (this.sessionsJson === "") return;
    try {
      let json = this.sessionsJson;
      if (keep !== null) {
        const all = JSON.parse(json) as Record<string, string>;
        delete all[keep];
        if (Object.keys(all).length === 0) return;
        json = JSON.stringify(all);
      }
      this.p.wasm.import_sessions(json);
    } catch {
      this.p.log.warn("[Engine] could not restore sessions after a failed decrypt");
    }
  }

  private nowSecs(): bigint {
    return BigInt(Math.floor(this.p.clock.now() / 1000));
  }

  // ── Snapshot and simple queries ──────────────────────────────────

  private peer(peer: string): PeerState {
    let st = this.peers.get(peer);
    if (!st) this.peers.set(peer, st = newPeerState());
    return st;
  }

  private setPath(peer: string, path: PathState): void {
    const st = this.peer(peer);
    if (st.path !== path) {
      st.path = path;
      this.emit({ kind: "Path", peerId: peer, state: path });
    }
  }

  private queuedFor(peer: string): number {
    let n = 0;
    for (const e of this.outbox) {
      if (e.peerId === peer && e.kind === "text") n++;
    }
    return n;
  }

  private pairingOpen(): boolean {
    return this.pairing !== null &&
      this.p.clock.now() < this.pairing.expiresAtMs;
  }

  private currentPairing(): PairingCode | null {
    return this.pairingOpen() && this.pairing
      ? Object.freeze({
        code: this.pairing.code,
        expiresAtMs: this.pairing.expiresAtMs,
      })
      : null;
  }

  /** A consistent, immutable picture of the engine's state. */
  snapshot(): Snapshot {
    const contacts: ContactView[] = [...this.contacts.values()].map((c) => {
      const cs = this.contactState.get(c.peerId);
      return Object.freeze({
        contact: toContact(c),
        path: this.peers.get(c.peerId)?.path ?? "Unknown",
        queued: this.queuedFor(c.peerId),
        unread: cs?.unread ?? 0,
        lastActivityMs: cs?.lastActivityMs ?? c.addedMs,
      });
    });
    return Object.freeze({
      peerId: this.peerId,
      publicKey: this.publicKey,
      relay: this.relayState,
      contacts: Object.freeze(contacts),
      pairingOpen: this.pairingOpen(),
      pairing: this.currentPairing(),
      turnConfigured: this.turn !== null,
      relayOnly: this.turn?.relayOnly === true,
      call: this.calls.current(),
    });
  }

  /** The history with a contact, oldest first. */
  messages(peerId: string): Promise<ChatMessage[]> {
    return this.post(async () =>
      (await this.p.storage.getAllByPeer<MessageRow>("messages", peerId)).map(
        toMessage,
      )
    );
  }

  /** The 60-digit safety number to compare with a contact out of band (PNP-002 §10). */
  safetyNumber(peerId: string): string | null {
    if (!isPeerId(peerId)) return null;
    try {
      return this.p.wasm.safety_number(this.peerId, peerId.toLowerCase());
    } catch {
      return null;
    }
  }

  /**
   * The ICE servers new connections use, without the TURN credential: the relay's own STUN
   * and the user's TURN server, nothing else.
   */
  iceServers(): IceServer[] {
    return this.rtcConfig().iceServers.map((s) => ({ urls: s.urls }));
  }

  private rtcConfig(): PeerConfig {
    return peerConfig(this.stun, this.turn);
  }

  // ── Contacts ─────────────────────────────────────────────────────

  private contactOrThrow(peerId: string): ContactRow {
    const c = this.contacts.get(peerId);
    if (!c) {
      throw new EngineError(
        "UnknownContact",
        `unknown contact ${shortId(peerId)}`,
      );
    }
    return c;
  }

  /**
   * Add a contact or fill in what is missing. Never overwrites a name or downgrades a
   * verification (the old PWA rewrote the whole row on every incoming message).
   */
  private upsertContact(
    peer: string,
    identityKey: string | null,
    verified: Verification | null,
  ): { row: ContactRow; isNew: boolean; changed: boolean } {
    const now = this.p.clock.now();
    const existing = this.contacts.get(peer);
    if (existing) {
      let changed = false;
      const row = { ...existing };
      if (identityKey !== null && row.identityKey !== identityKey) {
        row.identityKey = identityKey;
        changed = true;
      }
      if (verified === "in-person" && row.verified !== "in-person") {
        row.verified = "in-person";
        row.verifiedMs = now;
        changed = true;
      }
      if (changed) this.contacts.set(peer, row);
      return { row, isNew: false, changed };
    }
    const row: ContactRow = {
      peerId: peer,
      name: this.cfg.defaultContactName ?? shortId(peer),
      identityKey,
      addedMs: now,
      verified: verified ?? "no",
      verifiedMs: verified && verified !== "no" ? now : null,
    };
    this.contacts.set(peer, row);
    return { row, isNew: true, changed: true };
  }

  /** Rename a contact. Local only: the name is never sent anywhere. */
  renameContact(peerId: string, name: string): Promise<Contact> {
    return this.post(async () => {
      const row = { ...this.contactOrThrow(peerId), name: name.trim() };
      if (row.name.length === 0) {
        throw new EngineError("Config", "a contact needs a name");
      }
      await this.save([{ op: "put", store: "contacts", value: row }]);
      this.contacts.set(peerId, row);
      const contact = toContact(row);
      this.emit({ kind: "ContactUpdated", contact });
      return contact;
    });
  }

  /**
   * Record that the user compared safety numbers with this contact (`"compared"`), or take
   * a verification back (`"no"`). `"in-person"` is only ever set by pairing with a camera scan.
   */
  setVerification(
    peerId: string,
    verified: "compared" | "no",
  ): Promise<Contact> {
    return this.post(async () => {
      const existing = this.contactOrThrow(peerId);
      if (verified !== "compared" && verified !== "no") {
        throw new EngineError("Config", 'verification is "compared" or "no"');
      }
      // Comparing numbers does not undo having met in person.
      const keep = verified === "compared" && existing.verified === "in-person";
      const row: ContactRow = keep ? existing : {
        ...existing,
        verified,
        verifiedMs: verified === "no" ? null : this.p.clock.now(),
      };
      await this.save([{ op: "put", store: "contacts", value: row }]);
      this.contacts.set(peerId, row);
      const contact = toContact(row);
      this.emit({ kind: "ContactUpdated", contact });
      return contact;
    });
  }

  private activityOp(peer: string, unreadDelta: number | "reset"): WriteOp {
    const prev = this.contactState.get(peer);
    const row: ContactStateRow = {
      peerId: peer,
      lastActivityMs: unreadDelta === "reset" ? (prev?.lastActivityMs ?? 0) : this.p.clock.now(),
      unread: unreadDelta === "reset" ? 0 : (prev?.unread ?? 0) + unreadDelta,
    };
    this.contactState.set(peer, row);
    return { op: "put", store: "contactState", value: row };
  }

  private emitActivity(peer: string): void {
    const cs = this.contactState.get(peer);
    if (cs) {
      this.emit({
        kind: "ContactActivity",
        peerId: peer,
        unread: cs.unread,
        lastActivityMs: cs.lastActivityMs,
      });
    }
  }

  /** The user read the conversation: its unread count goes to zero. */
  markRead(peerId: string): Promise<void> {
    return this.post(async () => {
      if ((this.contactState.get(peerId)?.unread ?? 0) === 0) return;
      await this.save([this.activityOp(peerId, "reset")]);
      this.emitActivity(peerId);
    });
  }

  private sendWatch(): void {
    if (!this.registered) return;
    const ids = [...this.contacts.values()]
      .map((c) => ({
        id: c.peerId,
        at: this.contactState.get(c.peerId)?.lastActivityMs ?? c.addedMs,
      }))
      .sort((a, b) => b.at - a.at)
      .slice(0, WATCH_MAX)
      .map((c) => c.id);
    this.relay.send({ type: "watch", peer_ids: ids });
  }

  // ── Pairing (PNP-003) ────────────────────────────────────────────

  /**
   * Show this to a contact (as a QR code or text). A new call replaces the previous code.
   * While it is valid, offers from strangers are accepted; the window closes when the code
   * expires, when someone pairs with it, or on `cancelPairing`. The pending half lives in
   * wasm memory only, so a reload invalidates the code (the snapshot then has no `pairing`).
   */
  createPairingCode(): Promise<PairingCode> {
    return this.post(() => {
      let code: string;
      try {
        code = this.p.wasm.generate_qr_payload(this.publicKey, null)
          .toLowerCase();
      } catch {
        throw new EngineError("Crypto", "could not create a pairing code");
      }
      const payload = parsePairingCode(code);
      if (!payload) {
        throw new EngineError("Crypto", "could not create a pairing code");
      }
      // The scanner measures the code's age from its own timestamp, which is floored to
      // 300 s: the window is exactly as long as the code can still be scanned.
      const expiresAtMs = (payload.ts + PAIRING_CODE_LIFETIME_SECS) * 1000;
      this.closePairing(false);
      const timer = this.after(
        expiresAtMs - this.p.clock.now(),
        () => this.closePairing(true),
      );
      this.pairing = { code, expiresAtMs, timer };
      const pairing = this.currentPairing()!;
      this.emit({ kind: "Pairing", pairing });
      return pairing;
    });
  }

  /** Stop showing the code: strangers' offers are refused again. */
  cancelPairing(): Promise<void> {
    return this.post(() => this.closePairing(true));
  }

  private closePairing(announce: boolean): void {
    if (!this.pairing) return;
    this.cancel(this.pairing.timer);
    this.pairing = null;
    if (announce) this.emit({ kind: "Pairing", pairing: null });
  }

  /**
   * Pair with a contact's code. `via` says how the user obtained it: a camera scan means the
   * two devices were together (`verified: "in-person"`); a pasted code proves nothing.
   * Establishes the session, queues the bootstrap envelope and starts connecting.
   */
  pairWithCode(code: string, how: { via: "scan" | "paste" }): Promise<Contact> {
    return this.post(async () => {
      const { wasm, clock } = this.p;
      const clean = String(code).replace(/[\s"']/g, "").toLowerCase();
      const payload = clean.length > 64 ? parsePairingCode(clean) : null;
      if (!payload) {
        throw new EngineError(
          "InvalidCode",
          "expected the full pairing code from the contact's app",
        );
      }
      if (payload.identityKey === this.publicKey) {
        throw new EngineError("OwnCode", "that is your own code");
      }
      if (
        Math.floor(clock.now() / 1000) - payload.ts > PAIRING_CODE_LIFETIME_SECS
      ) {
        throw new EngineError(
          "CodeExpired",
          "that code has expired; ask for a new one",
        );
      }
      let peer: string;
      try {
        const scanned = wasm.process_scanned_qr(clean);
        peer = String(scanned.peer_id).toLowerCase();
      } catch (e) {
        if (/expired/i.test(String((e as Error)?.message))) {
          throw new EngineError(
            "CodeExpired",
            "that code has expired; ask for a new one",
          );
        }
        throw new EngineError(
          "InvalidCode",
          "that pairing code cannot be used",
        );
      }
      if (!isPeerId(peer)) {
        throw new EngineError(
          "InvalidCode",
          "that pairing code cannot be used",
        );
      }

      // PNP-001 §5.3.1 / MUST-063: the first envelope carries our identity key as
      // source_hint so the presenter can materialise its responder session.
      let bootstrap: string;
      try {
        bootstrap = wasm.envelope_encode(
          peer,
          MsgType.CONTROL,
          new Uint8Array(0),
          this.nowSecs(),
          this.publicKey,
        );
      } catch {
        throw new EngineError("Crypto", "could not start the session");
      }
      // The new session replaces an earlier bootstrap envelope. Queued texts stay: they are
      // plaintext until flushed, so they go out under the new session.
      const stale = this.outbox.filter((e) => e.peerId === peer && e.kind === "bootstrap");
      const entry: OutboxRow = {
        id: this.nextOutboxId++,
        peerId: peer,
        kind: "bootstrap",
        envelopeHex: bootstrap,
        createdMs: clock.now(),
      };
      const { row, isNew } = this.upsertContact(
        peer,
        payload.identityKey,
        how?.via === "scan" ? "in-person" : null,
      );
      const ops: WriteOp[] = [
        this.sessionsOp(),
        { op: "put", store: "outbox", value: entry },
        { op: "put", store: "contacts", value: row },
        ...stale.map((e): WriteOp => ({
          op: "delete",
          store: "outbox",
          key: e.id,
        })),
      ];
      if (!this.contactState.has(peer)) ops.push(this.activityOp(peer, 0));
      await this.save(ops);
      this.outbox = this.outbox.filter((e) => !stale.includes(e));
      this.outbox.push(entry);
      const contact = toContact(row);
      this.emit(
        isNew ? { kind: "ContactAdded", contact } : { kind: "ContactUpdated", contact },
      );
      this.sendWatch();
      // The presenter does not know us yet, so it neither watches us nor offers: offer now.
      const st = this.peer(peer);
      st.online = null;
      st.offlineByError = false;
      st.quietProbe = false;
      st.attempt = 0;
      st.failures = 0;
      this.probes.clear(peer);
      this.dropConn(peer);
      this.dial(peer, true);
      return contact;
    });
  }

  // ── Chat and the sender-side queue ───────────────────────────────

  /**
   * Send a text message: at once over a verified data channel, else it waits on this
   * device (`state: "Queued"`) and goes out, in order, when the channel next verifies.
   */
  sendText(peerId: string, text: string): Promise<ChatMessage> {
    return this.post(async () => {
      const { wasm, clock } = this.p;
      this.contactOrThrow(peerId);
      if (!wasm.has_session(peerId)) {
        throw new EngineError(
          "NoSession",
          `no secure session with ${shortId(peerId)}`,
        );
      }
      this.checkText(text);
      const now = clock.now();
      const row: MessageRow = {
        id: this.nextMessageId++,
        peerId,
        direction: "Sent",
        text,
        timestampMs: now,
        state: "Queued",
      };
      const entry: OutboxRow = {
        id: this.nextOutboxId++,
        peerId,
        kind: "text",
        messageId: row.id,
        text,
        createdMs: now,
      };
      const dropped = this.overLimit(peerId, now);
      await this.save([
        { op: "put", store: "messages", value: row },
        { op: "put", store: "outbox", value: entry },
        this.activityOp(peerId, 0),
        ...(await this.dropOps(dropped)),
      ]);
      this.outbox.push(entry);
      this.announceDropped(dropped);
      const sent = await this.flushQueue(peerId, row.id);
      const state: DeliveryState = sent.has(row.id) ? "Sent" : "Queued";
      if (state === "Queued") {
        this.dial(peerId, false);
        // A soft-offline contact is now waited for: its next probe may be due sooner.
        this.armProbeWake();
      }
      const message = toMessage({ ...row, state });
      this.emit({ kind: "Message", message });
      this.emitActivity(peerId);
      return message;
    });
  }

  private checkText(text: string): void {
    if (typeof text !== "string" || text.length === 0) {
      throw new EngineError("Config", "a message needs some text");
    }
    const bytes = utf8(text);
    const tooLong = bytes.length > MAX_TEXT_BYTES;
    wipe(bytes);
    if (tooLong) {
      throw new EngineError(
        "TooLong",
        "that message is too long to send in one piece",
      );
    }
  }

  /**
   * Take back a message that is still queued on this device: it is removed from the queue
   * and from the history. `EngineError("NotQueued")` once it has been sent.
   */
  takeBack(messageId: number): Promise<void> {
    return this.post(async () => {
      const entry = this.queuedEntry(messageId);
      await this.save([
        { op: "delete", store: "outbox", key: entry.id },
        { op: "delete", store: "messages", key: messageId },
      ]);
      this.outbox = this.outbox.filter((e) => e !== entry);
      this.emit({
        kind: "MessageRemoved",
        peerId: entry.peerId,
        id: messageId,
      });
    });
  }

  /**
   * Change the text of a message that is still queued. Queued messages are kept as plaintext
   * and encrypted only when they are flushed, so this never touches the ratchet.
   */
  editQueued(messageId: number, text: string): Promise<ChatMessage> {
    return this.post(async () => {
      const entry = this.queuedEntry(messageId);
      this.checkText(text);
      const row = await this.p.storage.get<MessageRow>("messages", messageId);
      if (!row) {
        throw new EngineError(
          "UnknownMessage",
          "that message no longer exists",
        );
      }
      const edited: MessageRow = { ...row, text, editedMs: this.p.clock.now() };
      const next: OutboxRow = { ...entry, text };
      await this.save([
        { op: "put", store: "outbox", value: next },
        { op: "put", store: "messages", value: edited },
      ]);
      this.outbox = this.outbox.map((e) => (e === entry ? next : e));
      const message = toMessage(edited);
      this.emit({ kind: "MessageEdited", message });
      return message;
    });
  }

  private queuedEntry(messageId: number): OutboxRow & { kind: "text" } {
    for (const e of this.outbox) {
      if (e.kind === "text" && e.messageId === messageId) return e;
    }
    throw new EngineError(
      "NotQueued",
      "that message has already left this device",
    );
  }

  /** Entries past the queue's age limit. */
  private expired(now: number): OutboxRow[] {
    return this.outbox.filter((e) => now - e.createdMs > QUEUE_MAX_AGE_MS);
  }

  /**
   * What has to go so that one more entry for `peer` fits: the expired, then the oldest of
   * that peer beyond the per-peer limit, then the oldest overall beyond the total.
   */
  private overLimit(peer: string, now: number): OutboxRow[] {
    const drop = new Set<OutboxRow>(this.expired(now));
    const live = () => this.outbox.filter((e) => !drop.has(e));
    const mine = live().filter((e) => e.peerId === peer);
    for (
      const e of mine.slice(
        0,
        Math.max(0, mine.length + 1 - QUEUE_MAX_PER_PEER),
      )
    ) drop.add(e);
    const all = live();
    for (
      const e of all.slice(0, Math.max(0, all.length + 1 - QUEUE_MAX_ENTRIES))
    ) drop.add(e);
    return [...drop];
  }

  /** The writes that drop queue entries (their messages become `Dropped`). */
  private async dropOps(entries: readonly OutboxRow[]): Promise<WriteOp[]> {
    const ops: WriteOp[] = [];
    for (const e of entries) {
      ops.push({ op: "delete", store: "outbox", key: e.id });
      if (e.kind === "text") {
        const row = await this.p.storage.get<MessageRow>(
          "messages",
          e.messageId,
        );
        if (row) {
          ops.push({
            op: "put",
            store: "messages",
            value: { ...row, state: "Dropped" },
          });
        }
      }
    }
    if (entries.length > 0) {
      this.outbox = this.outbox.filter((e) => !entries.includes(e));
    }
    return ops;
  }

  private announceDropped(entries: readonly OutboxRow[]): void {
    for (const e of entries) {
      if (e.kind === "text") {
        this.emit({
          kind: "MessageState",
          peerId: e.peerId,
          id: e.messageId,
          state: "Dropped",
        });
      }
    }
  }

  private verifiedConn(peer: string): Conn | null {
    const conn = this.peers.get(peer)?.conn;
    return conn && conn.open && conn.verified ? conn : null;
  }

  /** Send an envelope on the open data channel, verified or not. */
  private sendRaw(conn: Conn, envelopeHex: string): boolean {
    if (!conn.open || !conn.dc || conn.dc.readyState !== "open") return false;
    try {
      conn.dc.send(chatFrame(envelopeHex));
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Send the queued texts for `peer`, oldest first, if its channel is verified
   * (PNP-001-SHOULD-018). Each chunk is encrypted, the advanced ratchet is saved, and only
   * then does anything go on the wire: a crash can skip a message number or send a message
   * twice, but never reuses a message key. Returns the ids of the messages sent; the one in
   * `quiet` gets no `MessageState` event (its caller reports it).
   */
  private async flushQueue(peer: string, quiet?: number): Promise<Set<number>> {
    const sent = new Set<number>();
    const { wasm } = this.p;
    for (;;) {
      const conn = this.verifiedConn(peer);
      if (!conn) return sent;
      const chunk = this.outbox
        .filter((e): e is OutboxRow & { kind: "text" } => e.peerId === peer && e.kind === "text")
        .slice(0, FLUSH_CHUNK);
      if (chunk.length === 0) return sent;
      const ready: { entry: OutboxRow & { kind: "text" }; envelope: string }[] = [];
      const failed: OutboxRow[] = [];
      for (const entry of chunk) {
        const plaintext = utf8(entry.text);
        try {
          ready.push({
            entry,
            envelope: wasm.envelope_encode(
              peer,
              MsgType.TEXT,
              plaintext,
              this.nowSecs(),
              null,
            ),
          });
        } catch {
          // It can never be sent (too large for an envelope, or the session is gone): do
          // not let it block the queue.
          failed.push(entry);
        } finally {
          wipe(plaintext);
        }
      }
      await this.save([this.sessionsOp(), ...(await this.dropOps(failed))]);
      this.announceDropped(failed);
      const delivered: (OutboxRow & { kind: "text" })[] = [];
      for (const r of ready) {
        if (
          this.verifiedConn(peer) !== conn || !this.sendRaw(conn, r.envelope)
        ) break;
        delivered.push(r.entry);
      }
      const ops: WriteOp[] = [];
      for (const e of delivered) {
        ops.push({ op: "delete", store: "outbox", key: e.id });
        const row = await this.p.storage.get<MessageRow>(
          "messages",
          e.messageId,
        );
        if (row) {
          ops.push({
            op: "put",
            store: "messages",
            value: { ...row, state: "Sent" },
          });
        }
      }
      this.outbox = this.outbox.filter((e) =>
        !delivered.includes(e as OutboxRow & { kind: "text" })
      );
      await this.save(ops);
      for (const e of delivered) {
        sent.add(e.messageId);
        if (e.messageId !== quiet) {
          this.emit({
            kind: "MessageState",
            peerId: peer,
            id: e.messageId,
            state: "Sent",
          });
        }
      }
      if (delivered.length < ready.length) return sent;
      for (
        let i = 0;
        i < 100 && conn.dc && conn.dc.bufferedAmount > SEND_BUFFER_HIGH;
        i++
      ) {
        await this.sleep(50);
      }
    }
  }

  /**
   * Send the bootstrap-completing envelope (we scanned the peer's code) before the binding:
   * the presenter needs it to have a session at all.
   */
  private async flushBootstrap(peer: string, conn: Conn): Promise<void> {
    const entries = this.outbox.filter((e) => e.peerId === peer && e.kind === "bootstrap");
    const sentEntries: OutboxRow[] = [];
    for (const e of entries) {
      if (e.kind === "bootstrap" && this.sendRaw(conn, e.envelopeHex)) {
        sentEntries.push(e);
      } else break;
    }
    if (sentEntries.length === 0) return;
    this.outbox = this.outbox.filter((e) => !sentEntries.includes(e));
    await this.save(
      sentEntries.map((e): WriteOp => ({
        op: "delete",
        store: "outbox",
        key: e.id,
      })),
    );
  }

  /** PNP-001-MUST-079: our CHANNEL_BINDING, once the channel is open and we hold a session. */
  private async sendBinding(peer: string, conn: Conn): Promise<void> {
    const { wasm, log } = this.p;
    if (!conn.open || conn.bindingSent) return;
    if (!wasm.has_session(peer)) return; // the presenter, before the scanner's bootstrap
    // Read the descriptions live, never from a copy made earlier: the binding has to cover
    // what the connection actually negotiated.
    const local = conn.pc.localDescription?.sdp;
    const remote = conn.pc.remoteDescription?.sdp;
    if (!local || !remote) {
      log.warn(`[WebRTC] no descriptions to bind for ${shortId(peer)}`);
      return;
    }
    let envelope: string;
    try {
      const body = wasm.channel_binding_body(local, remote);
      envelope = wasm.envelope_encode(
        peer,
        MsgType.CHANNEL_BINDING,
        body,
        this.nowSecs(),
        null,
      );
    } catch {
      log.warn(`[WebRTC] cannot bind the channel to ${shortId(peer)}`);
      return;
    }
    conn.bindingSent = true;
    await this.save([this.sessionsOp()]);
    if (this.live(peer, conn)) this.sendRaw(conn, envelope);
  }

  /** PNP-001-MUST-080: check the peer's binding against our view of the connection. */
  private async onBinding(
    peer: string,
    conn: Conn,
    body: Uint8Array,
  ): Promise<void> {
    const { wasm, log } = this.p;
    if (!conn.open || conn.verified) return;
    const local = conn.pc.localDescription?.sdp;
    const remote = conn.pc.remoteDescription?.sdp;
    let ok = false;
    try {
      ok = !!local && !!remote &&
        wasm.channel_binding_verify(body, local, remote);
    } catch {
      ok = false;
    }
    if (!ok) {
      log.warn(`[WebRTC] channel binding refused for ${shortId(peer)}`);
      const name = this.contacts.get(peer)?.name ?? shortId(peer);
      this.emit({
        kind: "Notice",
        text: `The direct connection to ${name} failed its end-to-end check. ` +
          "Someone between you, such as the relay, may be interfering; it was closed.",
      });
      this.connFailed(peer, conn, "Binding");
      return;
    }
    conn.verified = true;
    const st = this.peer(peer);
    st.attempt = 0;
    st.failures = 0;
    st.wanted = false;
    log.info(`[WebRTC] direct channel verified with ${shortId(peer)}`);
    // A presenter whose session appeared with this very connection binds now.
    await this.sendBinding(peer, conn);
    if (!this.live(peer, conn)) return;
    this.setPath(peer, "Direct");
    await this.flushQueue(peer);
  }

  // ── Relay ────────────────────────────────────────────────────────

  private onRelayState(state: RelayState): void {
    if (state.kind === "Connecting" && this.relayState.kind === "Connecting") {
      return;
    }
    this.relayState = Object.freeze({ ...state }) as RelayState;
    this.emit({ kind: "Relay", state: this.relayState });
    if (state.kind !== "Registered") {
      this.registered = false;
      return;
    }
    this.registered = true;
    this.rateLimitHits = 0;
    const gen = ++this.registerGen;
    this.sendWatch();
    let started = false;
    const go = () => {
      if (started || gen !== this.registerGen || !this.registered) return;
      started = true;
      // Probe contacts we hold messages for (presence only comes from mutual watchers, so
      // a fresh pairing gets no push).
      for (const c of this.contacts.values()) {
        if (this.queuedFor(c.peerId) > 0 || this.hasBootstrapQueued(c.peerId)) {
          this.dial(c.peerId, false);
        }
      }
      this.runProbes();
    };
    if (this.cfg.stunServers) {
      go();
      return;
    }
    // STUN comes from our own relay and from nowhere else; connections made before the
    // answer (bounded) would have host candidates only.
    void fetchStun(this.p.fetch, this.p.clock, this.cfg.relayUrl).then((
      answer,
    ) =>
      this.internal(() => {
        if (gen !== this.registerGen) return;
        if (answer) {
          this.stun = answer.stun;
          if (answer.stun.length > 0) {
            this.p.log.info(`[WebRTC] ICE servers from ${answer.url}`);
          }
        }
        go();
      })
    );
    this.after(STUN_WAIT_MS, go);
  }

  private hasBootstrapQueued(peer: string): boolean {
    return this.outbox.some((e) => e.peerId === peer && e.kind === "bootstrap");
  }

  /** The network came back or the page became visible: reconnect to the relay now. */
  networkChanged(): void {
    if (!this.stopped) this.relay.nudge();
  }

  private async onFrame(frame: ServerFrame): Promise<void> {
    switch (frame.type) {
      case "presence":
        this.onPresence(frame.peerId, frame.online);
        return;
      case "signal":
        await this.onSignal(frame.kind, frame.from, frame.payload);
        return;
      case "error":
        this.onRelayError(frame.code, frame.peerId);
        return;
      default:
        return;
    }
  }

  private onRelayError(code: string, peer: string | null): void {
    const now = this.p.clock.now();
    if (code === "peer_offline" && peer) {
      const st = this.peer(peer);
      // After a presence push said offline the relay tells us when that changes. Otherwise
      // nobody will: the verdict is soft and the contact is probed again with backoff.
      const pushed = st.online === false && !st.offlineByError;
      st.online = false;
      st.offlineByError = !pushed;
      if (!st.conn?.open) {
        this.dropConn(peer);
        this.setPath(peer, "Offline");
      }
      if (!pushed && this.contacts.has(peer)) {
        this.probes.noteOffline(peer, now, this.p.random.next());
        this.armProbeWake();
      }
    } else if (code === "rate_limited") {
      const wait = Math.min(
        RATE_LIMIT_BASE_MS * 2 ** Math.min(this.rateLimitHits, 4),
        RATE_LIMIT_MAX_MS,
      );
      this.rateLimitHits += 1;
      this.signalingBackoffUntil = now + wait;
      this.p.log.warn(
        `[Relay] rate-limited; pausing offers for ${Math.round(wait / 1000)} s`,
      );
    } else {
      this.p.log.debug(`[Relay] error ${code.slice(0, 40)}`);
    }
  }

  private onPresence(peer: string, online: boolean): void {
    // A push is authoritative either way: the relay reports the next change too.
    this.probes.clear(peer);
    const st = this.peer(peer);
    const was = st.online;
    st.online = online;
    st.offlineByError = false;
    st.quietProbe = false;
    if (online) {
      if (was !== true) {
        st.attempt = 0;
        st.failures = 0;
      }
      if (!st.conn) {
        if (this.contacts.has(peer)) this.dial(peer, false);
        if (st.path === "Offline" || st.path === "Unknown") {
          this.setPath(peer, "Connecting");
        }
      }
    } else if (!st.conn?.open) {
      this.dropConn(peer);
      this.setPath(peer, "Offline");
    }
  }

  private signal(kind: SignalKind, to: string, payload: string): boolean {
    return this.registered && this.relay.send({ type: kind, to, payload });
  }

  /**
   * Accepting an offer shows our IP address to its sender: only contacts, a peer we already
   * connect to, or anyone while our pairing code is valid.
   */
  private offerAllowed(from: string): boolean {
    return this.contacts.has(from) || !!this.peers.get(from)?.conn ||
      this.pairingOpen();
  }

  private async onSignal(
    kind: SignalKind,
    from: string,
    payload: string,
  ): Promise<void> {
    if (!isPeerId(from) || from === this.peerId) return;
    if (kind === "rtc_offer") {
      if (!this.offerAllowed(from)) {
        this.p.log.info(
          `[WebRTC] ignoring an offer from a non-contact ${shortId(from)}`,
        );
        return;
      }
      const sdp = parseSdpPayload(payload, "offer");
      if (sdp === null) return;
      const conn = this.peers.get(from)?.conn;
      if (conn) {
        if (
          conn.initiator && !conn.remoteSet && shouldInitiate(this.peerId, from)
        ) {
          // Glare: the designated initiator keeps its own offer.
          return;
        }
        // Glare where we yield, or the peer restarted: take the new offer.
        this.dropConn(from);
      }
      this.markOnline(from);
      this.startConn(from, false, sdp);
      return;
    }
    const conn = this.peers.get(from)?.conn;
    if (!conn) return;
    if (kind === "rtc_answer") {
      if (!conn.initiator || conn.remoteSet || !conn.descriptionSent) return;
      const sdp = parseSdpPayload(payload, "answer");
      if (sdp === null) return;
      conn.remoteSet = true;
      // An answer means the contact is there (a probe found it).
      this.markOnline(from);
      if (this.peer(from).path === "Offline") this.setPath(from, "Connecting");
      try {
        await conn.pc.setRemoteDescription({ type: "answer", sdp });
      } catch {
        if (this.live(from, conn)) this.connFailed(from, conn, "Error");
        return;
      }
      if (!this.live(from, conn)) return;
      for (const c of conn.pendingIce.splice(0)) {
        void conn.pc.addIceCandidate(c).catch(() => {});
      }
      return;
    }
    // rtc_ice
    const candidate = parseIcePayload(payload);
    if (!candidate || !candidate.candidate) return; // malformed, or end-of-candidates
    if (this.turn?.relayOnly && !/ typ relay( |$)/.test(candidate.candidate)) {
      return;
    }
    if (conn.remoteSet && conn.pc.remoteDescription) {
      void conn.pc.addIceCandidate(candidate).catch(() => {});
    } else if (conn.pendingIce.length < PENDING_ICE_MAX) {
      conn.pendingIce.push(candidate);
    }
  }

  // ── Connections ──────────────────────────────────────────────────

  /**
   * The user opened a chat or pressed retry: try to connect now (the offer limiter still
   * applies) and start the soft-offline backoff over.
   */
  connect(peerId: string): void {
    void this.internal(() => {
      const st = this.peer(peerId);
      st.attempt = 0;
      st.quietProbe = false;
      st.wanted = this.contacts.has(peerId) &&
        this.verifiedConn(peerId) === null;
      this.probes.restart(peerId, this.p.clock.now());
      this.dial(peerId, true);
      this.armProbeWake();
    });
  }

  /**
   * Ask for a data channel to `peer`. No-op while one is open or being set up. The designated
   * initiator offers; the other side waits for that offer and then offers itself. `force`
   * offers now (pairing, retries, user intent).
   */
  private dial(peer: string, force: boolean): void {
    if (peer === this.peerId || !isPeerId(peer) || !this.registered) return;
    const st = this.peer(peer);
    if (st.conn) return;
    if (st.online === false && !force) return;
    if (force || shouldInitiate(this.peerId, peer)) {
      this.scheduleOffer(peer);
    } else if (!st.fallbackArmed) {
      st.fallbackArmed = true;
      const jitter = this.p.random.next() * OFFER_FALLBACK_JITTER_MS;
      this.after(OFFER_FALLBACK_MS + jitter, () => {
        st.fallbackArmed = false;
        if (!st.conn && st.online !== false) this.scheduleOffer(peer);
        else this.armProbeWake();
      });
    }
  }

  /** Start an offer now, or when the stagger window and any rate-limit pause allow. */
  private scheduleOffer(peer: string): void {
    const st = this.peer(peer);
    if (st.offerWaiting) return;
    const now = this.p.clock.now();
    let wait = Math.max(0, this.signalingBackoffUntil - now);
    if (wait === 0) {
      this.offerHistory = this.offerHistory.filter((t) => now - t < OFFER_WINDOW_MS);
      if (this.offerHistory.length < OFFERS_PER_WINDOW) {
        this.offerHistory.push(now);
      } else wait = Math.max(1, OFFER_WINDOW_MS - (now - this.offerHistory[0]));
    }
    if (wait === 0) {
      this.startConn(peer, true, null);
      return;
    }
    st.offerWaiting = true;
    this.after(wait, () => {
      st.offerWaiting = false;
      if (!st.conn) this.scheduleOffer(peer);
    });
  }

  private live(peer: string, conn: Conn): boolean {
    return this.peers.get(peer)?.conn === conn;
  }

  private connTimer(
    peer: string,
    conn: Conn,
    ms: number,
    fn: () => Promise<void> | void,
  ): void {
    conn.timers.push(this.after(ms, () => {
      if (this.live(peer, conn)) return fn();
    }));
  }

  private startConn(
    peer: string,
    initiator: boolean,
    remoteOffer: string | null,
  ): void {
    const st = this.peer(peer);
    st.fallbackArmed = false;
    // A background probe of a contact believed offline shows nothing until it is answered.
    const quiet = st.quietProbe && st.online === false;
    st.quietProbe = false;
    if (!quiet && st.path !== "NoDirectPath" && st.path !== "BindingFailed") {
      this.setPath(peer, "Connecting");
    }
    let pc: PeerConnection;
    try {
      pc = this.p.peerConnections(this.rtcConfig());
    } catch {
      this.p.log.warn(
        `[WebRTC] could not create a connection to ${shortId(peer)}`,
      );
      this.afterFailure(peer, false, initiator, "Error");
      return;
    }
    const conn: Conn = {
      pc,
      initiator,
      remoteSet: false,
      pendingIce: [],
      dc: null,
      open: false,
      bindingSent: false,
      verified: false,
      descriptionSent: false,
      lateIce: 0,
      timers: [],
    };
    st.conn = conn;

    pc.onconnectionstatechange = () => {
      const state = pc.connectionState;
      void this.internal(() => {
        if (!this.live(peer, conn)) return;
        if (state === "disconnected") {
          this.connTimer(peer, conn, DISCONNECT_GRACE_MS, () => {
            const now = conn.pc.connectionState;
            if (now === "disconnected" || now === "failed") {
              this.connFailed(peer, conn, "Timeout");
            }
          });
        } else if (state === "failed") {
          this.connFailed(peer, conn, "IceFailed");
        } else if (state === "closed") {
          this.connFailed(peer, conn, "Closed");
        }
      });
    };
    pc.onicecandidate = (ev) => {
      const c = ev.candidate;
      if (!c || !c.candidate) return;
      const init: IceCandidateInit = typeof c.toJSON === "function" ? c.toJSON() : {
        candidate: c.candidate,
        sdpMid: c.sdpMid,
        sdpMLineIndex: c.sdpMLineIndex,
        usernameFragment: c.usernameFragment,
      };
      void this.internal(() => this.onLateCandidate(peer, conn, init));
    };
    if (initiator) {
      this.attachChannel(
        peer,
        conn,
        pc.createDataChannel(DATA_CHANNEL_LABEL, { ordered: true }),
      );
    } else {
      pc.ondatachannel = (ev) => {
        // Only the `parolnet` channel, and only one.
        if (ev.channel.label !== DATA_CHANNEL_LABEL || conn.dc) {
          try {
            ev.channel.close();
          } catch { /* nothing to close */ }
          return;
        }
        this.attachChannel(peer, conn, ev.channel);
      };
    }
    this.connTimer(peer, conn, CONNECT_TIMEOUT_MS, () => {
      if (!conn.open) this.connFailed(peer, conn, "Timeout");
    });
    this.negotiate(peer, conn, remoteOffer).catch(() =>
      this.internal(() => {
        if (this.live(peer, conn)) this.connFailed(peer, conn, "Error");
      })
    );
  }

  /** Wire a data channel's callbacks at once (a message can follow in the same task). */
  private attachChannel(peer: string, conn: Conn, dc: DataChannel): void {
    conn.dc = dc;
    dc.onopen = () => void this.internal(() => this.onChannelOpen(peer, conn));
    dc.onmessage = (ev) => {
      const data = ev.data;
      void this.internal(() => this.onData(peer, conn, data));
    };
    dc.onclose = () =>
      void this.internal(() => {
        if (this.live(peer, conn)) this.connFailed(peer, conn, "Closed");
      });
    if (dc.readyState === "open") {
      void this.internal(() => this.onChannelOpen(peer, conn));
    }
  }

  /** Offer or answer, non-trickle: the description is sent once gathering is done or capped. */
  private async negotiate(
    peer: string,
    conn: Conn,
    remoteOffer: string | null,
  ): Promise<void> {
    const pc = conn.pc;
    if (conn.initiator) {
      await pc.setLocalDescription(await pc.createOffer());
    } else {
      await pc.setRemoteDescription({ type: "offer", sdp: remoteOffer ?? "" });
      await this.internal(() => {
        if (!this.live(peer, conn)) return;
        conn.remoteSet = true;
        for (const c of conn.pendingIce.splice(0)) {
          void pc.addIceCandidate(c).catch(() => {});
        }
      });
      await pc.setLocalDescription(await pc.createAnswer());
    }
    await this.gathered(pc);
    await this.internal(() => this.sendDescription(peer, conn));
  }

  private gathered(pc: PeerConnection): Promise<void> {
    if (pc.iceGatheringState === "complete") return Promise.resolve();
    return new Promise((resolve) => {
      const done = () => {
        this.p.clock.clearTimeout(timer);
        pc.onicegatheringstatechange = null;
        resolve();
      };
      const timer = this.p.clock.setTimeout(done, GATHER_CAP_MS);
      pc.onicegatheringstatechange = () => {
        if (pc.iceGatheringState === "complete") done();
      };
    });
  }

  private sendDescription(peer: string, conn: Conn): void {
    if (!this.live(peer, conn)) return;
    const local = conn.pc.localDescription;
    if (!local || !local.sdp) {
      this.connFailed(peer, conn, "Error");
      return;
    }
    if (this.turn?.relayOnly && !hasCandidates(local.sdp)) {
      // Relay-only never falls back to a direct path.
      this.noticeNoRelay();
      this.connFailed(peer, conn, "NoRelay");
      return;
    }
    const payload = JSON.stringify({
      type: conn.initiator ? "offer" : "answer",
      sdp: local.sdp,
    });
    if (payload.length > SDP_PAYLOAD_MAX) {
      this.p.log.warn(
        `[WebRTC] description for ${shortId(peer)} exceeds the relay's size cap`,
      );
    }
    if (
      !this.signal(conn.initiator ? "rtc_offer" : "rtc_answer", peer, payload)
    ) {
      this.connFailed(peer, conn, "Error");
      return;
    }
    conn.descriptionSent = true;
    if (conn.initiator) {
      this.connTimer(peer, conn, ANSWER_TIMEOUT_MS, () => {
        if (!conn.remoteSet) this.connFailed(peer, conn, "Timeout");
      });
    }
  }

  /** A candidate found after the description went out: at most a few go as `rtc_ice`. */
  private onLateCandidate(
    peer: string,
    conn: Conn,
    candidate: IceCandidateInit,
  ): void {
    if (!this.live(peer, conn) || !conn.descriptionSent || conn.open) return;
    if (conn.lateIce >= LATE_ICE_MAX) return;
    if (
      this.turn?.relayOnly && !/ typ relay( |$)/.test(candidate.candidate ?? "")
    ) return;
    const payload = JSON.stringify(candidate);
    if (payload.length > ICE_PAYLOAD_MAX) return;
    if (this.signal("rtc_ice", peer, payload)) conn.lateIce += 1;
  }

  private async onChannelOpen(peer: string, conn: Conn): Promise<void> {
    if (!this.live(peer, conn) || conn.open || !conn.dc) return;
    conn.open = true;
    try {
      conn.dc.send(identityFrame(this.peerId));
    } catch { /* the close handler deals with it */ }
    this.markOnline(peer);
    // PNP-001 §10.5.1: the bootstrap-completing envelope first (we scanned the peer's code),
    // then our binding. Everything else waits for the peer's binding.
    this.connTimer(peer, conn, BINDING_TIMEOUT_MS, () => {
      if (!conn.verified) {
        this.p.log.info(
          `[WebRTC] no channel binding from ${shortId(peer)}; closing`,
        );
        this.connFailed(peer, conn, "Timeout");
      }
    });
    await this.flushBootstrap(peer, conn);
    if (this.live(peer, conn)) await this.sendBinding(peer, conn);
  }

  private closeConn(conn: Conn): void {
    for (const t of conn.timers) this.cancel(t);
    conn.timers = [];
    const { pc, dc } = conn;
    pc.onconnectionstatechange =
      pc.onicecandidate =
      pc.ondatachannel =
      pc.onicegatheringstatechange =
        null;
    if (dc) dc.onopen = dc.onmessage = dc.onclose = null;
    try {
      dc?.close();
    } catch { /* already closed */ }
    try {
      pc.close();
    } catch { /* already closed */ }
  }

  private dropConn(peer: string): void {
    const st = this.peers.get(peer);
    if (st?.conn) {
      const conn = st.conn;
      st.conn = null;
      this.closeConn(conn);
    }
  }

  private connFailed(peer: string, conn: Conn, reason: FailReason): void {
    if (!this.live(peer, conn)) return;
    this.peer(peer).conn = null;
    this.closeConn(conn);
    this.p.log.info(
      `[WebRTC] connection to ${shortId(peer)} ended (${reason})`,
    );
    this.afterFailure(peer, conn.open, conn.initiator, reason);
  }

  private afterFailure(
    peer: string,
    wasOpen: boolean,
    wasInitiator: boolean,
    reason: FailReason,
  ): void {
    const st = this.peer(peer);
    if (st.online === false) {
      this.setPath(peer, "Offline");
      return;
    }
    if (!wasOpen) st.failures += 1;
    let path: PathState;
    if (reason === "Binding") path = "BindingFailed";
    else if (reason === "NoRelay") path = "NoDirectPath";
    else if (wasOpen) path = "Unknown";
    else if (
      (reason === "IceFailed" && st.failures >= 1) ||
      (reason === "Timeout" && st.failures >= 2)
    ) {
      path = "NoDirectPath";
    } else path = "Connecting";
    this.setPath(peer, path);
    if (wasOpen) st.attempt = 0;
    this.scheduleRetry(peer, wasInitiator);
  }

  /** Tell the user (at most once a minute) that relay-only has no relay to use. */
  private noticeNoRelay(): void {
    const now = this.p.clock.now();
    if (this.turnNoticeAt !== null && now - this.turnNoticeAt < 60_000) return;
    this.turnNoticeAt = now;
    this.emit({
      kind: "Notice",
      text: "Your TURN server cannot be used. Relay-only is on, so no connection is made " +
        "without it; check the server in Settings.",
    });
  }

  private scheduleRetry(peer: string, wasInitiator: boolean): void {
    if (!this.contacts.has(peer)) return;
    const weOffer = wasInitiator || shouldInitiate(this.peerId, peer);
    const st = this.peer(peer);
    if (st.online === false || st.retryArmed) return;
    if (st.attempt >= RETRY_MAX_ATTEMPTS && st.online !== true) {
      this.p.log.info(
        `[WebRTC] giving up on ${shortId(peer)} until presence says online`,
      );
      return;
    }
    const n = Math.min(st.attempt, RETRY_MAX_ATTEMPTS);
    st.attempt += 1;
    st.retryArmed = true;
    const base = Math.min(RETRY_BASE_MS * 2 ** n, RETRY_MAX_MS);
    const jitter = base * 0.25 * this.p.random.next();
    // The side that would not offer waits longer, so the initiator's retry usually wins.
    const extra = weOffer ? 0 : OFFER_FALLBACK_MS;
    this.after(base + jitter + extra, () => {
      st.retryArmed = false;
      if (!st.conn && st.online !== false) this.dial(peer, true);
      // A soft-offline contact could not be probed while this retry was pending.
      else this.armProbeWake();
    });
  }

  private markOnline(peer: string): void {
    const st = this.peer(peer);
    st.online = true;
    st.offlineByError = false;
    this.probes.clear(peer);
  }

  private probeActive = (peer: string): boolean =>
    this.queuedFor(peer) > 0 || this.hasBootstrapQueued(peer) ||
    this.peers.get(peer)?.wanted === true;

  private probeReady = (peer: string): boolean => {
    const st = this.peers.get(peer);
    return !st ||
      (!st.conn && !st.retryArmed && !st.offerWaiting && !st.fallbackArmed);
  };

  /**
   * Offer again to the soft-offline contacts that are due. Nothing goes out while the relay
   * is away or has rate-limited us.
   */
  private runProbes(): void {
    const now = this.p.clock.now();
    if (!this.registered || now < this.signalingBackoffUntil) return;
    const due = this.probes.takeDue(
      now,
      this.probeActive,
      this.probeReady,
      () => this.p.random.next(),
    );
    for (const peer of due) {
      const st = this.peers.get(peer);
      if (
        !st || st.online !== false || !st.offlineByError ||
        !this.contacts.has(peer)
      ) {
        this.probes.clear(peer);
        continue;
      }
      st.quietProbe = true;
      this.dial(peer, true);
    }
    this.armProbeWake();
  }

  /** Make sure a timer fires when the next probe is due. */
  private armProbeWake(): void {
    const now = this.p.clock.now();
    const at = this.probes.nextWake(now, this.probeActive, this.probeReady);
    if (at === null) return;
    if (
      this.probeWakeAt !== null && this.probeWakeAt > now &&
      this.probeWakeAt <= at
    ) return;
    this.probeWakeAt = at;
    this.after(Math.max(at - now, 20), () => {
      if (this.probeWakeAt === at) this.probeWakeAt = null;
      this.runProbes();
    });
  }

  private armTick(): void {
    this.after(TICK_MS, async () => {
      this.armTick();
      const expired = this.expired(this.p.clock.now());
      if (expired.length > 0) {
        await this.save(await this.dropOps(expired));
        this.announceDropped(expired);
      }
      if (!this.registered) return;
      for (const c of this.contacts.values()) {
        const st = this.peer(c.peerId);
        if (st.conn || st.retryArmed || st.offerWaiting || st.fallbackArmed) {
          continue;
        }
        if (
          st.online === null &&
          (this.queuedFor(c.peerId) > 0 || this.hasBootstrapQueued(c.peerId))
        ) {
          this.dial(c.peerId, false);
        }
      }
      // Also the fallback for probes held back while the relay was away or rate-limiting.
      this.runProbes();
    });
  }

  // ── Incoming content ─────────────────────────────────────────────

  private async onData(peer: string, conn: Conn, data: unknown): Promise<void> {
    if (!this.live(peer, conn)) return;
    const frame = parseDcFrame(data);
    if (frame.type === "identity") {
      // Informational. The channel's peer is the signaling peer, proven by the binding.
      if (frame.peerId.toLowerCase() !== peer) {
        this.p.log.warn(
          `[WebRTC] identity frame from ${shortId(peer)} names someone else`,
        );
      }
      return;
    }
    if (frame.type !== "envelope") return; // `gossip` and anything unknown
    if (frame.hex.length > 2 * 16384 || !/^[0-9a-fA-F]+$/.test(frame.hex)) {
      return;
    }
    await this.onEnvelope(peer, conn, frame.hex);
  }

  private async onEnvelope(
    peer: string,
    conn: Conn,
    envelopeHex: string,
  ): Promise<void> {
    const { wasm, log } = this.p;
    let msgType: number | null = null;
    let plaintextHex = "";
    let bootstrappedKey: string | null = null;

    // Only the session of the channel's own peer may decrypt what arrives on it.
    if (wasm.has_session(peer)) {
      try {
        const d = wasm.envelope_decode(peer, envelopeHex);
        msgType = d.msg_type;
        plaintextHex = d.plaintext_hex;
      } catch {
        log.debug(`[Engine] an envelope from ${shortId(peer)} did not decrypt`);
        this.rollbackSessions();
      }
    }
    // PNP-001 §5.3.1: while our code is valid, the scanner's first envelope materialises
    // our session. Its cleartext source_hint is the scanner's identity key and must hash to
    // the PeerId this channel was signalled with, or anyone holding the code could pair us
    // with a third party's identity.
    if (msgType === null && this.pairingOpen()) {
      const hint = envelopeSourceHint(envelopeHex);
      const hintBytes = hint === null ? null : fromHex(hint);
      if (
        hint !== null && hintBytes !== null &&
        toHex(await this.p.sha256(hintBytes)) === peer
      ) {
        if (!this.live(peer, conn) || !this.pairingOpen()) return;
        try {
          const d = wasm.trial_decrypt(envelopeHex);
          if (
            d.bootstrapped === true &&
            String(d.source_peer_id).toLowerCase() === peer
          ) {
            msgType = d.msg_type;
            plaintextHex = d.plaintext_hex;
            bootstrappedKey = hint;
          }
        } catch {
          log.info(`[Engine] bootstrap from ${shortId(peer)} failed`);
        }
        // `trial_decrypt` tries every existing session before the pending bootstrap: undo
        // what that did to them (and keep the session it may just have made for this peer).
        this.rollbackSessions(bootstrappedKey !== null ? peer : null);
      }
    }
    if (msgType === null) return;

    const ops: WriteOp[] = [this.sessionsOp()];
    const events: AppEvent[] = [];
    if (bootstrappedKey !== null) {
      // The code is used up: the pending half is gone and the window closes with it.
      this.closePairing(true);
      const { row, isNew } = this.upsertContact(peer, bootstrappedKey, null);
      ops.push({ op: "put", store: "contacts", value: row });
      if (!this.contactState.has(peer)) ops.push(this.activityOp(peer, 0));
      const contact = toContact(row);
      events.push(
        isNew ? { kind: "ContactAdded", contact } : { kind: "ContactUpdated", contact },
      );
    }

    // PNP-001-MUST-081 / SHOULD-018: until the binding verifies, only the bootstrap envelope
    // and the binding itself are acted on.
    const early = msgType === MsgType.CONTROL ||
      msgType === MsgType.CHANNEL_BINDING;
    let received: MessageRow | null = null;
    if (!conn.verified && !early) {
      log.warn(
        `[Engine] dropped a message from ${shortId(peer)} that came before the binding`,
      );
    } else if (msgType === MsgType.TEXT) {
      const bytes = fromHex(plaintextHex) ?? new Uint8Array(0);
      if (!this.contacts.has(peer)) {
        const { row } = this.upsertContact(peer, null, null);
        ops.push({ op: "put", store: "contacts", value: row });
        events.push({ kind: "ContactAdded", contact: toContact(row) });
      }
      received = {
        id: this.nextMessageId++,
        peerId: peer,
        direction: "Received",
        text: fromUtf8(bytes),
        timestampMs: this.p.clock.now(),
        state: "Received",
      };
      wipe(bytes);
      ops.push(
        { op: "put", store: "messages", value: received },
        this.activityOp(peer, 1),
      );
    }
    // The advanced ratchet and what it decrypted are saved together, before anything shows.
    await this.save(ops);
    for (const ev of events) this.emit(ev);
    if (events.length > 0) this.sendWatch();
    if (received) {
      this.emit({ kind: "Message", message: toMessage(received) });
      this.emitActivity(peer);
    }
    if (!this.live(peer, conn)) return;
    // We may hold a session only now (the presenter, on the scanner's bootstrap envelope).
    if (msgType !== MsgType.CHANNEL_BINDING) await this.sendBinding(peer, conn);
    if (!this.live(peer, conn)) return;

    if (msgType === MsgType.CHANNEL_BINDING) {
      const body = fromHex(plaintextHex);
      if (body) await this.onBinding(peer, conn, body);
    } else if (msgType === MsgType.CALL_SIGNAL && conn.verified) {
      const bytes = fromHex(plaintextHex);
      const sig = bytes ? parseCallSignal(fromUtf8(bytes)) : null;
      if (sig) await this.calls.onSignal(peer, sig);
    }
    // CONTROL carries nothing; DECOY and unknown types are discarded (PNP-001-MUST-008).
  }

  // ── Calls ────────────────────────────────────────────────────────

  /** A call signal on the contact's verified channel. Never queued. */
  private async sendCallSignal(
    peer: string,
    sig: CallSignal,
  ): Promise<boolean> {
    const conn = this.verifiedConn(peer);
    if (!conn) return false;
    let envelope: string;
    const body = utf8(callSignalJson(sig));
    try {
      envelope = this.p.wasm.envelope_encode(
        peer,
        MsgType.CALL_SIGNAL,
        body,
        this.nowSecs(),
        null,
      );
    } catch {
      return false;
    }
    await this.save([this.sessionsOp()]);
    return this.verifiedConn(peer) === conn && this.sendRaw(conn, envelope);
  }

  /** Call a contact over a verified direct connection: audio, plus video when `video`. */
  startCall(peerId: string, video: boolean): Promise<CallInfo> {
    return this.post(() => this.calls.start(peerId, video));
  }

  /** Accept the incoming call. */
  acceptCall(callId: string): Promise<CallInfo> {
    return this.post(() => this.calls.accept(callId));
  }

  /** Decline the incoming call. */
  rejectCall(callId: string): Promise<void> {
    return this.post(() => this.calls.reject(callId));
  }

  /** End a call (outgoing, connecting or active); declines one that is still ringing. */
  hangup(callId: string): Promise<void> {
    return this.post(() => this.calls.hangup(callId));
  }

  /** The current call's streams, for `<audio>` / `<video>` elements. */
  callMedia(
    callId: string,
  ): { local: MediaStreamLike | null; remote: MediaStreamLike | null } | null {
    return this.calls.media(callId);
  }

  /** Mute or unmute our microphone (no signalling, no renegotiation). */
  setMuted(callId: string, muted: boolean): void {
    this.calls.setMuted(callId, muted);
  }

  /** Switch our camera off or on (the track stays). */
  setCameraOff(callId: string, off: boolean): void {
    this.calls.setCameraOff(callId, off);
  }

  // ── Settings ─────────────────────────────────────────────────────

  /** The user's TURN server, for the settings view (snapshots only say whether one is set). */
  turnSettings(): Promise<TurnSettings | null> {
    return this.post(() => (this.turn ? { ...this.turn } : null));
  }

  /**
   * Use the user's own TURN server from now on (`null`: forget it). New connections use it
   * at once and existing data connections are rebuilt. A contact in a call keeps its
   * connections until the next reconnect.
   */
  setTurnSettings(settings: TurnSettings | null): Promise<void> {
    return this.post(async () => {
      const next = settings === null ? null : validateTurn(settings);
      if (JSON.stringify(next) === JSON.stringify(this.turn)) return;
      await this.save([
        next === null ? { op: "delete", store: "settings", key: "turn" } : {
          op: "put",
          store: "settings",
          value: { key: "turn", value: next } satisfies SettingRow,
        },
      ]);
      this.turn = next;
      this.turnNoticeAt = null;
      const inCall = this.calls.busyPeer();
      for (const [peer, st] of this.peers) {
        if (!st.conn || peer === inCall) continue;
        this.dropConn(peer);
        if (st.online === false) continue; // a probe was under way; the next uses the new settings
        st.attempt = 0;
        st.failures = 0;
        this.setPath(peer, "Connecting");
        this.dial(peer, true);
      }
      // Contacts that had no path (and may have run out of retries) get a fresh try.
      for (const c of this.contacts.values()) {
        const st = this.peers.get(c.peerId);
        if (
          st && !st.conn && st.online !== false && st.path === "NoDirectPath"
        ) {
          st.attempt = 0;
          st.failures = 0;
          this.setPath(c.peerId, "Connecting");
          this.dial(c.peerId, true);
        }
      }
    });
  }

  // ── Lifecycle ────────────────────────────────────────────────────

  private async halt(): Promise<void> {
    // The contact hears the hangup while the data channel is still there.
    await this.calls.shutdown();
    this.stopped = true;
    for (const peer of [...this.peers.keys()]) this.dropConn(peer);
    for (const t of [...this.timers]) this.cancel(t);
    this.closePairing(false);
    this.relay.stop();
  }

  /** Close every connection, save state and stop. The engine cannot be used afterwards. */
  async shutdown(): Promise<void> {
    if (this.stopped) return;
    await this.post(async () => {
      try {
        await this.save([this.sessionsOp()]);
      } catch { /* nothing more can be done */ }
      await this.halt();
    }).catch(() => {});
    this.p.storage.close();
    this.p.lock?.release();
  }

  /**
   * "Delete all data on this device": stop, clear the identity and sessions from wasm
   * memory, and delete the database (identity key, sessions, contacts, history, queue,
   * settings). The next start makes a new identity.
   */
  async wipe(): Promise<void> {
    if (!this.stopped) {
      await this.post(() => this.halt()).catch(() => {});
      this.stopped = true;
    }
    try {
      this.p.wasm.panic_wipe?.();
    } catch { /* wasm state is gone with the page anyway */ }
    this.contacts.clear();
    this.contactState.clear();
    this.outbox = [];
    this.turn = null;
    try {
      await this.p.storage.destroy();
    } finally {
      this.p.lock?.release();
    }
  }
}
