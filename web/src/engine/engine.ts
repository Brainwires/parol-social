// The engine: one serial mailbox owns the identity, sessions, contacts, outbox and every
// contact connection. Commands from the UI, relay frames, WebRTC callbacks and timers all
// become mailbox tasks, so the logic reads like the native actor it mirrors
// (crates/parolnet-app/src/engine.rs). No DOM, no framework: everything comes in through
// `Platform`.
import { fromHex, fromUtf8, utf8, wipe } from "./bytes.ts";
import { CallManager } from "./calls.ts";
import { TransferManager } from "./transfers.ts";
import { fetchStun, hasCandidates, peerConfig, validateTurn } from "./ice.ts";
import type {
  DataChannel,
  FileSource,
  IceCandidateInit,
  IceServer,
  MediaStreamLike,
  PairingAnswered,
  PairingStarted,
  PairingStep,
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
  PendingPairingRow,
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
  type PairingFailure,
  type PathState,
  type RelayState,
  type SasCheck,
  shortId,
  type Snapshot,
  type TransferInfo,
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
/** How long a verified connection to a restored contact must stay open to clear its mark. */
export const RESTORED_PROVEN_MS = 10_000;
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
  /** File offers above this size are declined without asking (PNP-010 §8; default 4 GiB). */
  maxAcceptSize?: number;
  /**
   * Ask for the verification code (the SAS of PNP-003 §5.5) in every pairing: both devices
   * then show it and the contact is made only once both people confirmed it. On unless
   * turned off (PNP-003-SHOULD-004, -SHOULD-006); a device that turns it off still shows and
   * checks the code when the contact's device asks for it.
   */
  requestSas?: boolean;
}

/** One pairing (PNP-003) under way with a peer. The protocol state is in wasm. */
interface PairingSlot {
  /** We scanned or pasted the peer's code (the initiator), else we showed ours. */
  readonly initiator: boolean;
  /** HANDSHAKE payloads (hex) waiting for the data channel. */
  outbox: string[];
  /**
   * Our next envelope is the bootstrap-completing one: it carries our identity key as
   * `source_hint` (PNP-001-MUST-063).
   */
  hint: boolean;
  /** A handshake message went out or came in: losing the connection now ends the pairing. */
  started: boolean;
  /** This pairing added the contact (it goes again if the pairing fails). */
  readonly createdContact: boolean;
  /** The code was scanned with the camera: the contact is verified in person once paired. */
  readonly inPerson: boolean;
  /** The verification code, once the pairing shows it. */
  sas: { digits: string; emoji: string } | null;
  /** The user said the code matches. */
  confirmed: boolean;
}

/** The reason a wasm pairing call gave (the Error's message) as the engine reports it. */
function pairingFailure(error: unknown): PairingFailure {
  switch ((error as Error)?.message) {
    case "sas-mismatch":
      return "SasMismatch";
    case "sas-rejected":
      return "SasRejected";
    case "timeout":
      return "Timeout";
    default:
      return "Failed";
  }
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
  private readonly files: TransferManager;
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
  /** The pairings under way, by peer. In memory only: none survives a restart. */
  private readonly pairings = new Map<string, PairingSlot>();
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
      relayName: (host, port) => platform.wasm.relay_name(host, port),
      sign: (nonceHex, relayName) => platform.wasm.sign_relay_register(nonceHex, relayName),
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
    this.files = new TransferManager({
      platform,
      isContact: (peer) => this.contacts.has(peer),
      hasSession: (peer) => platform.wasm.has_session(peer),
      verified: (peer) => this.verifiedConn(peer),
      openChannel: (peer, label) =>
        this.verifiedConn(peer)?.pc.createDataChannel(label, { ordered: true }) ?? null,
      sendControl: (peer, body) => this.sendTransferControl(peer, body),
      connect: (peer) => {
        this.dial(peer, false);
        this.armProbeWake();
      },
      noteIncoming: async (peer) => {
        await this.save([this.activityOp(peer, 1)]);
        this.emitActivity(peer);
      },
      save: (ops) => this.save(ops),
      emit: (ev) => this.emit(ev),
      after: (ms, fn) => this.after(ms, fn),
      cancel: (h) => this.cancel(h),
      internal: (fn) => void this.internal(fn),
      maxAcceptSize: cfg.maxAcceptSize,
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
    for (const c of await storage.getAll<ContactRow>("contacts")) {
      if (isPeerId(c.peerId)) this.contacts.set(c.peerId, c);
    }
    // A pairing lives in memory only, so a contact still marked as pairing was never
    // finished (the page was closed or reloaded meanwhile). The session stored for it is the
    // bootstrap session, or a PNP-002 session the contact never saw confirmed: it is not
    // loaded, and the rest is cleaned up below.
    const unfinished = [...this.contacts.values()].filter((c) => c.pairing !== undefined);
    const sessions = await storage.get<SessionsRow>("sessions", "blob");
    let sessionsJson = sessions?.json ?? "";
    if (sessionsJson && unfinished.length > 0) {
      try {
        const all = JSON.parse(sessionsJson) as Record<string, string>;
        for (const c of unfinished) delete all[c.peerId];
        sessionsJson = Object.keys(all).length > 0 ? JSON.stringify(all) : "";
      } catch {
        sessionsJson = "";
      }
    }
    if (sessionsJson) {
      try {
        wasm.import_sessions(sessionsJson);
        this.sessionsJson = sessionsJson;
      } catch {
        this.p.log.warn(
          "[Engine] stored sessions are unreadable; contacts must pair again",
        );
      }
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
    await this.restorePairing();
    await this.files.load();
    if (unfinished.length > 0) {
      await this.forgetUnfinishedPairings(unfinished, sessionsJson);
    }
    // Entries that outlived the queue's age limit while the app was closed.
    const ops = await this.dropOps(this.expired(clock.now()));
    if (ops.length > 0) await storage.write(ops);
  }

  /**
   * What `load` does with contacts whose pairing a restart interrupted: one the pairing had
   * added goes with everything kept about it; one that was a contact before stays, without
   * a session, and what was waiting for it is dropped. `sessionsJson` is the stored sessions
   * without theirs.
   */
  private async forgetUnfinishedPairings(
    unfinished: readonly ContactRow[],
    sessionsJson: string,
  ): Promise<void> {
    const { storage } = this.p;
    const ops: WriteOp[] = [{
      op: "put",
      store: "sessions",
      value: { id: "blob", json: sessionsJson } satisfies SessionsRow,
    }];
    for (const c of unfinished) {
      const peer = c.peerId;
      const queued = this.outbox.filter((e) => e.peerId === peer);
      if (c.pairing === "new") {
        this.contacts.delete(peer);
        this.contactState.delete(peer);
        this.outbox = this.outbox.filter((e) => e.peerId !== peer);
        ops.push(
          { op: "delete", store: "contacts", key: peer },
          { op: "delete", store: "contactState", key: peer },
          ...queued.map((e): WriteOp => ({ op: "delete", store: "outbox", key: e.id })),
          ...(await this.files.forgetPeer(peer)),
        );
        for (const m of await storage.getAllByPeer<MessageRow>("messages", peer)) {
          ops.push({ op: "delete", store: "messages", key: m.id });
        }
      } else {
        const row = { ...c };
        delete row.pairing;
        this.contacts.set(peer, row);
        ops.push({ op: "put", store: "contacts", value: row }, ...(await this.dropOps(queued)));
      }
    }
    await storage.write(ops);
    this.p.log.info("[Engine] removed what an unfinished pairing left behind");
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
          code: "Storage",
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
        text: this.pairing.text,
        expiresAtMs: this.pairing.expiresAtMs,
      })
      : null;
  }

  private sasOf(peer: string): SasCheck | null {
    const slot = this.pairings.get(peer);
    return slot?.sas
      ? Object.freeze({
        peerId: peer,
        digits: slot.sas.digits,
        emoji: slot.sas.emoji,
        confirmed: slot.confirmed,
      })
      : null;
  }

  /** The verification code to show: the pairing that has waited longest for its user. */
  private currentSas(): SasCheck | null {
    let waiting: SasCheck | null = null;
    for (const peer of this.pairings.keys()) {
      const sas = this.sasOf(peer);
      if (sas && !sas.confirmed) return sas;
      waiting ??= sas;
    }
    return waiting;
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
      sas: this.currentSas(),
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
   * verification (the old PWA rewrote the whole row on every incoming message). With
   * `pairing`, the row is marked as being paired (see `ContactRow.pairing`).
   */
  private upsertContact(
    peer: string,
    identityKey: string | null,
    verified: Verification | null,
    pairing = false,
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
      // Added again: the session is new, whatever a backup brought.
      if (identityKey !== null && row.restoredMs !== undefined) {
        delete row.restoredMs;
        changed = true;
      }
      // A pairing that replaces one still under way keeps what that one knew: a contact the
      // first one added is still one that goes if this one fails.
      if (pairing && row.pairing === undefined) {
        row.pairing = "again";
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
    if (pairing) row.pairing = "new";
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

  /**
   * Remove a contact and everything this device keeps about it: the history, what was
   * waiting to be sent, and the session. Ends a call with it first. The contact is not
   * told; to talk again both sides pair again.
   */
  removeContact(peerId: string): Promise<void> {
    return this.post(async () => {
      this.contactOrThrow(peerId);
      const { wasm, storage } = this.p;
      const call = this.calls.current();
      if (call && call.peerId === peerId) await this.calls.hangup(call.callId);
      // A pairing under way with it ends here; everything else about it goes below.
      const paired = this.pairings.delete(peerId);
      if (paired) {
        try {
          wasm.pairing_abort(peerId);
        } catch { /* nothing under way in wasm */ }
      }
      this.dropConn(peerId);

      // The saved sessions without this contact's.
      let sessions: Record<string, string> = {};
      try {
        const json = wasm.export_sessions();
        if (json) sessions = JSON.parse(json) as Record<string, string>;
      } catch {
        throw new EngineError("Crypto", "could not read the sessions");
      }
      delete sessions[peerId];
      const sessionsJson = Object.keys(sessions).length > 0 ? JSON.stringify(sessions) : "";

      const ops: WriteOp[] = [
        { op: "delete", store: "contacts", key: peerId },
        { op: "delete", store: "contactState", key: peerId },
        ...(await this.files.forgetPeer(peerId)),
        {
          op: "put",
          store: "sessions",
          value: { id: "blob", json: sessionsJson } satisfies SessionsRow,
        },
      ];
      for (const m of await storage.getAllByPeer<MessageRow>("messages", peerId)) {
        ops.push({ op: "delete", store: "messages", key: m.id });
      }
      for (const e of this.outbox) {
        if (e.peerId === peerId) ops.push({ op: "delete", store: "outbox", key: e.id });
      }
      await this.save(ops);

      this.sessionsJson = sessionsJson;
      this.outbox = this.outbox.filter((e) => e.peerId !== peerId);
      this.contacts.delete(peerId);
      this.contactState.delete(peerId);
      this.peers.delete(peerId);
      this.probes.clear(peerId);
      this.forgetSession(peerId, sessionsJson);
      this.sendWatch();
      this.emit({ kind: "ContactRemoved", peerId });
      if (paired) this.emit({ kind: "PairingFailed", peerId, reason: "Cancelled" });
    });
  }

  /**
   * Take one session out of wasm memory. The core has no call for that yet, so without
   * `remove_session` the identity is reloaded with the remaining sessions; that also drops
   * a pairing code being shown, which is then closed. Storage no longer holds the session
   * either way.
   */
  private forgetSession(peerId: string, remainingJson: string): void {
    const { wasm } = this.p;
    try {
      if (typeof wasm.remove_session === "function") {
        wasm.remove_session(peerId);
        return;
      }
      if (typeof wasm.panic_wipe !== "function") return;
      const secret = wasm.export_secret_key();
      wasm.panic_wipe();
      wasm.initialize_from_key(secret);
      if (remainingJson) wasm.import_sessions(remainingJson);
      this.closePairing(true);
    } catch {
      this.p.log.warn("[Engine] could not clear a removed contact's session from memory");
    }
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
   * expires, when someone pairs with it, or on `cancelPairing`. Where the core can export its
   * pending half, it is stored with the code, so the code survives a reload within its
   * lifetime; otherwise a reload invalidates it (the snapshot then has no `pairing`).
   */
  createPairingCode(): Promise<PairingCode> {
    return this.post(async () => {
      let made: { code: string; text: string; expiresAtMs: number };
      try {
        const created = this.p.wasm.pairing_create_code(null);
        made = {
          code: String(created.code),
          text: String(created.text),
          // The scanner measures the code's age from its own timestamp, which is floored to
          // 300 s: the window is exactly as long as the code can still be scanned.
          expiresAtMs: Number(created.expires_secs) * 1000,
        };
      } catch {
        throw new EngineError("Crypto", "could not create a pairing code");
      }
      if (!made.code || !Number.isFinite(made.expiresAtMs)) {
        throw new EngineError("Crypto", "could not create a pairing code");
      }
      // The new pending half has replaced the old one in wasm; the stored row is replaced
      // below.
      this.closePairing(false, false);
      await this.storePairing(made.code, made.text, made.expiresAtMs);
      this.openPairing(made.code, made.text, made.expiresAtMs);
      const pairing = this.currentPairing()!;
      this.emit({ kind: "Pairing", pairing });
      return pairing;
    });
  }

  /** Stop showing the code: strangers' offers are refused again. */
  cancelPairing(): Promise<void> {
    return this.post(() => this.closePairing(true));
  }

  private openPairing(code: string, text: string, expiresAtMs: number): void {
    const timer = this.after(
      expiresAtMs - this.p.clock.now(),
      () => this.closePairing(true),
    );
    this.pairing = { code, text, expiresAtMs, timer };
  }

  /** Keep the code and its pending half for a reload, where the core can export it. */
  private async storePairing(code: string, text: string, expiresAtMs: number): Promise<void> {
    const { wasm } = this.p;
    if (typeof wasm.export_pending_bootstrap !== "function") return;
    const pendingHex = wasm.export_pending_bootstrap();
    if (typeof pendingHex !== "string") return;
    await this.save([{
      op: "put",
      store: "identity",
      value: { id: "pairing", code, text, expiresAtMs, pendingHex } satisfies PendingPairingRow,
    }]);
  }

  /** A code stored before a reload, still within its lifetime: show it again. */
  private async restorePairing(): Promise<void> {
    const { wasm, storage, clock } = this.p;
    const row = await storage.get<PendingPairingRow>("identity", "pairing");
    if (!row) return;
    if (
      typeof wasm.import_pending_bootstrap === "function" &&
      typeof row.pendingHex === "string" && typeof row.code === "string" &&
      typeof row.text === "string" && clock.now() < row.expiresAtMs
    ) {
      try {
        wasm.import_pending_bootstrap(row.pendingHex);
        this.openPairing(row.code, row.text, row.expiresAtMs);
        return;
      } catch {
        this.p.log.warn("[Engine] the stored pairing code is unreadable; a new one is needed");
      }
    }
    await storage.write([{ op: "delete", store: "identity", key: "pairing" }]);
  }

  /**
   * Close the pairing window. `forget` (every case but a new code replacing this one and the
   * engine stopping) also clears the pending half from wasm memory and from storage, so the
   * code cannot be used however the page goes on.
   */
  private closePairing(announce: boolean, forget = true): void {
    if (forget) {
      try {
        this.p.wasm.clear_pending_bootstrap?.();
      } catch { /* nothing pending */ }
      if (typeof this.p.wasm.export_pending_bootstrap === "function") {
        this.p.storage.write([{ op: "delete", store: "identity", key: "pairing" }]).catch(
          () => this.p.log.warn("[Engine] could not delete the stored pairing code"),
        );
      }
    }
    if (!this.pairing) return;
    this.cancel(this.pairing.timer);
    this.pairing = null;
    if (announce) this.emit({ kind: "Pairing", pairing: null });
  }

  private requestSas(): boolean {
    return this.cfg.requestSas !== false;
  }

  /**
   * Pair with a contact's code (PNP-003 §5.1, §5.4), in either form (`PairingCode.code` or
   * `.text`). `via` says how the user obtained it: a camera scan means the two devices were
   * together (`verified: "in-person"` once the pairing completes); a pasted code proves
   * nothing. Starts the pairing and connects. The contact is returned at once, marked
   * `pairing`: it can be used when `PairingComplete` follows; if `PairingFailed` follows
   * instead, a contact this pairing added is removed again.
   */
  pairWithCode(code: string, how: { via: "scan" | "paste" }): Promise<Contact> {
    return this.post(async () => {
      const { wasm, clock } = this.p;
      const sessionsBefore = this.sessionsJson;
      let started: PairingStarted;
      try {
        // Validated in the core: decoded, well-formed, not older than 30 minutes
        // (PNP-003-MUST-010, -MUST-011).
        started = wasm.pairing_initiate(String(code), this.requestSas(), clock.now());
      } catch (e) {
        switch ((e as Error)?.message) {
          case "code-expired":
            throw new EngineError("CodeExpired", "that code has expired; ask for a new one");
          case "own-code":
            throw new EngineError("OwnCode", "that is your own code");
          default:
            throw new EngineError(
              "InvalidCode",
              "expected the full pairing code from the contact's app",
            );
        }
      }
      const peer = String(started.peer_id).toLowerCase();
      const previous = this.contacts.get(peer);
      const { row, isNew } = this.upsertContact(
        peer,
        String(started.identity_key).toLowerCase(),
        null,
        true,
      );
      // It takes the place of a pairing still under way with that peer. The bootstrap
      // session carries the handshake and is replaced by the PNP-002 session; queued texts
      // stay as they are (plaintext until flushed) and go out under that one.
      this.pairings.set(peer, {
        initiator: true,
        outbox: [started.init_hex],
        hint: true,
        started: false,
        createdContact: row.pairing === "new",
        inPerson: how?.via === "scan",
        sas: null,
        confirmed: false,
      });
      const ops: WriteOp[] = [this.sessionsOp(), { op: "put", store: "contacts", value: row }];
      if (!this.contactState.has(peer)) ops.push(this.activityOp(peer, 0));
      try {
        // On record before anything is sent: if the page goes away now, the next start
        // removes what this pairing left.
        await this.save(ops);
      } catch (e) {
        this.pairings.delete(peer);
        try {
          wasm.pairing_abort(peer);
        } catch { /* nothing under way in wasm */ }
        if (previous) this.contacts.set(peer, previous);
        else {
          this.contacts.delete(peer);
          this.contactState.delete(peer);
        }
        // The session this replaced comes back.
        this.sessionsJson = sessionsBefore;
        this.rollbackSessions();
        throw e;
      }
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

  /**
   * The user says the verification code is the one the contact's device shows
   * (PNP-003-MUST-028). The pairing goes on once the contact has confirmed too.
   * `EngineError("NoPairing")` when no code is waiting for an answer.
   */
  confirmSas(peerId: string): Promise<void> {
    return this.post(async () => {
      const { wasm, clock } = this.p;
      const slot = this.pairings.get(peerId);
      const none = () =>
        new EngineError("NoPairing", `no verification code is waiting for ${shortId(peerId)}`);
      if (!slot || !slot.sas || slot.confirmed) throw none();
      let steps: PairingStep[];
      try {
        steps = wasm.pairing_confirm_sas(peerId, clock.now());
      } catch (e) {
        // `wrong-state` changes nothing; anything else ended the pairing.
        if (wasm.pairing_state(peerId) === undefined) {
          await this.abortPairing(peerId, pairingFailure(e));
        }
        throw none();
      }
      slot.confirmed = true;
      this.emitSas(peerId);
      await this.applySteps(peerId, steps);
    });
  }

  /**
   * The user says the verification codes differ (or will not compare them): the pairing is
   * aborted, its secrets are erased and a contact it added is removed (PNP-003 §4).
   */
  rejectSas(peerId: string): Promise<void> {
    return this.post(async () => {
      if (this.pairings.get(peerId)?.sas) await this.abortPairing(peerId, "SasRejected");
    });
  }

  /**
   * Stop a pairing that is still under way (the user does not want to wait for it): as
   * `rejectSas`, at any point of it. Nothing happens when there is none.
   */
  stopPairing(peerId: string): Promise<void> {
    return this.post(() => this.abortPairing(peerId, "Cancelled"));
  }

  private emitSas(peer: string): void {
    const sas = this.sasOf(peer);
    if (sas) this.emit({ kind: "Sas", sas });
  }

  /** A pairing has a message waiting for the connection to its peer. */
  private pairingWaits(peer: string): boolean {
    return (this.pairings.get(peer)?.outbox.length ?? 0) > 0;
  }

  /**
   * Send the waiting handshake messages on the open data channel, as HANDSHAKE envelopes of
   * the session held with the peer. A scanner's first one is the bootstrap-completing
   * envelope and carries our identity key (PNP-001 §5.3.1). As everywhere, the advanced
   * ratchet is saved before the envelope goes on the wire.
   */
  private async flushPairing(peer: string): Promise<void> {
    const { wasm, log } = this.p;
    for (;;) {
      const slot = this.pairings.get(peer);
      const conn = this.peers.get(peer)?.conn;
      if (!slot || slot.outbox.length === 0 || !conn || !conn.open) return;
      if (!wasm.has_session(peer)) return;
      const payload = fromHex(slot.outbox[0]);
      if (!payload) {
        slot.outbox.shift();
        continue;
      }
      let envelope: string;
      try {
        envelope = wasm.envelope_encode(
          peer,
          MsgType.HANDSHAKE,
          payload,
          this.nowSecs(),
          slot.hint ? this.publicKey : null,
        );
      } catch {
        log.warn(`[Engine] could not encrypt a pairing message for ${shortId(peer)}`);
        return;
      }
      await this.save([this.sessionsOp()]);
      if (this.pairings.get(peer) !== slot || !this.live(peer, conn)) return;
      if (!this.sendRaw(conn, envelope)) return;
      slot.outbox.shift();
      slot.hint = false;
      slot.started = true;
    }
  }

  /**
   * The presenter's side of PNP-001 §5.3.1 step 6: the scanner's first envelope decrypted
   * under the session the code's seed materialised. That used the code up (one bootstrap per
   * code, PNP-003-MUST-040). The core accepted it only as a BootstrapHandshake with a valid
   * proof (PNP-003-MUST-022); otherwise the bootstrap is aborted and nothing is kept.
   */
  private async onBootstrap(
    peer: string,
    conn: Conn,
    answered: PairingAnswered,
  ): Promise<void> {
    const had = this.pairings.has(peer);
    // The code is spent either way: the window closes and strangers are not answered any more.
    this.closePairing(true);
    if (!answered.accepted || typeof answered.identity_key !== "string") {
      this.p.log.info(`[Engine] bootstrap from ${shortId(peer)} aborted`);
      // An earlier pairing with that peer went with it (the core removed its session).
      if (had) {
        await this.abortPairing(peer, "Failed");
        return;
      }
      await this.save([this.sessionsOp()]);
      this.emit({ kind: "PairingFailed", peerId: peer, reason: "Failed" });
      if (!this.contacts.has(peer) && this.live(peer, conn)) this.dropConn(peer);
      return;
    }
    const { row, isNew } = this.upsertContact(
      peer,
      answered.identity_key.toLowerCase(),
      null,
      true,
    );
    this.pairings.set(peer, {
      initiator: false,
      outbox: [],
      hint: false,
      started: true,
      createdContact: row.pairing === "new",
      inPerson: false,
      sas: null,
      confirmed: false,
    });
    const ops: WriteOp[] = [
      this.sessionsOp(),
      { op: "put", store: "contacts", value: row },
      // With the contact, so that a reload cannot bring the used code back.
      { op: "delete", store: "identity", key: "pairing" },
    ];
    if (!this.contactState.has(peer)) ops.push(this.activityOp(peer, 0));
    try {
      await this.save(ops);
    } catch (e) {
      await this.abortPairing(peer, "Failed").catch(() => {});
      throw e;
    }
    const contact = toContact(row);
    this.emit(isNew ? { kind: "ContactAdded", contact } : { kind: "ContactUpdated", contact });
    this.sendWatch();
    await this.applySteps(peer, answered.steps);
    // We hold the session only now: our binding can go out. One that went out before (to a
    // contact that is being added again) was made under the session this one replaced, and
    // the peer could not read it.
    conn.bindingSent = false;
    if (this.live(peer, conn)) await this.sendBinding(peer, conn);
  }

  /** A HANDSHAKE envelope from a peer a pairing is under way with. */
  private async onHandshake(peer: string, payloadHex: string): Promise<void> {
    const { wasm, clock, log } = this.p;
    const slot = this.pairings.get(peer);
    if (!slot) {
      log.debug(`[Engine] a handshake message from ${shortId(peer)} without a pairing`);
      return;
    }
    slot.started = true;
    let steps: PairingStep[];
    try {
      steps = wasm.pairing_on_message(peer, payloadHex, clock.now());
    } catch (e) {
      // A proof or a confirmation that did not verify, a replay, a broken handshake: the
      // core has aborted the pairing and erased its secrets (PNP-003-MUST-022, -MUST-029).
      await this.abortPairing(peer, pairingFailure(e));
      return;
    }
    await this.applySteps(peer, steps);
  }

  /** Carry out what the core asks for after a step of a pairing, in order. */
  private async applySteps(peer: string, steps: readonly PairingStep[]): Promise<void> {
    const { wasm } = this.p;
    for (const step of steps) {
      const slot = this.pairings.get(peer);
      if (!slot) return;
      switch (step.kind) {
        case "send":
          slot.outbox.push(step.payload_hex);
          await this.flushPairing(peer);
          break;
        case "sas":
          // PNP-003-MUST-026, -MUST-027: shown as digits and as emoji.
          slot.sas = { digits: String(step.digits), emoji: String(step.emoji) };
          this.emitSas(peer);
          break;
        case "session":
          // What is still waiting was meant for the session this one replaces.
          if (slot.outbox.length > 0) {
            await this.abortPairing(peer, "ConnectionLost");
            return;
          }
          try {
            wasm.pairing_install_session(peer);
          } catch {
            await this.abortPairing(peer, "Failed");
            return;
          }
          await this.save([this.sessionsOp()]);
          break;
        case "established":
          await this.pairingEstablished(peer, slot, step.sas_verified === true);
          break;
      }
    }
  }

  /**
   * The PNP-002 session is ESTABLISHED and the core has erased the Bootstrap Secret
   * (PNP-003-MUST-024): the contact is made, and content flows from here on.
   */
  private async pairingEstablished(
    peer: string,
    slot: PairingSlot,
    sasVerified: boolean,
  ): Promise<void> {
    const { wasm, clock, log } = this.p;
    this.pairings.delete(peer);
    let first: string | null = null;
    if (slot.initiator) {
      // PNP-002-MUST-021: the first Double Ratchet message confirms the session to the peer.
      try {
        first = wasm.envelope_encode(
          peer,
          MsgType.CONTROL,
          new Uint8Array(0),
          this.nowSecs(),
          null,
        );
      } catch {
        log.warn(`[Engine] could not confirm the session to ${shortId(peer)}`);
      }
    }
    const ops: WriteOp[] = [this.sessionsOp()];
    const existing = this.contacts.get(peer);
    let contact: Contact | null = null;
    if (existing) {
      const row = { ...existing };
      delete row.pairing;
      // About the identity, not about one pairing: never taken back by a later one.
      if (sasVerified) row.sasVerified = true;
      if (slot.inPerson && row.verified !== "in-person") {
        row.verified = "in-person";
        row.verifiedMs = clock.now();
      }
      this.contacts.set(peer, row);
      ops.push({ op: "put", store: "contacts", value: row });
      contact = toContact(row);
    }
    await this.save(ops);
    const conn = this.peers.get(peer)?.conn;
    if (first !== null && conn) this.sendRaw(conn, first);
    if (contact) this.emit({ kind: "ContactUpdated", contact });
    this.emit({ kind: "PairingComplete", peerId: peer, sasVerified });
    // The channel may have verified while the pairing was under way: it is usable now.
    const verified = this.verifiedConn(peer);
    if (verified) await this.usable(peer, verified);
  }

  /**
   * Abort a pairing (PNP-003 §4: back to NO_CONTACT). Everything in memory happens here, at
   * once: the core erases the pairing's secrets and removes its session, a contact the
   * pairing added goes, the connection is closed. Returns what is left to do in storage, or
   * null when no pairing was under way.
   */
  private abortPairingNow(
    peer: string,
    reason: PairingFailure,
  ): (() => Promise<void>) | null {
    const slot = this.pairings.get(peer);
    if (!slot) return null;
    const { wasm, storage } = this.p;
    this.pairings.delete(peer);
    try {
      wasm.pairing_abort(peer);
    } catch { /* the core already dropped it */ }
    // What a failed decrypt is rolled back to must not bring the session back.
    this.sessionsOp();
    const row = this.contacts.get(peer);
    const removed = slot.createdContact && row !== undefined;
    const queued = this.outbox.filter((e) => e.peerId === peer);
    let kept: ContactRow | null = null;
    if (removed) {
      this.contacts.delete(peer);
      this.contactState.delete(peer);
      this.outbox = this.outbox.filter((e) => e.peerId !== peer);
      this.probes.clear(peer);
    } else if (row) {
      kept = { ...row };
      delete kept.pairing;
      this.contacts.set(peer, kept);
    }
    this.dropConn(peer);
    if (removed) {
      this.peers.delete(peer);
      this.emit({ kind: "ContactRemoved", peerId: peer });
      this.sendWatch();
    } else {
      this.setPath(peer, "Unknown");
      if (kept) this.emit({ kind: "ContactUpdated", contact: toContact(kept) });
    }
    this.emit({ kind: "PairingFailed", peerId: peer, reason });
    return async () => {
      const ops: WriteOp[] = [this.sessionsOp()];
      let dropped: OutboxRow[] = [];
      if (removed) {
        // Unless the same contact was added again meanwhile.
        if (!this.contacts.has(peer)) {
          ops.push(
            { op: "delete", store: "contacts", key: peer },
            { op: "delete", store: "contactState", key: peer },
            ...queued.map((e): WriteOp => ({ op: "delete", store: "outbox", key: e.id })),
            ...(await this.files.forgetPeer(peer)),
          );
          for (const m of await storage.getAllByPeer<MessageRow>("messages", peer)) {
            ops.push({ op: "delete", store: "messages", key: m.id });
          }
        }
      } else if (kept && this.contacts.get(peer) === kept) {
        // The contact stays, without a session: what was waiting for it cannot be sent.
        dropped = queued.filter((e) => this.outbox.includes(e));
        ops.push({ op: "put", store: "contacts", value: kept }, ...(await this.dropOps(dropped)));
      }
      await this.save(ops);
      this.announceDropped(dropped);
    };
  }

  /** `abortPairingNow` and its storage, for callers inside a mailbox task. */
  private async abortPairing(peer: string, reason: PairingFailure): Promise<void> {
    const persist = this.abortPairingNow(peer, reason);
    if (persist) await persist();
  }

  /**
   * The connection to `peer` is gone. A pairing whose handshake was under way on it is over:
   * its messages are not repeated on another connection. True when one was aborted.
   */
  private pairingConnGone(peer: string): boolean {
    if (this.stopped || !this.pairings.get(peer)?.started) return false;
    const persist = this.abortPairingNow(peer, "ConnectionLost");
    if (persist) void this.internal(persist);
    return true;
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

  /**
   * The contact's data channel, once it can carry content: open, its binding verified, and
   * no pairing under way (while one is, the session is about to be replaced and nothing but
   * the pairing's own messages uses the channel).
   */
  private verifiedConn(peer: string): Conn | null {
    if (this.pairings.has(peer)) return null;
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
      const chunk = this.outbox.filter((e) => e.peerId === peer).slice(0, FLUSH_CHUNK);
      if (chunk.length === 0) return sent;
      const ready: { entry: OutboxRow; envelope: string }[] = [];
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
      const delivered: OutboxRow[] = [];
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
      this.outbox = this.outbox.filter((e) => !delivered.includes(e));
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
        code: "BindingFailed",
        peerId: peer,
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
    // While the contact's pairing is still under way the path is not usable yet: it is shown
    // as direct when the pairing completes.
    if (this.pairings.has(peer)) return;
    await this.usable(peer, conn);
  }

  /** The contact's channel is verified and no pairing is in the way: content flows. */
  private async usable(peer: string, conn: Conn): Promise<void> {
    this.setPath(peer, "Direct");
    this.connTimer(peer, conn, RESTORED_PROVEN_MS, () => this.restoredProven(peer));
    await this.flushQueue(peer);
    if (this.live(peer, conn)) await this.files.onVerified(peer);
  }

  /**
   * A contact restored from a backup has a session that may be older than the one its
   * device holds. Our check of their binding passing is half the proof: a stale session
   * usually still reads what they send, while they cannot read what we send and close the
   * connection at once. A verified connection that is still open a little later is the
   * other half; the mark comes off then (and when the contact is added again).
   */
  private async restoredProven(peer: string): Promise<void> {
    const existing = this.contacts.get(peer);
    if (!existing || existing.restoredMs === undefined) return;
    const row = { ...existing };
    delete row.restoredMs;
    try {
      await this.save([{ op: "put", store: "contacts", value: row }]);
    } catch {
      return; // It stays marked; the next connection tries again.
    }
    this.contacts.set(peer, row);
    this.emit({ kind: "ContactUpdated", contact: toContact(row) });
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
        if (
          this.queuedFor(c.peerId) > 0 || this.pairingWaits(c.peerId) ||
          this.files.wants(c.peerId)
        ) {
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
      // Offering shows our address to whoever receives it: contacts only.
      if (!this.contacts.has(peerId)) return;
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
    // Offering shows our address to whoever receives it: contacts only (a retry may come due
    // after its contact was removed).
    if (!this.contacts.has(peer)) return;
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
    }
    pc.ondatachannel = (ev) => {
      const channel = ev.channel;
      // The answerer's one `parolnet` channel.
      if (!initiator && channel.label === DATA_CHANNEL_LABEL && !conn.dc) {
        this.attachChannel(peer, conn, channel);
        return;
      }
      // Anything else is a file-transfer channel the contact opened (PNP-010 §5.1), or is
      // closed: the transfers decide, in the mailbox, with the connection as it is then.
      const early = this.files.adopt(channel);
      void this.internal(() =>
        this.files.onRemoteChannel(
          peer,
          this.live(peer, conn) && conn.open && conn.verified && !this.pairings.has(peer)
            ? conn
            : null,
          channel,
          early,
        )
      );
    };
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
    // PNP-001 §10.5.1: the bootstrap-completing envelope first (we scanned the peer's code:
    // it carries the pairing's BOOTSTRAP_INIT), then our binding. Everything else waits for
    // the peer's binding.
    this.connTimer(peer, conn, BINDING_TIMEOUT_MS, () => {
      if (!conn.verified) {
        this.p.log.info(
          `[WebRTC] no channel binding from ${shortId(peer)}; closing`,
        );
        this.connFailed(peer, conn, "Timeout");
      }
    });
    await this.flushPairing(peer);
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
      void this.internal(() => this.files.onConnGone(peer));
      this.pairingConnGone(peer);
    }
  }

  private connFailed(peer: string, conn: Conn, reason: FailReason): void {
    if (!this.live(peer, conn)) return;
    this.peer(peer).conn = null;
    this.closeConn(conn);
    void this.internal(() => this.files.onConnGone(peer));
    this.p.log.info(
      `[WebRTC] connection to ${shortId(peer)} ended (${reason})`,
    );
    // A pairing that was under way on it is over, and with it the reason to connect again.
    if (this.pairingConnGone(peer)) return;
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
      code: "TurnUnusable",
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
    this.queuedFor(peer) > 0 || this.pairingWaits(peer) ||
    this.files.wants(peer) ||
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
      // The timeouts of PNP-003 §4 and of the PNP-002 handshake.
      for (const peer of this.p.wasm.pairing_timeouts(this.p.clock.now())) {
        await this.abortPairing(String(peer).toLowerCase(), "Timeout");
      }
      if (!this.registered) return;
      for (const c of this.contacts.values()) {
        const st = this.peer(c.peerId);
        if (st.conn || st.retryArmed || st.offerWaiting || st.fallbackArmed) {
          continue;
        }
        if (
          st.online === null &&
          (this.queuedFor(c.peerId) > 0 || this.pairingWaits(c.peerId) ||
            this.files.wants(c.peerId))
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
    const { wasm, log, clock } = this.p;
    let msgType: number | null = null;
    let plaintextHex = "";

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
    // our session. The core refuses it unless its cleartext source_hint (the scanner's
    // identity key) hashes to the PeerId this channel was signalled with, or anyone holding
    // the code could pair us with a third party's identity; and what it carries has to be
    // the scanner's BootstrapHandshake (PNP-003 §5.4).
    if (msgType === null && this.pairingOpen()) {
      let answered: PairingAnswered | null = null;
      try {
        answered = wasm.pairing_respond(peer, envelopeHex, this.requestSas(), clock.now());
      } catch {
        log.info(`[Engine] bootstrap from ${shortId(peer)} failed`);
      }
      if (answered) await this.onBootstrap(peer, conn, answered);
      return;
    }
    if (msgType === null) return;

    // The responder of a PNP-002 handshake waits for the session's first message: this is it.
    if (this.pairings.has(peer)) {
      const steps = wasm.pairing_first_message(peer);
      if (steps.length > 0) await this.applySteps(peer, steps);
    }

    const ops: WriteOp[] = [this.sessionsOp()];
    const events: AppEvent[] = [];

    // PNP-001-MUST-081 / SHOULD-018: until the binding verifies, only a pairing's own
    // messages and the binding itself are acted on. The same holds while a pairing is under
    // way, whose session is about to be replaced.
    const early = msgType === MsgType.CONTROL || msgType === MsgType.HANDSHAKE ||
      msgType === MsgType.CHANNEL_BINDING;
    const content = conn.verified && !this.pairings.has(peer);
    let received: MessageRow | null = null;
    if (!content && !early) {
      log.warn(
        conn.verified
          ? `[Engine] dropped a message from ${
            shortId(peer)
          } that came before its pairing completed`
          : `[Engine] dropped a message from ${shortId(peer)} that came before the binding`,
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
    if (msgType !== MsgType.CHANNEL_BINDING) await this.sendBinding(peer, conn);
    if (!this.live(peer, conn)) return;

    if (msgType === MsgType.CHANNEL_BINDING) {
      const body = fromHex(plaintextHex);
      if (body) await this.onBinding(peer, conn, body);
    } else if (msgType === MsgType.HANDSHAKE) {
      await this.onHandshake(peer, plaintextHex);
    } else if (msgType === MsgType.CALL_SIGNAL && content) {
      const bytes = fromHex(plaintextHex);
      const sig = bytes ? parseCallSignal(fromUtf8(bytes)) : null;
      if (sig) await this.calls.onSignal(peer, sig);
    } else if (msgType === MsgType.FILE_TRANSFER && content) {
      const body = fromHex(plaintextHex);
      if (body) {
        await this.files.onControl(peer, body);
        // An offer carries the file key.
        wipe(body);
      }
    }
    // CONTROL carries nothing (the first message of a new session); DECOY and unknown types
    // are discarded (PNP-001-MUST-008).
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

  // ── File transfer (PNP-010) ──────────────────────────────────────

  /** A FILE_TRANSFER message on the contact's verified channel; false when there is none. */
  private async sendTransferControl(peer: string, body: Uint8Array): Promise<boolean> {
    const conn = this.verifiedConn(peer);
    if (!conn) return false;
    let envelope: string;
    try {
      envelope = this.p.wasm.envelope_encode(
        peer,
        MsgType.FILE_TRANSFER,
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

  /**
   * Offer a file to a contact. The file is read once for its SHA-256 before the offer is
   * made, then slice by slice while it is sent; the page must stay open until the transfer
   * is over (a reload cancels it: a web page keeps no handle on the file). The offer goes
   * out at once over a verified direct connection, else when one comes up.
   */
  async offerFile(peerId: string, file: FileSource): Promise<TransferInfo> {
    if (this.stopped) throw new EngineError("Stopped", "the engine has stopped");
    const sha256 = await this.files.hash(file);
    return this.post(() => this.files.offer(peerId, file, sha256));
  }

  /** Accept a file a contact offered: it arrives whenever a direct connection exists. */
  acceptTransfer(id: string): Promise<TransferInfo> {
    return this.post(() => this.files.accept(id));
  }

  /** Decline a file a contact offered. */
  declineTransfer(id: string): Promise<TransferInfo> {
    return this.post(() => this.files.decline(id));
  }

  /** Stop a transfer for good, as sender or receiver. What was received of it is removed. */
  cancelTransfer(id: string): Promise<TransferInfo> {
    return this.post(() => this.files.cancelTransfer(id));
  }

  /** The transfers with one contact (or all), oldest first, finished ones included. */
  transfers(peerId?: string): Promise<TransferInfo[]> {
    return this.post(() => this.files.list(peerId));
  }

  /** A received, complete file as a Blob over what is stored on this device; null otherwise. */
  transferFile(id: string): Promise<Blob | null> {
    return this.post(() => this.files.file(id));
  }

  /** Take a finished transfer out of the conversation and delete its stored file. */
  removeTransfer(id: string): Promise<void> {
    return this.post(() => this.files.remove(id));
  }

  /**
   * Whether a file being received survives a reload of the page: true where the browser
   * lets a page write its origin private file system, false where parts are kept in memory.
   */
  receivedFilesPersist(): boolean {
    return this.files.persistent;
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

  /**
   * Send the video of `stream` instead of the camera the call started with (another
   * camera, chosen by the UI). No renegotiation. The engine takes the stream over: it stops
   * the old video track once `CallMedia` has announced the new one, and this one when the
   * call ends. Rejects with `UnknownCall`
   * when the call is over or has no video (the stream is stopped then).
   */
  replaceCamera(callId: string, stream: MediaStreamLike): Promise<void> {
    return this.calls.replaceCamera(callId, stream);
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
    await this.files.shutdown();
    this.stopped = true;
    for (const peer of [...this.peers.keys()]) this.dropConn(peer);
    for (const t of [...this.timers]) this.cancel(t);
    // Stopping (a reload, another tab taking over) keeps a stored code for the next start.
    this.closePairing(false, false);
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
    this.pairings.clear();
    this.outbox = [];
    this.turn = null;
    await this.files.clear();
    try {
      await this.p.storage.destroy();
    } finally {
      this.p.lock?.release();
    }
  }
}
