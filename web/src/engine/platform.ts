// Everything the engine needs from its surroundings, as small interfaces. The engine imports
// no DOM global and no framework; `browser.ts` supplies the real implementations and the unit
// tests supply fakes.

// ── wasm ─────────────────────────────────────────────────────────

/** What `envelope_decode` returns. */
export interface DecodedEnvelope {
  source_hint: string | null;
  msg_type: number;
  plaintext_hex: string;
  timestamp: number | bigint;
}

/** `pairing_create_code`: a code to show, with its pending half kept in wasm memory. */
export interface CreatedCode {
  /** What the QR code encodes: base45 of the CBOR payload. */
  code: string;
  /** The same code for copying as text. */
  text: string;
  /** The payload's timestamp, seconds. */
  ts: number | bigint;
  /** When a scanner stops accepting it, seconds. */
  expires_secs: number | bigint;
}

/**
 * What to do next in a pairing, in order (crates/parolnet-wasm/src/pairing.rs):
 * - `send`: send `payload_hex` as a HANDSHAKE envelope of the session held with the peer now;
 * - `sas`: show the verification code and ask whether the contact shows the same;
 * - `session`: call `pairing_install_session` (after every `send` before it was encrypted);
 * - `established`: the pairing is over; an initiator sends the session's first message.
 */
export type PairingStep =
  | { kind: "send"; payload_hex: string }
  | { kind: "sas"; digits: string; emoji: string }
  | { kind: "session" }
  | { kind: "established"; sas_verified: boolean };

/** `pairing_initiate`. */
export interface PairingStarted {
  peer_id: string;
  identity_key: string;
  /** The BOOTSTRAP_INIT to send first. */
  init_hex: string;
}

/** `pairing_respond`: the code is spent either way. */
export interface PairingAnswered {
  accepted: boolean;
  identity_key?: string;
  /** Why the bootstrap was aborted, when `accepted` is false. */
  reason?: string;
  steps: PairingStep[];
}

/**
 * The parolnet-wasm exports the engine uses (crates/parolnet-wasm/src/lib.rs). One wasm
 * instance holds one identity and its sessions in a module-global, so one engine needs one
 * instance of its own.
 */
export interface WasmApi {
  /** New identity; returns the PeerId (hex). */
  initialize(): string;
  /** Restore an identity from its 32-byte secret (hex); returns the PeerId (hex). */
  initialize_from_key(secretKeyHex: string): string;
  export_secret_key(): string;
  get_peer_id(): string;
  /** Ed25519 public key, hex. */
  get_public_key(): string;
  /**
   * The canonical name (`host:port`) of the relay at a host and port (PNP-001 §10.7).
   * Throws when the host is not one a relay can have.
   */
  relay_name(host: string, port: number): string;
  /**
   * The answer to a relay's register challenge: the Ed25519 signature (hex) over the
   * register message for the 32-byte nonce and the relay's canonical name. Valid at that
   * relay only.
   */
  sign_relay_register(nonceHex: string, relayName: string): string;
  /** Encrypt for a peer and pad to a bucket; returns the envelope hex. Advances the ratchet. */
  envelope_encode(
    destPeerIdHex: string,
    msgType: number,
    plaintext: Uint8Array,
    nowSecs: bigint,
    sourceHintHex?: string | null,
  ): string;
  /** Decrypt with the session of one peer. Throws when it does not decrypt. */
  envelope_decode(
    sourcePeerIdHex: string,
    envelopeHex: string,
  ): DecodedEnvelope;
  has_session(peerIdHex: string): boolean;
  /** JSON `{peerHex: sessionHex}`, or `""` with no sessions. Secret. */
  export_sessions(): string;
  import_sessions(json: string): number;
  /** CBOR CHANNEL_BINDING body; throws when a description has no fingerprint. */
  channel_binding_body(localSdp: string, remoteSdp: string): Uint8Array;
  channel_binding_verify(
    body: Uint8Array,
    localSdp: string,
    remoteSdp: string,
  ): boolean;

  // ── PNP-003 pairing (crates/parolnet-wasm/src/pairing.rs) ──
  // One pairing per peer is kept in wasm memory with its secrets; these calls return what
  // the engine has to carry or show. Errors are short codes in the Error's message.
  /** Makes a code and keeps its pending half (in wasm memory), replacing an earlier one. */
  pairing_create_code(relayHint?: string | null): CreatedCode;
  /**
   * Scanner side: validates the code (either form), sets up the bootstrap session and starts
   * the pairing. Throws `code-invalid`, `code-expired` or `own-code`.
   */
  pairing_initiate(text: string, requestSas: boolean, nowMs: number): PairingStarted;
  /**
   * Presenter side: the scanner's bootstrap envelope, from the peer the connection belongs
   * to. Throws when it is not that (nothing changed, the code stays valid).
   */
  pairing_respond(
    expectedPeerIdHex: string,
    envelopeHex: string,
    requestSas: boolean,
    nowMs: number,
  ): PairingAnswered;
  /** A HANDSHAKE payload from the peer. Throws the reason when the pairing was aborted. */
  pairing_on_message(peerIdHex: string, payloadHex: string, nowMs: number): PairingStep[];
  /** An envelope of the peer's session decrypted: a waiting responder is established. */
  pairing_first_message(peerIdHex: string): PairingStep[];
  /** The user says the code matches. Throws `wrong-state` when none is waiting. */
  pairing_confirm_sas(peerIdHex: string, nowMs: number): PairingStep[];
  /** Carries out a `session` step: the PNP-002 session replaces the bootstrap session. */
  pairing_install_session(peerIdHex: string): void;
  /** Aborts a pairing: its secrets and its session are gone. True when there was one. */
  pairing_abort(peerIdHex: string): boolean;
  /** The peers whose pairing just timed out (each aborted as by `pairing_abort`). */
  pairing_timeouts(nowMs: number): string[];
  /** `secret_shared`, `sas_pending`, `handshaking`, `accepted`, or undefined: no pairing. */
  pairing_state(peerIdHex: string): string | undefined;
  safety_number(peerAHex: string, peerBHex: string): string;
  version(): string;
  /**
   * Argon2id (RFC 9106): `len` bytes of key from a passphrase. Secret. Throws on parameters
   * out of range. The passphrase lock and the backup file use it (./vault.ts).
   */
  argon2id(
    passphrase: Uint8Array,
    salt: Uint8Array,
    memoryKiB: number,
    passes: number,
    lanes: number,
    len: number,
  ): Uint8Array;
  /** Clears the identity, sessions and pending bootstrap from wasm memory. */
  panic_wipe?(): void;
  /** Drops one peer's session (its keys are zeroized). Feature-detected: older cores lack it. */
  remove_session?(peerIdHex: string): void;
  /** The pending bootstrap as a hex blob (secret), or undefined when there is none. */
  export_pending_bootstrap?(): string | undefined;
  /** Restores a pending bootstrap exported by `export_pending_bootstrap`. Throws on a bad blob. */
  import_pending_bootstrap?(blobHex: string): void;
  /** Forgets the pending bootstrap: the code shown for it stops working. */
  clear_pending_bootstrap?(): void;

  // ── PNP-010 file transfer (crates/parolnet-wasm/src/transfer.rs) ──
  /** A new offer with a fresh id and file key. Throws when a field is outside the limits. */
  pnp010_new_offer(name: string, size: number, mime: string, sha256Hex: string): TransferControl;
  pnp010_encode_offer(
    idHex: string,
    name: string,
    size: number,
    mime: string,
    sha256Hex: string,
    keyHex: string,
  ): Uint8Array;
  /** `kind`: accept, decline, cancel (with `reason`) or complete. */
  pnp010_encode_control(kind: string, idHex: string, reason: number): Uint8Array;
  /** Throws when the body is not a well-formed PNP-010 message. */
  pnp010_decode_control(body: Uint8Array): TransferControl;
  /** `ignore`, `new`, or the phase the transfer moves to. */
  pnp010_on_control(
    role: string | undefined,
    phase: string | undefined,
    kind: string,
  ): string;
  /** The transfer id to serve, `close`, or `foreign`. */
  pnp010_admit_channel(
    label: string,
    verified: boolean,
    open: number,
    role: string | undefined,
    phase: string | undefined,
  ): string;
  pnp010_label_id(label: string): string | undefined;
  pnp010_label(idHex: string): string;
  pnp010_admit_offer(
    size: number,
    maxSize: number,
    pending: number,
    withinRate: boolean,
  ): boolean;
  pnp010_sanitize_file_name(offered: string): string;
  pnp010_numbered_file_name(name: string, n: number): string;
  pnp010_limits(): TransferLimits;
  TransferOfferLimiter: new (nowMs: number) => WasmOfferLimiter;
  TransferHasher: new () => WasmTransferHasher;
  TransferSender: new (idHex: string, size: number, keyHex: string) => WasmTransferSender;
  TransferReceiver: new (
    idHex: string,
    size: number,
    sha256Hex: string,
    keyHex: string,
    next: number,
  ) => WasmTransferReceiver;
}

/** A decoded `FILE_TRANSFER` message. `key` is secret: stored, never logged. */
export interface TransferControl {
  t: "offer" | "accept" | "decline" | "cancel" | "complete";
  id: string;
  name?: string;
  size?: number;
  mime?: string;
  sha256?: string;
  key?: string;
  reason?: number;
}

/** The constants of PNP-010 (`pnp010_limits`). */
export interface TransferLimits {
  msgType: number;
  chunkSize: number;
  messageMax: number;
  bufferHigh: number;
  bufferLow: number;
  maxConcurrent: number;
  maxPendingOffers: number;
  defaultMaxAcceptSize: number;
  maxFileSize: number;
  maxRecordFailures: number;
  transferMaxAgeMs: number;
  labelPrefix: string;
  reservedPrefix: string;
}

export interface WasmOfferLimiter {
  allow(nowMs: number): boolean;
  free(): void;
}

export interface WasmTransferHasher {
  update(bytes: Uint8Array): void;
  length(): number;
  /** Consumes the hasher. */
  finalize(): string;
}

export interface WasmTransferSender {
  /** Throws: close the channel. */
  begin(resume: Uint8Array): Uint8Array;
  /** -1 when there is nothing (more) to send in this attempt. */
  next_offset(): number;
  next_len(): number;
  seal(chunk: Uint8Array): Uint8Array;
  is_finished(): boolean;
  sent_bytes(): number;
  end_attempt(): void;
  free(): void;
}

export interface WasmTransferReceiver {
  absorb_stored(bytes: Uint8Array): void;
  begin(): Uint8Array;
  /** The plaintext to store, or undefined for START. Throws: close the channel. */
  on_message(message: Uint8Array): Uint8Array | undefined;
  end_attempt(): void;
  next_record(): number;
  stored_bytes(): number;
  is_complete(): boolean;
  record_failures(): number;
  finish(): boolean;
  free(): void;
}

// ── files ────────────────────────────────────────────────────────

/** A file to send: the part of a browser `File` the engine uses. */
export interface FileSource {
  readonly name: string;
  readonly size: number;
  readonly type: string;
  slice(start: number, end: number): { arrayBuffer(): Promise<ArrayBuffer> };
}

/** One segment of a received file being written. */
export interface SegmentWriter {
  write(chunk: Uint8Array): Promise<void>;
  /** Finish the segment: from here on it is stored (durably, where the store is). */
  close(): Promise<void>;
  /** Drop what was written. */
  abort(): Promise<void>;
}

/**
 * Where a received file is kept while it arrives and until the user saves it: a sequence of
 * segments per transfer, each written once, front to back. A file is never held in one
 * piece in memory. The engine hands a store only ciphertext (./sealed-files.ts): a segment
 * is opaque bytes to it, and `blob` is not what the person saves.
 */
export interface FileStore {
  /** Stored parts survive a reload (OPFS), or not (memory). */
  readonly persistent: boolean;
  /** How many segments 0..n-1 are stored for a transfer. */
  segments(id: string): Promise<number>;
  readSegment(id: string, index: number): Promise<Uint8Array>;
  /** Start segment `index`, dropping any stored segment from `index` on. */
  writer(id: string, index: number): Promise<SegmentWriter>;
  /** Segments 0..count-1 as one Blob of the given MIME type. */
  blob(id: string, count: number, type: string): Promise<Blob>;
  remove(id: string): Promise<void>;
  /** Remove every stored part ("delete all data on this device"). */
  clear(): Promise<void>;
}

// ── storage ──────────────────────────────────────────────────────

export type StoreName =
  | "identity"
  | "sessions"
  | "contacts"
  | "messages"
  | "outbox"
  | "contactState"
  | "settings";

export type WriteOp =
  | { op: "put"; store: StoreName; value: unknown }
  | { op: "delete"; store: StoreName; key: string | number };

/** A small key-value store with one index (`peerId` on `messages` and `outbox`). */
export interface Storage {
  get<T>(store: StoreName, key: string | number): Promise<T | undefined>;
  /** In key order. */
  getAll<T>(store: StoreName): Promise<T[]>;
  /** Rows of `messages` or `outbox` for one peer, in key order. */
  getAllByPeer<T>(store: "messages" | "outbox", peerId: string): Promise<T[]>;
  /** The largest numeric key of a store; 0 when it is empty. */
  maxKey(store: "messages" | "outbox"): Promise<number>;
  /** Apply every operation or none. */
  write(ops: readonly WriteOp[]): Promise<void>;
  close(): void;
  /** Close and delete the database. */
  destroy(): Promise<void>;
}

// ── sockets ──────────────────────────────────────────────────────

/** The part of `WebSocket` the relay client uses. */
export interface Socket {
  onopen: (() => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onclose: ((ev: { code?: number; reason?: string }) => void) | null;
  onerror: (() => void) | null;
  send(data: string): void;
  close(code?: number, reason?: string): void;
}

export type SocketFactory = (url: string) => Socket;

// ── WebRTC ───────────────────────────────────────────────────────

export interface SessionDescription {
  type: string;
  sdp: string;
}

export interface IceCandidateInit {
  candidate?: string;
  sdpMid?: string | null;
  sdpMLineIndex?: number | null;
  usernameFragment?: string | null;
}

export interface IceServer {
  urls: string | string[];
  username?: string;
  credential?: string;
}

export interface PeerConfig {
  iceServers: IceServer[];
  iceTransportPolicy?: "all" | "relay";
}

/** The part of `RTCDataChannel` the engine uses. */
export interface DataChannel {
  readonly label: string;
  readonly readyState: string;
  readonly bufferedAmount: number;
  onopen: (() => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onclose: (() => void) | null;
  /** Transfer channels: `"arraybuffer"`. */
  binaryType?: string;
  bufferedAmountLowThreshold?: number;
  onbufferedamountlow?: (() => void) | null;
  send(data: string | Uint8Array): void;
  close(): void;
}

/** Opaque to the engine: a browser `MediaStreamTrack`. */
export interface MediaTrack {
  readonly kind: string;
  enabled: boolean;
  stop(): void;
}

/** Opaque to the engine: a browser `MediaStream`. */
export interface MediaStreamLike {
  getTracks(): MediaTrack[];
  getAudioTracks(): MediaTrack[];
  getVideoTracks(): MediaTrack[];
}

/** The part of `RTCRtpSender` the engine uses. */
export interface RtpSender {
  readonly track: MediaTrack | null;
  replaceTrack(track: MediaTrack | null): Promise<void>;
  /** The DTLS transport it sends on, once descriptions are set (where the browser has it). */
  readonly transport?: DtlsTransport | null;
}

/** The part of `RTCDtlsTransport` the engine uses. */
export interface DtlsTransport {
  readonly state: string;
  addEventListener(type: "statechange", listener: () => void): void;
}

/** The part of `RTCPeerConnection` the engine uses. */
export interface PeerConnection {
  /** Read live at binding time (the interop driver overrides this getter). */
  readonly localDescription: SessionDescription | null;
  readonly remoteDescription: SessionDescription | null;
  readonly connectionState: string;
  readonly iceGatheringState: string;
  onconnectionstatechange: (() => void) | null;
  onicegatheringstatechange: (() => void) | null;
  onicecandidate:
    | ((
      ev: {
        candidate: (IceCandidateInit & { toJSON?(): IceCandidateInit }) | null;
      },
    ) => void)
    | null;
  ondatachannel: ((ev: { channel: DataChannel }) => void) | null;
  ontrack:
    | ((ev: { track: MediaTrack; streams: readonly MediaStreamLike[] }) => void)
    | null;
  createDataChannel(
    label: string,
    options?: { ordered?: boolean },
  ): DataChannel;
  createOffer(): Promise<SessionDescription>;
  createAnswer(): Promise<SessionDescription>;
  setLocalDescription(desc: SessionDescription): Promise<void>;
  setRemoteDescription(desc: SessionDescription): Promise<void>;
  addIceCandidate(candidate: IceCandidateInit): Promise<void>;
  addTrack(track: MediaTrack, stream: MediaStreamLike): unknown;
  /** Optional: switching cameras during a call needs it. */
  getSenders?(): RtpSender[];
  close(): void;
}

/**
 * Makes a peer connection. The browser implementation looks `RTCPeerConnection` up on
 * `globalThis` at every call, never at module load (the interop driver wraps the constructor).
 */
export type PeerConnectionFactory = (config: PeerConfig) => PeerConnection;

export interface MediaConstraints {
  audio: boolean;
  video: boolean | { width?: number; height?: number };
}

/** Media capture. The UI layer supplies it (and owns any permission prompt). */
export interface MediaDevices {
  getUserMedia(constraints: MediaConstraints): Promise<MediaStreamLike>;
}

// ── time, randomness, HTTP, logging ──────────────────────────────

export interface Clock {
  /** Milliseconds since the Unix epoch. */
  now(): number;
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface Random {
  /** Uniform in [0, 1). Used for jitter only, never for keys. */
  next(): number;
  /** Cryptographically strong bytes (call ids). */
  bytes(n: number): Uint8Array;
}

export interface FetchResponse {
  ok: boolean;
  status: number;
  text(): Promise<string>;
}

export type Fetch = (
  url: string,
  init?: { signal?: AbortSignal },
) => Promise<FetchResponse>;

export type Sha256 = (data: Uint8Array) => Promise<Uint8Array>;

/** Diagnostics. The engine never passes a secret to it. */
export interface Logger {
  debug(...args: unknown[]): void;
  info(...args: unknown[]): void;
  warn(...args: unknown[]): void;
}

/** Makes sure one engine at a time uses the database (two tabs would fork the ratchets). */
export interface InstanceLock {
  /** True when this instance now holds the lock. */
  acquire(): Promise<boolean>;
  release(): void;
}

export interface Platform {
  wasm: WasmApi;
  storage: Storage;
  sockets: SocketFactory;
  peerConnections: PeerConnectionFactory;
  clock: Clock;
  random: Random;
  fetch: Fetch;
  sha256: Sha256;
  /** WebCrypto: received files are sealed with it before they are stored (./sealed-files.ts). */
  subtle: SubtleCrypto;
  log: Logger;
  /** Optional: calls need it. */
  media?: MediaDevices;
  /** Optional: single-instance guard. */
  lock?: InstanceLock;
  /**
   * Optional: where received files are kept, sealed (default: memory, lost on reload).
   */
  files?: FileStore;
}
