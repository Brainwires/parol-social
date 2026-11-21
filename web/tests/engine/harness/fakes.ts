// Fakes for the engine's platform interfaces: a clock the test moves, a relay that speaks
// the signaling-only protocol in process, and a WebRTC "network" whose peer connections link
// up when an offer and its answer have both been applied.
import type {
  Clock,
  DataChannel,
  IceCandidateInit,
  MediaStreamLike,
  MediaTrack,
  PeerConfig,
  PeerConnection,
  SessionDescription,
  Socket,
} from "../../../src/engine/platform.ts";

/** One turn of the event loop (lets promise chains and crypto.subtle settle). */
export function tick(): Promise<void> {
  // A message port turn is a macrotask without the timer clamp of setTimeout(0).
  return new Promise((resolve) => {
    const channel = new MessageChannel();
    channel.port1.onmessage = () => {
      channel.port1.close();
      resolve();
    };
    channel.port2.postMessage(null);
  });
}

// ── Clock ────────────────────────────────────────────────────────

interface Timer {
  id: number;
  at: number;
  fn: () => void;
}

export class FakeClock implements Clock {
  // Real time at the start: the wasm stamps pairing codes with the real clock.
  private t = Date.now();
  private nextId = 1;
  private timers: Timer[] = [];

  now(): number {
    return this.t;
  }

  setTimeout(fn: () => void, ms: number): unknown {
    const id = this.nextId++;
    this.timers.push({ id, at: this.t + Math.max(0, ms), fn });
    return id;
  }

  clearTimeout(handle: unknown): void {
    this.timers = this.timers.filter((t) => t.id !== handle);
  }

  get pending(): number {
    return this.timers.length;
  }

  /** Jump without firing anything (the page was suspended). */
  jump(ms: number): void {
    this.t += ms;
  }

  /** Move time forward, firing timers in order and letting async work settle after each. */
  async advance(ms: number, settle: () => Promise<void>): Promise<void> {
    // Whatever was started just before (a command, a socket opening) happens "now".
    await settle();
    const target = this.t + ms;
    for (;;) {
      this.timers.sort((a, b) => a.at - b.at || a.id - b.id);
      const next = this.timers[0];
      if (!next || next.at > target) break;
      this.timers.shift();
      this.t = Math.max(this.t, next.at);
      next.fn();
      await settle();
    }
    this.t = target;
    await settle();
  }
}

// ── Relay ────────────────────────────────────────────────────────

type Frame = Record<string, unknown>;

export class FakeSocket implements Socket {
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: ((ev: { code?: number; reason?: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  peerId: string | null = null;
  registered = false;
  closed = false;
  closeCode: number | undefined;
  watch = new Set<string>();
  /** Every frame the client sent on this socket. */
  sent: Frame[] = [];
  nonce = "";

  constructor(readonly relay: FakeRelay, readonly url: string) {}

  send(data: string): void {
    if (this.closed) throw new Error("socket closed");
    const frame = JSON.parse(data) as Frame;
    this.sent.push(frame);
    this.relay.onClientFrame(this, frame);
  }

  close(code?: number): void {
    if (this.closed) return;
    this.closed = true;
    this.closeCode = code;
    this.relay.onSocketClosed(this);
  }

  /** Deliver a frame from the relay (asynchronously, like a real socket). */
  deliver(frame: Frame): void {
    queueMicrotask(() => {
      if (!this.closed) this.onmessage?.({ data: JSON.stringify(frame) });
    });
  }

  /** The relay side drops the connection. */
  drop(code = 1006): void {
    if (this.closed) return;
    this.closed = true;
    this.relay.onSocketClosed(this);
    queueMicrotask(() => this.onclose?.({ code }));
  }
}

/** The signaling-only relay, in process. */
export class FakeRelay {
  sockets: FakeSocket[] = [];
  /** Refuse new connections (they close at once). */
  down = false;
  /** Accept frames but answer nothing (a dead TCP connection). */
  silent = false;
  profile = "signaling-only";
  /** Answer the next N signaling frames with `rate_limited`. */
  rateLimitNext = 0;
  /** Rewrite a signaling payload in flight (a relay that meddles). */
  rewrite:
    | ((kind: string, from: string, to: string, payload: string) => string)
    | null = null;
  /** Present a sender under another PeerId: real id → the id recipients see. */
  alias = new Map<string, string>();
  /** Swallow signaling frames of these kinds (they are neither forwarded nor answered). */
  swallow = new Set<string>();
  /** Every signaling frame forwarded or refused: for assertions. */
  signals: { type: string; from: string; to: string }[] = [];
  private nonceCounter = 0;

  factory = (url: string): Socket => {
    const s = new FakeSocket(this, url);
    this.sockets.push(s);
    queueMicrotask(() => {
      if (this.down) {
        s.closed = true;
        s.onclose?.({ code: 1006 });
      } else {
        s.onopen?.();
      }
    });
    return s;
  };

  socketOf(peerId: string): FakeSocket | undefined {
    return this.sockets.find((s) => !s.closed && s.registered && s.peerId === peerId);
  }

  online(peerId: string): boolean {
    return this.socketOf(peerId) !== undefined;
  }

  private mutual(a: FakeSocket, b: FakeSocket): boolean {
    return !!a.peerId && !!b.peerId && a.watch.has(b.peerId) &&
      b.watch.has(a.peerId);
  }

  private pushPresence(changed: FakeSocket, online: boolean): void {
    for (const other of this.sockets) {
      if (other === changed || other.closed || !other.registered) continue;
      if (this.mutual(changed, other)) {
        other.deliver({ type: "presence", peer_id: changed.peerId, online });
        if (online) {
          changed.deliver({
            type: "presence",
            peer_id: other.peerId,
            online: true,
          });
        }
      }
    }
  }

  onClientFrame(s: FakeSocket, f: Frame): void {
    if (this.silent) return;
    switch (f.type) {
      case "register": {
        if (typeof f.signature !== "string") {
          s.peerId = String(f.peer_id);
          s.nonce = (++this.nonceCounter).toString(16).padStart(64, "0");
          s.deliver({ type: "challenge", nonce: s.nonce });
          return;
        }
        if (
          f.nonce !== s.nonce || typeof f.pubkey !== "string" ||
          f.peer_id !== s.peerId
        ) {
          s.deliver({ type: "error", code: "bad_signature", message: "" });
          return;
        }
        s.registered = true;
        s.deliver({
          type: "registered",
          peer_id: s.peerId,
          profile: this.profile,
        });
        return;
      }
      case "ping":
        s.deliver({ type: "pong" });
        return;
      case "watch": {
        if (!s.registered) return;
        const before = new Set(s.watch);
        s.watch = new Set((f.peer_ids as string[]).slice(0, 256));
        for (const other of this.sockets) {
          if (
            other === s || other.closed || !other.registered || !other.peerId
          ) continue;
          if (!before.has(other.peerId) && this.mutual(s, other)) {
            s.deliver({
              type: "presence",
              peer_id: other.peerId,
              online: true,
            });
            other.deliver({
              type: "presence",
              peer_id: s.peerId,
              online: true,
            });
          }
        }
        return;
      }
      case "rtc_offer":
      case "rtc_answer":
      case "rtc_ice": {
        if (!s.registered || !s.peerId) {
          s.deliver({ type: "error", code: "not_registered", message: "" });
          return;
        }
        const to = String(f.to);
        this.signals.push({ type: f.type, from: s.peerId, to });
        if (this.swallow.has(f.type)) return;
        if (this.rateLimitNext > 0) {
          this.rateLimitNext -= 1;
          s.deliver({
            type: "error",
            code: "rate_limited",
            message: "slow down",
          });
          return;
        }
        // An aliased sender is reached under its alias.
        let realTo = to;
        for (const [real, shown] of this.alias) if (shown === to) realTo = real;
        const target = this.socketOf(realTo);
        if (!target) {
          s.deliver({
            type: "error",
            code: "peer_offline",
            message: "",
            peer_id: to,
          });
          return;
        }
        const from = this.alias.get(s.peerId) ?? s.peerId;
        const payload = this.rewrite
          ? this.rewrite(f.type, s.peerId, realTo, String(f.payload))
          : String(f.payload);
        target.deliver({ type: f.type, from, payload });
        return;
      }
      default:
        s.deliver({ type: "error", code: "signaling_only", message: "" });
    }
  }

  onSocketClosed(s: FakeSocket): void {
    if (s.registered) {
      s.registered = false;
      this.pushPresence(s, false);
    }
  }

  /** Called by tests after `registered` reached a client that watches others. */
  framesFrom(peerId: string, type: string): Frame[] {
    return this.sockets.filter((s) => s.peerId === peerId).flatMap((s) => s.sent).filter((f) =>
      f.type === type
    );
  }
}

// ── WebRTC ───────────────────────────────────────────────────────

function randomFingerprint(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0").toUpperCase())
    .join(":");
}

export class FakeTrack implements MediaTrack {
  enabled = true;
  stopped = false;
  constructor(readonly kind: string) {}
  stop(): void {
    this.stopped = true;
  }
}

export class FakeStream implements MediaStreamLike {
  constructor(readonly tracks: FakeTrack[]) {}
  getTracks(): MediaTrack[] {
    return this.tracks;
  }
  getAudioTracks(): MediaTrack[] {
    return this.tracks.filter((t) => t.kind === "audio");
  }
  getVideoTracks(): MediaTrack[] {
    return this.tracks.filter((t) => t.kind === "video");
  }
}

export class FakeDc implements DataChannel {
  readyState = "connecting";
  bufferedAmount = 0;
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  other: FakeDc | null = null;
  /** Everything sent on this end. */
  sent: string[] = [];

  constructor(readonly pc: FakePc, readonly label: string) {}

  send(data: string): void {
    if (this.readyState !== "open") throw new Error("channel not open");
    this.sent.push(data);
    const rtc = this.pc.rtc;
    if (rtc.dropFrame?.(this.pc, data)) return;
    const other = this.other;
    queueMicrotask(() => {
      if (other && other.readyState === "open") other.onmessage?.({ data });
    });
  }

  /** Put a raw frame in front of the other end, as if this end had sent it. */
  inject(data: string): void {
    const other = this.other;
    queueMicrotask(() => other?.onmessage?.({ data }));
  }

  close(): void {
    if (this.readyState === "closed") return;
    this.readyState = "closed";
    const other = this.other;
    if (other && other.readyState !== "closed") {
      other.readyState = "closed";
      queueMicrotask(() => other.onclose?.());
    }
  }
}

export class FakePc implements PeerConnection {
  private static next = 1;
  readonly id = FakePc.next++;
  readonly fingerprint = randomFingerprint();
  localDescription: SessionDescription | null = null;
  remoteDescription: SessionDescription | null = null;
  connectionState = "new";
  iceGatheringState = "new";
  onconnectionstatechange: (() => void) | null = null;
  onicegatheringstatechange: (() => void) | null = null;
  onicecandidate: PeerConnection["onicecandidate"] = null;
  ondatachannel: ((ev: { channel: DataChannel }) => void) | null = null;
  ontrack: PeerConnection["ontrack"] = null;
  channels: FakeDc[] = [];
  remoteCandidates: IceCandidateInit[] = [];
  senders: { track: MediaTrack; stream: MediaStreamLike }[] = [];
  peer: FakePc | null = null;

  constructor(readonly rtc: FakeRtc, readonly config: PeerConfig) {}

  private sdp(): string {
    const media = this.senders.length > 0
      ? "m=audio 9 UDP/TLS/RTP/SAVPF 111"
      : "m=application 9 UDP/DTLS/SCTP webrtc-datachannel";
    const lines = [
      "v=0",
      "o=- 1 1 IN IP4 127.0.0.1",
      "s=-",
      "t=0 0",
      `a=x-fake-pc:${this.id}`,
      media,
      "c=IN IP4 0.0.0.0",
      `a=fingerprint:sha-256 ${this.fingerprint}`,
      "a=setup:actpass",
    ];
    const relayOnly = this.config.iceTransportPolicy === "relay";
    if (!relayOnly) {
      lines.push("a=candidate:1 1 udp 2122260223 192.0.2.1 5000 typ host");
    } else if (!this.rtc.turnUnreachable) {
      lines.push("a=candidate:2 1 udp 41885439 198.51.100.1 6000 typ relay");
    }
    return lines.join("\r\n") + "\r\n";
  }

  createDataChannel(label: string): DataChannel {
    const dc = new FakeDc(this, label);
    this.channels.push(dc);
    return dc;
  }

  createOffer(): Promise<SessionDescription> {
    return Promise.resolve({ type: "offer", sdp: this.sdp() });
  }

  createAnswer(): Promise<SessionDescription> {
    return Promise.resolve({ type: "answer", sdp: this.sdp() });
  }

  setLocalDescription(desc: SessionDescription): Promise<void> {
    this.localDescription = desc;
    if (!this.rtc.neverFinishGathering) {
      queueMicrotask(() => {
        this.iceGatheringState = "complete";
        this.onicegatheringstatechange?.();
      });
    }
    // An answerer's local description completes the exchange on its side.
    return Promise.resolve();
  }

  setRemoteDescription(desc: SessionDescription): Promise<void> {
    if (!/a=fingerprint:/.test(desc.sdp)) {
      return Promise.reject(new Error("bad sdp"));
    }
    this.remoteDescription = desc;
    if (desc.type === "answer") this.rtc.link(this, desc.sdp);
    return Promise.resolve();
  }

  addIceCandidate(candidate: IceCandidateInit): Promise<void> {
    this.remoteCandidates.push(candidate);
    return Promise.resolve();
  }

  addTrack(track: MediaTrack, stream: MediaStreamLike): unknown {
    this.senders.push({ track, stream });
    return {};
  }

  setState(state: string): void {
    if (this.connectionState === "closed") return;
    this.connectionState = state;
    this.onconnectionstatechange?.();
  }

  close(): void {
    if (this.connectionState === "closed") return;
    this.connectionState = "closed";
    for (const dc of this.channels) dc.close();
    const peer = this.peer;
    if (peer && peer.connectionState !== "closed") {
      queueMicrotask(() => peer.setState("disconnected"));
    }
  }

  /** The network path broke: both ends see the connection fail. */
  sever(): void {
    const peer = this.peer;
    this.setState("failed");
    peer?.setState("failed");
  }
}

export class FakeRtc {
  pcs: FakePc[] = [];
  /** Offers and answers are exchanged but ICE never completes. */
  blockConnect = false;
  /** ICE fails as soon as the answer is applied. */
  failIce = false;
  neverFinishGathering = false;
  /** Relay-only connections gather no candidate at all. */
  turnUnreachable = false;
  /** Return true to lose a data-channel frame in flight. */
  dropFrame: ((from: FakePc, data: string) => boolean) | null = null;

  factory = (config: PeerConfig): PeerConnection => {
    const pc = new FakePc(this, config);
    this.pcs.push(pc);
    return pc;
  };

  /** Connections that are not closed. */
  get open(): FakePc[] {
    return this.pcs.filter((p) => p.connectionState !== "closed");
  }

  link(offerer: FakePc, answerSdp: string): void {
    const id = Number(/a=x-fake-pc:(\d+)/.exec(answerSdp)?.[1]);
    const answerer = this.pcs.find((p) => p.id === id);
    if (!answerer || answerer.connectionState === "closed") return;
    if (this.blockConnect) return;
    queueMicrotask(() => {
      if (
        offerer.connectionState === "closed" ||
        answerer.connectionState === "closed"
      ) return;
      if (this.failIce) {
        offerer.setState("failed");
        answerer.setState("failed");
        return;
      }
      offerer.peer = answerer;
      answerer.peer = offerer;
      offerer.setState("connected");
      answerer.setState("connected");
      for (const dc of offerer.channels) {
        const mirror = new FakeDc(answerer, dc.label);
        answerer.channels.push(mirror);
        dc.other = mirror;
        mirror.other = dc;
        dc.readyState = "open";
        mirror.readyState = "open";
        answerer.ondatachannel?.({ channel: mirror });
        dc.onopen?.();
        mirror.onopen?.();
      }
      for (const [a, b] of [[offerer, answerer], [answerer, offerer]]) {
        for (const s of a.senders) {
          b.ontrack?.({ track: s.track, streams: [s.stream] });
        }
      }
    });
  }
}
