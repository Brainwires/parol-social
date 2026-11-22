// The relay WebSocket client, in the page: connects, registers by Ed25519 challenge, keeps
// the socket alive (PNP-001 §10.3: ping every 20 s, dead after 40 s of silence) and reconnects
// with backoff and jitter. Signaling frames are never queued here: a frame given while the
// socket is not registered is refused, and the engine retries at its own level.
import type { Clock, Logger, Random, Socket, SocketFactory } from "./platform.ts";
import type { RelayState } from "./types.ts";
import { type ClientFrame, parseServerFrame, type ServerFrame } from "./wire.ts";

/** PNP-001-MUST-065. */
export const PING_EVERY_MS = 20_000;
/** PNP-001-MUST-066. */
export const DEAD_AFTER_MS = 40_000;
const CHECK_EVERY_MS = 5_000;
/** After the page slept through a ping, the relay gets this long to answer the catch-up. */
const CATCH_UP_GRACE_MS = 5_000;
export const BACKOFF_MIN_MS = 1_000;
export const BACKOFF_MAX_MS = 30_000;
/**
 * After a connection to the relay ended, the next one is not opened before this long has
 * passed (PNP-006-MUST-024): no rapid connect / disconnect pattern on the wire.
 */
export const RECONNECT_WAIT_MS = 30_000;
const BACKOFF_JITTER = 0.25;
/** From `new WebSocket` to `registered` (the relay itself closes at 10 s unregistered). */
const REGISTER_TIMEOUT_MS = 15_000;
/** The relay accepts at most 4 `register` frames per socket (PNP-001-MUST-075). */
const MAX_SIGNED_REGISTERS = 2;

const CLOSE_SILENT = 4000;

/**
 * The relay's caps on signaling frames (PNP-001 §10.5): 60 a minute and 240 an hour per
 * sender, 64 per 10 minutes per (sender, recipient). The client stays a little under each so
 * that a `rate_limited` answer is the exception.
 */
export const SIGNAL_BUDGET = {
  perMinute: 54,
  perHour: 216,
  perPair10Min: 58,
} as const;

/** Sliding-window counters for outgoing `rtc_*` frames. */
export class SignalBudget {
  private all: number[] = [];
  private readonly pairs = new Map<string, number[]>();

  /** Count one frame to `to` if every window has room. */
  take(to: string, now: number): boolean {
    this.all = this.all.filter((t) => now - t < 3_600_000);
    const lastMinute = this.all.reduce(
      (n, t) => n + (now - t < 60_000 ? 1 : 0),
      0,
    );
    if (
      lastMinute >= SIGNAL_BUDGET.perMinute ||
      this.all.length >= SIGNAL_BUDGET.perHour
    ) {
      return false;
    }
    const pair = (this.pairs.get(to) ?? []).filter((t) => now - t < 600_000);
    if (pair.length >= SIGNAL_BUDGET.perPair10Min) {
      this.pairs.set(to, pair);
      return false;
    }
    pair.push(now);
    this.pairs.set(to, pair);
    this.all.push(now);
    if (this.pairs.size > 1024) {
      for (const [k, v] of this.pairs) {
        if (v.every((t) => now - t >= 600_000)) this.pairs.delete(k);
      }
    }
    return true;
  }
}

export interface RelayOptions {
  /** `ws://` or `wss://` URL of the relay's `/ws`. */
  url: string;
  peerId: string;
  publicKey: string;
  /** Signs the hex-decoded nonce with the identity key; returns the signature hex. */
  sign(nonceHex: string): string;
  sockets: SocketFactory;
  clock: Clock;
  random: Random;
  log: Logger;
}

export interface RelayListener {
  onState(state: RelayState): void;
  /** Every frame but `challenge`, `registered` and `pong`. */
  onFrame(frame: ServerFrame): void;
}

export class RelayClient {
  private socket: Socket | null = null;
  private registeredFlag = false;
  private running = false;
  private backoffMs = BACKOFF_MIN_MS;
  /** The current socket reached `open`: a connection existed. */
  private opened = false;
  /** No new connection before this time (PNP-006-MUST-024); 0 when nothing is owed. */
  private earliestConnect = 0;
  private reconnectTimer: unknown = null;
  private registerTimer: unknown = null;
  private pingTimer: unknown = null;
  private checkTimer: unknown = null;
  private lastInbound = 0;
  private lastPing = 0;
  private lastCheck = 0;
  private signedRegisters = 0;
  private readonly budget = new SignalBudget();

  constructor(
    private readonly opts: RelayOptions,
    private readonly listener: RelayListener,
  ) {}

  get registered(): boolean {
    return this.registeredFlag;
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.connect();
  }

  /** Close the socket and stop reconnecting. */
  stop(): void {
    this.running = false;
    this.clearTimers();
    this.opts.clock.clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
    const s = this.socket;
    this.socket = null;
    this.registeredFlag = false;
    if (s) {
      this.detach(s);
      try {
        s.close(1000);
      } catch { /* already closed */ }
    }
  }

  /**
   * The network came back or the page became visible: reconnect if we were waiting to
   * (without the backoff, but not before the wait after a disconnect is over), and check
   * the socket if we have one.
   */
  nudge(): void {
    if (!this.running) return;
    if (this.socket === null) {
      const { clock } = this.opts;
      clock.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
      this.backoffMs = BACKOFF_MIN_MS;
      const wait = this.earliestConnect - clock.now();
      if (wait <= 0) {
        this.connect();
      } else {
        this.reconnectTimer = clock.setTimeout(() => {
          this.reconnectTimer = null;
          this.connect();
        }, wait);
      }
    } else if (this.registeredFlag) {
      this.check();
    }
  }

  /**
   * Send a frame. False when the socket is not registered, or (for `rtc_*`) when the
   * client-side rate budget is spent: nothing was sent.
   */
  send(frame: ClientFrame): boolean {
    const s = this.socket;
    if (!s || !this.registeredFlag) return false;
    if (
      frame.type === "rtc_offer" || frame.type === "rtc_answer" ||
      frame.type === "rtc_ice"
    ) {
      if (!this.budget.take(frame.to, this.opts.clock.now())) {
        this.opts.log.warn("[Relay] signaling budget spent; frame not sent");
        return false;
      }
    }
    return this.raw(s, frame);
  }

  private raw(s: Socket, frame: ClientFrame): boolean {
    try {
      s.send(JSON.stringify(frame));
      return true;
    } catch {
      return false;
    }
  }

  private connect(): void {
    if (!this.running || this.socket) return;
    const { clock, opts } = { clock: this.opts.clock, opts: this.opts };
    this.listener.onState({ kind: "Connecting" });
    let s: Socket;
    try {
      s = opts.sockets(opts.url);
    } catch {
      this.down(null, "could not open a socket");
      return;
    }
    this.socket = s;
    this.opened = false;
    this.signedRegisters = 0;
    this.registerTimer = clock.setTimeout(() => {
      if (this.socket === s && !this.registeredFlag) {
        this.down(s, "connect timed out");
      }
    }, REGISTER_TIMEOUT_MS);
    s.onopen = () => {
      if (this.socket !== s) return;
      this.opened = true;
      this.lastInbound = clock.now();
      // Exactly two `register` frames per socket: this one, then the signed one.
      this.raw(s, { type: "register", peer_id: opts.peerId });
    };
    s.onmessage = (ev) => {
      if (this.socket !== s) return;
      this.lastInbound = clock.now();
      if (typeof ev.data !== "string") return;
      const frame = parseServerFrame(ev.data);
      if (frame) this.onFrame(s, frame);
    };
    s.onclose = () => {
      if (this.socket === s) this.down(s, "closed");
    };
    s.onerror = () => {
      // A close event follows; nothing to do here (and no detail to log: it has none).
    };
  }

  private onFrame(s: Socket, frame: ServerFrame): void {
    const { clock, opts } = { clock: this.opts.clock, opts: this.opts };
    switch (frame.type) {
      case "challenge": {
        if (
          this.registeredFlag || this.signedRegisters >= MAX_SIGNED_REGISTERS
        ) return;
        if (!/^([0-9a-fA-F]{2})+$/.test(frame.nonce)) return;
        this.signedRegisters += 1;
        let signature: string;
        try {
          signature = opts.sign(frame.nonce);
        } catch {
          this.down(s, "could not sign the challenge");
          return;
        }
        this.raw(s, {
          type: "register",
          peer_id: opts.peerId,
          pubkey: opts.publicKey,
          signature,
          nonce: frame.nonce,
        });
        return;
      }
      case "registered": {
        if (this.registeredFlag) return;
        this.registeredFlag = true;
        this.backoffMs = BACKOFF_MIN_MS;
        clock.clearTimeout(this.registerTimer);
        this.registerTimer = null;
        this.lastPing = clock.now();
        this.lastCheck = clock.now();
        this.armPing(s);
        this.armCheck(s);
        opts.log.info(`Registered with relay. Profile: ${frame.profile}`);
        this.listener.onState({ kind: "Registered", profile: frame.profile });
        return;
      }
      case "pong":
        return;
      default:
        if (this.registeredFlag) this.listener.onFrame(frame);
    }
  }

  private armPing(s: Socket): void {
    this.pingTimer = this.opts.clock.setTimeout(() => {
      if (this.socket !== s) return;
      this.ping(s);
      this.armPing(s);
    }, PING_EVERY_MS);
  }

  private armCheck(s: Socket): void {
    this.checkTimer = this.opts.clock.setTimeout(() => {
      if (this.socket !== s) return;
      this.check();
      if (this.socket === s) this.armCheck(s);
    }, CHECK_EVERY_MS);
  }

  private ping(s: Socket): void {
    this.lastPing = this.opts.clock.now();
    this.raw(s, { type: "ping", ts: this.lastPing });
  }

  /** PNP-001-MUST-066, with the catch-up ping of MUST-065 after the page slept. */
  private check(): void {
    const s = this.socket;
    if (!s || !this.registeredFlag) return;
    const now = this.opts.clock.now();
    const slept = now - this.lastCheck > 2 * CHECK_EVERY_MS;
    this.lastCheck = now;
    if (slept) {
      // Timers were throttled (a hidden tab): no ping went out, so silence proves nothing
      // yet. Ping now and give the relay a moment.
      this.ping(s);
      this.lastInbound = Math.max(
        this.lastInbound,
        now - (DEAD_AFTER_MS - CATCH_UP_GRACE_MS),
      );
      return;
    }
    if (now - this.lastInbound >= DEAD_AFTER_MS) {
      this.down(s, "relay silent", CLOSE_SILENT);
      return;
    }
    if (now - this.lastPing >= PING_EVERY_MS) this.ping(s);
  }

  private clearTimers(): void {
    const c = this.opts.clock;
    c.clearTimeout(this.registerTimer);
    c.clearTimeout(this.pingTimer);
    c.clearTimeout(this.checkTimer);
    this.registerTimer = this.pingTimer = this.checkTimer = null;
  }

  private detach(s: Socket): void {
    s.onopen =
      s.onmessage =
      s.onclose =
      s.onerror =
        null;
  }

  /** The socket is gone (or never was): report it and schedule a reconnect. */
  private down(s: Socket | null, reason: string, closeCode?: number): void {
    this.clearTimers();
    if (s) {
      this.detach(s);
      try {
        s.close(closeCode ?? 1000);
      } catch { /* already closed */ }
    }
    this.socket = null;
    this.registeredFlag = false;
    // A connection that existed is not replaced before RECONNECT_WAIT_MS has passed,
    // whatever asks for it. An attempt that never opened left nothing to wait after.
    const now = this.opts.clock.now();
    if (this.opened) this.earliestConnect = now + RECONNECT_WAIT_MS;
    this.opened = false;
    this.listener.onState({ kind: "Disconnected", reason });
    if (!this.running) return;
    const base = this.backoffMs;
    const delay = Math.max(
      base + base * BACKOFF_JITTER * this.opts.random.next(),
      this.earliestConnect - now,
    );
    // Reset only by `registered`, never by a mere TCP open.
    this.backoffMs = Math.min(base * 2, BACKOFF_MAX_MS);
    this.reconnectTimer = this.opts.clock.setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }
}
