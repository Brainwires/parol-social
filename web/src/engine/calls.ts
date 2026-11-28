// 1:1 voice and video calls. A call runs on its own RTCPeerConnection, set up by `offer` /
// `answer` CALL_SIGNAL envelopes on the contact's verified data channel, so its DTLS
// fingerprints are authenticated end to end (crates/parolnet-app/src/call.rs and the call
// half of engine.rs are the reference).
//
// Differences from the old PWA, on purpose: offers and answers are non-trickle (the SDP
// carries the candidates; incoming `ice` is still accepted, also before the user accepts),
// every signal is matched by `callId`, a second call is answered `reject`, and `reject` /
// `hangup` tear the call down on both sides.
//
// Everything here runs inside the engine's mailbox except media capture and SDP work, which
// re-enter it through `host.internal`.
import { toHex } from "./bytes.ts";
import { endOfCandidates, hasCandidates, hasEndOfCandidates } from "./ice.ts";
import type {
  DtlsTransport,
  IceCandidateInit,
  MediaStreamLike,
  MediaTrack,
  PeerConfig,
  PeerConnection,
  Platform,
} from "./platform.ts";
import {
  type AppEvent,
  type CallEnd,
  type CallInfo,
  type CallState,
  EngineError,
  shortId,
} from "./types.ts";
import type { CallSignal } from "./wire.ts";

/** An unanswered call rings this long. */
export const CALL_RING_TIMEOUT_MS = 60_000;
/** From accepting (or the answer) to media flowing. */
export const CALL_CONNECT_TIMEOUT_MS = 30_000;
const CALL_PENDING_ICE_MAX = 64;
const CALL_GATHER_CAP_MS = 3_000;
const CALL_LATE_ICE_MAX = 16;

/**
 * The `reason` of a call that failed because the microphone or camera could not be used
 * (no permission, no device), so a UI can say that instead of "could not connect".
 */
export const CALL_FAILED_MEDIA = "the microphone or camera could not be used";

class NoCapture extends Error {}

export interface CallHost {
  platform: Platform;
  me: string;
  isContact(peer: string): boolean;
  /** The contact's data channel is open and verified. */
  isVerified(peer: string): boolean;
  /** Ask for a direct path now. */
  connect(peer: string): void;
  /** Send on the verified channel; false when there is none. */
  sendSignal(peer: string, sig: CallSignal): Promise<boolean>;
  peerConfig(): PeerConfig;
  emit(ev: AppEvent): void;
  after(ms: number, fn: () => Promise<void> | void): unknown;
  cancel(handle: unknown): void;
  /** Run inside the engine's mailbox. */
  internal(fn: () => Promise<void> | void): void;
}

interface Call {
  callId: string;
  peerId: string;
  video: boolean;
  incoming: boolean;
  state: CallState;
  muted: boolean;
  cameraOff: boolean;
  pc: PeerConnection | null;
  /** Incoming: the caller's offer until we accept. */
  remoteOffer: string | null;
  remoteSet: boolean;
  pendingIce: IceCandidateInit[];
  descriptionSent: boolean;
  lateIce: number;
  /** The peer has our end of candidates: in the description, or as an `ice` signal. */
  endSent: boolean;
  local: MediaStreamLike | null;
  remote: MediaStreamLike | null;
  ringTimer: unknown;
  connectTimer: unknown;
}

/** The call's capture after a camera switch: the old audio tracks, the new video. */
function mergedStream(audio: MediaTrack[], video: MediaStreamLike): MediaStreamLike {
  const withTracks = video as MediaStreamLike & { addTrack?(track: MediaTrack): void };
  if (typeof withTracks.addTrack === "function") {
    for (const t of audio) withTracks.addTrack(t);
    return video;
  }
  const tracks = [...audio, ...video.getVideoTracks()];
  return {
    getTracks: () => tracks,
    getAudioTracks: () => audio,
    getVideoTracks: () => video.getVideoTracks(),
  };
}

export class CallManager {
  /** At most one call is alive; an ended call is forgotten. */
  private call: Call | null = null;

  constructor(private readonly host: CallHost) {}

  private info(c: Call): CallInfo {
    return Object.freeze({
      callId: c.callId,
      peerId: c.peerId,
      video: c.video,
      incoming: c.incoming,
      state: c.state,
      muted: c.muted,
      cameraOff: c.cameraOff,
    });
  }

  current(): CallInfo | null {
    return this.call ? this.info(this.call) : null;
  }

  /** The peer we are in a call with, if any. */
  busyPeer(): string | null {
    return this.call?.peerId ?? null;
  }

  media(
    callId: string,
  ): { local: MediaStreamLike | null; remote: MediaStreamLike | null } | null {
    const c = this.call;
    return c && c.callId === callId ? { local: c.local, remote: c.remote } : null;
  }

  private alive(c: Call): boolean {
    return this.call === c;
  }

  private emit(c: Call): void {
    this.host.emit({ kind: "Call", call: this.info(c) });
  }

  private setState(c: Call, state: CallState): void {
    if (c.state.kind !== state.kind) {
      c.state = state;
      this.emit(c);
    }
  }

  private newCall(
    callId: string,
    peer: string,
    video: boolean,
    incoming: boolean,
  ): Call {
    const c: Call = {
      callId,
      peerId: peer,
      video,
      incoming,
      state: { kind: incoming ? "Incoming" : "Outgoing" },
      muted: false,
      cameraOff: false,
      pc: null,
      remoteOffer: null,
      remoteSet: false,
      pendingIce: [],
      descriptionSent: false,
      lateIce: 0,
      endSent: false,
      local: null,
      remote: null,
      ringTimer: null,
      connectTimer: null,
    };
    this.call = c;
    return c;
  }

  private armRing(c: Call): void {
    c.ringTimer = this.host.after(CALL_RING_TIMEOUT_MS, async () => {
      if (
        !this.alive(c) ||
        (c.state.kind !== "Outgoing" && c.state.kind !== "Incoming")
      ) return;
      // The caller tells the callee to stop ringing; a missed incoming call ends silently.
      if (!c.incoming) {
        await this.host.sendSignal(c.peerId, {
          action: "hangup",
          callId: c.callId,
        });
      }
      this.end(c, { kind: "NoAnswer" });
    });
  }

  private armConnect(c: Call): void {
    this.host.cancel(c.connectTimer);
    c.connectTimer = this.host.after(CALL_CONNECT_TIMEOUT_MS, async () => {
      if (!this.alive(c) || c.state.kind !== "Connecting") return;
      await this.host.sendSignal(c.peerId, {
        action: "hangup",
        callId: c.callId,
      });
      this.end(c, {
        kind: "Failed",
        reason: "the media connection did not come up",
      });
    });
  }

  /**
   * The call is over. What the person sees comes first: the ended state is published before
   * any media is let go, and the browser's own teardown (stopping the capture, closing the
   * connection) runs afterwards in tasks of its own, where nothing waits on it.
   *
   * The order matters in WebKit on Linux (GStreamer): a track that ends while a media
   * element is still playing its stream can block the main thread for good, inside
   * `RTCPeerConnection.close()` or `MediaStreamTrack.stop()` (tests/e2e/repro). A listener
   * of the `Ended` event must therefore detach its media elements before it returns; the
   * release below starts in a later task.
   */
  private end(c: Call, why: CallEnd): void {
    if (!this.alive(c)) return;
    this.call = null;
    this.host.cancel(c.ringTimer);
    this.host.cancel(c.connectTimer);
    const pc = c.pc;
    const local = c.local;
    c.pc = null;
    c.local = null;
    c.remote = null;
    if (pc) {
      pc.onconnectionstatechange =
        pc.onicecandidate =
        pc.ontrack =
        pc.onicegatheringstatechange =
          null;
    }
    c.state = { kind: "Ended", end: why };
    this.host.platform.log.info(
      `[Call] ${shortId(c.callId)} over (${why.kind})`,
    );
    this.emit(c);
    this.release(c.callId, local?.getTracks() ?? [], pc);
  }

  /**
   * Let a call's media go, after whoever showed it had a turn to stop showing it: first the
   * capture the engine asked for, then the connection, each in a task of its own and each
   * guarded, so one that fails does not keep the next from running. A line is logged before
   * each browser call: if one never returns, the last line names it.
   */
  private release(callId: string, tracks: MediaTrack[], pc: PeerConnection | null): void {
    const { clock, log } = this.host.platform;
    const id = shortId(callId);
    const steps: Array<() => void> = [];
    if (tracks.length > 0) {
      steps.push(() => {
        log.info(`[Call] ${id} releasing the capture`);
        for (const t of tracks) {
          try {
            t.stop();
          } catch { /* already stopped */ }
        }
      });
    }
    if (pc) {
      steps.push(() => {
        log.info(`[Call] ${id} closing the media connection`);
        try {
          pc.close();
        } catch { /* already closed */ }
      });
    }
    if (steps.length === 0) return;
    const next = () => {
      const step = steps.shift();
      if (!step) {
        log.info(`[Call] ${id} released`);
        return;
      }
      try {
        step();
      } finally {
        // The platform's clock, not the engine's timers: this also runs after `stop()`.
        clock.setTimeout(next, 0);
      }
    };
    clock.setTimeout(next, 0);
  }

  // ── Commands ─────────────────────────────────────────────────────

  start(peer: string, video: boolean): CallInfo {
    const { host } = this;
    if (!host.isContact(peer)) {
      throw new EngineError(
        "UnknownContact",
        `unknown contact ${shortId(peer)}`,
      );
    }
    if (!host.platform.media) {
      throw new EngineError("Media", "no microphone or camera access here");
    }
    // PNP-001-MUST-081: call signals only on a verified channel.
    if (!host.isVerified(peer)) {
      host.connect(peer);
      throw new EngineError(
        "NotConnected",
        `no verified direct connection to ${shortId(peer)} yet`,
      );
    }
    if (this.call) throw new EngineError("Busy", "already in a call");
    const c = this.newCall(
      toHex(host.platform.random.bytes(16)),
      peer,
      video === true,
      false,
    );
    this.emit(c);
    this.negotiate(c);
    return this.info(c);
  }

  accept(callId: string): CallInfo {
    const c = this.call;
    if (!c || c.callId !== callId || c.state.kind !== "Incoming") {
      throw new EngineError("UnknownCall", "that call is no longer ringing");
    }
    if (!this.host.platform.media) {
      throw new EngineError("Media", "no microphone or camera access here");
    }
    this.host.cancel(c.ringTimer);
    this.setState(c, { kind: "Connecting" });
    this.armConnect(c);
    this.negotiate(c);
    return this.info(c);
  }

  async reject(callId: string): Promise<void> {
    const c = this.call;
    if (!c || c.callId !== callId || c.state.kind !== "Incoming") return;
    await this.host.sendSignal(c.peerId, { action: "reject", callId });
    this.end(c, { kind: "Declined" });
  }

  async hangup(callId: string): Promise<void> {
    const c = this.call;
    if (!c || c.callId !== callId) return;
    if (c.state.kind === "Incoming") return await this.reject(callId);
    await this.host.sendSignal(c.peerId, { action: "hangup", callId });
    this.end(c, { kind: "HungUp" });
  }

  setMuted(callId: string, muted: boolean): void {
    const c = this.call;
    if (!c || c.callId !== callId) return;
    c.muted = muted === true;
    this.applyToggles(c);
    this.emit(c);
  }

  setCameraOff(callId: string, off: boolean): void {
    const c = this.call;
    if (!c || c.callId !== callId) return;
    c.cameraOff = off === true;
    this.applyToggles(c);
    this.emit(c);
  }

  async replaceCamera(callId: string, stream: MediaStreamLike): Promise<void> {
    const stop = () => {
      for (const t of stream.getTracks()) {
        try {
          t.stop();
        } catch { /* already stopped */ }
      }
    };
    const c = this.call;
    const next = stream.getVideoTracks()[0];
    const sender = c?.pc?.getSenders?.().find((s) => s.track?.kind === "video");
    if (!c || c.callId !== callId || !c.video || !c.local || !next || !sender) {
      stop();
      throw new EngineError("UnknownCall", "that call has no camera to switch");
    }
    try {
      await sender.replaceTrack(next);
    } catch {
      stop();
      throw new EngineError("Media", "the camera could not be switched");
    }
    await this.inMailbox(() => {
      if (!this.alive(c) || !c.local) {
        stop();
        return;
      }
      const replaced = c.local.getVideoTracks();
      // Our audio keeps flowing from the capture the call started with.
      c.local = mergedStream(c.local.getAudioTracks(), stream);
      this.applyToggles(c);
      this.host.emit({ kind: "CallMedia", callId: c.callId });
      // As at the end of a call: whoever shows the old camera lets go of it first.
      this.release(c.callId, replaced, null);
    });
  }

  private applyToggles(c: Call): void {
    for (const t of c.local?.getAudioTracks() ?? []) t.enabled = !c.muted;
    for (const t of c.local?.getVideoTracks() ?? []) t.enabled = !c.cameraOff;
  }

  /** The engine is stopping: tell the contact and tear the call down. */
  async shutdown(): Promise<void> {
    const c = this.call;
    if (!c) return;
    if (c.state.kind !== "Incoming") {
      try {
        await this.host.sendSignal(c.peerId, { action: "hangup", callId: c.callId });
      } catch { /* the call ends here either way */ }
    }
    this.end(c, { kind: "HungUp" });
  }

  // ── Media and SDP (outside the mailbox) ──────────────────────────

  private negotiate(c: Call): void {
    this.setup(c).catch((e) =>
      this.host.internal(async () => {
        if (!this.alive(c)) return;
        if (c.descriptionSent || c.incoming) {
          await this.host.sendSignal(c.peerId, {
            action: "hangup",
            callId: c.callId,
          });
        }
        this.end(c, {
          kind: "Failed",
          reason: e instanceof NoCapture ? CALL_FAILED_MEDIA : "the call could not be set up",
        });
      })
    );
  }

  private inMailbox<T>(fn: () => Promise<T> | T): Promise<T> {
    return new Promise((resolve, reject) => {
      this.host.internal(async () => {
        try {
          resolve(await fn());
        } catch (e) {
          reject(e);
        }
      });
    });
  }

  private async setup(c: Call): Promise<void> {
    const { host } = this;
    const media = host.platform.media!;
    let stream: MediaStreamLike;
    try {
      stream = await media.getUserMedia({ audio: true, video: c.video });
    } catch {
      throw new NoCapture();
    }
    const pc = await this.inMailbox(() => {
      if (!this.alive(c)) {
        for (const t of stream.getTracks()) t.stop();
        return null;
      }
      c.local = stream;
      this.applyToggles(c);
      const pc = host.platform.peerConnections(host.peerConfig());
      c.pc = pc;
      this.wire(c, pc);
      for (const t of stream.getTracks()) pc.addTrack(t, stream);
      host.emit({ kind: "CallMedia", callId: c.callId });
      return pc;
    });
    if (!pc) return;
    if (c.incoming) {
      await pc.setRemoteDescription({
        type: "offer",
        sdp: c.remoteOffer ?? "",
      });
      await this.inMailbox(() => {
        if (!this.alive(c)) return;
        c.remoteSet = true;
        c.remoteOffer = null;
        for (const cand of c.pendingIce.splice(0)) {
          void pc.addIceCandidate(cand).catch(() => {});
        }
      });
      await pc.setLocalDescription(await pc.createAnswer());
      this.watchTransports(c, pc);
    } else {
      await pc.setLocalDescription(await pc.createOffer());
    }
    await this.gathered(pc);
    await this.inMailbox(async () => {
      if (!this.alive(c)) return;
      const sdp = pc.localDescription?.sdp;
      if (!sdp) throw new Error("no local description");
      if (
        host.peerConfig().iceTransportPolicy === "relay" && !hasCandidates(sdp)
      ) {
        throw new Error("no relay candidate");
      }
      const sent = await host.sendSignal(c.peerId, {
        action: c.incoming ? "answer" : "offer",
        callId: c.callId,
        video: c.video,
        sdp,
      });
      if (!this.alive(c)) return;
      if (!sent) {
        this.end(c, {
          kind: "Failed",
          reason: "no verified connection to the contact",
        });
        return;
      }
      c.descriptionSent = true;
      // PNP-011-MUST-035: the description ends our gathering when it says so; otherwise an
      // `ice` signal does, now or once gathering completes.
      c.endSent = hasEndOfCandidates(sdp);
      if (!c.endSent && pc.iceGatheringState === "complete") {
        await this.sendEndOfCandidates(c, pc);
        if (!this.alive(c)) return;
      }
      if (!c.incoming) this.armRing(c);
    });
  }

  private gathered(pc: PeerConnection): Promise<void> {
    if (pc.iceGatheringState === "complete") return Promise.resolve();
    const clock = this.host.platform.clock;
    return new Promise((resolve) => {
      const done = () => {
        clock.clearTimeout(timer);
        pc.onicegatheringstatechange = null;
        resolve();
      };
      const timer = clock.setTimeout(done, CALL_GATHER_CAP_MS);
      pc.onicegatheringstatechange = () => {
        if (pc.iceGatheringState === "complete") done();
      };
    });
  }

  /**
   * The call is up once every DTLS transport still in use is connected: the spec's own
   * rule for `connectionState`, applied here as well. Linux WebKit (GStreamer) does not
   * recompute its `connectionState` when the answer bundles the media lines and the
   * offerer's extra transport closes: the caller's state stays "connecting" with the
   * bundled transport connected and media flowing, and the call never became Active.
   * Where the browser does not expose transports, `connectionState` alone decides.
   */
  private watchTransports(c: Call, pc: PeerConnection): void {
    const transports = new Set<DtlsTransport>();
    for (const sender of pc.getSenders?.() ?? []) {
      if (sender.transport) transports.add(sender.transport);
    }
    if (transports.size === 0) return;
    const check = () => {
      const live = [...transports].filter((t) => t.state !== "closed");
      if (live.length === 0 || !live.every((t) => t.state === "connected")) return;
      this.host.internal(() => this.connected(c, pc));
    };
    for (const t of transports) t.addEventListener("statechange", check);
    check();
  }

  private connected(c: Call, pc: PeerConnection): void {
    if (!this.alive(c) || c.pc !== pc || c.state.kind === "Active") return;
    this.host.cancel(c.connectTimer);
    this.setState(c, { kind: "Active" });
  }

  private wire(c: Call, pc: PeerConnection): void {
    const { host } = this;
    pc.onconnectionstatechange = () => {
      const state = pc.connectionState;
      host.internal(async () => {
        if (!this.alive(c) || c.pc !== pc) return;
        if (state === "connected") {
          this.connected(c, pc);
        } else if (state === "failed" || state === "closed") {
          await host.sendSignal(c.peerId, {
            action: "hangup",
            callId: c.callId,
          });
          this.end(c, { kind: "Failed", reason: `media connection ${state}` });
        }
      });
    };
    pc.ontrack = (ev) => {
      const stream = ev.streams[0] ?? null;
      host.internal(() => {
        if (!this.alive(c) || c.pc !== pc || !stream || c.remote === stream) {
          return;
        }
        c.remote = stream;
        host.emit({ kind: "CallMedia", callId: c.callId });
      });
    };
    pc.onicecandidate = (ev) => {
      const cand = ev.candidate;
      if (!cand) {
        // Gathering is complete on every transport: after the description, its end follows.
        host.internal(async () => {
          if (!this.alive(c) || c.pc !== pc || !c.descriptionSent || c.endSent) return;
          await this.sendEndOfCandidates(c, pc);
        });
        return;
      }
      if (!cand.candidate) return;
      const init: IceCandidateInit = typeof cand.toJSON === "function" ? cand.toJSON() : {
        candidate: cand.candidate,
        sdpMid: cand.sdpMid,
        sdpMLineIndex: cand.sdpMLineIndex,
        usernameFragment: cand.usernameFragment,
      };
      host.internal(async () => {
        // Only what was found after the description went out; the rest is inside the SDP.
        if (
          !this.alive(c) || c.pc !== pc || !c.descriptionSent ||
          c.lateIce >= CALL_LATE_ICE_MAX
        ) return;
        c.lateIce += 1;
        await host.sendSignal(c.peerId, {
          action: "ice",
          callId: c.callId,
          candidate: init,
        });
      });
    };
  }

  /**
   * Our end-of-candidates indication as an `ice` signal (PNP-011-MUST-035), once per call; it
   * is not one of the `CALL_LATE_ICE_MAX` candidates.
   */
  private async sendEndOfCandidates(c: Call, pc: PeerConnection): Promise<void> {
    const sdp = pc.localDescription?.sdp;
    if (!sdp) return;
    c.endSent = true;
    await this.host.sendSignal(c.peerId, {
      action: "ice",
      callId: c.callId,
      candidate: endOfCandidates(sdp),
    });
  }

  // ── Signals from the contact ─────────────────────────────────────

  async onSignal(peer: string, sig: CallSignal): Promise<void> {
    const { host } = this;
    const c = this.call && this.call.callId === sig.callId ? this.call : null;
    if (c && c.peerId !== peer) {
      host.platform.log.warn(
        `[Call] signal from ${shortId(peer)} for someone else's call`,
      );
      return;
    }
    switch (sig.action) {
      case "offer": {
        if (c) return; // a duplicate
        if (this.call) {
          // Busy.
          await host.sendSignal(peer, { action: "reject", callId: sig.callId });
          return;
        }
        if (!host.isContact(peer)) return;
        const call = this.newCall(sig.callId, peer, sig.video, true);
        call.remoteOffer = sig.sdp;
        this.armRing(call);
        this.emit(call);
        return;
      }
      case "answer": {
        if (!c || c.incoming || c.remoteSet || !c.pc || !c.descriptionSent) {
          return;
        }
        c.remoteSet = true;
        host.cancel(c.ringTimer);
        try {
          await c.pc.setRemoteDescription({ type: "answer", sdp: sig.sdp });
        } catch {
          if (this.alive(c)) {
            await host.sendSignal(peer, { action: "hangup", callId: c.callId });
            this.end(c, { kind: "Failed", reason: "bad answer" });
          }
          return;
        }
        if (!this.alive(c) || !c.pc) return;
        for (const cand of c.pendingIce.splice(0)) {
          void c.pc.addIceCandidate(cand).catch(() => {});
        }
        this.watchTransports(c, c.pc);
        if (c.state.kind === "Outgoing") {
          this.setState(c, { kind: "Connecting" });
          this.armConnect(c);
        }
        return;
      }
      case "ice": {
        // A candidate, or the contact's end of candidates (an empty `candidate`), which is
        // applied or held the same way (PNP-011-MUST-036); `addIceCandidate` takes it as is,
        // and one of a generation the call does not have is refused there and ignored here.
        if (!c) return;
        if (c.remoteSet && c.pc && c.pc.remoteDescription) {
          void c.pc.addIceCandidate(sig.candidate).catch(() => {});
        } else if (c.pendingIce.length < CALL_PENDING_ICE_MAX) {
          // Also before the user accepts: the old PWA dropped these.
          c.pendingIce.push(sig.candidate);
        }
        return;
      }
      case "hangup":
        if (c) this.end(c, { kind: "RemoteHungUp" });
        return;
      case "reject":
        if (c && !c.incoming) this.end(c, { kind: "Rejected" });
        return;
    }
  }
}
