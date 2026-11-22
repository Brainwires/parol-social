// Wire formats shared with the relay, the desktop client and the old PWA
// (crates/parolnet-app/src/wire.rs and call.rs are the reference).
//
// - Relay frames: JSON over the relay's `/ws` (PNP-001 §10.5).
// - SDP payloads: the JSON of an `RTCSessionDescription`, as a string inside the relay frame.
// - Data-channel frames on the `parolnet` channel: JSON text.
// - Call signals: the JSON body of a CALL_SIGNAL (0x0B) envelope.
import type { IceCandidateInit } from "./platform.ts";

export const DATA_CHANNEL_LABEL = "parolnet";

/** PNP-001 §3.4 message types the engine handles. */
export const MsgType = {
  /** TEXT: the plaintext is the raw UTF-8 chat text. */
  TEXT: 0x01,
  /** CONTROL: the scanner's bootstrap envelope carries an empty CONTROL body. */
  CONTROL: 0x03,
  /** DECOY: dropped silently. */
  DECOY: 0x04,
  CALL_SIGNAL: 0x0b,
  CHANNEL_BINDING: 0x14,
} as const;

/** Relay caps the client checks before sending (PNP-001-MUST-072). */
export const SDP_PAYLOAD_MAX = 16384;
export const ICE_PAYLOAD_MAX = 2048;
export const WATCH_MAX = 256;

export function isPeerId(s: unknown): s is string {
  return typeof s === "string" && /^[0-9a-fA-F]{64}$/.test(s);
}

/** The initiator tie-break: the lexicographically smaller lower-case hex PeerId offers. */
export function shouldInitiate(me: string, them: string): boolean {
  const a = me.toLowerCase();
  const b = them.toLowerCase();
  return a !== b && a < b;
}

// ── relay frames ─────────────────────────────────────────────────

export type SignalKind = "rtc_offer" | "rtc_answer" | "rtc_ice";

export type ClientFrame =
  | {
    type: "register";
    peer_id: string;
    pubkey?: string;
    signature?: string;
    nonce?: string;
    /** The canonical name of the relay this client dialed (PNP-001 §10.7); signed. */
    relay?: string;
  }
  | { type: "watch"; peer_ids: string[] }
  | { type: SignalKind; to: string; payload: string }
  | { type: "ping"; ts: number };

export type ServerFrame =
  | { type: "challenge"; nonce: string }
  | { type: "registered"; profile: string }
  | { type: "presence"; peerId: string; online: boolean }
  | { type: "signal"; kind: SignalKind; from: string; payload: string }
  | { type: "error"; code: string; message: string; peerId: string | null }
  | { type: "pong" }
  | { type: "other"; name: string };

function str(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

/**
 * The host and port a relay URL points at, as the browser's URL parser reads it: the same
 * parser the WebSocket constructor uses, so this is the endpoint the socket goes to. A URL
 * that names no port has its scheme's default (443 for `wss:`, 80 for `ws:`). Throws for
 * anything that is not a plain `ws:` / `wss:` URL (user information included): the answer
 * to a relay's challenge is signed for this endpoint (PNP-001 §10.7), so there must be no
 * doubt about which one it is.
 */
export function relayEndpoint(url: string): { host: string; port: number } {
  const u = new URL(url);
  let port: number;
  if (u.protocol === "wss:") port = 443;
  else if (u.protocol === "ws:") port = 80;
  else throw new Error("not a ws: or wss: URL");
  if (u.username !== "" || u.password !== "") {
    throw new Error("a relay URL carries no user information");
  }
  if (u.hostname === "") throw new Error("a relay URL names a host");
  if (u.port !== "") port = Number(u.port);
  return { host: u.hostname, port };
}

/** Parse a relay text frame. `null` for malformed JSON or a frame missing a required field. */
export function parseServerFrame(text: string): ServerFrame | null {
  let raw: Record<string, unknown>;
  try {
    const v = JSON.parse(text);
    if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
    raw = v as Record<string, unknown>;
  } catch {
    return null;
  }
  const type = str(raw.type);
  switch (type) {
    case null:
      return null;
    case "challenge": {
      const nonce = str(raw.nonce);
      return nonce === null ? null : { type, nonce };
    }
    case "registered":
      // A relay that announces no profile is a pre-v0.11 `relay` (PNP-001-MUST-070).
      return { type, profile: str(raw.profile) ?? "relay" };
    case "presence": {
      const peerId = str(raw.peer_id);
      if (!isPeerId(peerId)) return null;
      return {
        type,
        peerId: peerId.toLowerCase(),
        online: raw.online === true,
      };
    }
    case "rtc_offer":
    case "rtc_answer":
    case "rtc_ice": {
      const from = str(raw.from);
      const payload = str(raw.payload);
      if (!isPeerId(from) || payload === null) return null;
      return { type: "signal", kind: type, from: from.toLowerCase(), payload };
    }
    case "error": {
      const peerId = str(raw.peer_id);
      return {
        type,
        code: str(raw.code) ?? "",
        message: str(raw.message) ?? "",
        peerId: isPeerId(peerId) ? peerId.toLowerCase() : null,
      };
    }
    case "pong":
      return { type };
    default:
      return { type: "other", name: type };
  }
}

/** A session description from a relay payload; `null` unless it is the expected type. */
export function parseSdpPayload(
  payload: string,
  want: "offer" | "answer",
): string | null {
  try {
    const v = JSON.parse(payload);
    if (v && v.type === want && typeof v.sdp === "string" && v.sdp.length > 0) {
      return v.sdp;
    }
  } catch { /* malformed */ }
  return null;
}

export function parseIcePayload(payload: string): IceCandidateInit | null {
  try {
    const v = JSON.parse(payload);
    if (!v || typeof v !== "object" || typeof v.candidate !== "string") {
      return null;
    }
    return {
      candidate: v.candidate,
      sdpMid: typeof v.sdpMid === "string" ? v.sdpMid : null,
      sdpMLineIndex: typeof v.sdpMLineIndex === "number" ? v.sdpMLineIndex : null,
      usernameFragment: typeof v.usernameFragment === "string" ? v.usernameFragment : null,
    };
  } catch {
    return null;
  }
}

// ── data-channel frames ──────────────────────────────────────────

export type DcFrame =
  /** Sent once by each side when the channel opens. Informational; never trusted. */
  | { type: "identity"; peerId: string }
  /** A hex-encoded PNP-001 envelope. */
  | { type: "envelope"; hex: string }
  /** Anything else (the old PWA's `gossip`, future types): ignored. */
  | { type: "other" };

export function identityFrame(peerId: string): string {
  return JSON.stringify({ type: "identity", peerId });
}

export function chatFrame(envelopeHex: string): string {
  return JSON.stringify({ type: "chat", payload: envelopeHex });
}

/** Parse a data-channel message. Like the desktop, bare hex is taken as an envelope. */
export function parseDcFrame(data: unknown): DcFrame {
  if (typeof data !== "string") return { type: "other" };
  try {
    const v = JSON.parse(data);
    if (v && typeof v === "object") {
      if (v.type === "identity" && typeof v.peerId === "string") {
        return { type: "identity", peerId: v.peerId };
      }
      if (v.type === "chat" && typeof v.payload === "string") {
        return { type: "envelope", hex: v.payload };
      }
    }
    return { type: "other" };
  } catch {
    const t = data.trim();
    if (t.length > 0 && t.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(t)) {
      return { type: "envelope", hex: t };
    }
    return { type: "other" };
  }
}

// ── call signals ─────────────────────────────────────────────────

export type CallSignal =
  | { action: "offer"; callId: string; video: boolean; sdp: string }
  | { action: "answer"; callId: string; video: boolean; sdp: string }
  | { action: "ice"; callId: string; candidate: IceCandidateInit }
  | { action: "hangup"; callId: string }
  | { action: "reject"; callId: string };

const MAX_CALL_ID = 64;

export function callSignalJson(sig: CallSignal): string {
  switch (sig.action) {
    case "offer":
    case "answer":
      return JSON.stringify({
        action: sig.action,
        callId: sig.callId,
        withVideo: sig.video,
        sdp: sig.sdp,
      });
    case "ice":
      return JSON.stringify({
        action: "ice",
        callId: sig.callId,
        candidate: sig.candidate,
      });
    default:
      return JSON.stringify({ action: sig.action, callId: sig.callId });
  }
}

/** Parse a signal body. `null` for anything malformed or unknown. */
export function parseCallSignal(json: string): CallSignal | null {
  let v: Record<string, unknown>;
  try {
    const parsed = JSON.parse(json);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return null;
    }
    v = parsed;
  } catch {
    return null;
  }
  const callId = v.callId;
  if (
    typeof callId !== "string" || callId.length === 0 ||
    callId.length > MAX_CALL_ID
  ) {
    return null;
  }
  const video = v.withVideo === true;
  switch (v.action) {
    case "offer":
    case "answer":
      return typeof v.sdp === "string" ? { action: v.action, callId, video, sdp: v.sdp } : null;
    case "ice": {
      const c = v.candidate as Record<string, unknown> | null;
      if (!c || typeof c !== "object" || typeof c.candidate !== "string") {
        return null;
      }
      return {
        action: "ice",
        callId,
        candidate: {
          candidate: c.candidate,
          sdpMid: typeof c.sdpMid === "string" ? c.sdpMid : null,
          sdpMLineIndex: typeof c.sdpMLineIndex === "number" ? c.sdpMLineIndex : null,
          usernameFragment: typeof c.usernameFragment === "string" ? c.usernameFragment : null,
        },
      };
    }
    case "hangup":
    case "reject":
      return { action: v.action, callId };
    default:
      return null;
  }
}
