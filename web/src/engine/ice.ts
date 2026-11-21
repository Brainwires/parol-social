// ICE servers: STUN from the home relay's `/turn-credentials`, TURN only from the user
// (PNP-001-MUST-082; crates/parolnet-app/src/ice.rs is the reference).
//
// The engine asks exactly one host for ICE servers: the relay it is registered with. There is
// no fallback to any other host. From the answer it keeps `stun:` URIs and nothing else, so a
// relay cannot put itself on the media path by announcing a TURN server.
import type { Clock, Fetch, IceServer, PeerConfig } from "./platform.ts";
import { EngineError, type TurnSettings } from "./types.ts";

/** The HTTP(S) base of a relay's WebSocket URL (`wss://host/ws` → `https://host`). */
export function httpBase(relayWsUrl: string): string | null {
  let rest: string;
  if (relayWsUrl.startsWith("wss://")) rest = "https://" + relayWsUrl.slice(6);
  else if (relayWsUrl.startsWith("ws://")) {
    rest = "http://" + relayWsUrl.slice(5);
  } else return null;
  rest = rest.replace(/\/+$/, "");
  return rest.endsWith("/ws") ? rest.slice(0, -3) : rest;
}

/** `stun:host[:port]` and nothing more: no spaces, no second URI, no query. */
const STUN_URI = /^stun:(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)(:\d{1,5})?$/i;

/** The STUN URIs of a `/turn-credentials` answer. TURN URIs and credentials are not read. */
export function stunUrisFromAnswer(
  json: string,
): { stun: string[]; profile: string | null } {
  try {
    const v = JSON.parse(json);
    const uris: unknown[] = Array.isArray(v?.uris) ? v.uris : [];
    const stun = uris.filter((u): u is string => typeof u === "string" && STUN_URI.test(u))
      .slice(0, 8);
    return { stun, profile: typeof v?.profile === "string" ? v.profile : null };
  } catch {
    return { stun: [], profile: null };
  }
}

/**
 * Fetch the STUN URIs the relay announces. Empty on any failure: the engine then has host
 * candidates only, which still connect peers on one network.
 */
export async function fetchStun(
  fetch: Fetch,
  clock: Clock,
  relayWsUrl: string,
  timeoutMs = 8000,
): Promise<{ url: string; stun: string[] } | null> {
  const base = httpBase(relayWsUrl);
  if (base === null) return null;
  const url = `${base}/turn-credentials`;
  const abort = typeof AbortController === "function" ? new AbortController() : null;
  const timer = abort ? clock.setTimeout(() => abort.abort(), timeoutMs) : null;
  try {
    const resp = await fetch(url, abort ? { signal: abort.signal } : undefined);
    if (!resp.ok) return { url, stun: [] };
    return { url, stun: stunUrisFromAnswer(await resp.text()).stun };
  } catch {
    return { url, stun: [] };
  } finally {
    if (timer !== null) clock.clearTimeout(timer);
  }
}

const TURN_URI = /^turn:(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)(:\d{1,5})?(\?transport=(udp|tcp))?$/i;

/** Trimmed and checked: a usable `turn:` URI, a username and a password. */
export function validateTurn(settings: TurnSettings): TurnSettings {
  const uri = String(settings.uri ?? "").trim();
  const username = String(settings.username ?? "").trim();
  const password = String(settings.password ?? "");
  if (!TURN_URI.test(uri)) {
    throw new EngineError(
      "Config",
      "the TURN server must be turn:host[:port], optionally with ?transport=udp or tcp",
    );
  }
  if (username.length === 0) {
    throw new EngineError("Config", "the TURN server needs a username");
  }
  if (password.length === 0) {
    throw new EngineError("Config", "the TURN server needs a password");
  }
  return { uri, username, password, relayOnly: settings.relayOnly === true };
}

/**
 * The configuration of a new connection. Without the user's own settings there is no TURN at
 * all; with `relayOnly` the browser gathers relay candidates only.
 */
export function peerConfig(
  stun: readonly string[],
  turn: TurnSettings | null,
): PeerConfig {
  const iceServers: IceServer[] = stun.map((urls) => ({ urls }));
  if (turn) {
    iceServers.push({
      urls: turn.uri,
      username: turn.username,
      credential: turn.password,
    });
  }
  return { iceServers, iceTransportPolicy: turn?.relayOnly ? "relay" : "all" };
}

/** True when a description carries at least one ICE candidate. */
export function hasCandidates(sdp: string): boolean {
  return /^a=candidate:/m.test(sdp);
}
