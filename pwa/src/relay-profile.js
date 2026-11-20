// ParolNet PWA — Relay server profile + pure connection-policy helpers
//
// The home relay announces its profile in the `registered` reply (and in
// `GET /turn-credentials`):
//   - "signaling-only": the server only helps peers set up direct WebRTC
//     connections (register, SDP/ICE signaling, presence, STUN). No user
//     content may go through it: no `message` frames, no mailbox, no onion
//     cells, no cover traffic, no Privacy Pass tokens, no telemetry.
//   - "relay": the full-feature server (mailbox, TURN, tokens, federation).
//     A `registered` reply without a `profile` field comes from an older
//     server and is treated as "relay".
// Until the reply arrives (and while the relay socket is down) the profile is
// "unknown": content then waits in the sender-side queue instead of touching
// any relay path, so nothing leaks to a server whose profile we do not know.
//
// This module has NO imports so node --test can load it directly; every
// helper below is pure and unit-tested in tests/unit.test.mjs.

export const PROFILE_UNKNOWN = 'unknown';
export const PROFILE_RELAY = 'relay';
export const PROFILE_SIGNALING_ONLY = 'signaling-only';

let profile = PROFILE_UNKNOWN;
const listeners = new Set();

/// Map a wire value to a known profile. Missing / unrecognized = "relay"
/// (older servers do not send the field).
export function normalizeProfile(value) {
    return value === PROFILE_SIGNALING_ONLY ? PROFILE_SIGNALING_ONLY : PROFILE_RELAY;
}

export function getServerProfile() {
    return profile;
}

/// Set the current home-relay profile. Pass PROFILE_UNKNOWN to reset (relay
/// socket closed); any other value goes through normalizeProfile.
export function setServerProfile(value) {
    const next = value === PROFILE_UNKNOWN ? PROFILE_UNKNOWN : normalizeProfile(value);
    if (next === profile) return false;
    const prev = profile;
    profile = next;
    for (const fn of listeners) {
        try { fn(next, prev); } catch (e) { console.warn('[Profile] listener threw:', e && e.message); }
    }
    return true;
}

export function onServerProfileChange(fn) {
    listeners.add(fn);
    return () => listeners.delete(fn);
}

export function isSignalingOnly() {
    return profile === PROFILE_SIGNALING_ONLY;
}

/// True only when the home relay is known to accept content frames. Every
/// relay / cross-relay / onion / token / cover-traffic / telemetry path is
/// gated on this.
export function relayPathsAllowed() {
    return profile === PROFILE_RELAY;
}

/// @internal — tests only.
export function _resetProfileForTests() {
    profile = PROFILE_UNKNOWN;
    listeners.clear();
}

// ── Routing decision ───────────────────────────────────────

/// Decide how sendRawEnvelope delivers an envelope.
///   'direct' — an open data channel exists
///   'queue'  — keep it on the sender until the data channel opens
///   'onion'  — relay-profile server with onion mode active
///   'relay'  — relay-profile server: home-relay / cross-relay path
export function chooseSendRoute({ hasDirect, profile: p, onionActive }) {
    if (hasDirect) return 'direct';
    if (p !== PROFILE_RELAY) return 'queue';
    if (onionActive) return 'onion';
    return 'relay';
}

// ── Initiator tie-break ────────────────────────────────────

/// Deterministic WebRTC initiator: the lexicographically smaller peer id
/// sends the offer, the other side waits for it (with a fallback timer), so
/// a presence event seen by both sides at once does not cause glare.
export function shouldInitiate(myPeerId, theirPeerId) {
    if (typeof myPeerId !== 'string' || typeof theirPeerId !== 'string') return true;
    const a = myPeerId.toLowerCase();
    const b = theirPeerId.toLowerCase();
    if (a === b) return false;
    return a < b;
}

// ── Retry backoff ──────────────────────────────────────────

export const RETRY_BASE_MS = 5_000;
export const RETRY_MAX_MS = 5 * 60_000;
export const RETRY_MAX_ATTEMPTS = 8;

/// Exponential backoff for connection retries: 5 s, 10 s, 20 s, ... capped at
/// 5 minutes, with up to +25 % jitter. `rand` is injectable for tests.
export function nextRetryDelayMs(attempt, rand = Math.random) {
    const n = Math.max(0, Math.floor(attempt || 0));
    const base = Math.min(RETRY_BASE_MS * Math.pow(2, n), RETRY_MAX_MS);
    return Math.round(base * (1 + 0.25 * rand()));
}

/// Backoff after a `rate_limited` error from the signaling server: 60 s,
/// doubling per consecutive hit, capped at 10 minutes.
export function rateLimitBackoffMs(consecutiveHits) {
    const n = Math.max(0, Math.floor(consecutiveHits || 0));
    return Math.min(60_000 * Math.pow(2, n), 10 * 60_000);
}

// ── Offer stagger ──────────────────────────────────────────

export const OFFER_WINDOW_MS = 10_000;
export const OFFERS_PER_WINDOW = 3;

/// Sliding-window slot check for new outbound offers. `history` is an array
/// of send timestamps (mutated: old entries pruned, the new one appended when
/// a slot is granted). Returns 0 when the caller may send now, else the
/// number of ms to wait.
export function takeOfferSlot(history, now, max = OFFERS_PER_WINDOW, windowMs = OFFER_WINDOW_MS) {
    while (history.length > 0 && now - history[0] >= windowMs) history.shift();
    if (history.length < max) {
        history.push(now);
        return 0;
    }
    return Math.max(1, windowMs - (now - history[0]));
}

// ── Sender queue limits ────────────────────────────────────

export const QUEUE_LIMITS = Object.freeze({
    maxAgeMs: 30 * 24 * 60 * 60 * 1000, // 30 days
    maxEntries: 2000,
    maxPerPeer: 500,
    maxBytes: 50 * 1024 * 1024,          // ~50 MiB of payload
});

export function payloadBytes(payload) {
    if (typeof payload === 'string') return payload.length;
    if (payload && typeof payload.byteLength === 'number') return payload.byteLength;
    return 0;
}

/// Given the current queue (oldest first) and a new entry about to be
/// appended, return the existing entries to drop so every limit holds after
/// the append: the peer's oldest first for the per-peer cap, then the oldest
/// overall for the total entry and byte caps. Age-expired entries are always
/// dropped. Pure: the caller removes the returned entries.
export function planQueueEviction(queue, entry, limits = QUEUE_LIMITS, now = Date.now()) {
    const drop = new Set();
    for (const e of queue) {
        if (typeof e.timestamp === 'number' && now - e.timestamp > limits.maxAgeMs) drop.add(e);
    }
    const live = () => queue.filter(e => !drop.has(e));

    const peerEntries = live().filter(e => e.toPeerId === entry.toPeerId);
    let peerExcess = peerEntries.length + 1 - limits.maxPerPeer;
    for (let i = 0; i < peerEntries.length && peerExcess > 0; i++, peerExcess--) {
        drop.add(peerEntries[i]);
    }

    let remaining = live();
    let entryExcess = remaining.length + 1 - limits.maxEntries;
    for (let i = 0; i < remaining.length && entryExcess > 0; i++, entryExcess--) {
        drop.add(remaining[i]);
    }

    remaining = live();
    let bytes = remaining.reduce((n, e) => n + payloadBytes(e.payload), 0) + payloadBytes(entry.payload);
    for (let i = 0; i < remaining.length && bytes > limits.maxBytes; i++) {
        drop.add(remaining[i]);
        bytes -= payloadBytes(remaining[i].payload);
    }
    return queue.filter(e => drop.has(e));
}

// ── Presence watch list ────────────────────────────────────

export const WATCH_MAX = 256;

/// Build the `watch` peer-id list: valid 64-hex contact ids, most recently
/// active first, capped at WATCH_MAX. `activity` maps peerId -> ms timestamp.
export function selectWatchList(contactIds, activity, max = WATCH_MAX) {
    const seen = new Set();
    const ids = [];
    for (const raw of contactIds || []) {
        if (typeof raw !== 'string') continue;
        const id = raw.toLowerCase();
        if (!/^[0-9a-f]{64}$/.test(id) || seen.has(id)) continue;
        seen.add(id);
        ids.push(id);
    }
    const at = (id) => (activity && (activity.get ? activity.get(id) : activity[id])) || 0;
    ids.sort((a, b) => at(b) - at(a));
    return ids.slice(0, max);
}

export function sameWatchSet(a, b) {
    if (!a || !b || a.length !== b.length) return false;
    const s = new Set(a);
    return b.every(x => s.has(x));
}

// ── ICE / signaling payload helpers ────────────────────────

export const MAX_SDP_PAYLOAD = 16 * 1024;
export const MAX_ICE_PAYLOAD = 2 * 1024;
export const MAX_LATE_ICE_PER_ATTEMPT = 4;

/// Strip TURN entries from a signaling-only server's /turn-credentials
/// answer (it must not have any) and turn the rest into RTCIceServer
/// entries. Returns { stun: [...], turn: [...] }.
export function parseTurnCredentials(creds) {
    const out = { stun: [], turn: [], profile: null };
    if (!creds || !Array.isArray(creds.uris)) return out;
    out.profile = creds.profile ? normalizeProfile(creds.profile) : null;
    for (const u of creds.uris) {
        if (typeof u !== 'string') continue;
        if (u.startsWith('stun:') || u.startsWith('stuns:')) {
            out.stun.push({ urls: u });
        } else if (u.startsWith('turn:') || u.startsWith('turns:')) {
            if (out.profile === PROFILE_SIGNALING_ONLY) continue;
            out.turn.push({ urls: u, username: creds.username, credential: creds.credential });
        }
    }
    return out;
}

/// True if a list of RTCIceServer entries contains at least one TURN URL.
export function iceServersHaveTurn(servers) {
    if (!Array.isArray(servers)) return false;
    return servers.some(s => {
        const u = s && (s.urls || s.url);
        const list = Array.isArray(u) ? u : [u];
        return list.some(x => typeof x === 'string' && (x.startsWith('turn:') || x.startsWith('turns:')));
    });
}
