// ParolNet PWA — Wire-level Cover Traffic (H7, PNP-006)
//
// Emits encrypted DECOY envelopes at a constant-rate cadence so an observer
// watching the WSS connection cannot distinguish real user activity from
// background noise. Every real send pre-empts the next decoy tick so the
// aggregate rate stays constant (PNP-006-MUST-005: real data has priority).
//
// NORMAL mode only: 500ms base interval + uniform ≤100ms jitter. LOW / HIGH
// modes and burst pacing (PNP-006 §3.1 Table, MUST-007/008) are follow-ups.

import { MSG_TYPE_DECOY } from './protocol-constants.js';

const NORMAL_INTERVAL_MS = 500;
const NORMAL_JITTER_MS = 100;
const DECOY_PLAINTEXT_BYTES = 8;

// Module-internal state
let running = false;
let timerId = null;
let realSentThisInterval = false;
let tickCount = 0;       // diagnostics
let decoySentCount = 0;  // diagnostics

/**
 * Call whenever a real (non-decoy) envelope is pushed onto the wire. The next
 * scheduled decoy tick will be skipped so the observable frame rate does not
 * exceed the base cadence.
 */
export function markRealSend() {
    realSentThisInterval = true;
}

function pickJitterMs() {
    // Uniform 0..NORMAL_JITTER_MS inclusive-ish. Crypto rand isn't needed —
    // timing is purely for traffic shaping, not secrecy.
    return Math.floor(Math.random() * (NORMAL_JITTER_MS + 1));
}

function randomBytes(n) {
    const out = new Uint8Array(n);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        crypto.getRandomValues(out);
    } else {
        for (let i = 0; i < n; i++) out[i] = (Math.random() * 256) & 0xff;
    }
    return out;
}

/**
 * Select a peer we currently have an established Double Ratchet session with,
 * rotating through them in order. Returns null if none are available.
 *
 * @param {object} deps - { wasm, listContacts }
 */
async function pickTargetPeer(deps) {
    try {
        const contacts = await deps.listContacts();
        if (!contacts || contacts.length === 0) return null;
        const hasSession = deps.wasm && typeof deps.wasm.has_session === 'function';
        if (!hasSession) return null;
        const candidates = contacts
            .map(c => c && c.peerId)
            .filter(pid => typeof pid === 'string' && deps.wasm.has_session(pid));
        if (candidates.length === 0) return null;
        // Rotate target by tick count to spread decoys across peers.
        const idx = tickCount % candidates.length;
        return candidates[idx];
    } catch {
        return null;
    }
}

async function emitDecoy(deps) {
    const wasm = deps.wasm;
    if (!wasm || !wasm.envelope_encode || !wasm.has_session) return false;
    const target = await pickTargetPeer(deps);
    if (!target) return false;
    try {
        const plaintext = randomBytes(DECOY_PLAINTEXT_BYTES);
        const nowSecs = BigInt(Math.floor(Date.now() / 1000));
        const envelope = wasm.envelope_encode(target, MSG_TYPE_DECOY, plaintext, nowSecs);
        if (!envelope) return false;
        // Decoys go ONLY through the relay path (PNP-006: the observer being
        // confused is the WSS watcher). Do not duplicate via WebRTC.
        deps.sendToRelay(target, envelope);
        decoySentCount++;
        return true;
    } catch {
        // Silent failure — cover traffic is best-effort.
        return false;
    }
}

function scheduleNext(deps) {
    if (!running) return;
    const delay = NORMAL_INTERVAL_MS + pickJitterMs();
    timerId = setTimeout(() => tick(deps), delay);
}

async function tick(deps) {
    if (!running) return;
    tickCount++;
    if (realSentThisInterval) {
        // PNP-006-MUST-005: a real send during the just-elapsed interval
        // replaces this decoy. Clear the flag and reschedule.
        realSentThisInterval = false;
    } else {
        await emitDecoy(deps);
    }
    scheduleNext(deps);
}

/**
 * Start the cover-traffic timer. Safe to call when already running (no-op).
 *
 * @param {object} opts
 * @param {'NORMAL'} [opts.mode='NORMAL'] - Only NORMAL is supported for now.
 * @param {object} opts.wasm - The loaded WASM module (must expose envelope_encode + has_session).
 * @param {function} opts.sendToRelay - (toPeerId, envelopeHex) => void | boolean
 * @param {function} opts.listContacts - async () => Array<{ peerId }>
 */
export function startCoverTraffic(opts) {
    if (running) return;
    if (!opts || !opts.wasm || !opts.sendToRelay || !opts.listContacts) {
        throw new Error('startCoverTraffic: missing required dependency');
    }
    if (opts.mode && opts.mode !== 'NORMAL') {
        throw new Error('startCoverTraffic: only NORMAL mode is supported in this build');
    }
    running = true;
    realSentThisInterval = false;
    scheduleNext(opts);
}

/**
 * Stop the cover-traffic timer. Safe to call when not running.
 */
export function stopCoverTraffic() {
    running = false;
    if (timerId !== null) {
        clearTimeout(timerId);
        timerId = null;
    }
}

/**
 * Diagnostic accessor (exposed for tests).
 */
export function _coverTrafficStats() {
    return { running, tickCount, decoySentCount };
}

/**
 * Test hook: reset module state. Not part of the public API.
 */
export function _resetCoverTrafficForTest() {
    running = false;
    if (timerId !== null) { clearTimeout(timerId); timerId = null; }
    realSentThisInterval = false;
    tickCount = 0;
    decoySentCount = 0;
}
