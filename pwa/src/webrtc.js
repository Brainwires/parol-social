// ParolNet PWA — WebRTC Peer Connections & Gossip Mesh
//
// All user content (chat, files, group fan-out, call signals) rides the
// 'parolnet' RTCDataChannel opened here. The relay only carries the
// rtc_offer / rtc_answer / rtc_ice signaling frames that set it up.
//
// ICE policy: direct (host + srflx) with STUN from the relay's
// /turn-credentials by default. A direct connection shows each side's IP
// address to the contact it connects to (never to strangers: offers are only
// sent to, and accepted from, contacts and a peer we are pairing with). The
// opt-in "Relay through my own TURN server" mode uses ONLY the user's own
// TURN servers with iceTransportPolicy 'relay'. TURN URIs from a
// signaling-only server are never used (it should not announce any).
//
// Signaling budget: a signaling-only server caps every sender at 60 frames
// a minute / 240 an hour and every sender->recipient pair at 64 frames per
// 10 minutes. So connection setup is non-trickle (the offer / answer carries
// the gathered candidates in its SDP), new offers are staggered, retries back
// off exponentially and stop while the peer is known to be offline.
import { currentView, currentPeerId } from './state.js';
import { showToast } from './utils.js';
import { dbGet, dbPut, dbDelete } from './db.js';
import { telemetry } from './telemetry.js';
import { connMgr, flushMessageQueue } from './connection.js';
import { onIncomingMessage } from './messaging.js';
import { t } from './i18n.js';
import {
    shouldInitiate, nextRetryDelayMs, rateLimitBackoffMs, takeOfferSlot,
    parseTurnCredentials, iceServersHaveTurn, setServerProfile,
    RETRY_MAX_ATTEMPTS, MAX_SDP_PAYLOAD, MAX_ICE_PAYLOAD, MAX_LATE_ICE_PER_ATTEMPT,
} from './relay-profile.js';

// ── WebRTC Peer Connections ────────────────────────────────
export const rtcConnections = {}; // peerId -> { pc, dc, status, isInitiator, descSent, lateIce, pendingIce }

// No third-party STUN by default. Contacting public STUN (e.g. Google) leaks
// the client IP to the STUN operator. STUN comes from the relay we use
// (fetchTurnCredentials below) or from the user's own ICE servers.
const DEFAULT_STUN_SERVERS = [];

// User-configured ICE servers (Settings > own TURN server). Persisted under
// the `custom_stun_servers` settings key.
let userIceServers = null;
// ICE servers announced by the relay's /turn-credentials. On a
// signaling-only server this is STUN only.
let serverIceServers = [];

// Tracks the in-flight fetchTurnCredentials() promise so call / connection
// setup can await it before creating an RTCPeerConnection; without it a PC
// built during boot would have no STUN and gather host candidates only.
let turnReadyPromise = null;

// Opt-in: relay every connection through the user's OWN TURN server so no
// contact ever sees this device's IP. Stored under `webrtc_relay_only`
// (default off). The old `webrtc_privacy_mode` key is ignored on purpose:
// installs that stored true would otherwise be left with a relay-only
// config and no TURN server, i.e. no connection at all.
let relayOnlyPref = false;

export function hasUserTurnConfigured() {
    return iceServersHaveTurn(userIceServers);
}

/// Relay-only is effective only when the user has their own TURN server.
export function isRelayOnlyActive() {
    return relayOnlyPref && hasUserTurnConfigured();
}

// Kept for callers that predate the rename.
export const isWebrtcPrivacyMode = isRelayOnlyActive;

export function getRtcConfig() {
    if (isRelayOnlyActive()) {
        return { iceServers: userIceServers.slice(), iceTransportPolicy: 'relay' };
    }
    const servers = [];
    if (Array.isArray(userIceServers)) servers.push(...userIceServers);
    servers.push(...serverIceServers);
    if (servers.length === 0) servers.push(...DEFAULT_STUN_SERVERS);
    return { iceServers: servers };
}

export async function loadCustomStunServers() {
    try {
        const saved = await dbGet('settings', 'custom_stun_servers');
        if (saved && saved.value) {
            userIceServers = JSON.parse(saved.value);
        }
    } catch (e) {
        console.warn('[WebRTC] Failed to load custom ICE servers:', e);
    }
    try {
        const pref = await dbGet('settings', 'webrtc_relay_only');
        relayOnlyPref = !!(pref && pref.value === 'true');
    } catch (e) {
        console.warn('[WebRTC] Failed to load relay-only setting:', e);
    }
    turnReadyPromise = fetchTurnCredentials().catch(() => {});
}

// Resolves true once ICE servers are known (user's own, or the relay's
// answer). Resolves false on timeout; a PC built then still works for host
// candidates (same LAN) and the relay-only mode never waits on the relay.
export async function waitForTurnReady(timeoutMs = 5000) {
    if (isRelayOnlyActive()) return true;
    if (serverIceServers.length > 0 || (userIceServers && userIceServers.length > 0)) return true;
    if (!turnReadyPromise) {
        turnReadyPromise = fetchTurnCredentials().catch(() => {});
    }
    const timeout = new Promise(resolve => setTimeout(() => resolve('timeout'), timeoutMs));
    const result = await Promise.race([turnReadyPromise.then(() => 'ok'), timeout]);
    return result === 'ok' && getRtcConfig().iceServers.length > 0;
}

/// True if the effective config has a TURN entry (user's own, or a
/// relay-profile server's).
export function hasTurnConfigured() {
    return iceServersHaveTurn(getRtcConfig().iceServers);
}

/// Save the user's own TURN / STUN servers. Accepts a JSON array of
/// RTCIceServer entries. Returns true on success.
export async function setCustomStunServers(serversJson) {
    try {
        const servers = typeof serversJson === 'string' ? JSON.parse(serversJson) : serversJson;
        if (!Array.isArray(servers) || servers.length === 0) {
            throw new Error('Expected a non-empty array of ICE servers');
        }
        for (const s of servers) {
            if (!s || (!s.urls && !s.url)) {
                throw new Error('Each ICE server entry must have a "urls" property');
            }
        }
        userIceServers = servers;
        await dbPut('settings', { key: 'custom_stun_servers', value: JSON.stringify(servers) });
        showToast(t('toast.turnSaved'));
        updateWebRTCPrivacyUI();
        return true;
    } catch (e) {
        showToast(t('toast.turnInvalid', { error: e.message }));
        return false;
    }
}

export async function clearCustomStunServers() {
    userIceServers = null;
    try { await dbDelete('settings', 'custom_stun_servers'); } catch(e) {}
    if (relayOnlyPref) {
        relayOnlyPref = false;
        try { await dbPut('settings', { key: 'webrtc_relay_only', value: 'false' }); } catch (e) {}
        Object.keys(rtcConnections).forEach(cleanupRTC);
    }
    showToast(t('toast.turnCleared'));
    updateWebRTCPrivacyUI();
}

/// Settings form: build one TURN entry from the URL / username / credential
/// inputs and save it as the user's ICE servers.
export async function saveOwnTurnServerFromForm() {
    const url = (document.getElementById('own-turn-url')?.value || '').trim();
    const username = (document.getElementById('own-turn-username')?.value || '').trim();
    const credential = document.getElementById('own-turn-credential')?.value || '';
    if (!/^(turns?|stuns?):/.test(url)) {
        showToast(t('toast.turnInvalid', { error: 'turn:host:3478' }));
        return false;
    }
    const entry = { urls: url };
    if (username) entry.username = username;
    if (credential) entry.credential = credential;
    const ok = await setCustomStunServers([entry]);
    const credEl = document.getElementById('own-turn-credential');
    if (ok && credEl) credEl.value = '';
    return ok;
}

export async function setRelayOnlyMode(enabled) {
    const want = !!enabled;
    if (want && !hasUserTurnConfigured()) {
        showToast(t('settings.relayOwnTurnNeedsServer'));
        updateWebRTCPrivacyUI();
        return;
    }
    relayOnlyPref = want;
    await dbPut('settings', { key: 'webrtc_relay_only', value: String(want) });
    // Close existing connections so new ones use the updated config.
    Object.keys(rtcConnections).forEach(cleanupRTC);
    updateWebRTCPrivacyUI();
}

// Old name, kept so stale onchange handlers keep working.
export const setWebRTCPrivacyMode = setRelayOnlyMode;

export function updateWebRTCPrivacyUI() {
    if (typeof document === 'undefined') return;
    const hasTurn = hasUserTurnConfigured();
    const toggle = document.getElementById('webrtc-relay-only-toggle');
    if (toggle) {
        toggle.checked = isRelayOnlyActive();
        toggle.disabled = !hasTurn;
    }
    const status = document.getElementById('own-turn-status');
    if (status) {
        if (Array.isArray(userIceServers) && userIceServers.length > 0) {
            const urls = userIceServers.map(s => Array.isArray(s.urls) ? s.urls.join(', ') : (s.urls || s.url)).join(', ');
            status.textContent = t('settings.ownTurnConfigured', { urls });
        } else {
            status.textContent = t('settings.ownTurnNone');
        }
    }
    const clearBtn = document.getElementById('own-turn-clear');
    if (clearBtn) clearBtn.style.display = (userIceServers && userIceServers.length > 0) ? '' : 'none';
    const warning = document.getElementById('webrtc-privacy-warning');
    if (warning) {
        if (relayOnlyPref && !hasTurn) {
            warning.textContent = t('settings.relayOwnTurnNeedsServer');
            warning.style.display = 'block';
        } else {
            warning.style.display = 'none';
        }
    }
}

// Fallback STUN source when our relay has no /turn-credentials endpoint.
const FALLBACK_TURN_URL = 'https://parol.social/turn-credentials';

function relayHttpBase() {
    const relayUrl = connMgr && connMgr.relayUrl;
    if (!relayUrl) return null;
    return relayUrl.replace(/^ws(s?):/, 'http$1:').replace(/\/ws\/?$/, '');
}

// True once serverIceServers came from our own relay (not the fallback).
let iceFromOwnRelay = false;

/// After `registered`: if the ICE servers were fetched before the relay URL
/// was known (boot) or from the fallback server, fetch them from our relay.
export function refreshIceServersFromRelay() {
    if (iceFromOwnRelay || !relayHttpBase()) return;
    turnReadyPromise = fetchTurnCredentials().catch(() => {});
}

export async function fetchTurnCredentials() {
    const urls = [];
    const base = relayHttpBase();
    const ownUrl = base ? base + '/turn-credentials' : null;
    if (ownUrl) urls.push(ownUrl);
    if (ownUrl !== FALLBACK_TURN_URL) urls.push(FALLBACK_TURN_URL);

    for (const url of urls) {
        try {
            const resp = await fetch(url);
            if (!resp.ok) continue;
            const creds = await resp.json();
            const parsed = parseTurnCredentials(creds);
            if (parsed.stun.length === 0 && parsed.turn.length === 0) continue;
            // The profile in this answer describes OUR relay only when it
            // came from our relay; the fallback server's profile is not ours.
            if (url === ownUrl && parsed.profile) setServerProfile(parsed.profile);
            iceFromOwnRelay = url === ownUrl;
            // A TURN credential is only usable from the server that minted
            // it; never take TURN from a server announcing signaling-only.
            serverIceServers = [...parsed.stun, ...parsed.turn];
            console.log('[WebRTC] ICE servers from', url, '- stun:', parsed.stun.length,
                        'turn:', parsed.turn.length, 'profile:', parsed.profile || '(none)');
            return;
        } catch (e) {
            console.warn('[WebRTC] TURN fetch failed for', url, e.message);
        }
    }
    console.warn('[WebRTC] No STUN/TURN from the relay; host candidates only');
}

// ── Peer connection orchestration ──────────────────────────
//
// peerState[peerId] = {
//   online: true | false | undefined   (presence push; undefined = unknown)
//   attempt: number                    (consecutive failed attempts)
//   retryTimer, waitTimer, answerTimer
//   userIntentAt: ms                   (user opened the chat / tried a call)
// }
const peerState = {};
const offerHistory = [];
let signalingBackoffUntil = 0;
let rateLimitHits = 0;
const OFFER_FALLBACK_MS = 10_000;
const ANSWER_TIMEOUT_MS = 20_000;
const GATHER_TIMEOUT_MS = 3_000;
const DISCONNECT_GRACE_MS = 5_000;
const USER_INTENT_WINDOW_MS = 10 * 60_000;

function ps(peerId) {
    if (!peerState[peerId]) peerState[peerId] = { online: undefined, attempt: 0 };
    return peerState[peerId];
}

function clearTimer(st, name) {
    if (st[name]) { clearTimeout(st[name]); st[name] = null; }
}

function emitPath(peerId, state, extra) {
    if (typeof window === 'undefined' || typeof CustomEvent === 'undefined') return;
    try {
        window.dispatchEvent(new CustomEvent('parolnet:peer-path', {
            detail: Object.assign({ peerId, state }, extra || {}),
        }));
    } catch (_) {}
}

export function isPeerKnownOffline(peerId) {
    return !!peerState[peerId] && peerState[peerId].online === false;
}

export function isPeerKnownOnline(peerId) {
    return !!peerState[peerId] && peerState[peerId].online === true;
}

export function markUserIntent(peerId) {
    if (peerId) ps(peerId).userIntentAt = Date.now();
}

function hasRecentUserIntent(peerId) {
    const st = peerState[peerId];
    return !!(st && st.userIntentAt && Date.now() - st.userIntentAt < USER_INTENT_WINDOW_MS);
}

/// Presence push from the relay (`presence` frame), or `peer_offline` error.
export function setPeerOnline(peerId, online) {
    if (!peerId) return;
    const st = ps(peerId);
    const was = st.online;
    st.online = !!online;
    if (online) {
        if (was !== true) st.attempt = 0;
        if (!hasDirectConnection(peerId)) connectToPeer(peerId, { reason: 'presence' });
    } else {
        clearTimer(st, 'retryTimer');
        clearTimer(st, 'waitTimer');
        const conn = rtcConnections[peerId];
        if (conn && conn.status === 'connecting') cleanupRTC(peerId);
        emitPath(peerId, 'offline');
    }
}

/// A `rate_limited` error from the signaling server: pause new offers.
export function noteSignalingRateLimited() {
    const wait = rateLimitBackoffMs(rateLimitHits++);
    signalingBackoffUntil = Date.now() + wait;
    console.warn('[WebRTC] signaling rate-limited; pausing offers for', Math.round(wait / 1000), 's');
}

/// Ask for a data channel to `peerId`. Safe to call often: it is a no-op
/// while a connection is open or being set up. The deterministic initiator
/// (smaller peer id) offers; the other side waits OFFER_FALLBACK_MS for that
/// offer and then offers itself. `force` offers immediately (QR pairing,
/// retries).
export function connectToPeer(peerId, opts = {}) {
    if (typeof RTCPeerConnection === 'undefined') return;
    if (!peerId || peerId === window._peerId || peerId.startsWith('pending_')) return;
    if (opts.reason === 'user') markUserIntent(peerId);
    const conn = rtcConnections[peerId];
    if (conn && (conn.status === 'open' || conn.status === 'connecting')) return;
    const st = ps(peerId);
    if (st.online === false && !opts.force && opts.reason !== 'user') return;
    if (opts.force || shouldInitiate(window._peerId, peerId)) {
        clearTimer(st, 'waitTimer');
        scheduleOffer(peerId);
        return;
    }
    if (st.waitTimer) return;
    st.waitTimer = setTimeout(() => {
        st.waitTimer = null;
        const c = rtcConnections[peerId];
        if (c && (c.status === 'open' || c.status === 'connecting')) return;
        if (st.online === false) return;
        console.log('[WebRTC] no offer from', peerId.slice(0, 8), '- offering ourselves');
        scheduleOffer(peerId);
    }, OFFER_FALLBACK_MS + Math.floor(Math.random() * 2000));
}

function scheduleOffer(peerId) {
    const st = ps(peerId);
    if (st.offerTimer) return;
    const now = Date.now();
    let wait = signalingBackoffUntil > now ? signalingBackoffUntil - now : 0;
    if (wait === 0) wait = takeOfferSlot(offerHistory, now);
    if (wait === 0) {
        initWebRTC(peerId, true).catch(e => console.warn('[WebRTC] offer failed:', e && e.message));
        return;
    }
    st.offerTimer = setTimeout(() => {
        st.offerTimer = null;
        const c = rtcConnections[peerId];
        if (c && (c.status === 'open' || c.status === 'connecting')) return;
        scheduleOffer(peerId);
    }, wait);
}

function scheduleRetry(peerId, conn) {
    const st = ps(peerId);
    if (st.online === false) return;
    // Only the side that would offer retries; the other side waits for it
    // (and its own fallback timer covers an initiator that went quiet).
    const weOffer = (conn && conn.isInitiator) || shouldInitiate(window._peerId, peerId);
    if (!weOffer) return;
    if (st.attempt >= RETRY_MAX_ATTEMPTS && st.online !== true) {
        console.log('[WebRTC] giving up on', peerId.slice(0, 8), 'until presence says online');
        return;
    }
    const delay = nextRetryDelayMs(Math.min(st.attempt, RETRY_MAX_ATTEMPTS));
    st.attempt++;
    clearTimer(st, 'retryTimer');
    st.retryTimer = setTimeout(() => {
        st.retryTimer = null;
        if (st.online === false || hasDirectConnection(peerId)) return;
        console.log('[WebRTC] retrying', peerId.slice(0, 8), '(attempt', st.attempt + ')');
        connectToPeer(peerId, { reason: 'retry', force: true });
    }, delay);
}

function connectionFailed(peerId, pc, conn) {
    // Ignore events from a PC that has already been replaced (glare).
    if (rtcConnections[peerId] && rtcConnections[peerId].pc !== pc) return;
    cleanupRTC(peerId);
    emitPath(peerId, 'failed', { intent: hasRecentUserIntent(peerId) });
    scheduleRetry(peerId, conn);
}

// Wait until ICE gathering completes (or GATHER_TIMEOUT_MS passes) so the
// SDP we send carries the candidates and no per-candidate frames are needed.
function waitForGathering(pc, timeoutMs = GATHER_TIMEOUT_MS) {
    if (pc.iceGatheringState === 'complete') return Promise.resolve();
    return new Promise(resolve => {
        let done = false;
        const finish = () => {
            if (done) return;
            done = true;
            clearTimeout(timer);
            try { pc.removeEventListener('icegatheringstatechange', onChange); } catch (_) {}
            resolve();
        };
        const onChange = () => { if (pc.iceGatheringState === 'complete') finish(); };
        const timer = setTimeout(finish, timeoutMs);
        try { pc.addEventListener('icegatheringstatechange', onChange); } catch (_) { finish(); }
    });
}

function sendDescription(type, peerId, desc) {
    const payload = JSON.stringify(desc && desc.toJSON ? desc.toJSON() : desc);
    if (payload.length > MAX_SDP_PAYLOAD) {
        console.warn('[WebRTC]', type, 'payload', payload.length, 'bytes exceeds the signaling cap');
    }
    return connMgr.sendSignaling(type, peerId, payload);
}

export async function initWebRTC(peerId, isInitiator) {
    // Await ICE server discovery first, so the checks below and the
    // registration of the new record happen without an await in between.
    if (!isRelayOnlyActive()) await waitForTurnReady(3000);
    if (rtcConnections[peerId] && rtcConnections[peerId].status === 'open') return;
    if (isInitiator && rtcConnections[peerId] && rtcConnections[peerId].status === 'connecting') return;
    if (rtcConnections[peerId]) cleanupRTC(peerId);

    const pc = new RTCPeerConnection(getRtcConfig());
    const conn = { pc, dc: null, status: 'connecting', isInitiator: !!isInitiator,
                   descSent: false, lateIce: 0, pendingIce: [] };
    rtcConnections[peerId] = conn;
    const relayOnly = isRelayOnlyActive();

    // Candidates gathered before the description goes out ride inside the
    // SDP; only late ones (after the gather cap) go as rtc_ice, a few at most.
    pc.onicecandidate = (event) => {
        if (!event.candidate || !conn.descSent) return;
        const candidateStr = event.candidate.candidate || '';
        if (relayOnly && (candidateStr.includes('typ host') || candidateStr.includes('typ srflx'))) return;
        if (conn.lateIce >= MAX_LATE_ICE_PER_ATTEMPT) return;
        const payload = JSON.stringify(event.candidate);
        if (payload.length > MAX_ICE_PAYLOAD) return;
        conn.lateIce++;
        connMgr.sendSignaling('rtc_ice', peerId, payload);
    };

    pc.onconnectionstatechange = () => {
        console.log('[WebRTC]', peerId.slice(0,8), 'state:', pc.connectionState);
        if (pc.connectionState === 'failed') {
            telemetry.track('webrtc_connect_fail');
            connectionFailed(peerId, pc, conn);
        } else if (pc.connectionState === 'disconnected') {
            // Often transient (network switch); give ICE a moment to recover
            // before tearing down and spending signaling frames on a redo.
            setTimeout(() => {
                if (pc.connectionState === 'disconnected' || pc.connectionState === 'failed') {
                    connectionFailed(peerId, pc, conn);
                }
            }, DISCONNECT_GRACE_MS);
        } else if (pc.connectionState === 'closed') {
            if (rtcConnections[peerId] && rtcConnections[peerId].pc === pc) cleanupRTC(peerId);
        }
    };

    if (isInitiator) {
        const dc = pc.createDataChannel('parolnet', { ordered: true });
        setupDataChannel(peerId, dc, conn);

        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        await waitForGathering(pc);
        if (rtcConnections[peerId] !== conn) return; // replaced meanwhile
        if (!sendDescription('rtc_offer', peerId, pc.localDescription)) {
            console.log('[WebRTC] relay down; offer to', peerId.slice(0, 8), 'not sent');
            cleanupRTC(peerId);
            scheduleRetry(peerId, conn);
            return;
        }
        conn.descSent = true;
        const st = ps(peerId);
        clearTimer(st, 'answerTimer');
        st.answerTimer = setTimeout(() => {
            st.answerTimer = null;
            if (rtcConnections[peerId] !== conn) return;
            if (pc.remoteDescription && pc.remoteDescription.type) return;
            console.log('[WebRTC] no answer from', peerId.slice(0, 8));
            connectionFailed(peerId, pc, conn);
        }, ANSWER_TIMEOUT_MS);
    } else {
        pc.ondatachannel = (event) => {
            setupDataChannel(peerId, event.channel, conn);
        };
    }
}

function setupDataChannel(peerId, dc, conn) {
    conn.dc = dc;
    // Key the record by the CURRENT peer id: the identity frame may re-map
    // a pending_ id onto the full one after the channel opens.
    const keyOf = () => Object.keys(rtcConnections).find(k => rtcConnections[k] === conn) || peerId;

    dc.onopen = () => {
        const pid = keyOf();
        console.log('[WebRTC] Data channel open with', pid.slice(0,8));
        try {
            dc.send(JSON.stringify({ type: 'identity', peerId: window._peerId }));
        } catch(e) {}
        conn.status = 'open';
        const st = ps(pid);
        st.attempt = 0;
        st.online = true;
        clearTimer(st, 'retryTimer');
        clearTimer(st, 'waitTimer');
        clearTimer(st, 'answerTimer');
        updatePeerConnectionUI(pid, 'direct');
        emitPath(pid, 'open');
        flushMessageQueue({ peerId: pid });
    };

    dc.onclose = () => {
        const pid = keyOf();
        console.log('[WebRTC] Data channel closed with', pid.slice(0,8));
        if (rtcConnections[pid] === conn) cleanupRTC(pid);
        updatePeerConnectionUI(pid, 'relay');
        emitPath(pid, 'closed');
    };

    dc.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'identity' && msg.peerId) {
                const fullPeerId = msg.peerId;
                const pid = keyOf();
                if (pid !== fullPeerId && (pid.startsWith('pending_') || fullPeerId.startsWith(pid.slice(0, 40)))) {
                    if (rtcConnections[pid] === conn) {
                        delete rtcConnections[pid];
                        rtcConnections[fullPeerId] = conn;
                        console.log('[Identity] Mapped', pid.slice(0,8), '→', fullPeerId.slice(0,8));
                    }
                }
            } else if (msg.type === 'chat') {
                onIncomingMessage(msg.payload);
            } else if (msg.type === 'gossip') {
                if (!msg.msgId || !msg.payload || seenGossipMessages.has(msg.msgId)) return;

                const isForUs = !msg.to || msg.to === window._peerId;
                if (isForUs) {
                    onIncomingMessage(msg.payload);
                }

                if (msg.ttl > 0) {
                    gossipForward(keyOf(), msg.msgId, msg.to, msg.payload, msg.ttl - 1);
                }
            }
        } catch(e) {
            onIncomingMessage(event.data);
        }
    };
}

// ── Who may open a connection to us ────────────────────────
//
// Accepting an offer reveals our IP address to the sender, so offers are
// only accepted from contacts and from a peer we are pairing with: the
// pairing window opens while the add-contact QR / code is on screen or was
// just copied (the scanner's first envelope can only reach us over the data
// channel on a signaling-only relay).
let pairingWindowUntil = 0;

export function openPairingWindow(ms = 30 * 60_000) {
    pairingWindowUntil = Math.max(pairingWindowUntil, Date.now() + ms);
}

export function isPairingWindowOpen() {
    return Date.now() < pairingWindowUntil;
}

async function isAllowedRtcPeer(peerId) {
    if (!peerId || typeof peerId !== 'string') return false;
    if (rtcConnections[peerId]) return true; // we offered to them
    try {
        if (await dbGet('contacts', peerId)) return true;
    } catch (_) {}
    return isPairingWindowOpen();
}

export async function handleRTCOffer(fromPeerId, offerJson) {
    if (!(await isAllowedRtcPeer(fromPeerId))) {
        console.warn('[WebRTC] ignoring offer from non-contact', String(fromPeerId).slice(0, 8));
        return;
    }
    const existing = rtcConnections[fromPeerId];
    if (existing && existing.status === 'connecting' && existing.isInitiator &&
        existing.pc.signalingState === 'have-local-offer') {
        // Glare: both sides offered. The designated initiator keeps its
        // offer and ignores this one; the other side yields.
        if (shouldInitiate(window._peerId, fromPeerId)) {
            console.log('[WebRTC] glare with', fromPeerId.slice(0, 8), '- keeping our offer');
            return;
        }
        console.log('[WebRTC] glare with', fromPeerId.slice(0, 8), '- yielding to their offer');
        cleanupRTC(fromPeerId);
    }
    const st = ps(fromPeerId);
    clearTimer(st, 'waitTimer');
    st.online = true;
    await initWebRTC(fromPeerId, false);
    const conn = rtcConnections[fromPeerId];
    const pc = conn?.pc;
    if (!pc) return;

    const offer = JSON.parse(offerJson);
    await pc.setRemoteDescription(new RTCSessionDescription(offer));
    await flushPendingIce(conn);
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    await waitForGathering(pc);
    if (rtcConnections[fromPeerId] !== conn) return;
    if (sendDescription('rtc_answer', fromPeerId, pc.localDescription)) conn.descSent = true;
}

export async function handleRTCAnswer(fromPeerId, answerJson) {
    const conn = rtcConnections[fromPeerId];
    const pc = conn?.pc;
    if (!pc || pc.signalingState !== 'have-local-offer') return;
    const answer = JSON.parse(answerJson);
    await pc.setRemoteDescription(new RTCSessionDescription(answer));
    clearTimer(ps(fromPeerId), 'answerTimer');
    await flushPendingIce(conn);
}

async function flushPendingIce(conn) {
    const queued = conn.pendingIce.splice(0, conn.pendingIce.length);
    for (const c of queued) {
        try { await conn.pc.addIceCandidate(new RTCIceCandidate(c)); } catch (_) {}
    }
}

// Older clients still trickle every candidate; keep accepting them.
export async function handleRTCIce(fromPeerId, candidateJson) {
    const conn = rtcConnections[fromPeerId];
    const pc = conn?.pc;
    if (!pc) return;
    const candidate = JSON.parse(candidateJson);
    if (!pc.remoteDescription || !pc.remoteDescription.type) {
        if (conn.pendingIce.length < 32) conn.pendingIce.push(candidate);
        return;
    }
    await pc.addIceCandidate(new RTCIceCandidate(candidate));
}

export function sendViaWebRTC(peerId, payload) {
    const conn = rtcConnections[peerId];
    if (conn && conn.dc && conn.dc.readyState === 'open') {
        try {
            conn.dc.send(JSON.stringify({ type: 'chat', payload: payload }));
            return true;
        } catch (e) {
            console.warn('[WebRTC] dc.send failed:', e && e.message);
            return false;
        }
    }
    return false;
}

// Data-channel backpressure for bulk sends (file chunks): wait while more
// than SEND_BUFFER_HIGH bytes are queued in the channel, resuming on
// 'bufferedamountlow'. Resolves false if the channel is gone.
const SEND_BUFFER_HIGH = 1024 * 1024;
const SEND_BUFFER_LOW = 256 * 1024;

export function waitForSendBuffer(peerId, timeoutMs = 30_000) {
    const conn = rtcConnections[peerId];
    const dc = conn && conn.dc;
    if (!dc || dc.readyState !== 'open') return Promise.resolve(false);
    if (dc.bufferedAmount <= SEND_BUFFER_HIGH) return Promise.resolve(true);
    return new Promise(resolve => {
        let done = false;
        const finish = (ok) => {
            if (done) return;
            done = true;
            clearTimeout(timer);
            try { dc.removeEventListener('bufferedamountlow', onLow); } catch (_) {}
            try { dc.removeEventListener('close', onClose); } catch (_) {}
            resolve(ok);
        };
        const onLow = () => finish(true);
        const onClose = () => finish(false);
        const timer = setTimeout(() => finish(dc.readyState === 'open'), timeoutMs);
        try {
            dc.bufferedAmountLowThreshold = SEND_BUFFER_LOW;
            dc.addEventListener('bufferedamountlow', onLow);
            dc.addEventListener('close', onClose);
        } catch (_) { finish(dc.readyState === 'open'); }
    });
}

export function cleanupRTC(peerId) {
    const conn = rtcConnections[peerId];
    if (conn) {
        conn.status = 'closed';
        if (conn.dc) try { conn.dc.close(); } catch(e) {}
        if (conn.pc) try { conn.pc.close(); } catch(e) {}
    }
    delete rtcConnections[peerId];
    const st = peerState[peerId];
    if (st) clearTimer(st, 'answerTimer');
}

export function updatePeerConnectionUI(peerId, type) {
    if (currentView === 'chat' && currentPeerId === peerId) {
        const dot = document.getElementById('connection-dot');
        if (dot) {
            dot.className = 'connection-dot online';
            dot.title = type === 'direct' ? 'Direct (WebRTC)' : 'Relay';
        }
    }
}

export function hasDirectConnection(peerId) {
    const conn = rtcConnections[peerId];
    return !!(conn && conn.dc && conn.dc.readyState === 'open');
}

// ── WebRTC Gossip Mesh ─────────────────────────────────────
export const seenGossipMessages = new Set();
const SEEN_GOSSIP_MAX = 1000;
let gossipForwardCount = 0;
let gossipForwardResetTime = Date.now();
const GOSSIP_RATE_LIMIT = 10; // max forwards per second

export function markGossipSeen(msgId) {
    seenGossipMessages.add(msgId);
    if (seenGossipMessages.size > SEEN_GOSSIP_MAX) {
        const first = seenGossipMessages.values().next().value;
        seenGossipMessages.delete(first);
    }
}

export function gossipForward(originPeerId, msgId, to, payload, ttl) {
    if (seenGossipMessages.has(msgId)) return;
    markGossipSeen(msgId);

    // Rate limiting
    const now = Date.now();
    if (now - gossipForwardResetTime > 1000) {
        gossipForwardCount = 0;
        gossipForwardResetTime = now;
    }
    if (gossipForwardCount >= GOSSIP_RATE_LIMIT) return;

    const gossipMsg = JSON.stringify({
        type: 'gossip',
        msgId: msgId,
        from: originPeerId,
        to: to,
        payload: payload,
        ttl: ttl
    });

    for (const [peerId, conn] of Object.entries(rtcConnections)) {
        if (peerId === originPeerId) continue;
        if (conn.dc && conn.dc.readyState === 'open') {
            try {
                conn.dc.send(gossipMsg);
                gossipForwardCount++;
            } catch(e) {
                console.warn('[Gossip] Forward to', peerId.slice(0,8), 'failed:', e.message);
            }
        }
    }
}
