// ParolNet PWA — Connection Manager, Message Queue, Peer Discovery
//
// state.js is imported lazily to keep this module loadable from
// node --test (state.js transitively imports the DOM-dependent
// crypto-store.js). Under the browser the dynamic import resolves
// synchronously against the registry.
import { dbGet, dbGetAll, dbPut, dbDelete } from './db.js';
import { hasDirectConnection, connectToPeer, isPeerKnownOffline } from './webrtc.js';
import { showErrorToast } from './utils.js';
import { t } from './i18n.js';
import {
    QUEUE_LIMITS, planQueueEviction, selectWatchList, sameWatchSet, WATCH_MAX,
    relayPathsAllowed,
} from './relay-profile.js';

let _stateMod = null;
async function _state() {
    if (_stateMod) return _stateMod;
    try { _stateMod = await import('./state.js'); } catch (_) { _stateMod = {}; }
    return _stateMod;
}

// ── Connection Manager ─────────────────────────────────────
// Home-relay WebSocket lives in the Service Worker so it persists when
// the page is backgrounded. connMgr delegates all SW ops via
// postMessage; status comes back via relay_status.
//
// H12 Phase 2 adds a *second* category of relay WebSockets: OUTBOUND
// connections to peer relays for cross-relay message delivery. Those
// are short-lived (5-min idle close) and live in the page context. They
// are write-only from the PWA's perspective — we don't register as a
// subscriber on a relay that isn't our home; we just authenticate and
// send.
export const connMgr = {
    relayUrl: null,
    _swRelayConnected: false,
    _discoveredRelays: [],
    _currentRelayIndex: 0,

    // relayUrl -> { ws, authState: 'pending'|'challenged'|'open', lastActivityMs, openWaiters: [] }
    outbound: new Map(),
    OUTBOUND_IDLE_MS: 5 * 60 * 1000,

    _swPost(msg) {
        const sw = navigator.serviceWorker && navigator.serviceWorker.controller;
        if (sw) {
            sw.postMessage(msg);
        } else if (navigator.serviceWorker) {
            navigator.serviceWorker.ready.then(reg => {
                if (reg.active) reg.active.postMessage(msg);
            });
        }
    },

    async start() {
        // Load custom relay URL from IndexedDB
        let customRelayUrl = null;
        try {
            const saved = await dbGet('settings', 'custom_relay_url');
            if (saved && saved.value) customRelayUrl = saved.value;
        } catch(e) {}

        this.relayUrl = customRelayUrl ||
            (location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + location.host + '/ws';

        const s = await _state();
        const relayClient = s.relayClient;
        this._discoveredRelays = ((relayClient && relayClient.relays) || []).map(url => {
            let u = url.replace(/\/$/, '');
            if (u.startsWith('https://')) return 'wss://' + u.slice(8) + '/ws';
            if (u.startsWith('http://')) return 'ws://' + u.slice(7) + '/ws';
            return u;
        });
        this._currentRelayIndex = 0;

        // Tell SW to open the relay WebSocket
        this._swPost({ type: 'relay_connect', url: this.relayUrl, peerId: window._peerId || null });
    },

    registerPeer(peerId) {
        this._swPost({ type: 'relay_register', peerId });
    },

    sendSignaling(type, toPeerId, payload) {
        if (!this._swRelayConnected) return false;
        this._swPost({ type: 'relay_signaling', msgType: type, to: toPeerId, payload });
        return true;
    },

    // Presence subscription: the relay reports `presence` frames for peers
    // that watch us back. Each call replaces the previous set.
    sendWatch(peerIds) {
        if (!this._swRelayConnected) return false;
        this._swPost({ type: 'relay_watch', peerIds: (peerIds || []).slice(0, WATCH_MAX) });
        return true;
    },

    sendRelay(toPeerId, payload, token) {
        if (!this._swRelayConnected) return false;
        // Token is mandatory per PNP-001-MUST-048. The SW forwards it
        // verbatim in the `token` field of the outer frame.
        if (!token) return false;
        this._swPost({ type: 'relay_send', to: toPeerId, payload, token });
        return true;
    },

    isRelayConnected() {
        return this._swRelayConnected;
    },

    isConnected() {
        return this._swRelayConnected;
    },

    // ── H12 Phase 2: outbound relays ───────────────────────
    //
    // Open (or reuse) a direct WebSocket to `relayUrl` and complete the
    // Ed25519 challenge-response. Returns a Promise that resolves to
    // `true` once the ws is in state 'open' (post-challenge), or
    // `false` on any failure. Idempotent: concurrent callers share the
    // same pending auth.
    async openOutbound(relayUrl) {
        let entry = this.outbound.get(relayUrl);
        if (entry && entry.ws && entry.ws.readyState === 1 && entry.authState === 'open') {
            entry.lastActivityMs = Date.now();
            return true;
        }
        if (entry && entry.authState !== 'failed' && entry.ws && entry.ws.readyState <= 1) {
            // A connect is in flight — wait on it.
            return new Promise((resolve) => entry.openWaiters.push(resolve));
        }

        entry = { ws: null, authState: 'pending', lastActivityMs: Date.now(), openWaiters: [], authTimer: null };
        this.outbound.set(relayUrl, entry);

        const wsUrl = _toWsUrl(relayUrl);
        try {
            entry.ws = new WebSocket(wsUrl);
        } catch (_) {
            entry.authState = 'failed';
            this._notifyWaiters(entry, false);
            return false;
        }

        const settle = (ok) => {
            if (entry.authTimer) { clearTimeout(entry.authTimer); entry.authTimer = null; }
            this._notifyWaiters(entry, ok);
        };

        // 10s authentication watchdog. If the relay accepts the WS but never
        // sends 'challenge' (or 'registered' after our register), every
        // subsequent send to this relay would block on openWaiters forever.
        entry.authTimer = setTimeout(() => {
            if (entry.authState !== 'open') {
                console.warn('[Relay] openOutbound auth timeout for', relayUrl);
                entry.authState = 'failed';
                try { entry.ws && entry.ws.close(); } catch (_) {}
                this.outbound.delete(relayUrl);
                this._notifyWaiters(entry, false);
            }
        }, 10000);

        entry.ws.onmessage = async (ev) => {
            entry.lastActivityMs = Date.now();
            let msg;
            try { msg = JSON.parse(ev.data); } catch (_) { return; }
            const s = await _state();
            const wasm = s.wasm;
            // Challenge → sign nonce → send authenticated register.
            if (msg.type === 'challenge' && msg.nonce && wasm && wasm.sign_bytes && wasm.get_public_key) {
                try {
                    const signature = wasm.sign_bytes(msg.nonce);
                    const pubkey = wasm.get_public_key();
                    const peerId = window._peerId;
                    entry.ws.send(JSON.stringify({
                        type: 'register',
                        peer_id: peerId,
                        pubkey,
                        signature,
                        nonce: msg.nonce
                    }));
                    entry.authState = 'challenged';
                } catch (_) {
                    entry.authState = 'failed';
                    try { entry.ws.close(); } catch (_) {}
                    settle(false);
                }
                return;
            }
            if (msg.type === 'registered') {
                entry.authState = 'open';
                settle(true);
                return;
            }
            // Any incoming `message` frames on an outbound WS would be
            // unusual — the peer relay doesn't know us as a subscriber
            // in the home-relay sense. If one arrives, drop silently.
        };
        entry.ws.onclose = () => {
            entry.authState = 'failed';
            this.outbound.delete(relayUrl);
            settle(false);
        };
        entry.ws.onerror = () => {
            entry.authState = 'failed';
            try { entry.ws.close(); } catch (_) {}
            settle(false);
        };
        entry.ws.onopen = () => {
            // Some relays may begin the challenge immediately; if not,
            // an initial unauthenticated `register` prompts the
            // challenge-response.
            try {
                const peerId = window._peerId || null;
                if (peerId) {
                    entry.ws.send(JSON.stringify({ type: 'register', peer_id: peerId }));
                }
            } catch (_) {
                entry.authState = 'failed';
                try { entry.ws.close(); } catch (_) {}
                settle(false);
            }
        };

        return new Promise((resolve) => entry.openWaiters.push(resolve));
    },

    _notifyWaiters(entry, ok) {
        const ws = entry.openWaiters;
        entry.openWaiters = [];
        for (const w of ws) {
            try { w(ok); } catch (_) {}
        }
    },

    // Send via outbound connection. Assumes openOutbound() already
    // resolved truthy; no-ops if the entry is missing or not open.
    sendToRelayUrl(relayUrl, toPeerId, payload, token) {
        const entry = this.outbound.get(relayUrl);
        if (!entry || !entry.ws || entry.ws.readyState !== 1 || entry.authState !== 'open') {
            return false;
        }
        if (!token) return false;
        try {
            entry.ws.send(JSON.stringify({
                type: 'message',
                to: toPeerId,
                token,
                payload,
            }));
            entry.lastActivityMs = Date.now();
            return true;
        } catch (_) {
            return false;
        }
    },

    // Close and drop any outbound WS idle beyond OUTBOUND_IDLE_MS.
    // Also drops that relay's token pool entry — tokens forfeit per the
    // Phase 2 plan (see §9 in the authoritative plan).
    closeIdleOutbound(nowMs = Date.now()) {
        const stale = [];
        for (const [url, entry] of this.outbound.entries()) {
            if (nowMs - entry.lastActivityMs > this.OUTBOUND_IDLE_MS) {
                stale.push(url);
            }
        }
        if (stale.length === 0) return;
        // Late-bind the drop helper to avoid a circular import at
        // module-load time.
        import('./token-pool.js').then(({ dropTokenPoolFor }) => {
            for (const url of stale) {
                const entry = this.outbound.get(url);
                if (entry && entry.ws) { try { entry.ws.close(); } catch (_) {} }
                this.outbound.delete(url);
                if (dropTokenPoolFor) dropTokenPoolFor(url);
            }
        }).catch(() => {
            // If the token-pool module can't be imported (edge case),
            // at least close the sockets.
            for (const url of stale) {
                const entry = this.outbound.get(url);
                if (entry && entry.ws) { try { entry.ws.close(); } catch (_) {} }
                this.outbound.delete(url);
            }
        });
    }
};

function _toWsUrl(relayUrl) {
    let u = (relayUrl || '').replace(/\/$/, '');
    if (u.startsWith('https://')) u = 'wss://' + u.slice(8);
    else if (u.startsWith('http://')) u = 'ws://' + u.slice(7);
    if (!/\/ws$/.test(u)) u = u + '/ws';
    return u;
}

// ── Send To Relay (convenience wrapper) ───────────────────
// `token` is the hex-encoded Privacy Pass token to spend for this frame.
// Outer-frame callers must acquire it via `tokenPool.spendOneToken()`
// before invoking this function.
export function sendToRelay(toPeerId, payload, token) {
    return connMgr.sendRelay(toPeerId, payload, token);
}

// ── Message Queue (offline resilience) ─────────────────────
//
// In-memory queue is the source of truth during a session; every mutation
// mirrors to the `pending_sends` IndexedDB store so a tab close during a
// relay outage doesn't lose pending sends. On the next boot, `hydrate-
// PendingSends` reloads rows back into `messageQueue`.
const messageQueue = [];
// Sender-side queue. On a signaling-only relay this is the ONLY offline
// delivery: a message waits here until the contact's data channel opens
// (both must be online at once). Limits: 30 days, 2000 entries, 500 per
// contact and ~50 MiB of payload; oldest dropped first (relay-profile.js
// planQueueEviction).
const MAX_QUEUE_AGE_MS = QUEUE_LIMITS.maxAgeMs;
const RETRY_BACKOFF_MS = 5000;    // per-message head-of-line skip window

function emitQueueChanged(peerIds) {
    if (typeof window === 'undefined' || typeof CustomEvent === 'undefined') return;
    try {
        window.dispatchEvent(new CustomEvent('parolnet:queue-changed', {
            detail: { peerIds: Array.from(new Set(peerIds)) },
        }));
    } catch (_) {}
}

/// Number of envelopes waiting in the sender queue for `peerId`.
export function queuedCountFor(peerId) {
    let n = 0;
    for (const e of messageQueue) if (e.toPeerId === peerId) n++;
    return n;
}

// Fire-and-forget IDB write. Attaches the autoIncrement id back onto the
// in-memory entry so later flush attempts can target the exact row for
// deletion. Errors are logged but never thrown — the in-memory queue stays
// functional even if persistence fails (e.g., quota exhausted).
function _persistQueueEntry(entry) {
    const { toPeerId, payload, timestamp, nextTryAt, id, bootstrap } = entry;
    const row = { toPeerId, payload, timestamp, nextTryAt };
    if (bootstrap) row.bootstrap = true;
    if (id !== undefined) row.id = id;
    dbPut('pending_sends', row).then(newId => {
        // dbPut returns the (possibly-new) primary key. First write assigns
        // an autoIncrement id; subsequent updates return the same id.
        if (newId !== undefined && entry.id === undefined) entry.id = newId;
    }).catch(e => {
        console.warn('[Queue] failed to persist pending send:', e && e.message);
        showErrorToast(t('toast.pendingQueuePersistFailed'));
    });
}

function _deletePersisted(entry) {
    if (entry.id === undefined) return;
    dbDelete('pending_sends', entry.id).catch(e => {
        console.warn('[Queue] failed to drop pending send:', e && e.message);
        showErrorToast(t('toast.pendingQueueDropFailed'));
    });
}

/// `opts.bootstrap`: the QR scanner's bootstrap-completing envelope. It is the one envelope
/// sent on a new data channel before the peer's channel binding verifies (PNP-001 §10.5.1):
/// the presenter needs it to have a session at all.
export function queueMessage(toPeerId, payload, opts) {
    const entry = { toPeerId, payload, timestamp: Date.now(), nextTryAt: 0 };
    if (opts && opts.bootstrap) entry.bootstrap = true;
    const changed = [toPeerId];
    for (const dropped of planQueueEviction(messageQueue, entry)) {
        const i = messageQueue.indexOf(dropped);
        if (i >= 0) messageQueue.splice(i, 1);
        _deletePersisted(dropped);
        changed.push(dropped.toPeerId);
    }
    messageQueue.push(entry);
    _persistQueueEntry(entry);
    console.log('[Queue] Message queued for', toPeerId.slice(0, 8), '- queue size:', messageQueue.length);
    emitQueueChanged(changed);
}

/// Rehydrate the in-memory queue from `pending_sends`. Called once on boot
/// after the crypto store is unlocked (encrypted rows can't decrypt before
/// unlock). Safe to call multiple times — it unions on row id to avoid
/// duplicating entries already loaded.
export async function hydratePendingSends() {
    let rows;
    try { rows = await dbGetAll('pending_sends'); } catch { return 0; }
    if (!rows || rows.length === 0) return 0;
    const now = Date.now();
    const known = new Set(messageQueue.map(e => e.id).filter(id => id !== undefined));
    let loaded = 0;
    for (const row of rows) {
        if (row.id !== undefined && known.has(row.id)) continue;
        if (row.timestamp && now - row.timestamp > MAX_QUEUE_AGE_MS) {
            // Age-expired during downtime — drop from storage, don't hydrate.
            if (row.id !== undefined) dbDelete('pending_sends', row.id).catch(() => {});
            continue;
        }
        messageQueue.push({
            id: row.id,
            toPeerId: row.toPeerId,
            payload: row.payload,
            timestamp: row.timestamp || now,
            nextTryAt: row.nextTryAt || 0,
            bootstrap: !!row.bootstrap,
        });
        loaded++;
    }
    if (loaded > 0) {
        messageQueue.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
        console.log('[Queue] Hydrated', loaded, 'pending sends from IDB');
        emitQueueChanged(messageQueue.map(e => e.toPeerId));
    }
    return loaded;
}

/// Send the queued bootstrap envelopes for `peerId` through `send(payload) -> bool` (the
/// just-opened, not yet verified data channel), synchronously and in order, so they precede
/// our channel binding. Returns how many went out.
export function flushBootstrapQueue(peerId, send) {
    let sent = 0;
    for (let i = 0; i < messageQueue.length; ) {
        const e = messageQueue[i];
        if (e.toPeerId === peerId && e.bootstrap && send(e.payload)) {
            messageQueue.splice(i, 1);
            _deletePersisted(e);
            sent++;
        } else {
            i++;
        }
    }
    if (sent > 0) {
        console.log('[Queue] sent', sent, 'bootstrap envelope(s) to', peerId.slice(0, 8));
        emitQueueChanged([peerId]);
    }
    return sent;
}

// Flush the sender queue. `opts.peerId` limits the flush to one contact
// (its data channel just opened). Entries whose contact has no open data
// channel while relay paths are unavailable (signaling-only or unknown
// profile) are skipped untouched: no send attempt, no retry backoff burnt,
// so a flush for one contact never delays another contact's messages.
let flushScheduled = null;
export function flushMessageQueue(opts) {
    if (messageQueue.length === 0) return;
    const onlyPeer = opts && opts.peerId;
    // Dynamic import to break the connection.js ↔ messaging.js cycle:
    // messaging.js imports queueMessage from here, so we can't import
    // sendRawEnvelope at module-top. Flush only runs on reconnect /
    // WebRTC open so the lazy lookup cost is negligible.
    import('./messaging.js').then(async ({ sendRawEnvelope }) => {
        const now = Date.now();
        const relayOk = relayPathsAllowed();
        const toFlush = [];
        for (let i = 0; i < messageQueue.length; ) {
            const msg = messageQueue[i];
            const eligible = (!onlyPeer || msg.toPeerId === onlyPeer)
                && (relayOk || hasDirectConnection(msg.toPeerId)
                    || now - msg.timestamp > MAX_QUEUE_AGE_MS);
            if (eligible) { toFlush.push(msg); messageQueue.splice(i, 1); }
            else i++;
        }
        if (toFlush.length === 0) return;
        console.log('[Queue] Flushing', toFlush.length, 'queued messages',
                    onlyPeer ? 'for ' + onlyPeer.slice(0, 8) : '');
        let sentCount = 0, droppedAged = 0, deferredBackoff = 0, reQueued = 0;
        const changed = [];
        const requeue = [];
        for (const msg of toFlush) {
            if (now - msg.timestamp > MAX_QUEUE_AGE_MS) {
                _deletePersisted(msg);
                droppedAged++;
                changed.push(msg.toPeerId);
                continue;
            }
            // A data channel that just opened is always worth trying, even
            // inside the relay-path backoff window.
            const direct = hasDirectConnection(msg.toPeerId);
            if (!direct && msg.nextTryAt && msg.nextTryAt > now) {
                requeue.push(msg); // not yet time to retry
                deferredBackoff++;
                continue;
            }
            let sent = false;
            try {
                // Full routing path (sendRawEnvelope): data channel first,
                // then — only on a relay-profile server — onion / home relay
                // / cross relay. noPersist: flush already owns this row;
                // sendRawEnvelope must NOT re-queue on failure.
                const result = await sendRawEnvelope(msg.toPeerId, msg.payload, { noPersist: true });
                sent = result.ok;
            } catch (e) {
                console.warn('[Queue] sendRawEnvelope threw on flush:', e && e.message);
                sent = false;
            }
            if (sent) {
                _deletePersisted(msg);
                sentCount++;
                changed.push(msg.toPeerId);
            } else {
                msg.nextTryAt = Date.now() + RETRY_BACKOFF_MS;
                requeue.push(msg); // re-queue with backoff
                _persistQueueEntry(msg);  // update nextTryAt on disk
                reQueued++;
            }
        }
        // Keep oldest-first order: re-queued entries predate anything queued
        // while this flush was awaiting sends.
        messageQueue.unshift(...requeue);
        messageQueue.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
        console.log('[Queue] flush done — sent:', sentCount, 'droppedAged:', droppedAged,
                    'deferredBackoff:', deferredBackoff, 'reQueued:', reQueued,
                    'remaining:', messageQueue.length);
        if (changed.length) emitQueueChanged(changed);
        // Relay profile: retry the backed-off entries once the window ends
        // (previously they waited for the next reconnect event).
        if (requeue.length && relayPathsAllowed() && !flushScheduled) {
            flushScheduled = setTimeout(() => { flushScheduled = null; flushMessageQueue(); },
                                        RETRY_BACKOFF_MS + 500);
        }
    }).catch(() => {});
}

// ── Peer Discovery & Presence ──────────────────────────────
//
// Primary: presence push. After `registered` we send `watch` with our
// contacts' ids; the relay tells us when a contact who watches us back comes
// online or goes away, and webrtc.js connects with a deterministic
// initiator. Fallback: a 5-minute tick re-sends `watch` and, on a
// relay-profile server only, polls /bootstrap. A signaling-only server
// answers /bootstrap with [] and we never call it there.
let discoveryInterval = null;
let lastWatch = null;
let watchDebounce = null;

async function buildWatchList() {
    let contacts = [];
    try { contacts = await dbGetAll('contacts'); } catch (_) { return null; }
    const activity = new Map();
    try {
        for (const st of await dbGetAll('contact_state')) {
            if (st && st.peerId) activity.set(st.peerId, st.lastActivityAt || 0);
        }
    } catch (_) {}
    return selectWatchList(contacts.map(c => c && c.peerId), activity);
}

/// Send (or re-send) the presence watch list. `force` re-sends an unchanged
/// list (after a reconnect the server has forgotten it).
export async function sendPresenceWatch(force = false) {
    const ids = await buildWatchList();
    if (!ids) return;
    if (!force && sameWatchSet(ids, lastWatch)) return;
    if (connMgr.sendWatch(ids)) lastWatch = ids;
}

/// Contacts were added or removed: re-send the watch list (debounced; the
/// contacts store is also rewritten on every incoming message).
export function scheduleWatchRefresh() {
    if (watchDebounce) clearTimeout(watchDebounce);
    watchDebounce = setTimeout(() => {
        watchDebounce = null;
        sendPresenceWatch(false).catch(() => {});
    }, 1000);
}

if (typeof window !== 'undefined' && window.addEventListener && !window._parolnetWatchWired) {
    window._parolnetWatchWired = true;
    window.addEventListener('parolnet:contacts-changed', scheduleWatchRefresh);
}

/// Called on every `registered` reply (first connect and each reconnect).
export function onRelayRegistered() {
    lastWatch = null;
    sendPresenceWatch(true).catch(() => {});
    if (relayPathsAllowed()) discoverPeers();
    startDiscoveryInterval();
}

export async function discoverPeers() {
    if (!relayPathsAllowed()) return;
    try {
        const exclude = window._peerId || '';
        const resp = await fetch('/bootstrap?exclude=' + encodeURIComponent(exclude));
        if (!resp.ok) return;
        const peerIds = await resp.json();
        if (!Array.isArray(peerIds)) return;
        console.log('[Discovery]', peerIds.length, 'peers online');
        window._knownPeers = peerIds;

        // Attempt WebRTC to contacts who are online
        if (typeof RTCPeerConnection === 'undefined') return;
        let contacts;
        try { contacts = await dbGetAll('contacts'); } catch(e) { return; }
        const contactIds = new Set(contacts.map(c => c.peerId));

        for (const pid of peerIds) {
            if (contactIds.has(pid) && !hasDirectConnection(pid)) {
                connectToPeer(pid, { reason: 'discovery' });
            }
        }
    } catch(e) {
        console.warn('[Discovery] Failed:', e.message);
    }
}

function discoveryTick() {
    if (!connMgr.isRelayConnected()) return;
    sendPresenceWatch(true).catch(() => {});
    if (relayPathsAllowed()) {
        discoverPeers();
        return;
    }
    // Signaling-only fallback for queued messages to peers presence cannot
    // report (a contact that does not watch us back yet, e.g. a QR pairing
    // the other side has not completed): one offer per such peer per tick,
    // at most 5 peers. The server answers peer_offline if they are away.
    const pending = [];
    for (const e of messageQueue) {
        if (!pending.includes(e.toPeerId) && !hasDirectConnection(e.toPeerId)) pending.push(e.toPeerId);
        if (pending.length >= 5) break;
    }
    for (const pid of pending) connectToPeer(pid, { reason: 'retry', force: true });
}

export function startDiscoveryInterval() {
    if (!discoveryInterval) discoveryInterval = setInterval(discoveryTick, 300000);
}

/// A queued message for a contact we believe is reachable: try to open the
/// data channel (connectToPeer is a no-op while one is open / connecting).
export function requestDirectPath(peerId) {
    if (!peerId || hasDirectConnection(peerId) || isPeerKnownOffline(peerId)) return;
    connectToPeer(peerId, { reason: 'send' });
}
