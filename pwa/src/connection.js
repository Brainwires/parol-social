// ParolNet PWA — Connection Manager, Message Queue, Peer Discovery
//
// state.js is imported lazily to keep this module loadable from
// node --test (state.js transitively imports the DOM-dependent
// crypto-store.js). Under the browser the dynamic import resolves
// synchronously against the registry.
import { dbGet, dbGetAll, dbPut, dbDelete } from './db.js';
import { hasDirectConnection, sendViaWebRTC, initWebRTC } from './webrtc.js';
import { showErrorToast } from './utils.js';
import { t } from './i18n.js';

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

        entry = { ws: null, authState: 'pending', lastActivityMs: Date.now(), openWaiters: [] };
        this.outbound.set(relayUrl, entry);

        const wsUrl = _toWsUrl(relayUrl);
        try {
            entry.ws = new WebSocket(wsUrl);
        } catch (_) {
            entry.authState = 'failed';
            this._notifyWaiters(entry, false);
            return false;
        }

        const settle = (ok) => this._notifyWaiters(entry, ok);

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
const MAX_QUEUE_SIZE = 200;
const MAX_QUEUE_AGE_MS = 3600000; // 1 hour
const RETRY_BACKOFF_MS = 5000;    // per-message head-of-line skip window

// Fire-and-forget IDB write. Attaches the autoIncrement id back onto the
// in-memory entry so later flush attempts can target the exact row for
// deletion. Errors are logged but never thrown — the in-memory queue stays
// functional even if persistence fails (e.g., quota exhausted).
function _persistQueueEntry(entry) {
    const { toPeerId, payload, timestamp, nextTryAt, id } = entry;
    const row = { toPeerId, payload, timestamp, nextTryAt };
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

export function queueMessage(toPeerId, payload) {
    if (messageQueue.length >= MAX_QUEUE_SIZE) {
        const dropped = messageQueue.shift();
        if (dropped) _deletePersisted(dropped);
    }
    const entry = { toPeerId, payload, timestamp: Date.now(), nextTryAt: 0 };
    messageQueue.push(entry);
    _persistQueueEntry(entry);
    console.log('[Queue] Message queued for', toPeerId.slice(0, 8), '- queue size:', messageQueue.length);
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
        });
        loaded++;
    }
    if (loaded > 0) console.log('[Queue] Hydrated', loaded, 'pending sends from IDB');
    return loaded;
}

export function flushMessageQueue() {
    if (messageQueue.length === 0) return;
    // Late-bound import to avoid a circular dependency: messaging.js →
    // token-pool.js → connection.js. The flush path only runs on
    // reconnect so the lazy lookup cost is negligible.
    import('./token-pool.js').then(({ spendOneToken }) => {
        const now = Date.now();
        console.log('[Queue] Flushing', messageQueue.length, 'queued messages');
        const toFlush = messageQueue.splice(0, messageQueue.length);
        for (const msg of toFlush) {
            if (now - msg.timestamp > MAX_QUEUE_AGE_MS) {
                // Aged-out: drop from storage too.
                _deletePersisted(msg);
                continue;
            }
            if (msg.nextTryAt && msg.nextTryAt > now) {
                messageQueue.push(msg); // not yet time to retry
                continue;
            }
            let sent = false;
            if (hasDirectConnection(msg.toPeerId)) {
                sent = sendViaWebRTC(msg.toPeerId, msg.payload);
            }
            if (!sent) {
                let token;
                try { token = spendOneToken(connMgr.relayUrl); } catch { token = null; }
                if (token) sent = sendToRelay(msg.toPeerId, msg.payload, token);
            }
            if (sent) {
                _deletePersisted(msg);
            } else {
                msg.nextTryAt = now + RETRY_BACKOFF_MS;
                messageQueue.push(msg); // re-queue with backoff
                _persistQueueEntry(msg);  // update nextTryAt on disk
            }
        }
        if (messageQueue.length > 0) {
            console.log('[Queue]', messageQueue.length, 'messages still queued');
        }
    }).catch(() => {});
}

// ── Peer Discovery ─────────────────────────────────────────
let discoveryInterval = null;

export async function discoverPeers() {
    try {
        const exclude = window._peerId || '';
        const resp = await fetch('/bootstrap?exclude=' + encodeURIComponent(exclude));
        if (!resp.ok) return;
        const peerIds = await resp.json();
        console.log('[Discovery]', peerIds.length, 'peers online');
        window._knownPeers = peerIds;

        // Attempt WebRTC to contacts who are online
        if (typeof RTCPeerConnection === 'undefined') return;
        let contacts;
        try { contacts = await dbGetAll('contacts'); } catch(e) { return; }
        const contactIds = new Set(contacts.map(c => c.peerId));

        for (const pid of peerIds) {
            if (contactIds.has(pid) && !hasDirectConnection(pid)) {
                initWebRTC(pid, true).catch(() => {});
            }
        }
    } catch(e) {
        console.warn('[Discovery] Failed:', e.message);
    }
}

export function startDiscoveryInterval() {
    if (!discoveryInterval) discoveryInterval = setInterval(discoverPeers, 300000);
}
