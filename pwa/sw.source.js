// ParolNet Service Worker
// Cache-first strategy: the app works entirely offline after first load.
// If the source site goes down, the app continues to function from cache.

const CACHE_NAME = 'parolnet-v9';

// ── SRI hashes for critical resources ─────────────────────────
// SHA-256 hashes of critical cached resources. On cache hit for these files,
// the service worker verifies the cached content hasn't been tampered with.
// If the hash doesn't match, the resource is re-fetched from the network.
//
// The __RESOURCE_HASHES__ token below is substituted by pwa/build.mjs at
// build time — this file (sw.source.js) is tracked in git; the generated
// sw.js is gitignored. Keeping the hashes out of the source prevents every
// build from dirtying a tracked file.
const RESOURCE_HASHES = __RESOURCE_HASHES__;

// Compute SHA-256 hex digest of an ArrayBuffer.
async function sha256Hex(buffer) {
    const hashBuf = await crypto.subtle.digest('SHA-256', buffer);
    const bytes = new Uint8Array(hashBuf);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
}

// Produce the RESOURCE_HASHES lookup key from a request URL. The keys match
// ASSETS_TO_CACHE entries with the leading "./" stripped, so nested paths
// like "pkg/parolnet_wasm_bg.wasm" resolve correctly (basename alone would
// collide across directories).
function getResourceName(url) {
    const path = new URL(url).pathname;
    return path.replace(/^\/+/, '');
}

// All assets that must be cached for offline operation.
// The app is fully self-contained — zero external dependencies.
const ASSETS_TO_CACHE = [
    './',
    './index.html',
    './styles.css',
    './calculator.css',
    './app.js',
    './crypto-store.js',
    './data-export.js',
    './qrcode.js',
    './qrdecoder.js',
    './manifest.json',
    './manifest-calculator.json',
    './icons/icon.svg',
    './icons/icon-192.png',
    './icons/icon-512.png',
    './icons/calc-ios.svg',
    './icons/calc-android.svg',
    './icons/calc-windows.svg',
    './icons/calc-192.png',
    './icons/calc-512.png',
    './pkg/parolnet_wasm.js',
    './pkg/parolnet_wasm_bg.wasm',
    './network-config.js',
    './relay-client.js',
    './lang/en.json',
    './lang/ru.json',
    './lang/fa.json',
    './lang/zh-CN.json',
    './lang/zh-TW.json',
    './lang/ko.json',
    './lang/ja.json',
    './lang/fr.json',
    './lang/de.json',
    './lang/it.json',
    './lang/pt.json',
    './lang/ar.json',
    './lang/es.json',
    './lang/tr.json',
    './lang/my.json',
    './lang/vi.json',
];

// ── Install: cache all assets ──────────────────────────────────
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => {
                console.log('[SW] Caching all assets');
                return cache.addAll(ASSETS_TO_CACHE).catch(err => {
                    // Don't fail install if some assets aren't available yet
                    // (e.g., WASM not built yet during development)
                    console.warn('[SW] Some assets not cached:', err.message);
                });
            })
            // NOTE: skipWaiting() intentionally removed from install handler.
            // A compromised SW update should NOT immediately take control.
            // Users get the new SW on next visit. Explicit skipWaiting is
            // still available via message handler for manual updates.
    );
});

// ── Activate: clean up old caches ──────────────────────────────
self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys()
            .then(keys => {
                return Promise.all(
                    keys
                        .filter(key => key !== CACHE_NAME)
                        .map(key => {
                            console.log('[SW] Removing old cache:', key);
                            return caches.delete(key);
                        })
                );
            })
            .then(() => self.clients.claim())
    );
});

// ── Fetch: cache-first, fall back to network ───────────────────
// This is the key to offline-first operation:
// 1. Try the cache first (instant, works offline)
// 2. If not cached, try the network
// 3. If network fails and not cached, show offline page
self.addEventListener('fetch', event => {
    // Only handle same-origin requests
    if (!event.request.url.startsWith(self.location.origin)) {
        return;
    }

    // Only cache GET requests — Cache API doesn't support POST
    if (event.request.method !== 'GET') {
        return;
    }

    event.respondWith(
        caches.match(event.request)
            .then(async cachedResponse => {
                if (cachedResponse) {
                    // Cache hit — verify integrity for critical resources
                    const resourceName = getResourceName(event.request.url);
                    const expectedHash = RESOURCE_HASHES[resourceName];

                    if (expectedHash) {
                        // Clone before reading body (body can only be consumed once)
                        const clone = cachedResponse.clone();
                        try {
                            const buf = await clone.arrayBuffer();
                            const actualHash = await sha256Hex(buf);
                            if (actualHash !== expectedHash) {
                                console.warn('[SW] Integrity mismatch for', resourceName, '— refetching from network');
                                // Hash mismatch: cached resource may be tampered with.
                                // Attempt to fetch a fresh copy from network.
                                try {
                                    const freshResponse = await fetch(event.request);
                                    if (freshResponse && freshResponse.ok) {
                                        const freshClone = freshResponse.clone();
                                        const cache = await caches.open(CACHE_NAME);
                                        await cache.put(event.request, freshClone);
                                        return freshResponse;
                                    }
                                } catch {
                                    // Network unavailable — return cached even if tampered,
                                    // better than nothing for offline use
                                }
                            }
                        } catch {
                            // If integrity check itself fails, fall through to cached
                        }
                    }

                    // Also update cache in background (stale-while-revalidate)
                    fetch(event.request)
                        .then(networkResponse => {
                            if (networkResponse && networkResponse.ok) {
                                const netClone = networkResponse.clone();
                                caches.open(CACHE_NAME).then(cache => {
                                    cache.put(event.request, netClone);
                                });
                            }
                        })
                        .catch(() => {
                            // Network failed, but we have cache — that's fine
                        });

                    return cachedResponse;
                }

                // Not in cache — try network
                return fetch(event.request)
                    .then(networkResponse => {
                        if (networkResponse && networkResponse.ok) {
                            // Cache the new response
                            const clone = networkResponse.clone();
                            caches.open(CACHE_NAME).then(cache => {
                                cache.put(event.request, clone);
                            });
                        }
                        return networkResponse;
                    })
                    .catch(() => {
                        // Network failed and we have nothing cached.
                        //
                        // For document/navigation requests we own the whole
                        // viewport, so we render a self-healing offline
                        // screen with Retry + Reset buttons. For subresource
                        // requests (css/js/images) we let the browser's
                        // native network-error path run — forwarding a
                        // fabricated 503 HTML body as a stylesheet produces
                        // a misleading "server down" error in the console,
                        // which is what the offline-page misattribution bug
                        // looked like. A synthetic TypeError from a rejected
                        // promise is the correct shape for those.
                        const isNav =
                            event.request.mode === 'navigate' ||
                            (event.request.destination === '' &&
                             (event.request.headers.get('accept') || '').includes('text/html'));
                        if (!isNav) {
                            return Response.error();
                        }
                        return new Response(offlinePageHtml(), {
                            headers: { 'Content-Type': 'text/html; charset=utf-8' },
                            status: 200,
                        });
                    });
            })
    );
});

// Self-healing offline page. Inline HTML so it ships inside sw.js and needs
// no extra cached asset to render. Offers two escape hatches: (1) Retry,
// which is a plain reload — picks up service as soon as network is back;
// (2) Reset App, which unregisters every service worker, clears all caches,
// and reloads. Designed for the case where a stale SW or a misfired cache
// miss leaves the user stranded on a fake "server down" screen.
function offlinePageHtml() {
    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ParolNet — offline</title>
  <style>
    html, body { margin: 0; padding: 0; background: #0e1116; color: #e6edf3;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
      -webkit-font-smoothing: antialiased; height: 100%; }
    body { display: flex; align-items: center; justify-content: center; padding: 24px; }
    .card { max-width: 420px; width: 100%; text-align: center; }
    h1 { font-size: 24px; margin: 0 0 8px; }
    p  { color: #9aa4b2; font-size: 15px; line-height: 1.5; margin: 0 0 18px; }
    .row { display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; }
    button { font: inherit; cursor: pointer; padding: 12px 18px;
      border-radius: 10px; border: 1px solid #2d333b; background: #1f242c;
      color: #e6edf3; min-width: 140px; transition: background .15s; }
    button:hover { background: #2a3039; }
    button.primary { background: #2f81f7; border-color: #2f81f7; color: white; }
    button.primary:hover { background: #1f6feb; }
    .status { margin-top: 16px; font-size: 13px; color: #7d8590; min-height: 18px; }
    .footnote { margin-top: 28px; font-size: 12px; color: #636c77; }
  </style>
</head>
<body>
  <div class="card">
    <h1>You're offline</h1>
    <p>This page isn't in your offline cache and your device can't reach the server right now.
       The ParolNet server may still be healthy — this is your browser's service worker reporting that
       <em>this request</em> couldn't be completed.</p>
    <div class="row">
      <button id="retry" class="primary">Retry</button>
      <button id="reset">Reset app</button>
    </div>
    <div class="status" id="status"></div>
    <div class="footnote">Auto-retries when network comes back.</div>
  </div>
<script>
(function(){
  const status = document.getElementById('status');
  function setStatus(msg){ status.textContent = msg || ''; }

  document.getElementById('retry').addEventListener('click', () => {
    setStatus('Reloading…');
    location.reload();
  });

  document.getElementById('reset').addEventListener('click', async () => {
    setStatus('Clearing service worker + caches…');
    try {
      if (navigator.serviceWorker) {
        const regs = await navigator.serviceWorker.getRegistrations();
        await Promise.all(regs.map(r => r.unregister()));
      }
      if (window.caches && caches.keys) {
        const keys = await caches.keys();
        await Promise.all(keys.map(k => caches.delete(k)));
      }
    } catch (e) {
      setStatus('Reset partially failed: ' + (e && e.message ? e.message : e));
    }
    setStatus('Done. Reloading…');
    // Bypass any remaining SW control by forcing a hard navigation.
    location.href = location.pathname + '?sw-reset=' + Date.now();
  });

  // Auto-retry the moment the browser reports network is back, so users
  // who walked into a subway tunnel don't have to tap anything when they
  // come out.
  window.addEventListener('online', () => {
    setStatus('Network detected — reloading…');
    setTimeout(() => location.reload(), 200);
  });

  // Poll every 8s to see if the origin is reachable; reload when it is.
  async function probe() {
    try {
      const r = await fetch(location.origin + '/pwa/manifest.json', { cache: 'no-store' });
      if (r && r.ok) { setStatus('Server reachable — reloading…'); location.reload(); return; }
    } catch {}
    setTimeout(probe, 8000);
  }
  setTimeout(probe, 8000);
})();
</script>
</body>
</html>`;
}

// ── Push Notifications ─────────────────────────────────────────
// Handle incoming push messages from the network.
// The payload is expected to be JSON: { title, body, peerId }
self.addEventListener('push', event => {
    let data = { title: 'New Message', body: 'You have a new message.', peerId: '' };

    if (event.data) {
        try {
            data = Object.assign(data, event.data.json());
        } catch {
            data.body = event.data.text();
        }
    }

    const options = {
        body: data.body,
        icon: './icons/icon-192.png',
        badge: './icons/icon-192.png',
        tag: 'parolnet-' + (data.peerId || 'msg'),
        data: { peerId: data.peerId || '' },
        vibrate: [200, 100, 200],
        requireInteraction: false,
    };

    event.waitUntil(
        self.registration.showNotification(data.title, options)
    );
});

// ── Notification Click ─────────────────────────────────────────
// Open the app and navigate to the relevant chat when a notification is tapped.
self.addEventListener('notificationclick', event => {
    event.notification.close();

    const peerId = event.notification.data?.peerId || '';

    event.waitUntil(
        self.clients.matchAll({ type: 'window', includeUncontrolled: true })
            .then(clients => {
                // If an app window is already open, focus it
                for (const client of clients) {
                    if (client.url.includes('index.html') || client.url.endsWith('/')) {
                        client.postMessage({ type: 'openChat', peerId });
                        return client.focus();
                    }
                }
                // Otherwise open a new window
                const url = peerId
                    ? `./index.html?chat=${encodeURIComponent(peerId)}`
                    : './index.html';
                return self.clients.openWindow(url);
            })
    );
});

// ── Relay WebSocket (background communications) ────────────
// Owning the WebSocket here keeps it alive when the page is
// backgrounded (Android/Chrome/desktop). Page JS suspends;
// SW does not — messages still arrive.

let relayWs = null;
let relayUrl = null;
let relayPeerId = null;
let relayReconnectTimer = null;
let relayReconnectDelay = 1000;
// Has the relay confirmed our `register` with a `registered` response?
// This is a *precondition* for being live, not a proof of liveness — the
// authoritative answer is `relayIsLive()` below.
let relayRegistered = false;
// Last Date.now() at which ANY inbound frame arrived (pong, message, ...).
// PNP-001 §10.3 MUST-066: if now - lastInboundAt > 40s, the socket MUST
// be torn down. Initialized to 0 so an un-opened socket is correctly
// reported dead.
let lastInboundAt = 0;
// Heartbeat timers — created when the socket opens, cleared on close.
let pingIntervalTimer = null;
let livenessCheckTimer = null;

const PING_INTERVAL_MS = 20_000;      // PNP-001-MUST-065
const DEAD_THRESHOLD_MS = 40_000;     // PNP-001-MUST-066
const LIVENESS_CHECK_INTERVAL_MS = 5_000;

// When true, the page has explicitly asked the SW to stand down its
// relay socket (H3 onion mode uses a main-thread WebSocket instead).
// This suppresses the normal auto-reconnect loop until the page asks us
// to resume.
let relaySuspended = false;

// Authoritative "socket is usable right now" predicate. Any subsystem
// that wants to answer "is the relay up?" MUST read this, not the
// pre-v0.10 `relayConnected` bool which lied about dead sockets.
function relayIsLive() {
    if (!relayWs) return false;
    if (relayWs.readyState !== 1) return false; // 1 = OPEN
    if (!relayRegistered) return false;
    if (lastInboundAt === 0) return false;
    return (Date.now() - lastInboundAt) < DEAD_THRESHOLD_MS;
}

function swClearHeartbeatTimers() {
    if (pingIntervalTimer !== null) {
        clearInterval(pingIntervalTimer);
        pingIntervalTimer = null;
    }
    if (livenessCheckTimer !== null) {
        clearInterval(livenessCheckTimer);
        livenessCheckTimer = null;
    }
}

function swStartHeartbeat() {
    swClearHeartbeatTimers();
    // Outbound ping every 20s (PNP-001-MUST-065).
    pingIntervalTimer = setInterval(() => {
        if (!relayWs || relayWs.readyState !== 1) return;
        try {
            relayWs.send(JSON.stringify({ type: 'ping', ts: Date.now() }));
        } catch {}
    }, PING_INTERVAL_MS);
    // Dead-threshold watchdog (PNP-001-MUST-066). Check every 5s whether
    // the >40s silence rule has tripped. On trip: tear down, schedule
    // reconnect. No grace period — the spec is explicit.
    livenessCheckTimer = setInterval(() => {
        if (!relayWs) return;
        if (relayWs.readyState !== 1) return;
        const silentMs = Date.now() - lastInboundAt;
        if (lastInboundAt !== 0 && silentMs > DEAD_THRESHOLD_MS) {
            console.warn('[SW-Relay] dead socket — ' + silentMs + 'ms silence, tearing down');
            try { relayWs.close(4000, 'idle-timeout'); } catch {}
            // onclose handler fires and schedules reconnect.
        }
    }, LIVENESS_CHECK_INTERVAL_MS);
}

function swConnectRelay() {
    if (relaySuspended) return;
    // Only skip if we already have a live connection — readyState 0 means
    // "connecting but stuck", which in pre-v0.10 builds would block the
    // reconnect forever. If the socket's in CONNECTING (0), we let the
    // liveness watchdog decide; if it's past its deadline we close+reopen.
    if (relayWs && relayWs.readyState === 1 && relayRegistered) return;
    if (!relayUrl) return;
    try {
        relayWs = new WebSocket(relayUrl);
    } catch(e) {
        swScheduleReconnect();
        return;
    }

    relayRegistered = false;
    lastInboundAt = 0;

    relayWs.onopen = () => {
        console.log('[SW-Relay] WebSocket open, awaiting registration...');
        relayReconnectDelay = 1000;
        // The onopen itself counts as an inbound event for liveness
        // purposes — the socket demonstrably handshook.
        lastInboundAt = Date.now();
        if (relayPeerId) {
            relayWs.send(JSON.stringify({ type: 'register', peer_id: relayPeerId }));
        }
        swStartHeartbeat();
    };

    relayWs.onmessage = (event) => {
        // PNP-001-MUST-066: any inbound frame (not just pong) resets the
        // liveness timer. The relay's response to other traffic is equally
        // strong evidence the socket is alive.
        lastInboundAt = Date.now();
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'registered' && !relayRegistered) {
                console.log('[SW-Relay] registered with relay');
                relayRegistered = true;
                swBroadcastStatus(true);
            }
            // Pongs are purely for liveness; no app handling needed.
            if (msg.type === 'pong') return;
            swBroadcastOrBuffer(msg);
        } catch(e) {}
    };

    relayWs.onclose = () => {
        console.log('[SW-Relay] disconnected');
        swClearHeartbeatTimers();
        relayRegistered = false;
        lastInboundAt = 0;
        swBroadcastStatus(false);
        swScheduleReconnect();
    };

    relayWs.onerror = () => {};
}

function swScheduleReconnect() {
    if (relaySuspended) return;
    if (relayReconnectTimer) return;
    relayReconnectTimer = setTimeout(() => {
        relayReconnectTimer = null;
        relayReconnectDelay = Math.min(relayReconnectDelay * 2, 30000);
        swConnectRelay();
    }, relayReconnectDelay);
}

// Close the relay socket and suspend auto-reconnect. Called when the
// page enters high-anonymity mode and wants to own the relay connection
// itself (main-thread WebSocket + onion circuit).
function swSuspendRelay() {
    relaySuspended = true;
    if (relayReconnectTimer) {
        clearTimeout(relayReconnectTimer);
        relayReconnectTimer = null;
    }
    swClearHeartbeatTimers();
    if (relayWs) {
        try { relayWs.close(); } catch {}
    }
    relayWs = null;
    if (relayRegistered) {
        relayRegistered = false;
        swBroadcastStatus(false);
    }
    lastInboundAt = 0;
}

function swBroadcastStatus(connected) {
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
        for (const client of clients) {
            client.postMessage({ type: 'relay_status', connected });
        }
    });
}

async function swBroadcastOrBuffer(msg) {
    const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    if (clients.length > 0) {
        for (const client of clients) {
            client.postMessage({ type: 'relay_msg', msg });
        }
    } else {
        await swInboxWrite(msg);
    }
}

async function swInboxWrite(msg) {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open('parolnet-sw', 1);
        req.onupgradeneeded = (e) => {
            e.target.result.createObjectStore('sw-inbox', { keyPath: 'id', autoIncrement: true });
        };
        req.onsuccess = (e) => {
            const db = e.target.result;
            const tx = db.transaction('sw-inbox', 'readwrite');
            const store = tx.objectStore('sw-inbox');
            store.count().onsuccess = (ce) => {
                if (ce.target.result >= 200) {
                    store.openCursor().onsuccess = (cur) => {
                        if (cur.target.result) cur.target.result.delete();
                    };
                }
                store.add({ msg, timestamp: Date.now() });
            };
            tx.oncomplete = () => { db.close(); resolve(); };
            tx.onerror = () => { db.close(); reject(); };
        };
        req.onerror = reject;
    });
}

// ── Message handling ───────────────────────────────────────────
self.addEventListener('message', event => {
    if (event.data === 'skipWaiting') {
        self.skipWaiting();
        return;
    }

    if (event.data === 'panicWipe') {
        caches.keys().then(keys => {
            keys.forEach(key => caches.delete(key));
        });
        self.registration.unregister();
        return;
    }

    const d = event.data;
    if (!d || typeof d !== 'object') return;

    switch (d.type) {
        case 'relay_connect':
            relayUrl = d.url || relayUrl;
            relayPeerId = d.peerId || relayPeerId;
            // Waking back up from a suspension (page left onion mode) —
            // reset the backoff and open a fresh socket.
            if (relaySuspended) {
                relaySuspended = false;
                relayReconnectDelay = 1000;
            }
            swConnectRelay();
            break;
        case 'relay_disconnect':
            swSuspendRelay();
            break;
        case 'relay_register':
            relayPeerId = d.peerId;
            if (relayWs && relayWs.readyState === 1) {
                relayWs.send(JSON.stringify({ type: 'register', peer_id: d.peerId }));
            }
            break;
        case 'relay_register_auth':
            if (relayWs && relayWs.readyState === 1) {
                relayWs.send(JSON.stringify({
                    type: 'register',
                    peer_id: d.peerId,
                    pubkey: d.pubkey,
                    signature: d.signature,
                    nonce: d.nonce
                }));
            }
            break;
        case 'relay_send':
            // PNP-001-MUST-048: outer frame carries `token`, never `from`.
            if (relayWs && relayWs.readyState === 1) {
                relayWs.send(JSON.stringify({
                    type: 'message',
                    to: d.to,
                    token: d.token,
                    payload: d.payload,
                }));
            }
            break;
        case 'relay_signaling':
            if (relayWs && relayWs.readyState === 1) {
                relayWs.send(JSON.stringify({ type: d.msgType, to: d.to, payload: d.payload }));
            }
            break;
        case 'relay_status_query':
            if (event.source) {
                event.source.postMessage({ type: 'relay_status', connected: relayIsLive() });
            }
            break;
    }
});
