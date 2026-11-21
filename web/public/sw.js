// ParolNet service worker: offline shell and assets for the static export.
//
// `scripts/postexport.ts` replaces the PRECACHE literal below with the real list of exported
// files: { version, files: [{ url, revision, immutable }] }. `url` is relative to the worker's
// scope, `immutable` marks a file whose name carries a content hash or a version.
//
//   install   every listed file is fetched into the cache named after this version, all or
//             nothing, so a cache is always one consistent build.
//   fetch     immutable files: cache first. The shell (navigations) and the other unhashed
//             files: network first, the cached copy when the network fails.
//   update    a new worker waits until the page says "SKIP_WAITING" (the "A new version is
//             ready" notice), so a tab never mixes two builds.
//   takeover  the previous PWA registered /pwa/sw.js too, with caches named "parolnet-v<n>".
//             When one of those exists this worker activates at once, deletes them and
//             reloads the open windows into this app. Nobody has to do anything.
//
// No relay sockets, no push, no background sync here: the worker only serves files.

const PRECACHE = /*__PRECACHE__*/ { version: "dev", files: [] } /*__END_PRECACHE__*/;

const CACHE_PREFIX = "parolnet-web-";
const CACHE_NAME = CACHE_PREFIX + PRECACHE.version;
const LEGACY_CACHE = /^parolnet-v\d+$/;
const SHELL = "index.html";
const NETWORK_TIMEOUT_MS = 4000;

const scope = self.registration.scope;
const byUrl = new Map(PRECACHE.files.map((f) => [new URL(f.url, scope).href, f]));
const shellUrl = new URL(SHELL, scope).href;

async function legacyCaches() {
  return (await caches.keys()).filter((name) => LEGACY_CACHE.test(name));
}

self.addEventListener("install", (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    await Promise.all(PRECACHE.files.map(async (file) => {
      const url = new URL(file.url, scope).href;
      // "no-cache" revalidates with the server, so an intermediate HTTP cache cannot hand
      // this build a stale file under an unhashed name.
      const response = await fetch(url, { cache: "no-cache", credentials: "same-origin" });
      if (!response.ok) throw new Error(`precache ${file.url}: HTTP ${response.status}`);
      await cache.put(url, response);
    }));
    // Replacing the previous PWA: do not wait behind its worker.
    if ((await legacyCaches()).length > 0) await self.skipWaiting();
  })());
});

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    const names = await caches.keys();
    const legacy = names.filter((name) => LEGACY_CACHE.test(name));
    const stale = names.filter((name) => name.startsWith(CACHE_PREFIX) && name !== CACHE_NAME);
    await Promise.all([...legacy, ...stale].map((name) => caches.delete(name)));
    await self.clients.claim();
    if (legacy.length > 0) {
      // Windows still showing the previous PWA: load this app in them. Not awaited: the
      // navigation is served by this worker, which only answers once activation is over.
      const windows = await self.clients.matchAll({ type: "window" });
      for (const client of windows) client.navigate(client.url).catch(() => null);
    }
  })());
});

self.addEventListener("message", (event) => {
  const data = event.data;
  // The previous PWA's page posts the bare string; this app posts the object.
  if (data === "skipWaiting" || (data && data.type === "SKIP_WAITING")) {
    self.skipWaiting();
  } else if (data && data.type === "GET_VERSION" && event.ports[0]) {
    event.ports[0].postMessage({ version: PRECACHE.version });
  }
});

async function fromCache(url) {
  const cache = await caches.open(CACHE_NAME);
  return await cache.match(url, { ignoreSearch: true });
}

async function networkFirst(request, cacheUrl) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), NETWORK_TIMEOUT_MS);
  try {
    const response = await fetch(request, { signal: controller.signal });
    // A 5xx or a captive portal's error page is not the app: prefer the cached copy.
    if (response.ok) return response;
    return (await fromCache(cacheUrl)) ?? response;
  } catch (error) {
    const cached = await fromCache(cacheUrl);
    if (cached) return cached;
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function cacheFirst(request, cacheUrl) {
  return (await fromCache(cacheUrl)) ?? await fetch(request);
}

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET" || PRECACHE.files.length === 0) return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin || !url.href.startsWith(scope)) return;
  url.hash = "";
  url.search = "";

  if (request.mode === "navigate") {
    event.respondWith(networkFirst(request, shellUrl));
    return;
  }
  const file = byUrl.get(url.href);
  if (!file) return; // Not part of this build: the browser handles it.
  event.respondWith(
    file.immutable ? cacheFirst(request, url.href) : networkFirst(request, url.href),
  );
});
