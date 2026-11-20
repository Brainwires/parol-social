// Desktop <-> PWA chat interop test: NOT IMPLEMENTED YET (stub, M1 first slice).
//
//   node apps/desktop/interop/pwa-chat.mjs
//
// Exits 2 until the TODOs below are done. The plan, so the next slice can fill it in:
//
// Peers
//   - "desktop": the headless `parolnet-app` bot (`cargo run -p parolnet-app --example bot`),
//     the same core the GPUI app runs, speaking JSON lines on stdout / commands on stdin.
//   - "pwa": the real PWA in headless Chromium (puppeteer, as spike/send.mjs), launched with
//     --allow-loopback-in-peer-connection and --disable-features=WebRtcHideLocalIpsWithMdns
//     so its host candidates are plain 127.0.0.1 (the engine does not resolve mDNS `.local`
//     candidates yet).
//   - one local relay: target/debug/parolnet-relay in its default signaling-only profile
//     (RELAY_PORT, RELAY_KEY_FILE, RELAY_AUTHORITY_KEY_FILE, generous RELAY_* per-IP limits,
//     as crates/parolnet-app/tests/two_peers.rs starts it).
//
// Serving the PWA
//   The PWA connects to `location.host + '/ws'` unless the `custom_relay_url` setting is set
//   (pwa/src/connection.js). Serve pwa/ from a small node http server that also proxies
//   `/ws` (WebSocket upgrade) and `/turn-credentials` to the relay, so the PWA needs no
//   settings. Needs `npm run build:wasm` (wasm-pack, not installed on the dev Mac today) and
//   `npm run build` first.
//
// Cases (each with a fresh browser profile and bot data dir)
//   1. PWA presents, desktop scans: read the PWA's share code (`#qr-share-code`, produced by
//      wasm.generate_qr_payload), give it to the bot (`pair <code>`), wait for the bot's
//      `path ... Direct` and the PWA's "secure contact" toast, then message both ways
//      (bot `send`, PWA composer) and assert the texts on the other side.
//   2. Desktop presents, PWA scans: bot `code`, feed it to the PWA's scan path. TODO: the
//      PWA's "Paste Code" tab (connectViaPassphrase) only extracts a peer id and does not
//      establish a session; drive handleScannedQR (camera path) instead, e.g. through a
//      test hook, or fix the paste tab to accept the full QR payload.
//   3. Sender queue: close the PWA tab, bot sends (queued), reopen, assert delivery after the
//      presence push.
//
// TODO(m1): implement the server/proxy, the PWA driving and the three cases; run it on the
// linux pool with the desktop-spike workflow's Chrome.

console.error("pwa-chat interop test: not implemented yet (see the plan in this file)");
process.exit(2);
