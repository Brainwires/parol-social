// Desktop <-> PWA interop test: pairing, chat, the sender queue, the channel binding, calls.
//
//   node apps/desktop/interop/pwa-interop.mjs
//   INTEROP_BROWSER=firefox node apps/desktop/interop/pwa-interop.mjs
//   INTEROP_APP=web node apps/desktop/interop/pwa-interop.mjs
//
// The browser side (INTEROP_APP)
//   pwa  (default) the PWA in pwa/, as below.
//   web  the Denext web app in web/ that replaces it: its test build (web/out-test, from
//        `denext task build-wasm && denext task build:test` in web/), served under /pwa/ with
//        the production Content-Security-Policy by web/tests/e2e/static-server.mjs, the relay
//        behind it at the same origin. The cases and what they assert are the same; only how
//        the browser side is driven differs (see `class Web`): actions go through the
//        interface (first run, the add-a-contact screen, the composer, the call buttons), and
//        state is read from its `window.__parolnetTest` hooks, which
//        only the test build has. Where a case read old-PWA internals the web target has an
//        equivalent, listed at `class Web`. In this file "the PWA" means the browser side
//        under test, whichever it is.
//
// Peers
//   - "desktop": the headless `parolnet-app` bot (examples/bot.rs), the same core the GPUI app
//     runs, speaking JSON lines on stdout / commands on stdin.
//   - "pwa": the real PWA (pwa/, built with `npm run build:wasm && npm run build`) in a headless
//     browser through Playwright (`npx playwright install chromium firefox webkit`), a fresh
//     profile per case. INTEROP_BROWSER: chromium (default), firefox, webkit.
//   - one local relay: the `parolnet-relay` binary in its default signaling-only profile.
//
// A small HTTP server serves pwa/ and proxies the relay's endpoints (`/ws` upgrade included),
// so the PWA finds its relay at `location.host + '/ws'` with no settings.
//
// Browsers
//   chromium  The full browser in its headless mode (Playwright's `chromium` channel), with
//             Chromium's fake camera and microphone in the cases that need media.
//   firefox   Fake streams (`media.navigator.streams.fake`) and no permission prompt
//             (`media.navigator.permission.disabled`) in the cases that need media.
//   webkit    Playwright's WebKit build; meant for Linux (WPE with libwebrtc: mock capture
//             devices, VP8, Opus, data channels), which is what CI runs. Not run on macOS.
// No request leaves the machine: Chromium by a resolver rule, Firefox and WebKit by an HTTP
// proxy (for every host but 127.0.0.1) that refuses everything. The relay here announces no
// STUN server and the PWA's fallback (parol.social) is unreachable, so ICE uses host candidates
// only; the run fails if a page reports ICE servers.
//
// ICE (INTEROP_ICE)
//   mdns     (Chromium and Firefox; default on Linux) the browser as shipped: its host
//            candidates are mDNS `<uuid>.local` names (while the page holds no media
//            permission); the bot binds the default-route interface and resolves them with an
//            mDNS query (parolnet-rtc). The test fails unless the bot saw mDNS answers.
//   loopback (Chromium and Firefox; default elsewhere) the bot on 127.0.0.1, no multicast and
//            no LAN address (no macOS Local Network prompt on a developer's machine). Chromium:
//            --allow-loopback-in-peer-connection and
//            --disable-features=WebRtcHideLocalIpsWithMdns. Firefox:
//            media.peerconnection.ice.loopback, and
//            media.peerconnection.ice.obfuscate_host_addresses off.
//   host     (WebKit, its only mode) Playwright's Linux WebKit gathers the default-route address
//            as a plain host candidate: no mDNS name (so the mDNS path is not exercised in
//            WebKit) and no loopback candidate. The bot binds the default-route interface.
//
// Cases (the same in every browser; none is skipped anywhere)
//   1. PWA presents its code, the desktop enters it (bot `pair`): bootstrap over the data
//      channel, messages both ways. Then the desktop is told its network changed (bot
//      `network-changed`): the browser side does not take ICE restarts (PNP-011 section 8.2:
//      it lists no `ice-restart`), so the desktop must send none and leave the connection
//      alone; messages both ways again.
//   2. The desktop presents its code, the PWA pastes it ("Paste Code" tab): the paste path
//      pairs like a camera scan, messages both ways.
//   3. Sender queue: with case 2's pair, the PWA's browser closes; the bot's message waits in
//      its queue and is delivered when the PWA comes back (same browser profile).
//   4. Channel binding (PNP-001 §10.5.1): every case above requires both sides to verify the
//      other's binding before the path is direct; here the PWA binds a fingerprint it did not
//      see (as if a relay had swapped the desktop's), and the desktop must refuse the channel.
//   5. The desktop video-calls the PWA (the browser's fake camera and microphone); the PWA
//      accepts; the desktop sends its test pattern (VP8) and a tone (Opus): RTP flows both
//      ways and the browser decodes the desktop's video and audio. The browser side does not
//      renegotiate (it lists no `renegotiate`, PNP-011 section 7.5): the desktop's "camera
//      off" must leave the call as it was set up, and a network change must send no
//      `reoffer`; media goes on both ways. The desktop hangs up.
//   6. The PWA video-calls the desktop; the same checks; the PWA hangs up. The browser is then
//      the ICE controlling side (it offers). Chromium, holding media permission, gathers on
//      every interface and may move its nomination to another pair a moment after connecting;
//      the desktop (controlled) must follow the later nomination (webrtc-rs-rtc
//      v0.22.0+brainwires.5). INTEROP_PWA_CALLS=0 skips it.
//   7. A data channel the PWA offers while it holds camera and microphone permission (a live
//      getUserMedia stream): the same renomination as case 6 on a chat connection. The PWA
//      pastes the desktop's code and must be the offerer; bindings verified, messages both
//      ways, and again after the connection has settled.
//   8. (web app only) Files, PNP-010: the desktop offers a file, the web app accepts it in the
//      conversation and stores it; the web app then offers one (picked in the composer) and
//      the desktop accepts it. Each is INTEROP_FILE_MIB MiB (default 8; the M1 bar is 100) and
//      is compared by SHA-256 on the receiving side. The old PWA has no PNP-010: its target
//      skips the case. INTEROP_FILES=0 skips it; INTEROP_ONLY=files runs it alone.
//
// Every PWA connection records its selected ICE candidate pair changes (`window.__pcs[i]
// .__pairChanges`); a failure report prints them with the page console and the bot's stderr.
//
// Environment: PAROLNET_RELAY_BIN, PAROLNET_BOT_BIN (default: $CARGO_TARGET_DIR or target/,
// debug profile), INTEROP_BROWSER, INTEROP_ICE, CHROME_PATH / FIREFOX_PATH / WEBKIT_PATH (a
// browser binary instead of Playwright's), INTEROP_KEEP=1 (keep temp dirs), INTEROP_VERBOSE=1
// (page console and bot stderr on stdout).

import { chromium, firefox, webkit } from "playwright";
import { spawn } from "node:child_process";
import { createServer, request as httpRequest } from "node:http";
import { connect as netConnect, createServer as netCreateServer } from "node:net";
import { createHash, randomFillSync } from "node:crypto";
import { closeSync, createReadStream, existsSync, mkdtempSync, openSync, rmSync, statSync, writeSync } from "node:fs";
import { networkInterfaces, tmpdir } from "node:os";
import { dirname, extname, join, normalize, resolve, sep } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../../..");
const pwaDir = join(root, "pwa");
const webOutDir = join(root, "web", "out-test");
const target = process.env.INTEROP_APP || "pwa";
if (target !== "pwa" && target !== "web") {
  console.error(`INTEROP_APP must be pwa or web (got ${target})`);
  process.exit(2);
}
const exe = process.platform === "win32" ? ".exe" : "";
const targetDir = process.env.CARGO_TARGET_DIR || join(root, "target");
const relayBin = process.env.PAROLNET_RELAY_BIN || join(targetDir, "debug", `parolnet-relay${exe}`);
const botBin = process.env.PAROLNET_BOT_BIN || join(targetDir, "debug", "examples", `bot${exe}`);
const browserName = process.env.INTEROP_BROWSER || "chromium";
const engines = { chromium, firefox, webkit };
if (!engines[browserName]) {
  console.error(`INTEROP_BROWSER must be chromium, firefox or webkit (got ${browserName})`);
  process.exit(2);
}
// See "ICE" in the header.
const modes = browserName === "webkit" ? ["host"] : ["mdns", "loopback"];
const mode = process.env.INTEROP_ICE || (browserName === "webkit" ? "host" : process.platform === "linux" ? "mdns" : "loopback");
if (!modes.includes(mode)) {
  console.error(`INTEROP_ICE for ${browserName} must be ${modes.join(" or ")} (got ${mode})`);
  process.exit(2);
}
/// The browser's name in log lines.
const Browser = { chromium: "Chromium", firefox: "Firefox", webkit: "WebKit" }[browserName];
const verbose = process.env.INTEROP_VERBOSE === "1";
const keep = process.env.INTEROP_KEEP === "1";

const cleanups = [];
const openPwas = new Set();
const openBots = new Set();
const work = mkdtempSync(join(tmpdir(), "parolnet-interop-"));
cleanups.push(() => keep || rmSync(work, { recursive: true, force: true }));

function log(...args) {
  console.log(`[${new Date().toISOString().slice(11, 23)}]`, ...args);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function until(what, ms, fn, every = 200) {
  const deadline = Date.now() + ms;
  let last;
  while (Date.now() < deadline) {
    try {
      const v = await fn();
      if (v) return v;
    } catch (e) {
      last = e;
    }
    await sleep(every);
  }
  throw new Error(`timed out after ${ms} ms waiting for ${what}${last ? ` (${last.message})` : ""}`);
}

function freePort() {
  return new Promise((res, rej) => {
    const s = netCreateServer();
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => res(port));
    });
    s.on("error", rej);
  });
}

/// The address host candidates use in mdns and host mode: the default-route IPv4 interface.
function lanIPv4() {
  for (const list of Object.values(networkInterfaces())) {
    for (const a of list ?? []) {
      if (a.family === "IPv4" && !a.internal) return a.address;
    }
  }
  throw new Error(`no non-loopback IPv4 interface for ${mode} mode`);
}

// ── Relay ────────────────────────────────────────────────────

async function startRelay() {
  if (!existsSync(relayBin)) throw new Error(`relay binary not found: ${relayBin} (cargo build -p parolnet-relay-server)`);
  const port = await freePort();
  const dir = join(work, "relay");
  const child = spawn(relayBin, [], {
    env: {
      PATH: process.env.PATH,
      RELAY_PORT: String(port),
      RELAY_KEY_FILE: join(dir, "relay.key"),
      RELAY_AUTHORITY_KEY_FILE: join(dir, "relay-authority.cbor"),
      RUST_LOG: "warn",
      // Every client shares one address here.
      RELAY_CONN_PER_MINUTE: "1000",
      RELAY_MAX_PEERS_PER_IP: "16",
      RELAY_MAX_CONNS_PER_IP: "32",
    },
    stdio: ["ignore", "ignore", verbose ? "inherit" : "ignore"],
  });
  cleanups.push(() => child.kill());
  await until("the relay to listen", 20_000, () =>
    new Promise((res) => {
      const s = netConnect(port, "127.0.0.1", () => {
        s.end();
        res(true);
      });
      s.on("error", () => res(false));
    }),
  );
  log(`relay on 127.0.0.1:${port}`);
  return port;
}

// ── PWA server (static files + relay proxy) ──────────────────

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".wasm": "application/wasm",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".webmanifest": "application/manifest+json",
};

/// The web app's test build, hosted the way production hosts it: under /pwa/, behind the CSP
/// header, with the relay at the same origin (web/tests/e2e/static-server.mjs).
async function startWebServer(relayPort) {
  for (const f of ["index.html", "sw.js", "wasm/manifest.json"]) {
    if (!existsSync(join(webOutDir, f))) {
      throw new Error(`web/out-test/${f} is missing: in web/, run denext task build-wasm && denext task build:test first`);
    }
  }
  const { startServer } = await import("../../../web/tests/e2e/static-server.mjs");
  const server = await startServer({ root: webOutDir, relayPort });
  cleanups.push(() => server.close());
  log(`web app on ${server.url}`);
  return { port: Number(new URL(server.origin).port), path: "/pwa/" };
}

async function startPwaServer(relayPort) {
  for (const f of ["app.js", "sw.js", "pkg/parolnet_wasm_bg.wasm"]) {
    if (!existsSync(join(pwaDir, f))) {
      throw new Error(`pwa/${f} is missing: run npm run build:wasm && npm run build first`);
    }
  }
  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://x");
    let rel = decodeURIComponent(url.pathname);
    if (rel.endsWith("/")) rel += "index.html";
    const file = normalize(join(pwaDir, rel));
    if (file.startsWith(pwaDir + sep) && existsSync(file) && statSync(file).isFile()) {
      res.writeHead(200, {
        "content-type": MIME[extname(file)] ?? "application/octet-stream",
        "cache-control": "no-store",
      });
      createReadStream(file).pipe(res);
      return;
    }
    // Everything else is the relay's (/turn-credentials, /health, ...).
    const upstream = httpRequest(
      { host: "127.0.0.1", port: relayPort, method: req.method, path: req.url, headers: req.headers },
      (up) => {
        res.writeHead(up.statusCode ?? 502, up.headers);
        up.pipe(res);
      },
    );
    upstream.on("error", () => {
      res.writeHead(502);
      res.end();
    });
    req.pipe(upstream);
  });
  // WebSocket upgrades (/ws) go to the relay byte for byte.
  server.on("upgrade", (req, socket, head) => {
    const up = netConnect(relayPort, "127.0.0.1", () => {
      let raw = `${req.method} ${req.url} HTTP/1.1\r\n`;
      for (let i = 0; i < req.rawHeaders.length; i += 2) raw += `${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}\r\n`;
      up.write(raw + "\r\n");
      if (head?.length) up.write(head);
      up.pipe(socket);
      socket.pipe(up);
    });
    up.on("error", () => socket.destroy());
    socket.on("error", () => up.destroy());
  });
  const port = await freePort();
  await new Promise((r) => server.listen(port, "127.0.0.1", r));
  cleanups.push(() => server.close());
  log(`PWA on http://127.0.0.1:${port}/`);
  return { port, path: "/index.html" };
}

// ── Desktop bot ──────────────────────────────────────────────

class Bot {
  constructor(name, relayPort, bindIp, extraArgs = []) {
    this.name = name;
    this.events = [];
    this.stderr = [];
    openBots.add(this);
    const dir = join(work, `bot-${name}`);
    this.child = spawn(
      botBin,
      ["--relay", `ws://127.0.0.1:${relayPort}/ws`, "--data-dir", dir, "--host-only", "--bind", bindIp, ...extraArgs],
      {
        env: { ...process.env, RUST_LOG: process.env.RUST_LOG || "warn,parolnet_rtc=info,parolnet_app=info" },
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    cleanups.push(() => this.child.kill());
    createInterface({ input: this.child.stdout }).on("line", (line) => {
      try {
        const ev = JSON.parse(line);
        ev.at = new Date().toISOString().slice(11, 23);
        this.events.push(ev);
        if (verbose) log(`[bot ${name}]`, line);
      } catch {
        log(`[bot ${name}] (not json)`, line);
      }
    });
    createInterface({ input: this.child.stderr }).on("line", (line) => {
      this.stderr.push(line);
      if (verbose) log(`[bot ${name} stderr]`, line);
    });
    this.exited = new Promise((r) => this.child.on("exit", (code) => r(code)));
  }

  send(line) {
    this.child.stdin.write(line + "\n");
  }

  /// Wait for an event (searching from `from`, an index into the event log).
  async wait(what, pred, ms = 30_000, from = 0) {
    return until(`bot ${this.name}: ${what}`, ms, () => this.events.slice(from).find(pred), 100);
  }

  async quit() {
    this.send("quit");
    await Promise.race([this.exited, sleep(5000)]);
  }
}

// ── PWA in the browser ───────────────────────────────────────

/// Firefox and WebKit get this as their HTTP proxy for every host but 127.0.0.1: it refuses
/// everything, so no request leaves the machine, the service worker's included (Chromium has a
/// resolver rule for that). Refused requests are counted per host for the log.
const refusedHosts = new Map();
let deadProxyPort = null;
async function deadProxy() {
  if (deadProxyPort) return deadProxyPort;
  const note = (target) => {
    let host = target;
    try {
      host = new URL(target.includes("://") ? target : `http://${target}`).hostname;
    } catch {}
    refusedHosts.set(host, (refusedHosts.get(host) ?? 0) + 1);
  };
  const server = createServer((req, res) => {
    note(req.url);
    res.writeHead(502);
    res.end();
  });
  server.on("connect", (req, socket) => {
    note(req.url);
    socket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
  });
  server.on("clientError", (_e, socket) => socket.destroy());
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  cleanups.push(() => server.close());
  deadProxyPort = server.address().port;
  return deadProxyPort;
}

/// A browser with its profile in `profileDir` (a persistent context: IndexedDB and the service
/// worker survive a relaunch, as case 3 needs).
///
/// `media`: a synthetic camera and microphone with the permission granted. That also makes
/// Chromium gather host candidates on every interface (it does so once a page holds media
/// permission) and Firefox stop hiding its addresses behind mDNS names, so only the call cases
/// use it.
async function launchBrowser(profileDir, { media = false } = {}) {
  if (browserName === "chromium") {
    const args = [
      "--no-first-run",
      "--no-default-browser-check",
      // Nothing leaves the machine: the PWA's STUN fallback (parol.social) and any other remote
      // host fail to resolve, so ICE uses host candidates only.
      "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost",
      "--autoplay-policy=no-user-gesture-required",
    ];
    if (media) args.push("--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream");
    if (mode === "loopback") {
      args.push("--allow-loopback-in-peer-connection", "--disable-features=WebRtcHideLocalIpsWithMdns");
    }
    return chromium.launchPersistentContext(profileDir, {
      headless: true,
      // The full browser in its headless mode (as a user's Chromium), not the headless shell.
      channel: process.env.CHROME_PATH ? undefined : "chromium",
      executablePath: process.env.CHROME_PATH || undefined,
      // Playwright's default is no sandbox; keep Chromium's own wherever it can run.
      chromiumSandbox: !(process.platform === "linux" && process.env.CI),
      args,
    });
  }
  // Nothing leaves the machine (the PWA's fallback fetch to parol.social among them).
  const proxy = { server: `http://127.0.0.1:${await deadProxy()}`, bypass: "127.0.0.1" };
  if (browserName === "firefox") {
    const prefs = {
      "media.autoplay.default": 0,
      "media.autoplay.blocking_policy": 0,
      // mdns: Firefox as shipped (host candidates are `<uuid>.local` names while the page holds
      // no media permission). loopback: addresses as they are, 127.0.0.1 included.
      "media.peerconnection.ice.obfuscate_host_addresses": mode === "mdns",
      "media.peerconnection.ice.loopback": mode === "loopback",
    };
    if (media) {
      prefs["media.navigator.streams.fake"] = true;
      prefs["media.navigator.permission.disabled"] = true;
    }
    return firefox.launchPersistentContext(profileDir, {
      headless: true,
      executablePath: process.env.FIREFOX_PATH || undefined,
      firefoxUserPrefs: prefs,
      proxy,
    });
  }
  return webkit.launchPersistentContext(profileDir, {
    headless: true,
    executablePath: process.env.WEBKIT_PATH || undefined,
    permissions: media ? ["camera", "microphone"] : [],
    proxy,
  });
}

/// What both browser sides share: the page, its console, and what is read from the browser
/// itself (the connections it made, their statistics).
class Client {
  /// Open the app in `context`'s first page and wait until it is registered with the relay.
  static async open(context, site, name, { tamperBinding = false } = {}) {
    const page = context.pages()[0] ?? (await context.newPage());
    if (tamperBinding) {
      // Once connected, the local description the PWA binds names a fingerprint that is not
      // its certificate's: the binding then disagrees with what the desktop saw.
      await page.addInitScript(() => {
        const desc = Object.getOwnPropertyDescriptor(RTCPeerConnection.prototype, "localDescription");
        Object.defineProperty(RTCPeerConnection.prototype, "localDescription", {
          configurable: true,
          get() {
            const d = desc.get.call(this);
            if (!d || this.connectionState !== "connected") return d;
            const fake = Array(32).fill("AA").join(":");
            return { type: d.type, sdp: d.sdp.replace(/a=fingerprint:(\S+) [0-9A-Fa-f:]+/g, `a=fingerprint:$1 ${fake}`) };
          },
        });
      });
    }
    const p = new this(page, name);
    // Keep every RTCPeerConnection the PWA makes, for call stats.
    await page.addInitScript(() => {
      const Orig = window.RTCPeerConnection;
      window.__pcs = [];
      const t0 = performance.now();
      window.RTCPeerConnection = class extends Orig {
        constructor(...args) {
          super(...args);
          window.__pcs.push(this);
          // Selected candidate pair changes, for failure reports (renomination).
          this.__pairChanges = [];
          const watched = new Set();
          const record = (ice) => {
            const p = ice.getSelectedCandidatePair?.();
            const at = Math.round(performance.now() - t0);
            this.__pairChanges.push(
              p ? `${at} ms ${p.local.address}:${p.local.port}(${p.local.type}) -> ${p.remote.address}:${p.remote.port}(${p.remote.type})` : `${at} ms none`,
            );
          };
          const watch = () => {
            const transports = [this.sctp?.transport, ...this.getTransceivers().map((t) => t.sender.transport)];
            for (const dtls of transports) {
              const ice = dtls?.iceTransport;
              if (!ice || watched.has(ice)) continue;
              watched.add(ice);
              ice.addEventListener("selectedcandidatepairchange", () => record(ice));
              if (ice.getSelectedCandidatePair?.()) record(ice);
            }
          };
          this.addEventListener("connectionstatechange", watch);
          this.addEventListener("iceconnectionstatechange", watch);
        }
      };
    });
    page.on("console", (msg) => {
      const text = msg.text();
      p.console.push(text);
      p.consoleAt.push(new Date().toISOString().slice(11, 23));
      if (verbose) log(`[pwa ${name}]`, text);
    });
    page.on("pageerror", (e) => {
      p.console.push(`PAGE ERROR ${e.message}`);
      p.consoleAt.push(new Date().toISOString().slice(11, 23));
      p.pageErrors.push(e.message);
      // WebKit reports the refused fallback fetch (see deadProxy) as a page error.
      if (verbose || !e.message.includes("/turn-credentials due to access control checks")) log(`[pwa ${name}] PAGE ERROR`, e.message);
    });
    await page.goto(`http://127.0.0.1:${site.port}${site.path}`, { waitUntil: "domcontentloaded" });
    await p.start();
    log(`pwa ${name} is ${p.peerId.slice(0, 8)}`);
    return p;
  }

  constructor(page, name) {
    this.page = page;
    this.name = name;
    this.console = [];
    this.consoleAt = [];
    this.pageErrors = [];
    openPwas.add(this);
  }

  /// ICE / DTLS state of every connection, for a failure report.
  async diag() {
    return this.page
      .evaluate(async () => {
        const out = [];
        for (const pc of window.__pcs || []) {
          const r = { state: pc.connectionState, ice: pc.iceConnectionState, role: pc.localDescription?.type, pairChanges: pc.__pairChanges, pairs: [], transports: [] };
          const stats = await pc.getStats();
          const byId = new Map();
          stats.forEach((s) => byId.set(s.id, s));
          stats.forEach((s) => {
            if (s.type === "transport") r.transports.push({ dtls: s.dtlsState, role: s.dtlsRole, selected: s.selectedCandidatePairId });
            if (s.type === "candidate-pair" && (s.nominated || s.state === "succeeded")) {
              const l = byId.get(s.localCandidateId), rc = byId.get(s.remoteCandidateId);
              r.pairs.push(`${s.id} ${s.state}${s.nominated ? " nominated" : ""} ${l?.address}:${l?.port}(${l?.candidateType}) -> ${rc?.address}:${rc?.port}(${rc?.candidateType})`);
            }
          });
          out.push(r);
        }
        return out;
      })
      .catch((e) => `diag failed: ${e.message}`);
  }

  /// What the PWA's call connection receives: decoded video frames and audio.
  async callStats() {
    return this.page.evaluate(async () => {
      const out = { videoFrames: 0, videoPackets: 0, audioPackets: 0, audioSamples: 0, connected: false };
      for (const pc of window.__pcs || []) {
        if (pc.connectionState === "closed") continue;
        if (!pc.getReceivers().some((r) => r.track && r.track.kind === "video" || r.track && r.track.kind === "audio")) continue;
        if (pc.connectionState === "connected") out.connected = true;
        (await pc.getStats()).forEach((s) => {
          if (s.type !== "inbound-rtp") return;
          if (s.kind === "video") {
            out.videoFrames = Math.max(out.videoFrames, s.framesDecoded || 0);
            out.videoPackets = Math.max(out.videoPackets, s.packetsReceived || 0);
          } else if (s.kind === "audio") {
            out.audioPackets = Math.max(out.audioPackets, s.packetsReceived || 0);
            out.audioSamples = Math.max(out.audioSamples, s.totalSamplesReceived || 0);
          }
        });
      }
      return out;
    });
  }

  async openCallPcs() {
    return this.page.evaluate(
      () => (window.__pcs || []).filter((pc) => pc.connectionState !== "closed" && pc.getTransceivers().length > 0).length,
    );
  }
}

/// The PWA in pwa/: driven through its window functions, read from its IndexedDB and console.
class Pwa extends Client {
  /// The identity is loaded and the relay has registered it.
  async start() {
    this.peerId = await until(`pwa ${this.name}: identity`, 30_000, () =>
      this.page.evaluate(() => (typeof window._peerId === "string" && window._peerId.length === 64 ? window._peerId : null)),
    );
    await until(`pwa ${this.name}: registered with the relay`, 30_000, () =>
      // Not "SW registered: ...": the relay's own registration, or the desktop's first offer
      // can find the PWA offline (`peer_offline`).
      this.console.some((t) => t.startsWith("Registered with relay")),
    );
  }

  async showCode() {
    return this.page.evaluate(() => {
      window.showView("add-contact");
      window.showAddTab("qr-show");
      return document.getElementById("qr-share-code").textContent.trim();
    });
  }

  async pasteCode(code) {
    await this.page.evaluate((c) => {
      window.showView("add-contact");
      window.showAddTab("passphrase");
      document.querySelector("#add-tab-passphrase input").value = c;
      window.connectViaPassphrase();
    }, code);
  }

  async idbAll(store) {
    return this.page.evaluate(
      (store) =>
        new Promise((res, rej) => {
          const open = indexedDB.open("parolnet");
          open.onerror = () => rej(open.error);
          open.onsuccess = () => {
            const db = open.result;
            if (!db.objectStoreNames.contains(store)) return res([]);
            const req = db.transaction(store, "readonly").objectStore(store).getAll();
            req.onsuccess = () => res(req.result);
            req.onerror = () => rej(req.error);
          };
        }),
      store,
    );
  }

  async hasContact(peerId) {
    return (await this.idbAll("contacts")).some((c) => c.peerId === peerId);
  }

  async waitReceived(from, text, ms = 30_000) {
    await until(`pwa ${this.name}: message ${JSON.stringify(text)}`, ms, async () =>
      (await this.idbAll("messages")).some((m) => m.peerId === from && m.direction === "received" && m.content === text),
    );
  }

  async sendText(to, text) {
    await this.page.evaluate(
      async ({ to, text }) => {
        window.openChat(to);
        await new Promise((r) => setTimeout(r, 100));
        document.getElementById("message-input").value = text;
        await window.sendMessage();
      },
      { to, text },
    );
  }

  async verified(peerId) {
    return this.console.some((t) => t.includes("direct channel verified with") && t.includes(peerId.slice(0, 8)));
  }

  /// The incoming-call notification is showing.
  async ringing() {
    return this.page.evaluate(() => !document.getElementById("incoming-call-notification")?.classList.contains("hidden"));
  }

  async acceptCall() {
    await this.page.evaluate(() => window.acceptIncomingCall());
  }

  async startVideoCall(peer) {
    await this.page.evaluate((peer) => {
      window.openChat(peer);
      return window.initiateCall(peer, true);
    }, peer);
  }

  async hangupCall() {
    await this.page.evaluate(() => window.hangupCall());
  }

  /// The console line the PWA prints when it learned STUN / TURN servers, if it did.
  async learnedIceServers() {
    return this.console.find((t) => t.includes("[WebRTC] ICE servers from")) ?? null;
  }
}

/// The web app in web/ (its test build). Actions go through the interface, as a person's
/// would; state is read from `window.__parolnetTest`
/// (docs/web-port/interop.md §11.4), which exposes nothing the interface does not show.
///
/// Where the cases read old-PWA internals, this is what the web target checks instead:
///   - `window._peerId`                     -> `__parolnetTest.ready()`;
///   - console "Registered with relay"      -> `__parolnetTest.relayRegistered()` (and the
///                                             same console line, which the engine prints);
///   - IndexedDB `parolnet` / `contacts`    -> IndexedDB `parolnet-web` / `contacts` (the
///                                             contact is stored, not merely shown);
///   - IndexedDB `parolnet` / `messages`    -> IndexedDB `parolnet-web` / `messages`, a row
///     (`direction: "received"`, `content`)    with `direction: "Received"` and `text`, and the
///                                             same text in the history the interface shows;
///   - console "direct channel verified"    -> the same console line, and
///                                             `__parolnetTest.pathState(peer) === "direct"`,
///                                             which is only true once the binding verified;
///   - `#incoming-call-notification`        -> the ringing dialog (`data-testid="incoming-call"`)
///                                             is visible;
///   - console "[WebRTC] ICE servers from"  -> `__parolnetTest.iceServers()` is empty.
/// It also fails on any uncaught page error and on any Content-Security-Policy violation.
class Web extends Client {
  hook(method, ...args) {
    return this.page.evaluate(([m, a]) => window.__parolnetTest[m](...a), [method, args]);
  }

  async goTo(hash) {
    await this.page.evaluate((h) => {
      if (location.hash !== h) location.hash = h;
    }, hash);
  }

  async start() {
    await this.page.addInitScript(() => {
      window.__csp = [];
      document.addEventListener("securitypolicyviolation", (e) => window.__csp.push(`${e.violatedDirective} blocked ${e.blockedURI}`));
    });
    // A new browser profile shows the first-run screen: Start makes the identity. A profile
    // that already has one (case 3's relaunch) goes straight to the app.
    const first = await until(`web ${this.name}: the app or its first-run screen`, 30_000, () =>
      this.page.evaluate(() => {
        if (document.querySelector('[data-testid="first-run-start"]')) return "first-run";
        return window.__parolnetTest ? "running" : null;
      }),
    );
    if (first === "first-run") await this.page.click('[data-testid="first-run-start"]');
    await until(`web ${this.name}: the test hooks (is this the test build?)`, 30_000, () =>
      this.page.evaluate(() => window.__parolnetTest?.version === 1),
    );
    this.peerId = (await this.hook("ready")).peerId;
    await until(`web ${this.name}: registered with the relay`, 30_000, async () =>
      (await this.hook("relayRegistered")) && this.console.some((t) => t.startsWith("Registered with relay")),
    );
  }

  /// The add-a-contact screen shows this device's code.
  async showCode() {
    await this.goTo("#/add");
    return until(`web ${this.name}: its code on the add screen`, 15_000, async () => {
      const code = (await this.page.textContent('[data-testid="pairing-code"]').catch(() => null))?.trim();
      return code && code.length > 0 ? code : null;
    });
  }

  /// "Paste theirs" on the add-a-contact screen.
  async pasteCode(code) {
    await this.goTo("#/add");
    await this.page.click('[data-testid="pairing-paste-open"]');
    await this.page.fill('[data-testid="pairing-code-input"]', code);
    await this.page.click('[data-testid="pairing-code-submit"]');
  }

  // The web app's database is sealed at rest (docs/web-port/at-rest.md), so nothing can be
  // read from it here: what the app holds is asked of its test hooks.
  async hasContact(peerId) {
    return (await this.hook("contacts")).includes(peerId);
  }

  async waitReceived(from, text, ms = 30_000) {
    await until(`web ${this.name}: message ${JSON.stringify(text)}`, ms, async () =>
      (await this.hook("messages", from)).some((m) => m.direction === "received" && m.text === text),
    );
  }

  /// The conversation's composer: type, press Send.
  async sendText(to, text) {
    await this.goTo(`#/c/${to}`);
    await this.page.fill('[data-testid="composer-input"]', text);
    await this.page.click('[data-testid="composer-send"]');
  }

  async verified(peerId) {
    return (
      this.console.some((t) => t.includes("direct channel verified with") && t.includes(peerId.slice(0, 8))) &&
      (await this.hook("pathState", peerId)) === "direct"
    );
  }

  async ringing() {
    return this.page.isVisible('[data-testid="incoming-call"]');
  }

  async acceptCall() {
    await this.page.click('[data-testid="call-accept"]');
  }

  /// The video-call button in the conversation's header (enabled only on an open line).
  async startVideoCall(peer) {
    // The screen that says how the last call ended is still up for a few seconds: close it.
    const close = this.page.locator('[data-testid="call-close"]');
    if (await close.isVisible()) await close.click();
    await this.goTo(`#/c/${peer}`);
    await this.page.click('[data-testid="call-video"]:not([aria-disabled="true"])');
  }

  async hangupCall() {
    await this.page.click('[data-testid="call-hangup"]');
  }

  /// The file bubble of a transfer in the open conversation.
  bubble(id) {
    return this.page.locator(`[data-testid="transfer-bubble"][data-transfer-id="${id}"]`);
  }

  /// Accept an offered file in the conversation with `peer`.
  async acceptFile(peer, id) {
    await this.goTo(`#/c/${peer}`);
    await this.bubble(id).locator('[data-testid="transfer-accept"]').click();
  }

  /// Pick a file in the conversation's composer (the attach control's file input).
  async sendFile(peer, path) {
    await this.goTo(`#/c/${peer}`);
    await this.page.setInputFiles('[data-testid="composer-file"]', path);
  }

  async learnedIceServers() {
    const servers = await this.hook("iceServers").catch(() => []);
    if (servers.length > 0) return JSON.stringify(servers);
    return this.console.find((t) => t.includes("[WebRTC] ICE servers from")) ?? null;
  }

  /// Page errors and CSP violations so far (the web app must have neither).
  async problems() {
    const csp = await this.page.evaluate(() => window.__csp ?? []).catch(() => []);
    return [...this.pageErrors.map((e) => `page error: ${e}`), ...csp.map((v) => `CSP: ${v}`)];
  }
}

/// The browser side under test.
const App = target === "web" ? Web : Pwa;

/// What each page had learned of ICE servers when its browser closed (checked at the end).
const learned = [];

/// Before a case closes a browser: note what the page learned of ICE servers, and, for the
/// web app, fail on any page error or Content-Security-Policy violation. (The PWA target
/// keeps its original checks only.)
async function closing(pwa, tag) {
  learned.push([pwa, await pwa.learnedIceServers()]);
  if (!(pwa instanceof Web)) return;
  const problems = await pwa.problems();
  if (problems.length) throw new Error(`${tag}: the web app reported ${problems.join("; ")}`);
}

async function bothVerified(bot, pwa, tag) {
  await until(`${tag}: the PWA verifies the desktop's channel binding`, 20_000, () => pwa.verified(bot.peerId));
  await until(`${tag}: the desktop verifies the PWA's channel binding`, 20_000, () =>
    bot.stderr.some((l) => l.includes("direct channel verified")),
  );
}

// ── Cases ────────────────────────────────────────────────────

async function chatBothWays(bot, pwa, tag) {
  const fromBot = `hello from the desktop (${tag})`;
  bot.send(`send ${pwa.peerId} ${fromBot}`);
  await pwa.waitReceived(bot.peerId, fromBot);
  log(`${tag}: desktop -> PWA ok`);
  const fromPwa = `hi desktop, the PWA here (${tag})`;
  await pwa.sendText(bot.peerId, fromPwa);
  await bot.wait(`message ${JSON.stringify(fromPwa)}`, (e) => e.event === "message" && e.from === pwa.peerId && e.text === fromPwa);
  log(`${tag}: PWA -> desktop ok`);
}

async function caseDesktopEntersPwaCode(ctx) {
  const tag = "case 1 (PWA code -> desktop)";
  const profile = mkdtempSync(join(work, `${browserName}-1-`));
  const browser = await launchBrowser(profile);
  cleanups.push(() => browser.close().catch(() => {}));
  const bot = new Bot("one", ctx.relayPort, ctx.bindIp);
  const ready = await bot.wait("ready", (e) => e.event === "ready");
  bot.peerId = ready.peer_id;
  await bot.wait("registered", (e) => e.event === "relay" && e.state.includes("Registered"));
  const pwa = await App.open(browser, ctx.site, "one");

  const code = await pwa.showCode();
  if (!/^[0-9a-f]{100,}$/i.test(code)) throw new Error(`${tag}: unexpected PWA code ${code.slice(0, 40)}`);
  bot.send(`pair ${code}`);
  await bot.wait("paired", (e) => e.event === "paired" && e.peer_id === pwa.peerId);
  await bot.wait("direct path", (e) => e.event === "path" && e.peer_id === pwa.peerId && e.state === "Direct", 45_000);
  await until(`${tag}: the PWA adds the desktop as a secure contact`, 30_000, () => pwa.hasContact(bot.peerId));
  await bothVerified(bot, pwa, tag);
  log(`${tag}: paired, direct data channel, bindings verified`);
  await chatBothWays(bot, pwa, tag);
  // The desktop's network "changes". With a peer that takes ICE restarts it would send a
  // second rtc_offer; the browser side lists no such feature, would take that offer for a
  // new connection, and must not get one: nothing happens to the path.
  const mark = bot.events.length;
  bot.send("network-changed");
  await sleep(1500);
  const moved = bot.events.slice(mark).filter((e) => e.event === "path" || e.event === "notice");
  if (moved.length) throw new Error(`${tag}: the connection changed after a network change: ${JSON.stringify(moved)}`);
  if (bot.stderr.some((l) => l.includes("restarting ICE"))) throw new Error(`${tag}: the desktop restarted ICE with a peer that does not take restarts`);
  await chatBothWays(bot, pwa, `${tag}, after a network change`);
  await bot.quit();
  await closing(pwa, tag);
  await browser.close();
  return bot;
}

async function casePwaPastesDesktopCode(ctx) {
  const tag = "case 2 (desktop code -> PWA paste)";
  const profile = mkdtempSync(join(work, `${browserName}-2-`));
  let browser = await launchBrowser(profile);
  cleanups.push(() => browser.close().catch(() => {}));
  const bot = new Bot("two", ctx.relayPort, ctx.bindIp);
  const ready = await bot.wait("ready", (e) => e.event === "ready");
  bot.peerId = ready.peer_id;
  await bot.wait("registered", (e) => e.event === "relay" && e.state.includes("Registered"));
  let pwa = await App.open(browser, ctx.site, "two");

  const mark = bot.events.length;
  bot.send("code");
  const { code } = await bot.wait("code", (e) => e.event === "code", 10_000, mark);
  await pwa.pasteCode(code);
  await until(`${tag}: the PWA stores the desktop as a contact`, 10_000, () => pwa.hasContact(bot.peerId));
  await bot.wait("contact (presenter side)", (e) => e.event === "contact" && e.peer_id === pwa.peerId, 45_000);
  await bot.wait("direct path", (e) => e.event === "path" && e.peer_id === pwa.peerId && e.state === "Direct", 45_000);
  await bothVerified(bot, pwa, tag);
  log(`${tag}: paired, direct data channel, bindings verified`);
  await chatBothWays(bot, pwa, tag);

  // Case 3: the PWA goes away; the bot's message waits in its sender queue.
  const tag3 = "case 3 (sender queue)";
  await closing(pwa, tag);
  await browser.close();
  await bot.wait("PWA offline", (e) => e.event === "path" && e.peer_id === pwa.peerId && e.state === "Offline", 45_000, mark);
  const queuedMark = bot.events.length;
  const waiting = "sent while you were away";
  bot.send(`send ${pwa.peerId} ${waiting}`);
  const sent = await bot.wait("queued", (e) => e.event === "sent", 10_000, queuedMark);
  if (sent.state !== "Queued") throw new Error(`${tag3}: expected the message to queue, got ${sent.state}`);
  browser = await launchBrowser(profile);
  cleanups.push(() => browser.close().catch(() => {}));
  pwa = await App.open(browser, ctx.site, "two-again");
  await pwa.waitReceived(bot.peerId, waiting, 60_000);
  log(`${tag3}: queued message delivered after the PWA came back`);
  await bot.quit();
  await closing(pwa, tag3);
  await browser.close();
  return bot;
}

async function caseTamperedBindingIsRefused(ctx) {
  const tag = "case 4 (tampered channel binding)";
  const profile = mkdtempSync(join(work, `${browserName}-4-`));
  const browser = await launchBrowser(profile);
  cleanups.push(() => browser.close().catch(() => {}));
  const bot = new Bot("four", ctx.relayPort, ctx.bindIp);
  const ready = await bot.wait("ready", (e) => e.event === "ready");
  bot.peerId = ready.peer_id;
  await bot.wait("registered", (e) => e.event === "relay" && e.state.includes("Registered"));
  const pwa = await App.open(browser, ctx.site, "four", { tamperBinding: true });

  const code = await pwa.showCode();
  bot.send(`pair ${code}`);
  await bot.wait("paired", (e) => e.event === "paired" && e.peer_id === pwa.peerId);
  const notice = await bot.wait(
    "the end-to-end check to fail",
    (e) => e.event === "notice" && e.text.includes("failed its end-to-end check"),
    45_000,
  );
  await bot.wait("BindingFailed path", (e) => e.event === "path" && e.peer_id === pwa.peerId && e.state === "BindingFailed", 10_000);
  if (bot.events.some((e) => e.event === "path" && e.peer_id === pwa.peerId && e.state === "Direct")) {
    throw new Error(`${tag}: the desktop reported a direct path despite the bad binding`);
  }
  // Nothing the desktop queued went out on the refused channel.
  const mark = bot.events.length;
  bot.send(`send ${pwa.peerId} must not be delivered on a refused channel`);
  const sent = await bot.wait("queued", (e) => e.event === "sent", 10_000, mark);
  if (sent.state !== "Queued") throw new Error(`${tag}: expected the message to queue, got ${sent.state}`);
  log(`${tag}: refused (${notice.text.slice(0, 60)}...)`);
  await bot.quit();
  await closing(pwa, tag);
  await browser.close();
  return bot;
}

/// Wait until the bot reports at least `n` RTP packets of each kind for `callId`.
async function botMedia(bot, callId, n, what) {
  return bot.wait(what, (e) => e.event === "media" && e.call_id === callId && e.audio_rx >= n && e.video_rx >= n, 30_000);
}

async function pwaDecodes(pwa, what) {
  return until(what, 30_000, async () => {
    const s = await pwa.callStats();
    return s.connected && s.videoFrames >= 20 && s.audioPackets >= 50 && s.audioSamples > 0 ? s : null;
  });
}

async function caseCalls(ctx) {
  const profile = mkdtempSync(join(work, `${browserName}-5-`));
  const browser = await launchBrowser(profile, { media: true });
  cleanups.push(() => browser.close().catch(() => {}));
  const bot = new Bot("calls", ctx.relayPort, ctx.bindIp);
  const ready = await bot.wait("ready", (e) => e.event === "ready");
  bot.peerId = ready.peer_id;
  await bot.wait("registered", (e) => e.event === "relay" && e.state.includes("Registered"));
  const pwa = await App.open(browser, ctx.site, "calls");
  const code = await pwa.showCode();
  bot.send(`pair ${code}`);
  await bot.wait("direct path", (e) => e.event === "path" && e.peer_id === pwa.peerId && e.state === "Direct", 45_000);
  await bothVerified(bot, pwa, "calls");

  // Case 5: the desktop calls.
  let tag = "case 5 (desktop video-calls the PWA)";
  const mark = bot.events.length;
  bot.send(`call ${pwa.peerId} video`);
  const out = await bot.wait("outgoing", (e) => e.event === "call" && e.state === "Outgoing", 10_000, mark);
  await until(`${tag}: the PWA rings`, 20_000, () => pwa.ringing());
  await pwa.acceptCall();
  await bot.wait("active", (e) => e.event === "call" && e.call_id === out.call_id && e.state === "Active", 30_000, mark);
  const m6 = await botMedia(bot, out.call_id, 50, `${tag}: the desktop receives ${Browser}'s VP8 and Opus`);
  const s6 = await pwaDecodes(pwa, `${tag}: ${Browser} decodes the desktop's VP8 and Opus`);
  log(`${tag}: desktop got audio ${m6.audio_rx} / video ${m6.video_rx} packets; PWA decoded ${s6.videoFrames} frames, ${s6.audioSamples} audio samples`);
  // The browser side does not renegotiate: the call is not renegotiable, "camera off" leaves
  // the stream as it was set up, a network change sends no reoffer, and media goes on.
  const active = bot.events.slice(mark).filter((e) => e.event === "call" && e.call_id === out.call_id && e.state === "Active").pop();
  if (active.renegotiable !== false) throw new Error(`${tag}: the call with a browser must not be renegotiable: ${JSON.stringify(active)}`);
  bot.send(`video off ${out.call_id}`);
  const change = await bot.wait("the camera toggle's answer", (e) => e.event === "video-change" && e.call_id === out.call_id, 10_000, mark);
  if (change.how !== "Unchanged") throw new Error(`${tag}: camera off renegotiated with a browser: ${JSON.stringify(change)}`);
  bot.send("network-changed");
  const more = await botMedia(bot, out.call_id, Math.max(m6.audio_rx, m6.video_rx) + 60, `${tag}: media goes on after camera off and a network change`);
  if (bot.stderr.some((l) => l.includes("restarting the call's ICE"))) throw new Error(`${tag}: the desktop sent a reoffer to a peer that does not renegotiate`);
  const estimate = bot.events.slice(mark).filter((e) => e.event === "bitrate" && e.call_id === out.call_id);
  const quality = bot.events.slice(mark).filter((e) => e.event === "quality" && e.call_id === out.call_id).pop();
  if (!estimate.length || !quality) throw new Error(`${tag}: no bitrate estimate or quality report from the call`);
  log(`${tag}: not renegotiable; camera off left the stream; ${more.audio_rx} / ${more.video_rx} packets after a network change; estimate ${estimate[0].bps} -> ${estimate[estimate.length - 1].bps} bit/s; rtt ${quality.rtt_ms} ms, pair ${quality.local_candidate}/${quality.remote_candidate}`);
  bot.send(`hangup ${out.call_id}`);
  await bot.wait("ended", (e) => e.event === "call" && e.call_id === out.call_id && e.state === "Ended(HungUp)", 10_000, mark);
  await until(`${tag}: the PWA closes its call connection`, 15_000, async () => (await pwa.openCallPcs()) === 0);
  log(`${tag}: hung up by the desktop`);
  if (process.env.INTEROP_PWA_CALLS !== "0") {
    // Case 6: the PWA calls (see the header).
    tag = "case 6 (PWA video-calls the desktop)";
    await pwa.startVideoCall(bot.peerId);
    const ring = await bot.wait("incoming call", (e) => e.event === "call" && e.state === "Incoming" && e.peer_id === pwa.peerId, 30_000);
    if (!ring.video) throw new Error(`${tag}: the PWA's offer should carry video`);
    bot.send(`accept ${ring.call_id}`);
    await bot.wait("active", (e) => e.event === "call" && e.call_id === ring.call_id && e.state === "Active", 30_000);
    const m5 = await botMedia(bot, ring.call_id, 50, `${tag}: the desktop receives ${Browser}'s VP8 and Opus`);
    const s5 = await pwaDecodes(pwa, `${tag}: ${Browser} decodes the desktop's VP8 and Opus`);
    log(`${tag}: desktop got audio ${m5.audio_rx} / video ${m5.video_rx} packets; PWA decoded ${s5.videoFrames} frames, ${s5.audioSamples} audio samples`);
    log(`${tag}: selected-pair changes on the PWA's connections: ${JSON.stringify(await pairChanges(pwa))}`);
    await pwa.hangupCall();
    await bot.wait("remote hang-up", (e) => e.event === "call" && e.call_id === ring.call_id && e.state === "Ended(RemoteHungUp)", 15_000);
    log(`${tag}: hung up by the PWA`);
  } else {
    log("case 6 (PWA video-calls the desktop): skipped (INTEROP_PWA_CALLS=0)");
  }
  await bot.quit();
  await closing(pwa, "calls");
  await browser.close();
  return bot;
}

/// Selected-pair changes of the PWA's open connections, for a log line.
async function pairChanges(pwa) {
  return pwa.page.evaluate(() => (window.__pcs || []).filter((pc) => pc.connectionState !== "closed").map((pc) => pc.__pairChanges.length));
}

async function casePwaOffersWithMedia(ctx) {
  const tag = "case 7 (PWA-offered data channel with media permission)";
  const profile = mkdtempSync(join(work, `${browserName}-7-`));
  const browser = await launchBrowser(profile, { media: true });
  cleanups.push(() => browser.close().catch(() => {}));
  const bot = new Bot("seven", ctx.relayPort, ctx.bindIp);
  const ready = await bot.wait("ready", (e) => e.event === "ready");
  bot.peerId = ready.peer_id;
  await bot.wait("registered", (e) => e.event === "relay" && e.state.includes("Registered"));
  const pwa = await App.open(browser, ctx.site, "seven");
  // Hold the camera and microphone for the whole case, as a page in a call does.
  const tracks = await pwa.page.evaluate(async () => {
    window.__held = await navigator.mediaDevices.getUserMedia({ audio: true, video: true });
    return window.__held.getTracks().map((t) => `${t.kind}:${t.readyState}`);
  });
  log(`${tag}: the PWA holds ${tracks.join(", ")}`);

  const mark = bot.events.length;
  bot.send("code");
  const { code } = await bot.wait("code", (e) => e.event === "code", 10_000, mark);
  await pwa.pasteCode(code);
  await bot.wait("contact (presenter side)", (e) => e.event === "contact" && e.peer_id === pwa.peerId, 45_000);
  await bot.wait("direct path", (e) => e.event === "path" && e.peer_id === pwa.peerId && e.state === "Direct", 45_000);
  await bothVerified(bot, pwa, tag);
  const roles = await pwa.page.evaluate(() =>
    (window.__pcs || []).filter((pc) => pc.connectionState === "connected" && pc.sctp).map((pc) => pc.localDescription?.type),
  );
  if (!roles.includes("offer")) throw new Error(`${tag}: expected the PWA to offer the data channel, its connected roles are ${JSON.stringify(roles)}`);
  log(`${tag}: the PWA offered; paired, direct data channel, bindings verified`);
  await chatBothWays(bot, pwa, tag);
  // Past the moment Chromium renominates (about a second after connecting).
  await sleep(5000);
  await chatBothWays(bot, pwa, `${tag}, settled`);
  if (bot.events.slice(mark).some((e) => e.event === "path" && e.peer_id === pwa.peerId && e.state !== "Direct" && e.state !== "Connecting")) {
    log(`${tag}: note: path states ${bot.events.slice(mark).filter((e) => e.event === "path").map((e) => e.state).join(" -> ")}`);
  }
  log(`${tag}: selected-pair changes on the PWA's connections: ${JSON.stringify(await pairChanges(pwa))}`);
  await bot.quit();
  await closing(pwa, tag);
  await browser.close();
  return bot;
}

// ── Main ─────────────────────────────────────────────────────

/// A file of `size` random bytes; returns its SHA-256 (hex).
function writeRandomFile(path, size) {
  const fd = openSync(path, "w");
  const hash = createHash("sha256");
  const block = Buffer.alloc(1 << 20);
  for (let left = size; left > 0; ) {
    const n = Math.min(left, block.length);
    randomFillSync(block, 0, n);
    writeSync(fd, block, 0, n);
    hash.update(block.subarray(0, n));
    left -= n;
  }
  closeSync(fd);
  return hash.digest("hex");
}

async function caseFiles(ctx) {
  const tag = "case 8 (files, PNP-010)";
  const mib = Number(process.env.INTEROP_FILE_MIB || 8);
  const size = mib * 1024 * 1024 + 12_345;
  const patience = 120_000 + mib * 3_000;
  const profile = mkdtempSync(join(work, `${browserName}-8-`));
  const browser = await launchBrowser(profile);
  cleanups.push(() => browser.close().catch(() => {}));
  const downloads = join(work, "bot-files-downloads");
  const bot = new Bot("files", ctx.relayPort, ctx.bindIp, ["--downloads", downloads]);
  const ready = await bot.wait("ready", (e) => e.event === "ready");
  bot.peerId = ready.peer_id;
  await bot.wait("registered", (e) => e.event === "relay" && e.state.includes("Registered"));
  const pwa = await App.open(browser, ctx.site, "files");
  const mark = bot.events.length;
  bot.send("code");
  const { code } = await bot.wait("code", (e) => e.event === "code", 10_000, mark);
  await pwa.pasteCode(code);
  await bot.wait("direct path", (e) => e.event === "path" && e.peer_id === pwa.peerId && e.state === "Direct", 45_000);
  await bothVerified(bot, pwa, tag);

  // Desktop -> web app.
  const fromDesktop = join(work, "from the desktop.bin");
  const sha1 = writeRandomFile(fromDesktop, size);
  bot.send(`sendfile ${pwa.peerId} ${fromDesktop}`);
  const offered = await bot.wait("its offer delivered", (e) => e.event === "transfer" && e.direction === "Sent" && e.state === "Offered" && !e.pending);
  await until(`${tag}: the web app shows the desktop's offer`, 30_000, async () =>
    (await pwa.hook("transfers", bot.peerId)).some((t) => t.id === offered.id && t.state === "offered" && t.direction === "received"),
  );
  let t0 = Date.now();
  await pwa.acceptFile(bot.peerId, offered.id);
  await bot.wait("complete (the web app's word)", (e) => e.event === "transfer" && e.id === offered.id && e.state === "Complete", patience);
  const down = (mib * 1000) / (Date.now() - t0);
  await until(`${tag}: the web app has the whole file`, 30_000, async () =>
    (await pwa.hook("transfers", bot.peerId)).some((t) => t.id === offered.id && t.state === "complete" && t.available && t.bytesDone === size),
  );
  const stored = await pwa.hook("transferDigest", offered.id);
  if (!stored || stored.size !== size || stored.sha256 !== sha1) {
    throw new Error(`${tag}: the file in the web app is not the file the desktop sent (${JSON.stringify(stored)} vs ${size} ${sha1})`);
  }
  const shown = await pwa.bubble(offered.id).getAttribute("data-state");
  if (shown !== "complete") throw new Error(`${tag}: the web app's bubble says ${shown}, not complete`);
  if (!(await pwa.bubble(offered.id).locator('[data-testid="transfer-save"]').isVisible())) {
    throw new Error(`${tag}: the received file offers no way to save it`);
  }
  const persistent = await pwa.hook("filesPersist");
  log(`${tag}: desktop -> web app, ${mib} MiB verified by SHA-256, ${down.toFixed(1)} MiB/s, stored in ${persistent ? "OPFS" : "memory"}`);

  // Web app -> desktop.
  const fromWeb = join(work, "from the web app.bin");
  const sha2 = writeRandomFile(fromWeb, size);
  const offerMark = bot.events.length;
  await pwa.sendFile(bot.peerId, fromWeb);
  const incoming = await bot.wait(
    "the web app's offer",
    (e) => e.event === "transfer" && e.direction === "Received" && e.state === "Offered",
    patience,
    offerMark,
  );
  if (incoming.size !== size || incoming.name !== "from the web app.bin") {
    throw new Error(`${tag}: the desktop was offered ${incoming.name} (${incoming.size} bytes)`);
  }
  t0 = Date.now();
  bot.send(`acceptfile ${incoming.id}`);
  const done = await bot.wait("the file from the web app", (e) => e.event === "transfer" && e.id === incoming.id && e.state === "Complete", patience);
  const up = (mib * 1000) / (Date.now() - t0);
  if (done.sha256 !== sha2) throw new Error(`${tag}: the desktop received ${done.sha256}, the web app sent ${sha2}`);
  if (!done.path?.startsWith(downloads) || statSync(done.path).size !== size) {
    throw new Error(`${tag}: the desktop's file is at ${done.path}`);
  }
  await until(`${tag}: the web app learns that the desktop has the file`, 30_000, async () =>
    (await pwa.hook("transfers", bot.peerId)).some((t) => t.id === incoming.id && t.state === "complete" && t.direction === "sent"),
  );
  log(`${tag}: web app -> desktop, ${mib} MiB verified by SHA-256, ${up.toFixed(1)} MiB/s`);
  await bot.quit();
  await closing(pwa, tag);
  await browser.close();
  return bot;
}

async function main() {
  if (!existsSync(botBin)) throw new Error(`bot binary not found: ${botBin} (cargo build -p parolnet-app --example bot)`);
  const bindIp = mode === "loopback" ? "127.0.0.1" : lanIPv4();
  log(`${Browser}, ${target === "web" ? "the web app (web/)" : "the PWA (pwa/)"}, ICE mode ${mode}, desktop host candidate ${bindIp}`);
  const relayPort = await startRelay();
  const site = target === "web" ? await startWebServer(relayPort) : await startPwaServer(relayPort);
  const ctx = { relayPort, site, bindIp };

  const bots = [];
  const filesOnly = process.env.INTEROP_ONLY === "files";
  if (filesOnly && target !== "web") throw new Error("INTEROP_ONLY=files needs INTEROP_APP=web");
  if (!filesOnly) {
    bots.push(await caseDesktopEntersPwaCode(ctx));
    bots.push(await casePwaPastesDesktopCode(ctx));
    bots.push(await caseTamperedBindingIsRefused(ctx));
    if (process.env.INTEROP_CALLS !== "0") bots.push(await caseCalls(ctx));
    bots.push(await casePwaOffersWithMedia(ctx));
  }
  if (target === "web" && process.env.INTEROP_FILES !== "0") bots.push(await caseFiles(ctx));

  // Host candidates only: no page may have learned a STUN / TURN server (that would mean a
  // request left the machine).
  for (const [p, line] of learned) {
    if (line) throw new Error(`pwa ${p.name} learned ICE servers, so a request left the machine: ${line}`);
  }
  if (refusedHosts.size) log(`requests refused by the proxy: ${[...refusedHosts].map(([h, n]) => `${h} x${n}`).join(", ")}`);
  if (mode === "mdns") {
    const resolved = bots.some((b) => b.stderr.some((l) => l.includes("mDNS traffic received")));
    if (!resolved) throw new Error(`mDNS mode: the desktop never received an mDNS answer for ${Browser}'s .local candidates`);
    log(`mDNS: the desktop resolved ${Browser}'s .local candidates`);
  }
  const cases = filesOnly
    ? 1
    : 5 + (process.env.INTEROP_CALLS === "0" ? 0 : process.env.INTEROP_PWA_CALLS === "0" ? 1 : 2) +
      (target === "web" && process.env.INTEROP_FILES !== "0" ? 1 : 0);
  log(`PASS: desktop <-> ${target === "web" ? "web app" : "PWA"} interop, ${Browser}, ${mode} candidates (${cases} cases)`);
}

let status = 0;
try {
  await main();
} catch (e) {
  status = 1;
  console.error(`FAIL: ${e.message}`);
  for (const p of openPwas) {
    try {
      console.error(`pwa ${p.name} connections: ${JSON.stringify(await p.diag(), null, 1)}`);
      const lines = p.console.map((t, i) => `[${p.consoleAt[i]}] ${t}`).filter((t) => !t.includes("[DOM]"));
      console.error(`pwa ${p.name} console (last 40):\n  ${lines.slice(-40).join("\n  ")}`);
    } catch {}
  }
  for (const b of openBots) {
    console.error(`bot ${b.name} events (last 20):\n  ${b.events.slice(-20).map((e) => JSON.stringify(e)).join("\n  ")}`);
    console.error(`bot ${b.name} stderr (last 30):\n  ${b.stderr.slice(-30).join("\n  ")}`);
  }
}
for (const c of cleanups.reverse()) {
  try {
    await c();
  } catch {}
}
process.exit(status);
