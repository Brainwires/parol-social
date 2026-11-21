// Desktop <-> PWA interop test: pairing, chat, the sender queue, the channel binding, calls.
//
//   node apps/desktop/interop/pwa-interop.mjs
//
// Peers
//   - "desktop": the headless `parolnet-app` bot (examples/bot.rs), the same core the GPUI app
//     runs, speaking JSON lines on stdout / commands on stdin.
//   - "pwa": the real PWA (pwa/, built with `npm run build:wasm && npm run build`) in headless
//     Chromium through puppeteer, a fresh profile per case.
//   - one local relay: the `parolnet-relay` binary in its default signaling-only profile.
//
// A small HTTP server serves pwa/ and proxies the relay's endpoints (`/ws` upgrade included),
// so the PWA finds its relay at `location.host + '/ws'` with no settings.
//
// ICE (INTEROP_ICE):
//   mdns     (default on Linux) Chromium as shipped: its host candidates are mDNS `<uuid>.local`
//            names; the bot binds the default-route interface and resolves them with an mDNS
//            query (parolnet-rtc). The test fails unless the bot saw mDNS answers.
//   loopback (default elsewhere) --allow-loopback-in-peer-connection and
//            --disable-features=WebRtcHideLocalIpsWithMdns, the bot on 127.0.0.1: no multicast
//            and no LAN address (no macOS Local Network prompt on a developer's machine).
//
// Cases
//   1. PWA presents its code, the desktop enters it (bot `pair`): bootstrap over the data
//      channel, messages both ways.
//   2. The desktop presents its code, the PWA pastes it ("Paste Code" tab): the paste path
//      pairs like a camera scan, messages both ways.
//   3. Sender queue: with case 2's pair, the PWA tab closes; the bot's message waits in its
//      queue and is delivered when the PWA comes back (same browser profile).
//   4. Channel binding (PNP-001 §10.5.1): every case above requires both sides to verify the
//      other's binding before the path is direct; here the PWA binds a fingerprint it did not
//      see (as if a relay had swapped the desktop's), and the desktop must refuse the channel.
//   5. The desktop video-calls the PWA (Chromium's fake camera and microphone); the PWA
//      accepts; the desktop sends its test pattern (VP8) and a tone (Opus): RTP flows both
//      ways and Chromium decodes the desktop's video and audio; the desktop hangs up.
//   6. The PWA video-calls the desktop; the same checks; the PWA hangs up. Chromium is then
//      the ICE controlling side (it offers) and, holding media permission, gathers on every
//      interface and may move its nomination to another pair a moment after connecting; the
//      desktop (controlled) must follow the later nomination (webrtc-rs-rtc
//      v0.22.0+brainwires.5). INTEROP_PWA_CALLS=0 skips it.
//   7. A data channel the PWA offers while it holds camera and microphone permission (a live
//      getUserMedia stream): the same renomination as case 6 on a chat connection. The PWA
//      pastes the desktop's code and must be the offerer; bindings verified, messages both
//      ways, and again after the connection has settled.
//
// Every PWA connection records its selected ICE candidate pair changes (`window.__pcs[i]
// .__pairChanges`); a failure report prints them with the bot's stderr.
//
// Environment: PAROLNET_RELAY_BIN, PAROLNET_BOT_BIN (default: $CARGO_TARGET_DIR or target/,
// debug profile), CHROME_PATH, INTEROP_ICE, INTEROP_KEEP=1 (keep temp dirs), INTEROP_VERBOSE=1
// (page console and bot stderr on stdout).

import puppeteer from "puppeteer";
import { spawn } from "node:child_process";
import { createServer, request as httpRequest } from "node:http";
import { connect as netConnect, createServer as netCreateServer } from "node:net";
import { createReadStream, existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { networkInterfaces, tmpdir } from "node:os";
import { dirname, extname, join, normalize, resolve, sep } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../../..");
const pwaDir = join(root, "pwa");
const exe = process.platform === "win32" ? ".exe" : "";
const targetDir = process.env.CARGO_TARGET_DIR || join(root, "target");
const relayBin = process.env.PAROLNET_RELAY_BIN || join(targetDir, "debug", `parolnet-relay${exe}`);
const botBin = process.env.PAROLNET_BOT_BIN || join(targetDir, "debug", "examples", `bot${exe}`);
const mode = process.env.INTEROP_ICE || (process.platform === "linux" ? "mdns" : "loopback");
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

/// The address host candidates use in mDNS mode: the default-route IPv4 interface.
function lanIPv4() {
  for (const list of Object.values(networkInterfaces())) {
    for (const a of list ?? []) {
      if (a.family === "IPv4" && !a.internal) return a.address;
    }
  }
  throw new Error("no non-loopback IPv4 interface for mDNS mode");
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
  return port;
}

// ── Desktop bot ──────────────────────────────────────────────

class Bot {
  constructor(name, relayPort, bindIp) {
    this.name = name;
    this.events = [];
    this.stderr = [];
    openBots.add(this);
    const dir = join(work, `bot-${name}`);
    this.child = spawn(
      botBin,
      ["--relay", `ws://127.0.0.1:${relayPort}/ws`, "--data-dir", dir, "--host-only", "--bind", bindIp],
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

// ── PWA in Chromium ──────────────────────────────────────────

/// `media`: a synthetic camera and microphone with the permission granted. That also makes
/// Chromium gather host candidates on every interface (it does so once a page holds media
/// permission), so only the call cases use it.
async function launchBrowser(profileDir, { media = false } = {}) {
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
  if (process.platform === "linux" && process.env.CI) args.push("--no-sandbox");
  return puppeteer.launch({
    headless: true,
    executablePath: process.env.CHROME_PATH || undefined,
    userDataDir: profileDir,
    args,
  });
}

class Pwa {
  static async open(browser, port, name, { tamperBinding = false } = {}) {
    const page = await browser.newPage();
    if (tamperBinding) {
      // Once connected, the local description the PWA binds names a fingerprint that is not
      // its certificate's: the binding then disagrees with what the desktop saw.
      await page.evaluateOnNewDocument(() => {
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
    const p = new Pwa(page, name);
    // Keep every RTCPeerConnection the PWA makes, for call stats.
    await page.evaluateOnNewDocument(() => {
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
    page.on("pageerror", (e) => log(`[pwa ${name}] PAGE ERROR`, e.message));
    await page.goto(`http://127.0.0.1:${port}/index.html`, { waitUntil: "domcontentloaded" });
    p.peerId = await until(`pwa ${name}: identity`, 30_000, () =>
      page.evaluate(() => (typeof window._peerId === "string" && window._peerId.length === 64 ? window._peerId : null)),
    );
    await until(`pwa ${name}: registered with the relay`, 30_000, () =>
      // Not "SW registered: ...": the relay's own registration, or the desktop's first offer
      // can find the PWA offline (`peer_offline`).
      p.console.some((t) => t.startsWith("Registered with relay")),
    );
    log(`pwa ${name} is ${p.peerId.slice(0, 8)}`);
    return p;
  }

  constructor(page, name) {
    this.page = page;
    this.name = name;
    this.console = [];
    this.consoleAt = [];
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
      async (to, text) => {
        window.openChat(to);
        await new Promise((r) => setTimeout(r, 100));
        document.getElementById("message-input").value = text;
        await window.sendMessage();
      },
      to,
      text,
    );
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

  async verified(peerId) {
    return this.console.some((t) => t.includes("direct channel verified with") && t.includes(peerId.slice(0, 8)));
  }
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
  const profile = mkdtempSync(join(work, "chrome-1-"));
  const browser = await launchBrowser(profile);
  cleanups.push(() => browser.close().catch(() => {}));
  const bot = new Bot("one", ctx.relayPort, ctx.bindIp);
  const ready = await bot.wait("ready", (e) => e.event === "ready");
  bot.peerId = ready.peer_id;
  await bot.wait("registered", (e) => e.event === "relay" && e.state.includes("Registered"));
  const pwa = await Pwa.open(browser, ctx.pwaPort, "one");

  const code = await pwa.showCode();
  if (!/^[0-9a-f]{100,}$/i.test(code)) throw new Error(`${tag}: unexpected PWA code ${code.slice(0, 40)}`);
  bot.send(`pair ${code}`);
  await bot.wait("paired", (e) => e.event === "paired" && e.peer_id === pwa.peerId);
  await bot.wait("direct path", (e) => e.event === "path" && e.peer_id === pwa.peerId && e.state === "Direct", 45_000);
  await until(`${tag}: the PWA adds the desktop as a secure contact`, 30_000, () => pwa.hasContact(bot.peerId));
  await bothVerified(bot, pwa, tag);
  log(`${tag}: paired, direct data channel, bindings verified`);
  await chatBothWays(bot, pwa, tag);
  await bot.quit();
  await browser.close();
  return bot;
}

async function casePwaPastesDesktopCode(ctx) {
  const tag = "case 2 (desktop code -> PWA paste)";
  const profile = mkdtempSync(join(work, "chrome-2-"));
  let browser = await launchBrowser(profile);
  cleanups.push(() => browser.close().catch(() => {}));
  const bot = new Bot("two", ctx.relayPort, ctx.bindIp);
  const ready = await bot.wait("ready", (e) => e.event === "ready");
  bot.peerId = ready.peer_id;
  await bot.wait("registered", (e) => e.event === "relay" && e.state.includes("Registered"));
  let pwa = await Pwa.open(browser, ctx.pwaPort, "two");

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
  await browser.close();
  await bot.wait("PWA offline", (e) => e.event === "path" && e.peer_id === pwa.peerId && e.state === "Offline", 45_000, mark);
  const queuedMark = bot.events.length;
  const waiting = "sent while you were away";
  bot.send(`send ${pwa.peerId} ${waiting}`);
  const sent = await bot.wait("queued", (e) => e.event === "sent", 10_000, queuedMark);
  if (sent.state !== "Queued") throw new Error(`${tag3}: expected the message to queue, got ${sent.state}`);
  browser = await launchBrowser(profile);
  cleanups.push(() => browser.close().catch(() => {}));
  pwa = await Pwa.open(browser, ctx.pwaPort, "two-again");
  await pwa.waitReceived(bot.peerId, waiting, 60_000);
  log(`${tag3}: queued message delivered after the PWA came back`);
  await bot.quit();
  await browser.close();
  return bot;
}

async function caseTamperedBindingIsRefused(ctx) {
  const tag = "case 4 (tampered channel binding)";
  const profile = mkdtempSync(join(work, "chrome-4-"));
  const browser = await launchBrowser(profile);
  cleanups.push(() => browser.close().catch(() => {}));
  const bot = new Bot("four", ctx.relayPort, ctx.bindIp);
  const ready = await bot.wait("ready", (e) => e.event === "ready");
  bot.peerId = ready.peer_id;
  await bot.wait("registered", (e) => e.event === "relay" && e.state.includes("Registered"));
  const pwa = await Pwa.open(browser, ctx.pwaPort, "four", { tamperBinding: true });

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
  const profile = mkdtempSync(join(work, "chrome-5-"));
  const browser = await launchBrowser(profile, { media: true });
  cleanups.push(() => browser.close().catch(() => {}));
  const bot = new Bot("calls", ctx.relayPort, ctx.bindIp);
  const ready = await bot.wait("ready", (e) => e.event === "ready");
  bot.peerId = ready.peer_id;
  await bot.wait("registered", (e) => e.event === "relay" && e.state.includes("Registered"));
  const pwa = await Pwa.open(browser, ctx.pwaPort, "calls");
  const code = await pwa.showCode();
  bot.send(`pair ${code}`);
  await bot.wait("direct path", (e) => e.event === "path" && e.peer_id === pwa.peerId && e.state === "Direct", 45_000);
  await bothVerified(bot, pwa, "calls");

  // Case 5: the desktop calls.
  let tag = "case 5 (desktop video-calls the PWA)";
  const mark = bot.events.length;
  bot.send(`call ${pwa.peerId} video`);
  const out = await bot.wait("outgoing", (e) => e.event === "call" && e.state === "Outgoing", 10_000, mark);
  await until(`${tag}: the PWA rings`, 20_000, () =>
    pwa.page.evaluate(() => !document.getElementById("incoming-call-notification")?.classList.contains("hidden")),
  );
  await pwa.page.evaluate(() => window.acceptIncomingCall());
  await bot.wait("active", (e) => e.event === "call" && e.call_id === out.call_id && e.state === "Active", 30_000, mark);
  const m6 = await botMedia(bot, out.call_id, 50, `${tag}: the desktop receives Chromium's VP8 and Opus`);
  const s6 = await pwaDecodes(pwa, `${tag}: Chromium decodes the desktop's VP8 and Opus`);
  log(`${tag}: desktop got audio ${m6.audio_rx} / video ${m6.video_rx} packets; PWA decoded ${s6.videoFrames} frames, ${s6.audioSamples} audio samples`);
  bot.send(`hangup ${out.call_id}`);
  await bot.wait("ended", (e) => e.event === "call" && e.call_id === out.call_id && e.state === "Ended(HungUp)", 10_000, mark);
  await until(`${tag}: the PWA closes its call connection`, 15_000, async () => (await pwa.openCallPcs()) === 0);
  log(`${tag}: hung up by the desktop`);
  if (process.env.INTEROP_PWA_CALLS !== "0") {
    // Case 6: the PWA calls (see the header).
    tag = "case 6 (PWA video-calls the desktop)";
    await pwa.page.evaluate((peer) => {
      window.openChat(peer);
      return window.initiateCall(peer, true);
    }, bot.peerId);
    const ring = await bot.wait("incoming call", (e) => e.event === "call" && e.state === "Incoming" && e.peer_id === pwa.peerId, 30_000);
    if (!ring.video) throw new Error(`${tag}: the PWA's offer should carry video`);
    bot.send(`accept ${ring.call_id}`);
    await bot.wait("active", (e) => e.event === "call" && e.call_id === ring.call_id && e.state === "Active", 30_000);
    const m5 = await botMedia(bot, ring.call_id, 50, `${tag}: the desktop receives Chromium's VP8 and Opus`);
    const s5 = await pwaDecodes(pwa, `${tag}: Chromium decodes the desktop's VP8 and Opus`);
    log(`${tag}: desktop got audio ${m5.audio_rx} / video ${m5.video_rx} packets; PWA decoded ${s5.videoFrames} frames, ${s5.audioSamples} audio samples`);
    log(`${tag}: selected-pair changes on the PWA's connections: ${JSON.stringify(await pairChanges(pwa))}`);
    await pwa.page.evaluate(() => window.hangupCall());
    await bot.wait("remote hang-up", (e) => e.event === "call" && e.call_id === ring.call_id && e.state === "Ended(RemoteHungUp)", 15_000);
    log(`${tag}: hung up by the PWA`);
  } else {
    log("case 6 (PWA video-calls the desktop): skipped (INTEROP_PWA_CALLS=0)");
  }
  await bot.quit();
  await browser.close();
  return bot;
}

/// Selected-pair changes of the PWA's open connections, for a log line.
async function pairChanges(pwa) {
  return pwa.page.evaluate(() => (window.__pcs || []).filter((pc) => pc.connectionState !== "closed").map((pc) => pc.__pairChanges.length));
}

async function casePwaOffersWithMedia(ctx) {
  const tag = "case 7 (PWA-offered data channel with media permission)";
  const profile = mkdtempSync(join(work, "chrome-7-"));
  const browser = await launchBrowser(profile, { media: true });
  cleanups.push(() => browser.close().catch(() => {}));
  const bot = new Bot("seven", ctx.relayPort, ctx.bindIp);
  const ready = await bot.wait("ready", (e) => e.event === "ready");
  bot.peerId = ready.peer_id;
  await bot.wait("registered", (e) => e.event === "relay" && e.state.includes("Registered"));
  const pwa = await Pwa.open(browser, ctx.pwaPort, "seven");
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
  await browser.close();
  return bot;
}

// ── Main ─────────────────────────────────────────────────────

async function main() {
  if (!existsSync(botBin)) throw new Error(`bot binary not found: ${botBin} (cargo build -p parolnet-app --example bot)`);
  const bindIp = mode === "mdns" ? lanIPv4() : "127.0.0.1";
  log(`ICE mode ${mode}, desktop host candidate ${bindIp}`);
  const relayPort = await startRelay();
  const pwaPort = await startPwaServer(relayPort);
  const ctx = { relayPort, pwaPort, bindIp };

  const bots = [];
  bots.push(await caseDesktopEntersPwaCode(ctx));
  bots.push(await casePwaPastesDesktopCode(ctx));
  bots.push(await caseTamperedBindingIsRefused(ctx));
  if (process.env.INTEROP_CALLS !== "0") bots.push(await caseCalls(ctx));
  bots.push(await casePwaOffersWithMedia(ctx));

  if (mode === "mdns") {
    const resolved = bots.some((b) => b.stderr.some((l) => l.includes("mDNS traffic received")));
    if (!resolved) throw new Error("mDNS mode: the desktop never received an mDNS answer for Chromium's .local candidates");
    log("mDNS: the desktop resolved Chromium's .local candidates");
  }
  const cases = 5 + (process.env.INTEROP_CALLS === "0" ? 0 : process.env.INTEROP_PWA_CALLS === "0" ? 1 : 2);
  log(`PASS: desktop <-> PWA interop (${cases} cases)`);
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
