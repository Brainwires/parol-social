// Desktop <-> PWA chat interop test.
//
//   node apps/desktop/interop/pwa-chat.mjs
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

async function launchBrowser(profileDir) {
  const args = [
    "--no-first-run",
    "--no-default-browser-check",
    // Nothing leaves the machine: the PWA's STUN fallback (parol.social) and any other remote
    // host fail to resolve, so ICE uses host candidates only.
    "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost",
  ];
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
    page.on("console", (msg) => {
      const text = msg.text();
      p.console.push(text);
      if (verbose) log(`[pwa ${name}]`, text);
    });
    page.on("pageerror", (e) => log(`[pwa ${name}] PAGE ERROR`, e.message));
    await page.goto(`http://127.0.0.1:${port}/index.html`, { waitUntil: "domcontentloaded" });
    p.peerId = await until(`pwa ${name}: identity`, 30_000, () =>
      page.evaluate(() => (typeof window._peerId === "string" && window._peerId.length === 64 ? window._peerId : null)),
    );
    await until(`pwa ${name}: registered with the relay`, 30_000, () =>
      p.console.some((t) => /registered/i.test(t) && !/unregistered/i.test(t)),
    );
    log(`pwa ${name} is ${p.peerId.slice(0, 8)}`);
    return p;
  }

  constructor(page, name) {
    this.page = page;
    this.name = name;
    this.console = [];
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

  if (mode === "mdns") {
    const resolved = bots.some((b) => b.stderr.some((l) => l.includes("mDNS traffic received")));
    if (!resolved) throw new Error("mDNS mode: the desktop never received an mDNS answer for Chromium's .local candidates");
    log("mDNS: the desktop resolved Chromium's .local candidates");
  }
  log("PASS: desktop <-> PWA chat interop (4 cases)");
}

let status = 0;
try {
  await main();
} catch (e) {
  status = 1;
  console.error(`FAIL: ${e.message}`);
}
for (const c of cleanups.reverse()) {
  try {
    await c();
  } catch {}
}
process.exit(status);
