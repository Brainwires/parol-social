// End-to-end test of the web engine in real browsers, against the real relay (default
// signaling-only profile) and the native headless bot. Everything runs on this machine and
// no request may leave it: that is asserted.
//
//   deno task wasm && deno task e2e:build        (the harness page into e2e/dist)
//   cargo build -p parolnet-relay-server --bin parolnet-relay -p parolnet-app --example bot
//   npm ci && npx playwright install chromium firefox     (at the repository root)
//   E2E_BROWSER=chromium|firefox|webkit node web/tests/engine/e2e/run.mjs
//
// Environment: PAROLNET_RELAY_BIN, PAROLNET_BOT_BIN (default: target/debug), E2E_ICE
// (`loopback` on macOS/Windows, `host` for WebKit and on Linux), E2E_SKIP_BOT=1 to run only
// the browser-to-browser scenario, E2E_VERBOSE=1.
//
// Scenarios:
//   1. web ↔ web: register, pair by code, verified channel, chat both ways; one goes
//      offline, the other's messages stay Queued (one is edited, one taken back); it comes
//      back with the same profile and the queue flushes in order; wipe gives a new identity.
//   2. web presents, desktop scans: pair, verified on both sides, chat both ways.
//   3. desktop presents, web pastes: pair, verified, chat both ways; the web client goes
//      away, the desktop queues, the web client returns and receives.
//   4. tampered binding: the desktop refuses the channel and so does the web client.
import { spawn } from "node:child_process";
import { createReadStream, existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import { connect as netConnect, createServer as netCreateServer } from "node:net";
import { networkInterfaces, tmpdir } from "node:os";
import { dirname, extname, join, normalize, resolve, sep } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { chromium, firefox, webkit } from "playwright";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../../../..");
const dist = join(here, "dist");
const exe = process.platform === "win32" ? ".exe" : "";
const targetDir = process.env.CARGO_TARGET_DIR || join(root, "target");
const relayBin = process.env.PAROLNET_RELAY_BIN || join(targetDir, "debug", `parolnet-relay${exe}`);
const botBin = process.env.PAROLNET_BOT_BIN || join(targetDir, "debug", "examples", `bot${exe}`);
const browserName = process.env.E2E_BROWSER || "chromium";
const engines = { chromium, firefox, webkit };
if (!engines[browserName]) {
  console.error(`E2E_BROWSER must be chromium, firefox or webkit (got ${browserName})`);
  process.exit(2);
}
const mode = process.env.E2E_ICE ||
  (browserName === "webkit" || process.platform === "linux" ? "host" : "loopback");
const skipBot = process.env.E2E_SKIP_BOT === "1";
const verbose = process.env.E2E_VERBOSE === "1";

const cleanups = [];
const work = mkdtempSync(join(tmpdir(), "parolnet-web-e2e-"));
cleanups.push(() => rmSync(work, { recursive: true, force: true }));
/** Every URL a page asked for, and every host the dead proxy was asked for. */
const requested = [];
const refusedHosts = new Set();
/** Pages that are open, for the report when something fails. */
const openWebs = new Set();

function log(...args) {
  console.log(`[${new Date().toISOString().slice(11, 23)}]`, ...args);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function until(what, ms, fn, every = 150) {
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
  throw new Error(
    `timed out after ${ms} ms waiting for ${what}${last ? ` (${last.message})` : ""}`,
  );
}

function assert(cond, message) {
  if (!cond) throw new Error(`assertion failed: ${message}`);
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

function lanIPv4() {
  for (const list of Object.values(networkInterfaces())) {
    for (const a of list ?? []) if (a.family === "IPv4" && !a.internal) return a.address;
  }
  throw new Error(`no non-loopback IPv4 interface for ${mode} mode`);
}

// ── Relay, and the server that fronts it ─────────────────────────

async function startRelay() {
  if (!existsSync(relayBin)) throw new Error(`relay binary not found: ${relayBin}`);
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
    }));
  return port;
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".wasm": "application/wasm",
};

/** Serves the harness and passes everything else (`/ws`, `/turn-credentials`) to the relay. */
async function startServer(relayPort) {
  if (!existsSync(join(dist, "app.js"))) {
    throw new Error(`harness not built: ${dist} (deno task e2e:build)`);
  }
  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://x");
    let rel = decodeURIComponent(url.pathname);
    if (rel.endsWith("/")) rel += "index.html";
    const file = normalize(join(dist, rel));
    if (file.startsWith(dist + sep) && existsSync(file) && statSync(file).isFile()) {
      res.writeHead(200, {
        "content-type": MIME[extname(file)] ?? "application/octet-stream",
        "cache-control": "no-store",
      });
      createReadStream(file).pipe(res);
      return;
    }
    const upstream = httpRequest(
      {
        host: "127.0.0.1",
        port: relayPort,
        method: req.method,
        path: req.url,
        headers: req.headers,
      },
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
  server.on("upgrade", (req, socket, head) => {
    const up = netConnect(relayPort, "127.0.0.1", () => {
      let raw = `${req.method} ${req.url} HTTP/1.1\r\n`;
      for (let i = 0; i < req.rawHeaders.length; i += 2) {
        raw += `${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}\r\n`;
      }
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
  return port;
}

/** A proxy that refuses everything and remembers what it was asked for. */
let deadProxyPort = 0;
async function deadProxy() {
  if (deadProxyPort) return deadProxyPort;
  const note = (target) => {
    try {
      refusedHosts.add(target.includes("://") ? new URL(target).host : target);
    } catch {
      refusedHosts.add(String(target));
    }
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

// ── Browser ──────────────────────────────────────────────────────

/** A browser with its profile in `profileDir`: IndexedDB survives a relaunch. */
async function launchBrowser(profileDir) {
  if (browserName === "chromium") {
    const args = [
      "--no-first-run",
      "--no-default-browser-check",
      // Nothing can leave the machine: any other host fails to resolve.
      "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost",
    ];
    if (mode === "loopback") {
      args.push(
        "--allow-loopback-in-peer-connection",
        "--disable-features=WebRtcHideLocalIpsWithMdns",
      );
    }
    return chromium.launchPersistentContext(profileDir, {
      headless: true,
      channel: process.env.CHROME_PATH ? undefined : "chromium",
      executablePath: process.env.CHROME_PATH || undefined,
      chromiumSandbox: !(process.platform === "linux"),
      args,
    });
  }
  const proxy = { server: `http://127.0.0.1:${await deadProxy()}`, bypass: "127.0.0.1" };
  if (browserName === "firefox") {
    return firefox.launchPersistentContext(profileDir, {
      headless: true,
      firefoxUserPrefs: {
        "media.peerconnection.ice.obfuscate_host_addresses": mode === "mdns",
        "media.peerconnection.ice.loopback": mode === "loopback",
      },
      proxy,
    });
  }
  // See `holdMedia`.
  return webkit.launchPersistentContext(profileDir, {
    headless: true,
    proxy,
    permissions: ["camera", "microphone"],
  });
}

/**
 * WebKit only. Without media permission WebKit hides its host addresses behind mDNS names,
 * and a container has no mDNS responder, so two WebKit pages could never reach each other
 * here. A page that captures media gets real host candidates (as a page in a call would).
 */
async function holdMedia(page) {
  if (browserName !== "webkit") return;
  await page.evaluate(async () => {
    globalThis.__held = await navigator.mediaDevices.getUserMedia({ audio: true });
  });
}

/** The engine harness in a page, driven through `globalThis.__parolnetTest`. */
class Web {
  static async open(name, port, { profile, tamperBinding = false } = {}) {
    const dir = profile ?? mkdtempSync(join(work, `${browserName}-${name}-`));
    const context = await launchBrowser(dir);
    cleanups.push(() => context.close().catch(() => {}));
    const page = context.pages()[0] ?? (await context.newPage());
    const web = new Web(name, dir, context, page, port);
    openWebs.add(web);
    page.on("request", (r) => requested.push(r.url()));
    page.on("websocket", (ws) => requested.push(ws.url()));
    page.on("console", (m) => {
      web.console.push(m.text());
      if (verbose) log(`[${name}]`, m.text());
    });
    page.on("pageerror", (e) => web.errors.push(String(e)));
    if (tamperBinding) {
      // Once connected, the local description the page binds names a fingerprint that is not
      // its certificate's: the binding then disagrees with what the other side saw.
      await page.addInitScript(() => {
        const desc = Object.getOwnPropertyDescriptor(
          RTCPeerConnection.prototype,
          "localDescription",
        );
        Object.defineProperty(RTCPeerConnection.prototype, "localDescription", {
          configurable: true,
          get() {
            const d = desc.get.call(this);
            if (!d || this.connectionState !== "connected") return d;
            const fake = Array(32).fill("AA").join(":");
            return {
              type: d.type,
              sdp: d.sdp.replace(/a=fingerprint:(\S+) [0-9A-Fa-f:]+/g, `a=fingerprint:$1 ${fake}`),
            };
          },
        });
      });
    }
    // Proof that connections are made through the global constructor at call time.
    await page.addInitScript(() => {
      const Real = globalThis.RTCPeerConnection;
      globalThis.__pcs = [];
      globalThis.RTCPeerConnection = function (...args) {
        const pc = new Real(...args);
        globalThis.__pcs.push({ pc, config: args[0] });
        return pc;
      };
      globalThis.RTCPeerConnection.prototype = Real.prototype;
    });
    await page.goto(`http://127.0.0.1:${port}/index.html`);
    await until(`${name}: the engine to start`, 30_000, async () => {
      const h = await page.evaluate(() => globalThis.__harness);
      if (h?.state === "failed") throw new Error(`engine failed to start: ${h.error}`);
      return h?.state === "ready";
    });
    web.peerId = (await page.evaluate(() => globalThis.__parolnetTest.ready())).peerId;
    await holdMedia(page);
    await until(
      `${name}: relay registration`,
      20_000,
      () => page.evaluate(() => globalThis.__parolnetTest.relayRegistered()),
    );
    return web;
  }

  constructor(name, profile, context, page, port) {
    this.name = name;
    this.profile = profile;
    this.context = context;
    this.page = page;
    this.port = port;
    this.console = [];
    this.errors = [];
    this.peerId = "";
  }

  hook(method, ...args) {
    return this.page.evaluate(([m, a]) => globalThis.__parolnetTest[m](...a), [method, args]);
  }

  engine(method, ...args) {
    return this.page.evaluate(([m, a]) => globalThis.__engine[m](...a), [method, args]);
  }

  async waitPath(peer, state, ms = 45_000) {
    await until(
      `${this.name}: path to ${peer.slice(0, 8)} = ${state}`,
      ms,
      async () => (await this.hook("pathState", peer)) === state,
    );
  }

  async waitMessage(peer, direction, text, state, ms = 30_000) {
    await until(
      `${this.name}: ${direction} "${text}" ${state ?? ""}`,
      ms,
      async () =>
        (await this.hook("messages", peer)).some((m) =>
          m.direction === direction && m.text === text && (!state || m.state === state)
        ),
    );
  }

  async close() {
    openWebs.delete(this);
    await this.context.close();
  }

  /** What the page knows, for a failure report: console, path events, ICE candidates. */
  async report() {
    const state = await this.page.evaluate(() => ({
      events: (globalThis.__events ?? []).filter((e) => e.kind !== "Message").map((e) =>
        `${e.kind}:${e.state?.kind ?? e.state ?? e.text ?? ""}`
      ),
      candidates: (globalThis.__pcs ?? []).map((p) =>
        `${p.pc.connectionState}/${p.pc.iceConnectionState} ` +
        (p.pc.localDescription?.sdp.match(/a=candidate:.*/g) ?? []).map((c) =>
          c.split(" ").slice(4, 8).join(" ")
        ).join(" | ")
      ),
    })).catch((e) => ({ error: String(e) }));
    return { console: this.console.slice(-20), errors: this.errors, ...state };
  }
}

// ── The native bot ───────────────────────────────────────────────

class Bot {
  static async start(name, relayPort, bindIp) {
    if (!existsSync(botBin)) throw new Error(`bot binary not found: ${botBin}`);
    const bot = new Bot(name, relayPort, bindIp);
    bot.peerId = (await bot.wait("ready", (e) => e.event === "ready")).peer_id;
    await bot.wait("registered", (e) => e.event === "relay" && e.state.includes("Registered"));
    return bot;
  }

  constructor(name, relayPort, bindIp) {
    this.name = name;
    this.events = [];
    this.child = spawn(
      botBin,
      [
        "--relay",
        `ws://127.0.0.1:${relayPort}/ws`,
        "--data-dir",
        join(work, `bot-${name}`),
        "--host-only",
        "--bind",
        bindIp,
      ],
      {
        env: { ...process.env, RUST_LOG: "warn,parolnet_app=info" },
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    cleanups.push(() => this.child.kill());
    createInterface({ input: this.child.stdout }).on("line", (line) => {
      try {
        this.events.push(JSON.parse(line));
        if (verbose) log(`[bot ${name}]`, line);
      } catch { /* not an event */ }
    });
    createInterface({ input: this.child.stderr }).on("line", (line) => {
      if (verbose) log(`[bot ${name} stderr]`, line);
    });
    this.exited = new Promise((r) => this.child.on("exit", r));
  }

  send(line) {
    this.child.stdin.write(line + "\n");
  }

  wait(what, pred, ms = 30_000, from = 0) {
    return until(`bot ${this.name}: ${what}`, ms, () => this.events.slice(from).find(pred), 100);
  }

  async sendText(peer, text) {
    const mark = this.events.length;
    this.send(`send ${peer} ${text}`);
    return (await this.wait(
      "sent",
      (e) => e.event === "sent" || e.event === "error",
      10_000,
      mark,
    ));
  }

  async quit() {
    this.send("quit");
    await Promise.race([this.exited, sleep(5000)]);
  }
}

// ── Scenarios ────────────────────────────────────────────────────

async function webToWeb(port) {
  const tag = "1 (web ↔ web)";
  const a = await Web.open("alice", port);
  let b = await Web.open("bob", port);
  assert(a.peerId !== b.peerId && /^[0-9a-f]{64}$/.test(a.peerId), "two identities");
  assert(
    a.console.some((l) => l.startsWith("Registered with relay. Profile: signaling-only")),
    "the registered line",
  );

  const code = await a.hook("showPairingCode");
  assert(/^[0-9a-f]{100,}$/.test(code), "a pairing code");
  await b.hook("pairWithCode", code);
  await a.waitPath(b.peerId, "direct");
  await b.waitPath(a.peerId, "direct");
  assert((await a.hook("contacts")).includes(b.peerId), "alice has bob");
  for (const w of [a, b]) {
    assert(
      w.console.some((l) => l.includes("[WebRTC] direct channel verified with")),
      `${w.name}: verified line`,
    );
  }
  log(`${tag}: paired, channel verified on both sides`);

  assert(
    (await a.hook("sendText", b.peerId, "hello bob")).state === "Sent",
    "sent on the verified channel",
  );
  await b.waitMessage(a.peerId, "received", "hello bob");
  await b.hook("sendText", a.peerId, "hello alice ✓");
  await a.waitMessage(b.peerId, "received", "hello alice ✓");
  log(`${tag}: chat both ways`);

  // Bob goes offline.
  await b.close();
  await until(
    "alice to see bob leave",
    45_000,
    async () => (await a.hook("pathState", b.peerId)) !== "direct",
  );
  const queued = [];
  for (
    const text of ["while you were away 1", "typo mesage", "regretted", "while you were away 4"]
  ) {
    const r = await a.page.evaluate(([p, t]) => globalThis.__engine.sendText(p, t), [
      b.peerId,
      text,
    ]);
    assert(r.state === "Queued", `"${text}" is queued, not ${r.state}`);
    queued.push(r);
  }
  await a.engine("editQueued", queued[1].id, "typo message");
  await a.engine("takeBack", queued[2].id);
  const waiting = (await a.hook("messages", b.peerId)).filter((m) => m.state === "Queued").map((
    m,
  ) => m.text);
  assert(
    JSON.stringify(waiting) ===
      JSON.stringify(["while you were away 1", "typo message", "while you were away 4"]),
    `queue: ${waiting}`,
  );
  assert(
    (await a.page.evaluate(
      (p) => globalThis.__engine.snapshot().contacts.find((c) => c.contact.peerId === p).queued,
      b.peerId,
    )) ===
      3,
    "three queued",
  );
  await sleep(1500);
  assert(
    (await a.hook("messages", b.peerId)).filter((m) => m.state === "Queued").length === 3,
    "they stay queued",
  );
  log(`${tag}: bob offline, alice's messages queued (one edited, one taken back)`);

  // Bob comes back with the same profile: identity, contact and session come from IndexedDB.
  b = await Web.open("bob", port, { profile: b.profile });
  assert(b.peerId === (await a.hook("contacts"))[0], "bob kept his identity");
  assert((await b.hook("contacts")).includes(a.peerId), "bob kept his contact");
  await a.waitPath(b.peerId, "direct", 60_000);
  await b.waitMessage(a.peerId, "received", "while you were away 4", undefined, 60_000);
  const got = (await b.hook("messages", a.peerId)).filter((m) => m.direction === "received").map((
    m,
  ) => m.text);
  assert(
    JSON.stringify(got) ===
      JSON.stringify([
        "hello bob",
        "while you were away 1",
        "typo message",
        "while you were away 4",
      ]),
    `bob received, in order: ${got}`,
  );
  await until(
    "alice's queue to empty",
    10_000,
    async () => !(await a.hook("messages", b.peerId)).some((m) => m.state === "Queued"),
  );
  // The ratchet survived the restart in both directions.
  await b.hook("sendText", a.peerId, "back again");
  await a.waitMessage(b.peerId, "received", "back again");
  log(`${tag}: bob back, queue flushed in order`);

  for (const w of [a, b]) {
    const servers = await w.hook("iceServers");
    assert(
      servers.length === 0,
      `${w.name}: no ICE servers in the harness, got ${JSON.stringify(servers)}`,
    );
    const pcs = await w.page.evaluate(() => globalThis.__pcs.map((p) => p.config));
    assert(pcs.length >= 1, `${w.name}: connections were made through the global constructor`);
    assert(
      pcs.every((c) => c.iceServers.length === 0 && c.iceTransportPolicy === "all"),
      `${w.name}: direct policy, no servers`,
    );
    assert(
      !w.console.some((l) => l.includes("[WebRTC] ICE servers from")),
      `${w.name}: no ICE servers were learned`,
    );
    assert(w.errors.length === 0, `${w.name}: page errors ${w.errors}`);
  }

  // "Delete all data on this device".
  const old = b.peerId;
  await b.page.evaluate(() => globalThis.__engine.wipe());
  const dbs = await b.page.evaluate(
    async () => (indexedDB.databases ? (await indexedDB.databases()).map((d) => d.name) : []),
  );
  assert(!dbs.includes("parolnet-web"), `the database is gone, found ${dbs}`);
  await b.page.reload();
  await until("a new identity after the wipe", 30_000, async () => {
    const id = await b.page.evaluate(() =>
      globalThis.__harness?.state === "ready" && globalThis.__engine?.peerId
    );
    return id && id !== old;
  });
  assert((await b.hook("contacts")).length === 0, "nothing survived the wipe");
  log(`${tag}: wipe gives a new identity`);
  await a.close();
  await b.close();
}

async function chatBothWays(web, bot, tag) {
  const fromBot = `hello from the desktop (${tag})`;
  const sent = await bot.sendText(web.peerId, fromBot);
  assert(sent.state === "Sent", `the desktop's message was ${sent.state ?? sent.text}`);
  await web.waitMessage(bot.peerId, "received", fromBot);
  const fromWeb = `hello from the web (${tag})`;
  const mark = bot.events.length;
  assert(
    (await web.hook("sendText", bot.peerId, fromWeb)).state === "Sent",
    "the web's message was sent",
  );
  await bot.wait(
    "the web's message",
    (e) => e.event === "message" && e.from === web.peerId && e.text === fromWeb,
    20_000,
    mark,
  );
}

async function webPresentsToDesktop(port, relayPort, bindIp) {
  const tag = "2 (web code → desktop)";
  const bot = await Bot.start("two", relayPort, bindIp);
  const web = await Web.open("two", port);
  const code = await web.hook("showPairingCode");
  bot.send(`pair ${code}`);
  await bot.wait("paired", (e) => e.event === "paired" && e.peer_id === web.peerId);
  await bot.wait(
    "a direct path",
    (e) => e.event === "path" && e.peer_id === web.peerId && e.state === "Direct",
    45_000,
  );
  await web.waitPath(bot.peerId, "direct");
  assert(
    (await web.hook("contacts")).includes(bot.peerId),
    "the web client has the desktop as a contact",
  );
  // The presenter learned the desktop's identity key from the bootstrap envelope.
  const key = await web.page.evaluate(
    (p) =>
      globalThis.__engine.snapshot().contacts.find((c) => c.contact.peerId === p).contact
        .identityKey,
    bot.peerId,
  );
  const ready = bot.events.find((e) => e.event === "ready");
  assert(key === ready.public_key, "identity key of the desktop");
  await chatBothWays(web, bot, "case 2");
  log(`${tag}: paired, verified, chat both ways`);
  await bot.quit();
  await web.close();
}

async function desktopPresentsToWeb(port, relayPort, bindIp) {
  const tag = "3 (desktop code → web)";
  const bot = await Bot.start("three", relayPort, bindIp);
  let web = await Web.open("three", port);
  bot.send("code");
  const { code } = await bot.wait("its code", (e) => e.event === "code");
  await web.hook("pairWithCode", code);
  await until(
    "the contact on the web client",
    10_000,
    async () => (await web.hook("contacts")).includes(bot.peerId),
  );
  await bot.wait("the contact", (e) => e.event === "contact" && e.peer_id === web.peerId, 45_000);
  await bot.wait(
    "a direct path",
    (e) => e.event === "path" && e.peer_id === web.peerId && e.state === "Direct",
    45_000,
  );
  await web.waitPath(bot.peerId, "direct");
  // The web client scanned, so it offered: its data connection is the offer side.
  const offered = await web.page.evaluate(() =>
    globalThis.__pcs.some((p) =>
      p.pc.connectionState === "connected" && p.pc.localDescription?.type === "offer"
    )
  );
  assert(offered, "the web client was the offerer");
  await chatBothWays(web, bot, "case 3");
  log(`${tag}: paired, verified, chat both ways`);

  // The web client goes away; the desktop queues; the web client returns and receives.
  await web.close();
  await bot.wait(
    "the web client to go offline",
    (e) => e.event === "path" && e.peer_id === web.peerId && e.state === "Offline",
    45_000,
  );
  const away = await bot.sendText(web.peerId, "sent while you were away");
  assert(away.state === "Queued", `the desktop queued (${away.state})`);
  web = await Web.open("three", port, { profile: web.profile });
  await web.waitMessage(bot.peerId, "received", "sent while you were away", undefined, 60_000);
  await web.waitPath(bot.peerId, "direct");
  await chatBothWays(web, bot, "case 3, after the restart");
  log(`${tag}: the desktop's queue reached the returning web client`);
  await bot.quit();
  await web.close();
}

async function tamperedBinding(port, relayPort, bindIp) {
  const tag = "4 (tampered channel binding)";
  const bot = await Bot.start("four", relayPort, bindIp);
  const web = await Web.open("four", port, { tamperBinding: true });
  const code = await web.hook("showPairingCode");
  bot.send(`pair ${code}`);
  await bot.wait("paired", (e) => e.event === "paired" && e.peer_id === web.peerId);
  await bot.wait(
    "the end-to-end check to fail",
    (e) => e.event === "notice" && e.text.includes("failed its end-to-end check"),
    45_000,
  );
  await bot.wait(
    "BindingFailed",
    (e) => e.event === "path" && e.peer_id === web.peerId && e.state === "BindingFailed",
    10_000,
  );
  assert(
    !bot.events.some((e) => e.event === "path" && e.peer_id === web.peerId && e.state === "Direct"),
    "the desktop never reported a direct path",
  );
  // The web client compares the desktop's binding with the same (tampered) description.
  await until(
    "the web client to refuse too",
    20_000,
    async () => (await web.hook("pathState", bot.peerId)) === "binding-failed",
  );
  assert(
    !web.console.some((l) => l.includes("direct channel verified")),
    "the web client never verified",
  );
  const held = await bot.sendText(web.peerId, "must not be delivered on a refused channel");
  assert(held.state === "Queued", `the desktop held its message (${held.state})`);
  const webHeld = await web.hook("sendText", bot.peerId, "nor this one");
  assert(webHeld.state === "Queued", `the web client held its message (${webHeld.state})`);
  log(`${tag}: refused on both sides`);
  await bot.quit();
  await web.close();
}

// ── Main ─────────────────────────────────────────────────────────

async function main() {
  const relayPort = await startRelay();
  const port = await startServer(relayPort);
  const bindIp = mode === "loopback" ? "127.0.0.1" : lanIPv4();
  log(
    `${browserName}, ICE mode ${mode}; harness on http://127.0.0.1:${port}/, relay on :${relayPort}`,
  );
  await webToWeb(port);
  if (skipBot) {
    log("bot scenarios skipped (E2E_SKIP_BOT=1)");
  } else {
    await webPresentsToDesktop(port, relayPort, bindIp);
    await desktopPresentsToWeb(port, relayPort, bindIp);
    await tamperedBinding(port, relayPort, bindIp);
  }
  // Nothing left the machine.
  const allowed = new Set([`127.0.0.1:${port}`]);
  const outside = requested.filter((u) => !allowed.has(new URL(u).host));
  assert(outside.length === 0, `requests left localhost: ${[...new Set(outside)].join(", ")}`);
  assert(
    refusedHosts.size === 0,
    `the browser asked the proxy for: ${[...refusedHosts].join(", ")}`,
  );
  const paths = new Set(requested.map((u) => new URL(u).pathname));
  assert(
    paths.has("/ws") && paths.has("/turn-credentials"),
    `expected paths, saw ${[...paths].join(" ")}`,
  );
  log(`requests: ${requested.length}, all to 127.0.0.1:${port} (${[...paths].join(" ")})`);
  log(`PASS (${browserName})`);
}

let failed = false;
try {
  await main();
} catch (e) {
  failed = true;
  console.error(`FAIL (${browserName}): ${e.stack ?? e}`);
  for (const w of openWebs) console.error(`[${w.name}]`, JSON.stringify(await w.report(), null, 1));
} finally {
  for (const c of cleanups.reverse()) {
    try {
      await c();
    } catch { /* best effort */ }
  }
}
process.exit(failed ? 1 : 0);
