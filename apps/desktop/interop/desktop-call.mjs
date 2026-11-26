// The desktop app's call media against the headless bot (no window, no browser):
//
//   node apps/desktop/interop/desktop-call.mjs <parolnet-desktop binary>
//
// A relay (signaling-only), the bot showing its code and accepting calls, and
// `parolnet-desktop --call-check --video`: the desktop pairs, video-calls the bot and runs its
// call session (the test pattern through libvpx). Passes when the desktop decoded the bot's
// VP8 and Opus (call-check's own exit status) and the bot received the desktop's VP8.
//
// Environment: PAROLNET_RELAY_BIN, PAROLNET_BOT_BIN (default: $CARGO_TARGET_DIR or target/,
// debug), INTEROP_VERBOSE=1, INTEROP_LOG (the RUST_LOG of the bot and the desktop; on a
// failure both sides' output is printed).

import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { spawnRelay } from "../../../web/tests/e2e/relay-process.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const exe = process.platform === "win32" ? ".exe" : "";
const target = process.env.CARGO_TARGET_DIR || join(root, "target");
const relayBin = process.env.PAROLNET_RELAY_BIN || join(target, "debug", `parolnet-relay${exe}`);
const botBin = process.env.PAROLNET_BOT_BIN || join(target, "debug", "examples", `bot${exe}`);
const desktopBin = process.argv[2];
const verbose = process.env.INTEROP_VERBOSE === "1";
const work = mkdtempSync(join(tmpdir(), "parolnet-desktop-call-"));
const children = [];
const appLog = process.env.INTEROP_LOG || "parolnet_app=debug,parolnet_rtc=info,warn";
// Both sides' output, printed when the check fails.
const botOut = [];
let botErr = "";
let desktopErr = "";

const log = (...a) => console.log(`[${new Date().toISOString().slice(11, 23)}]`, ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  for (const b of [relayBin, botBin, desktopBin]) {
    if (!b || !existsSync(b)) throw new Error(`missing binary: ${b}`);
  }
  // Port 0: the relay picks its own and reports it (web/tests/e2e/relay-process.mjs).
  const { child: relay, port } = await spawnRelay(relayBin, {
    env: {
      PATH: process.env.PATH,
      RELAY_KEY_FILE: join(work, "relay.key"),
      RELAY_AUTHORITY_KEY_FILE: join(work, "relay-authority.cbor"),
      RUST_LOG: "warn",
      RELAY_CONN_PER_MINUTE: "1000",
      RELAY_MAX_PEERS_PER_IP: "16",
      RELAY_MAX_CONNS_PER_IP: "32",
    },
    echo: verbose,
  });
  children.push(relay);
  const url = `ws://127.0.0.1:${port}/ws`;

  const bot = spawn(botBin, ["--relay", url, "--data-dir", join(work, "bot"), "--host-only", "--bind", "127.0.0.1", "--show-code"], {
    stdio: ["pipe", "pipe", verbose ? "inherit" : "pipe"],
    env: { ...process.env, RUST_LOG: appLog },
  });
  children.push(bot);
  bot.stderr?.on("data", (d) => (botErr += d));
  const events = [];
  createInterface({ input: bot.stdout }).on("line", (line) => {
    botOut.push(`[${new Date().toISOString().slice(11, 23)}] ${line}`);
    if (verbose) log("[bot]", line);
    try {
      const ev = JSON.parse(line);
      events.push(ev);
      if (ev.event === "call" && ev.state === "Incoming") bot.stdin.write(`accept ${ev.call_id}\n`);
    } catch {}
  });
  const waitFor = async (pred, ms, what) => {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      const e = events.find(pred);
      if (e) return e;
      await sleep(100);
    }
    throw new Error(`timed out waiting for ${what}`);
  };
  const { code } = await waitFor((e) => e.event === "code", 15_000, "the bot's code");

  const desktop = spawn(
    desktopBin,
    ["--call-check", "--relay", url, "--data-dir", join(work, "desktop"), "--code", code, "--video", "--bind", "127.0.0.1", "--seconds", "8"],
    { stdio: ["ignore", "pipe", verbose ? "inherit" : "pipe"], env: { ...process.env, RUST_LOG: appLog } },
  );
  children.push(desktop);
  let result = "";
  createInterface({ input: desktop.stdout }).on("line", (line) => {
    log("[desktop]", line);
    if (line.startsWith("call-check")) result = line;
  });
  desktop.stderr?.on("data", (d) => (desktopErr += d));
  const status = await new Promise((r) => desktop.on("exit", (c) => r(c)));
  if (status !== 0) throw new Error(`call-check exited ${status}: ${result || desktopErr.slice(-2000)}`);
  const media = events.filter((e) => e.event === "media").pop();
  if (!media || media.video_rx < 30) throw new Error(`the bot received too little of the desktop's video: ${JSON.stringify(media)}`);
  log(`PASS: ${result}; the bot received ${media.video_rx} VP8 packets from the desktop`);
}

let code = 0;
try {
  await main();
} catch (e) {
  code = 1;
  console.error(`FAIL: ${e.message}`);
  const tail = (text, n) => text.split("\n").slice(-n).join("\n");
  console.error(`--- bot stdout (events) ---\n${botOut.slice(-200).join("\n")}`);
  console.error(`--- bot stderr (RUST_LOG=${appLog}) ---\n${tail(botErr, 400)}`);
  console.error(`--- desktop stderr (RUST_LOG=${appLog}) ---\n${tail(desktopErr, 400)}`);
}
for (const c of children) c.kill();
rmSync(work, { recursive: true, force: true });
process.exit(code);
