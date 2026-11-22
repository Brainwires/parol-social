// The relay client: registration, keepalive (PNP-001 §10.3), reconnect with backoff and
// jitter, and what it refuses to send.
import { assert, assertEquals } from "@std/assert";
import type { Logger } from "../../src/engine/platform.ts";
import {
  BACKOFF_MAX_MS,
  DEAD_AFTER_MS,
  PING_EVERY_MS,
  RECONNECT_WAIT_MS,
  RelayClient,
} from "../../src/engine/relay.ts";
import type { RelayState } from "../../src/engine/types.ts";
import type { ServerFrame } from "../../src/engine/wire.ts";
import { FakeClock, FakeRelay, tick } from "./harness/fakes.ts";

const ME = "0a".repeat(32);
const PK = "0b".repeat(32);

function setup(jitter = 0, url = "ws://relay.test/ws") {
  const clock = new FakeClock();
  const relay = new FakeRelay();
  const states: RelayState[] = [];
  const frames: ServerFrame[] = [];
  const logs: string[] = [];
  const log: Logger = {
    debug: () => {},
    info: (...a) => logs.push(a.join(" ")),
    warn: (...a) => logs.push(a.join(" ")),
  };
  const signed: [nonce: string, relayName: string][] = [];
  const client = new RelayClient({
    url,
    peerId: ME,
    publicKey: PK,
    relayName: (host, port) => {
      if (host === "bad.test") throw new Error("not a relay name");
      return `${host}:${port}`;
    },
    sign: (nonce, relayName) => {
      signed.push([nonce, relayName]);
      return "5a".repeat(64);
    },
    sockets: relay.factory,
    clock,
    random: { next: () => jitter, bytes: (n) => new Uint8Array(n) },
    log,
  }, { onState: (s) => states.push(s), onFrame: (f) => frames.push(f) });
  const settle = async () => {
    for (let i = 0; i < 4; i++) await tick();
  };
  const advance = (ms: number) => clock.advance(ms, settle);
  const kinds = () => states.map((s) => s.kind);
  return { clock, relay, client, states, frames, logs, signed, settle, advance, kinds };
}

Deno.test("relay: connect, challenge, signed register, registered", async () => {
  const t = setup();
  t.client.start();
  await t.settle();
  assertEquals(t.kinds(), ["Connecting", "Registered"]);
  assertEquals(t.states[1], { kind: "Registered", profile: "signaling-only" });
  const s = t.relay.sockets[0];
  assertEquals(s.url, "ws://relay.test/ws");
  assertEquals(s.sent, [
    { type: "register", peer_id: ME },
    {
      type: "register",
      peer_id: ME,
      pubkey: PK,
      signature: "5a".repeat(64),
      nonce: s.nonce,
      relay: "relay.test:80",
    },
  ]);
  // Signed for the relay that was dialed (PNP-001 §10.7), never the bare nonce.
  assertEquals(t.signed, [[s.nonce, "relay.test:80"]]);
  assert(t.client.registered);
  assert(t.logs.includes("Registered with relay. Profile: signaling-only"));
  t.client.stop();
});

Deno.test("relay: the answer names the relay the socket was opened to", async () => {
  for (
    const [url, name] of [
      ["wss://Relay.Test/ws", "relay.test:443"],
      ["wss://relay.test:8443/ws?x=1", "relay.test:8443"],
      ["ws://127.0.0.1:9000/ws", "127.0.0.1:9000"],
      ["ws://[::1]:9000/ws", "[::1]:9000"],
    ]
  ) {
    const t = setup(0, url);
    t.client.start();
    await t.settle();
    const s = t.relay.sockets[0];
    assertEquals(s.sent[1].relay, name, url);
    assertEquals(t.signed, [[s.nonce, name]], url);
    t.client.stop();
  }
});

Deno.test("relay: a URL that names no relay is never dialed", async () => {
  for (
    const url of [
      "wss://user:pw@relay.test/ws",
      "wss://user@relay.test/ws",
      "https://relay.test/ws",
      "not a url",
      "ws://bad.test/ws",
    ]
  ) {
    const t = setup(0, url);
    t.client.start();
    await t.settle();
    assertEquals(t.kinds(), ["Connecting", "Disconnected"], url);
    assertEquals(t.relay.sockets.length, 0, url);
    assertEquals(t.signed, [], url);
    t.client.stop();
  }
});

Deno.test("relay: a challenge that is not a 32-byte nonce is not signed", async () => {
  const t = setup();
  t.relay.silent = true;
  t.client.start();
  await t.settle();
  const s = t.relay.sockets[0];
  for (const nonce of ["", "00ff", "zz".repeat(32), "ab".repeat(31), "ab".repeat(33)]) {
    s.deliver({ type: "challenge", nonce });
  }
  await t.settle();
  assertEquals(t.signed, []);
  assertEquals(s.sent, [{ type: "register", peer_id: ME }]);
  s.deliver({ type: "challenge", nonce: "ab".repeat(32) });
  await t.settle();
  assertEquals(t.signed, [["ab".repeat(32), "relay.test:80"]]);
  t.client.stop();
});

Deno.test("relay: frames are refused before registration and forwarded after", async () => {
  const t = setup();
  t.client.start();
  assertEquals(t.client.send({ type: "watch", peer_ids: [] }), false);
  await t.settle();
  assertEquals(t.client.send({ type: "watch", peer_ids: ["0c".repeat(32)] }), true);
  assertEquals(t.client.send({ type: "rtc_offer", to: "0c".repeat(32), payload: "{}" }), true);
  await t.settle();
  // The peer is not there: the relay's answer reaches the listener.
  assertEquals(t.frames, [{
    type: "error",
    code: "peer_offline",
    message: "",
    peerId: "0c".repeat(32),
  }]);
  t.client.stop();
  assertEquals(t.client.send({ type: "watch", peer_ids: [] }), false);
});

Deno.test("relay: a ping every 20 s; pongs keep it alive", async () => {
  const t = setup();
  t.client.start();
  await t.settle();
  await t.advance(5 * PING_EVERY_MS + 1_000);
  const pings = t.relay.sockets[0].sent.filter((f) => f.type === "ping");
  assertEquals(pings.length, 5);
  assertEquals(typeof pings[0].ts, "number");
  assertEquals(t.kinds(), ["Connecting", "Registered"]);
  assertEquals(t.relay.sockets.length, 1);
  t.client.stop();
});

Deno.test("relay: 40 s of silence is a dead socket: closed with 4000 and reconnected", async () => {
  const t = setup();
  t.client.start();
  await t.settle();
  t.relay.silent = true;
  await t.advance(DEAD_AFTER_MS - 5_000);
  assertEquals(t.kinds(), ["Connecting", "Registered"]);
  await t.advance(5_100);
  assertEquals(t.states.at(-1), { kind: "Disconnected", reason: "relay silent" });
  assertEquals(t.relay.sockets[0].closeCode, 4000);
  assert(!t.client.registered);
  // Any inbound frame counts, not only pongs: a relay that talks is alive.
  t.relay.silent = false;
  // The connection existed, so the next one waits 30 s (PNP-006-MUST-024).
  await t.advance(RECONNECT_WAIT_MS - 1_000);
  assertEquals(t.kinds().at(-1), "Disconnected");
  await t.advance(1_100);
  assertEquals(t.kinds().slice(-2), ["Connecting", "Registered"]);
  t.client.stop();
});

Deno.test("relay: any inbound frame resets the silence timer", async () => {
  const t = setup();
  t.client.start();
  await t.settle();
  t.relay.silent = true;
  for (let i = 0; i < 6; i++) {
    await t.advance(15_000);
    t.relay.sockets[0].deliver({ type: "presence", peer_id: "0c".repeat(32), online: true });
    await t.settle();
  }
  assertEquals(t.kinds(), ["Connecting", "Registered"]);
  assertEquals(t.frames.length, 6);
  t.client.stop();
});

Deno.test("relay: reconnect backs off 1 s doubling to 30 s, with jitter, reset only by registered", async () => {
  const t = setup(1);
  t.relay.down = true;
  t.client.start();
  await t.settle();
  const gaps: number[] = [];
  let last = t.clock.now();
  let seen = t.relay.sockets.length;
  for (let i = 0; i < 8; i++) {
    while (t.relay.sockets.length === seen) await t.advance(250);
    seen = t.relay.sockets.length;
    gaps.push(t.clock.now() - last);
    last = t.clock.now();
  }
  // base × 1.25 with full jitter, measured in 250 ms steps.
  assertEquals(gaps, [1250, 2500, 5000, 10000, 20000, 37500, 37500, 37500]);
  assert(BACKOFF_MAX_MS * 1.25 === 37500);
  assertEquals(t.states.filter((s) => s.kind === "Registered").length, 0);
  // Back up: it registers. That connection existed, so when it drops the next attempt
  // waits 30 s (PNP-006-MUST-024). The backoff started over at the registration, so the
  // attempt after that one (which never opens) follows its second step, 2 s with jitter.
  t.relay.down = false;
  await t.advance(40_000);
  assert(t.client.registered);
  t.relay.down = true;
  t.relay.sockets.at(-1)!.drop();
  await t.settle();
  const n = t.relay.sockets.length;
  await t.advance(RECONNECT_WAIT_MS - 500);
  assertEquals(t.relay.sockets.length, n);
  await t.advance(600);
  assertEquals(t.relay.sockets.length, n + 1);
  await t.advance(2_600);
  assertEquals(t.relay.sockets.length, n + 2);
  t.client.stop();
});

Deno.test("relay: PNP-006-MUST-024: a dropped connection is replaced no sooner than 30 s later, nudged or not", async () => {
  assertEquals(RECONNECT_WAIT_MS, 30_000);
  const t = setup();
  t.client.start();
  await t.settle();
  assert(t.client.registered);
  for (const nudged of [false, true, true]) {
    const n = t.relay.sockets.length;
    const droppedAt = t.clock.now();
    t.relay.sockets.at(-1)!.drop();
    await t.settle();
    assertEquals(t.kinds().at(-1), "Disconnected");
    if (nudged) {
      // The network "came back" at once, and again later: neither shortens the wait.
      t.client.nudge();
      await t.settle();
      assertEquals(t.relay.sockets.length, n);
      await t.advance(10_000);
      t.client.nudge();
      await t.settle();
    }
    while (t.relay.sockets.length === n) {
      await t.advance(250);
      assert(t.clock.now() - droppedAt < 60_000, "never reconnected");
    }
    const waited = t.clock.now() - droppedAt;
    assert(waited >= RECONNECT_WAIT_MS, `reconnected after ${waited} ms`);
    assert(waited <= RECONNECT_WAIT_MS + 500, `reconnected only after ${waited} ms`);
    await t.settle();
    assert(t.client.registered);
  }
  t.client.stop();
});

Deno.test("relay: an open socket that never registers is given up after 15 s", async () => {
  const t = setup();
  t.relay.silent = true;
  t.client.start();
  await t.advance(14_000);
  assertEquals(t.kinds(), ["Connecting"]);
  await t.advance(1_100);
  assertEquals(t.states.at(-1), { kind: "Disconnected", reason: "connect timed out" });
  t.client.stop();
});

Deno.test("relay: nudge reconnects at once; after a suspended page it pings before judging", async () => {
  const t = setup();
  t.relay.down = true;
  t.client.start();
  await t.advance(20_000);
  t.relay.down = false;
  const before = t.relay.sockets.length;
  t.client.nudge();
  await t.settle();
  assertEquals(t.relay.sockets.length, before + 1);
  assert(t.client.registered);
  // The page slept for two minutes (timers throttled): no ping went out, so the silence
  // proves nothing. A catch-up ping goes first and the relay's pong keeps the socket.
  const pingsBefore = t.relay.sockets.at(-1)!.sent.filter((f) => f.type === "ping").length;
  t.clock.jump(120_000);
  t.client.nudge();
  await t.settle();
  assert(t.client.registered);
  assertEquals(
    t.relay.sockets.at(-1)!.sent.filter((f) => f.type === "ping").length,
    pingsBefore + 1,
  );
  await t.advance(10_000);
  assert(t.client.registered);
  // If the relay really is gone, the catch-up goes unanswered and the socket is torn down.
  t.relay.silent = true;
  t.clock.jump(120_000);
  t.client.nudge();
  await t.advance(11_000);
  assertEquals(
    t.states.at(-1)?.kind === "Disconnected" || t.states.at(-2)?.kind === "Disconnected",
    true,
  );
  t.client.stop();
});

Deno.test("relay: the client-side budget refuses signaling frames beyond 54 a minute", async () => {
  const t = setup();
  t.client.start();
  await t.settle();
  let sent = 0;
  for (let i = 0; i < 80; i++) {
    if (t.client.send({ type: "rtc_ice", to: i.toString(16).padStart(64, "0"), payload: "{}" })) {
      sent++;
    }
  }
  assertEquals(sent, 54);
  // Other frames are not metered.
  assert(t.client.send({ type: "watch", peer_ids: [] }));
  t.client.stop();
});

Deno.test("relay: stop closes the socket and nothing reconnects", async () => {
  const t = setup();
  t.client.start();
  await t.settle();
  t.client.stop();
  await t.advance(120_000);
  assertEquals(t.relay.sockets.length, 1);
  assert(t.relay.sockets[0].closed);
  assertEquals(t.clock.pending, 0);
});
