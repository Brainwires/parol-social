// The connection state machine: who offers, glare, the offer stagger, timeouts and retries,
// no-path detection, soft-offline probing, rate-limit pauses and ICE policy.
import { assert, assertEquals, assertRejects } from "@std/assert";
import {
  ANSWER_TIMEOUT_MS,
  OFFER_FALLBACK_MS,
  OFFER_WINDOW_MS,
  RATE_LIMIT_BASE_MS,
} from "../../src/engine/engine.ts";
import { RECONNECT_WAIT_MS } from "../../src/engine/relay.ts";
import { EngineError } from "../../src/engine/types.ts";
import { type Device, orderedPair, withWorld, type World } from "./harness/world.ts";

/** Restart both devices: they come back with contacts and sessions but no connection. */
async function restartBoth(
  w: World,
  a: Device,
  b: Device,
): Promise<[Device, Device]> {
  w.relay.down = true;
  const a2 = await w.restart(a);
  const b2 = await w.restart(b);
  return [a2, b2];
}

function offers(w: World, from: Device): number {
  return w.relay.signals.filter((s) => s.type === "rtc_offer" && s.from === from.id).length;
}

Deno.test(
  "initiator: on presence the smaller PeerId offers at once and the other waits",
  withWorld(async (w) => {
    const [x, y] = await orderedPair(w);
    await w.pair(x, y);
    const [small, large] = await restartBoth(w, x, y);
    w.relay.signals = [];
    w.relay.down = false;
    small.engine.networkChanged();
    large.engine.networkChanged();
    await w.advance(2_000);
    assertEquals(small.path(large), "Direct");
    assertEquals(large.path(small), "Direct");
    assertEquals(offers(w, small), 1);
    assertEquals(offers(w, large), 0);
    // Non-trickle: one offer, one answer, no rtc_ice.
    assertEquals(w.relay.signals.map((s) => s.type), [
      "rtc_offer",
      "rtc_answer",
    ]);
    const offerPc = small.pcs.at(-1)!;
    assert(offerPc.localDescription!.sdp.includes("a=candidate:"));
    assertEquals(offerPc.channels[0].label, "parolnet");
  }),
);

Deno.test(
  "initiator: when the designated offer never comes, the other side offers after 10-12 s",
  withWorld(async (w) => {
    const [x, y] = await orderedPair(w);
    await w.pair(x, y);
    const [small, large] = await restartBoth(w, x, y);
    w.relay.signals = [];
    w.relay.down = false;
    // The initiator's offers are lost in the relay.
    w.relay.swallow.add("rtc_offer");
    small.engine.networkChanged();
    large.engine.networkChanged();
    await w.advance(OFFER_FALLBACK_MS - 500);
    assertEquals(offers(w, large), 0);
    w.relay.swallow.clear();
    await w.advance(2_600);
    assertEquals(offers(w, large), 1);
    await w.settle();
    // Glare: the designated initiator still holds its own (lost) offer, so it keeps it and
    // ignores the fallback offer; that one times out and the retry wins.
    assertEquals(small.pcs.at(-1)!.remoteDescription, null);
    await w.advance(ANSWER_TIMEOUT_MS + 10_000);
    assertEquals(small.path(large), "Direct");
    assertEquals(large.path(small), "Direct");
  }),
);

Deno.test(
  "glare: the designated initiator keeps its offer; the other side yields to it",
  withWorld(async (w) => {
    const [x, y] = await orderedPair(w);
    await w.pair(x, y);
    const [small, large] = await restartBoth(w, x, y);
    w.relay.down = false;
    // Hold presence back so that both sides offer on the user's request at the same time.
    w.relay.swallow.add("rtc_offer");
    small.engine.networkChanged();
    large.engine.networkChanged();
    await w.settle();
    w.relay.swallow.clear();
    small.cut();
    large.cut();
    await w.settle();
    w.relay.signals = [];
    small.engine.connect(large.id);
    large.engine.connect(small.id);
    await w.advance(1_000);
    assertEquals(small.path(large), "Direct");
    assertEquals(large.path(small), "Direct");
    // The connection that survived is the one the smaller PeerId offered.
    assertEquals(small.pcs.at(-1)!.localDescription!.type, "offer");
    assertEquals(large.pcs.at(-1)!.localDescription!.type, "answer");
  }),
);

Deno.test(
  "stagger: at most 3 new offers go out per 10 s window",
  withWorld(async (w) => {
    const hub = await w.device("hub");
    const others: Device[] = [];
    for (let i = 0; i < 5; i++) {
      const d = await w.device(`p${i}`);
      await w.pair(hub, d);
      others.push(d);
    }
    hub.cut();
    await w.settle();
    // Nobody answers from now on, so every attempt stays an offer.
    w.relay.swallow.add("rtc_offer");
    w.relay.signals = [];
    for (const d of others) hub.engine.connect(d.id);
    await w.settle();
    assertEquals(offers(w, hub), 3);
    await w.advance(OFFER_WINDOW_MS - 1_000);
    assertEquals(offers(w, hub), 3);
    await w.advance(1_500);
    assertEquals(offers(w, hub), 5);
  }),
);

Deno.test(
  "retry: an unanswered offer times out after 20 s and is retried with backoff",
  withWorld(async (w) => {
    const [x, y] = await orderedPair(w);
    await w.pair(x, y);
    const [small, large] = await restartBoth(w, x, y);
    w.relay.down = false;
    w.relay.swallow.add("rtc_offer");
    w.relay.signals = [];
    small.engine.networkChanged();
    large.engine.networkChanged();
    await w.advance(1_000);
    assertEquals(offers(w, small), 1);
    assertEquals(small.path(large), "Connecting");
    await w.advance(ANSWER_TIMEOUT_MS);
    assertEquals(small.pcs.at(-1)!.connectionState, "closed");
    // First retry after 5 s, the second 10 s after the next timeout.
    await w.advance(5_500);
    assertEquals(offers(w, small), 2);
    await w.advance(ANSWER_TIMEOUT_MS + 8_000);
    assertEquals(offers(w, small), 2);
    await w.advance(2_000);
    assertEquals(offers(w, small), 3);
    // Two timeouts in a row with the contact online: there is no direct path.
    assertEquals(small.path(large), "NoDirectPath");
  }),
);

Deno.test(
  "no path: ICE failure with the contact online is NoDirectPath, and a later success is Direct",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b);
    w.rtc.failIce = true;
    a.cut();
    await w.settle();
    b.engine.connect(a.id);
    await w.advance(1_000);
    assertEquals(b.path(a), "NoDirectPath");
    assertEquals(a.path(b), "NoDirectPath");
    w.rtc.failIce = false;
    b.engine.connect(a.id);
    await w.advance(1_000);
    assertEquals(b.path(a), "Direct");
  }),
);

Deno.test(
  "presence: an offline push drops a pending attempt and shows Offline; online reconnects",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b);
    await b.engine.shutdown();
    w.devices = w.devices.filter((d) => d !== b);
    for (const pc of b.pcs) pc.close();
    await w.settle();
    assertEquals(a.path(b), "Offline");
    assertEquals(a.eventsOf("Path").at(-1), {
      kind: "Path",
      peerId: b.id,
      state: "Offline",
    });
    const b2 = await w.device("b", { storage: b.storage });
    await w.advance(OFFER_FALLBACK_MS + 3_000);
    assertEquals(a.path(b2), "Direct");
  }),
);

Deno.test(
  "probing: a peer_offline answer is soft; the contact is re-probed at 15 s, 30 s, 60 s...",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b);
    // b goes away without a's relay telling a (b never watched a back from a's view: drop
    // the mutual watch by making b unreachable silently).
    const socket = w.relay.socketOf(b.id)!;
    socket.watch.clear();
    await b.engine.shutdown();
    w.devices = w.devices.filter((d) => d !== b);
    for (const pc of b.pcs) pc.close();
    await w.settle();
    assert(a.path(b) !== "Offline", "no presence push arrived");
    w.relay.signals = [];
    // The user is waiting for b: a message is queued and they asked to connect.
    assertEquals(
      (await a.engine.sendText(b.id, "are you there")).state,
      "Queued",
    );
    a.engine.connect(b.id);
    await w.settle();
    assertEquals(a.path(b), "Offline");
    const first = offers(w, a);
    assert(first >= 1);
    const at = (ms: number) => w.advance(ms).then(() => offers(w, a) - first);
    assertEquals(await at(14_000), 0); // 14 s after the verdict
    assertEquals(await at(2_000), 1); // probe 1 at 15 s
    assertEquals(a.path(b), "Offline", "a probe is quiet");
    assertEquals(await at(28_000), 1);
    assertEquals(await at(2_000), 2); // probe 2, 30 s later
    assertEquals(await at(58_000), 2);
    assertEquals(await at(2_000), 3); // probe 3, 60 s later
    // An explicit connect restarts the backoff and offers now.
    a.engine.connect(b.id);
    await w.settle();
    assertEquals(offers(w, a) - first, 4);
    assertEquals(await at(14_000), 4);
    assertEquals(await at(2_000), 5);
    // The contact comes back: the next probe finds it and the queue flushes.
    const b2 = await w.device("b", { storage: b.storage });
    await w.advance(40_000);
    assertEquals(a.path(b2), "Direct");
    assertEquals((await b2.engine.messages(a.id)).map((m) => m.text), [
      "are you there",
    ]);
  }),
);

Deno.test(
  "probing: idle contacts back off to 15 min, waited-for ones to 5 min, under one budget",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b);
    w.relay.socketOf(b.id)!.watch.clear();
    await b.engine.shutdown();
    w.devices = w.devices.filter((d) => d !== b);
    for (const pc of b.pcs) pc.close();
    await w.settle();
    a.engine.connect(b.id); // learns "offline" from the answer; `wanted` makes it active
    await w.advance(1_000);
    assertEquals(a.path(b), "Offline");
    w.relay.signals = [];
    await w.advance(3_600_000);
    // 15+30+60+120+240 s, then every 300 s: an hour holds 5 + 10 or 11 probes.
    const active = offers(w, a);
    assert(active >= 15 && active <= 17, `active probes in an hour: ${active}`);
    assert(active <= 12 + 60, "under the probe budget");
  }),
);

Deno.test(
  "rate limit: rate_limited pauses new offers for 60 s, doubling, and resets on re-register",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b);
    w.relay.socketOf(b.id)!.watch.clear();
    await b.engine.shutdown();
    w.devices = w.devices.filter((d) => d !== b);
    await w.settle();
    w.relay.signals = [];
    const pauses = () =>
      a.logs.filter((l) => l.includes("rate-limited")).map((l) => l.replace(/.*for /, ""));
    w.relay.rateLimitNext = 1;
    a.engine.connect(b.id);
    await w.settle();
    assertEquals(offers(w, a), 1);
    assertEquals(pauses(), ["60 s"]);
    // During the pause nothing is offered, whatever the user does or a timer wants.
    a.engine.connect(b.id);
    await w.advance(RATE_LIMIT_BASE_MS - 1_000);
    assertEquals(offers(w, a), 1);
    await w.advance(2_000);
    assertEquals(offers(w, a), 2);
    // A second hit doubles the pause.
    w.relay.rateLimitNext = 1;
    a.engine.connect(b.id);
    await w.settle();
    assertEquals(pauses(), ["60 s", "120 s"]);
    // A new registration starts the count over.
    w.relay.socketOf(a.id)!.drop();
    await w.advance(2 * RATE_LIMIT_BASE_MS + 2_000);
    w.relay.rateLimitNext = 1;
    a.engine.connect(b.id);
    await w.settle();
    assertEquals(pauses(), ["60 s", "120 s", "60 s"]);
  }),
);

Deno.test(
  "ICE: STUN only from the app's own relay; relay TURN and other hosts are never used",
  withWorld(async (w) => {
    const a = await w.device("a", { config: { stunServers: undefined } });
    a.turnCredentials = JSON.stringify({
      username: "u",
      credential: "c",
      profile: "relay",
      uris: [
        "stun:relay.test:3478",
        "turn:relay.test:3478",
        "TURNS:relay.test:443?transport=tcp",
        "stun:x turn:relay.test:3478",
        "stuns:relay.test:5349",
      ],
      iceServers: [{
        urls: "turn:evil.example",
        username: "u",
        credential: "c",
      }],
    });
    // Re-register to fetch again with that answer (the reconnect waits 30 s, PNP-006-MUST-024).
    w.relay.socketOf(a.id)!.drop();
    await w.advance(RECONNECT_WAIT_MS + 2_000);
    assertEquals(
      new Set(a.fetched),
      new Set(["http://relay.test/turn-credentials"]),
    );
    assertEquals(a.engine.iceServers(), [{ urls: "stun:relay.test:3478" }]);
    assert(
      a.logs.includes(
        "[WebRTC] ICE servers from http://relay.test/turn-credentials",
      ),
    );
    const b = await w.device("b");
    await w.pair(a, b);
    assertEquals(a.pcs.at(-1)!.config, {
      iceServers: [{ urls: "stun:relay.test:3478" }],
      iceTransportPolicy: "all",
    });
  }),
);

Deno.test(
  "ICE: with no STUN announced nothing is logged and the default policy is direct, no servers",
  withWorld(async (w) => {
    const a = await w.device("a", { config: { stunServers: undefined } });
    const b = await w.device("b");
    await w.pair(a, b);
    assertEquals(a.fetched, ["http://relay.test/turn-credentials"]);
    assert(!a.logs.some((l) => l.includes("ICE servers from")));
    assertEquals(a.pcs.at(-1)!.config, {
      iceServers: [],
      iceTransportPolicy: "all",
    });
  }),
);

Deno.test(
  "TURN: the user's server is added; relayOnly sets the relay policy and rebuilds connections",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b);
    const bad = (s: Record<string, unknown>) =>
      assertRejects(() => a.engine.setTurnSettings(s as never), EngineError);
    await bad({ uri: "stun:x", username: "u", password: "p" });
    await bad({ uri: "turn:x y", username: "u", password: "p" });
    await bad({ uri: "turns:x", username: "u", password: "p" });
    await bad({ uri: "turn:x", username: "", password: "p" });
    await bad({ uri: "turn:x", username: "u", password: "" });
    const before = a.pcs.length;
    await a.engine.setTurnSettings({
      uri: " turn:turn.example:3478?transport=tcp ",
      username: "u",
      password: "p",
      relayOnly: true,
    });
    await w.advance(2_000);
    assert(a.pcs.length > before, "the data connection was rebuilt");
    assertEquals(a.pcs.at(-1)!.config, {
      iceServers: [{
        urls: "turn:turn.example:3478?transport=tcp",
        username: "u",
        credential: "p",
      }],
      iceTransportPolicy: "relay",
    });
    assertEquals(a.path(b), "Direct");
    assertEquals(a.engine.snapshot().relayOnly, true);
    // It is remembered.
    const a2 = await w.restart(a);
    assertEquals(a2.engine.snapshot().turnConfigured, true);
    assertEquals(a2.engine.snapshot().relayOnly, true);
    await a2.engine.setTurnSettings(null);
    assertEquals(a2.engine.snapshot().turnConfigured, false);
    assertEquals(await a2.storage.get("settings", "turn"), undefined);
  }),
);

Deno.test(
  "TURN: relay-only with an unreachable server never falls back to a direct path",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b);
    w.rtc.turnUnreachable = true;
    w.relay.signals = [];
    await a.engine.setTurnSettings({
      uri: "turn:turn.example",
      username: "u",
      password: "p",
      relayOnly: true,
    });
    await w.advance(2_000);
    assertEquals(a.path(b), "NoDirectPath");
    assertEquals(
      offers(w, a),
      0,
      "no description without a relay candidate left the device",
    );
    assert(a.notices().some((n) => n.includes("TURN server cannot be used")));
  }),
);
