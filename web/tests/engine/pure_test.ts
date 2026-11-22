// The pure parts: byte helpers, the CBOR reader, wire formats, ICE policy and the probe
// schedule. The pairing code, the envelope and the safety number come from the real wasm.
import { assert, assertEquals, assertThrows } from "@std/assert";
import { cborDecode, envelopeSourceHint, fromHex, isHex, toHex } from "../../src/engine/bytes.ts";
import {
  fetchStun,
  hasCandidates,
  httpBase,
  peerConfig,
  stunUrisFromAnswer,
  validateTurn,
} from "../../src/engine/ice.ts";
import { DEFAULT_RECONNECT, probeDelay, ProbeSchedule } from "../../src/engine/reconnect.ts";
import { SIGNAL_BUDGET, SignalBudget } from "../../src/engine/relay.ts";
import { MemoryStorage } from "../../src/engine/storage.ts";
import {
  callSignalJson,
  chatFrame,
  identityFrame,
  isPeerId,
  parseCallSignal,
  parseDcFrame,
  parseIcePayload,
  parseSdpPayload,
  parseServerFrame,
  relayEndpoint,
  shouldInitiate,
} from "../../src/engine/wire.ts";
import { FakeClock } from "./harness/fakes.ts";
import { newWasm } from "./harness/world.ts";

Deno.test("bytes: hex round trip and rejection", () => {
  assertEquals(toHex(new Uint8Array([0, 1, 254, 255])), "0001feff");
  assertEquals([...fromHex("0001FEff")!], [0, 1, 254, 255]);
  assertEquals(fromHex("abc"), null);
  assertEquals(fromHex("zz"), null);
  assert(isHex(""));
});

Deno.test("cbor: the subset decodes and anything else throws", () => {
  assertEquals(cborDecode(fromHex("83010203")!), [1, 2, 3]);
  assertEquals(cborDecode(fromHex("1903e8")!), 1000);
  assertEquals(cborDecode(fromHex("f6")!), null);
  const map = cborDecode(fromHex("a26161016162420102")!) as Map<string, unknown>;
  assertEquals(map.get("a"), 1);
  assertEquals([...(map.get("b") as Uint8Array)], [1, 2]);
  assertThrows(() => cborDecode(fromHex("83")!)); // truncated
  assertThrows(() => cborDecode(fromHex("9f01ff")!)); // indefinite length
  assertThrows(() => cborDecode(fromHex("5affffffff")!)); // length beyond the buffer
});

Deno.test("pairing code: base45 for the picture, no blanks as text, and garbage is refused", async () => {
  const presenter = await newWasm();
  const scanner = await newWasm();
  presenter.initialize();
  scanner.initialize();
  const made = presenter.pairing_create_code(null);
  // PNP-003-MUST-007: base45 of the CBOR payload.
  assert(/^[0-9A-Z $%*+\-./:]+$/.test(made.code), made.code);
  assertEquals(made.text, made.code.replaceAll(" ", "_"));
  const now = Math.floor(Date.now() / 1000);
  const ts = Number(made.ts);
  assert(ts % 300 === 0 && ts <= now && now - ts < 300);
  assertEquals(Number(made.expires_secs), ts + 1800);

  const refused = (text: string, at = Date.now()) => {
    try {
      scanner.pairing_initiate(text, true, at);
      return "accepted";
    } catch (e) {
      return (e as Error).message;
    }
  };
  assertEquals(refused("zz"), "code-invalid");
  assertEquals(refused(made.code.slice(0, 40)), "code-invalid");
  assertEquals(refused(made.text, (ts + 1801) * 1000), "code-expired");
  assertEquals(scanner.has_session(presenter.get_peer_id()), false);
  try {
    presenter.pairing_initiate(made.code, true, Date.now());
    throw new Error("its own code was accepted");
  } catch (e) {
    assertEquals((e as Error).message, "own-code");
  }
});

Deno.test("envelope: the bootstrap envelope carries the scanner's identity key as source_hint", async () => {
  const presenter = await newWasm();
  const scanner = await newWasm();
  presenter.initialize();
  scanner.initialize();
  const made = presenter.pairing_create_code(null);
  const started = scanner.pairing_initiate(made.text, false, Date.now());
  const peer = started.peer_id;
  assertEquals(peer, presenter.get_peer_id());
  assertEquals(started.identity_key, presenter.get_public_key());
  assertEquals(scanner.pairing_state(peer), "secret_shared");
  const now = BigInt(Math.floor(Date.now() / 1000));
  // PNP-001-MUST-063: the scanner's first envelope is its BOOTSTRAP_INIT, as HANDSHAKE.
  const bootstrap = scanner.envelope_encode(
    peer,
    0x05,
    fromHex(started.init_hex)!,
    now,
    scanner.get_public_key(),
  );
  assertEquals(envelopeSourceHint(bootstrap), scanner.get_public_key());
  // SHA-256 of that key is the scanner's PeerId: the check the core makes.
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", fromHex(scanner.get_public_key())! as BufferSource),
  );
  assertEquals(toHex(digest), scanner.get_peer_id());
  const plain = scanner.envelope_encode(peer, 0x01, new TextEncoder().encode("hi"), now, null);
  assertEquals(envelopeSourceHint(plain), null);
  assertEquals(envelopeSourceHint("00".repeat(256)), null);
  assertEquals(envelopeSourceHint("8487"), null);

  // The presenter answers only the peer the envelope names, and only once.
  let wrongPeer = "";
  try {
    presenter.pairing_respond("ab".repeat(32), bootstrap, false, Date.now());
  } catch (e) {
    wrongPeer = (e as Error).message;
  }
  assert(wrongPeer.length > 0, "an envelope from another peer was answered");
  const answered = presenter.pairing_respond(scanner.get_peer_id(), bootstrap, false, Date.now());
  assertEquals(answered.accepted, true);
  assertEquals(answered.identity_key, scanner.get_public_key());
  assertEquals(answered.steps.map((s) => s.kind), ["send"]);
  assertEquals(presenter.export_pending_bootstrap?.(), undefined);
  assertEquals(presenter.pairing_state(scanner.get_peer_id()), "handshaking");
});

Deno.test("safety number: the PNP-002 §10 vector", async () => {
  const wasm = await newWasm();
  const vectors = JSON.parse(
    await Deno.readTextFile(
      new URL("../../../specs/vectors/PNP-002/safety_number.json", import.meta.url),
    ),
  );
  const a: string = vectors.input.peer_id_a;
  const b: string = vectors.input.peer_id_b;
  const expected: string = vectors.expected.safety_number;
  assertEquals(expected, "0203903273 2487506436 7022175877 9751782849 2461095953 2148788959");
  assertEquals(wasm.safety_number(a, b), expected);
  assertEquals(wasm.safety_number(b, a), expected);
});

Deno.test("register answer: the PNP-001 §10.7 vector", async () => {
  const wasm = await newWasm();
  const v = JSON.parse(
    await Deno.readTextFile(
      new URL("../../../specs/vectors/PNP-001/relay_register.json", import.meta.url),
    ),
  );
  wasm.initialize_from_key(v.input.secret_key);
  assertEquals(wasm.get_public_key(), v.expected.public_key);
  // The name comes from the URL the socket is opened with.
  const { host, port } = relayEndpoint(v.input.relay_url);
  const name = wasm.relay_name(host, port);
  assertEquals(name, v.expected.relay_name);
  // Ed25519 is deterministic: the signature over the register message is the vector's.
  assertEquals(wasm.sign_relay_register(v.input.nonce, name), v.expected.signature);
  // Another relay, another signature; a name that is not canonical, or a nonce that is
  // not 32 bytes, is not signed at all.
  assert(wasm.sign_relay_register(v.input.nonce, "relay.example:443") !== v.expected.signature);
  assertThrows(() => wasm.sign_relay_register(v.input.nonce, "Parol.Social:443"));
  assertThrows(() => wasm.sign_relay_register(v.input.nonce, "parol.social"));
  assertThrows(() => wasm.sign_relay_register("00ff", name));
});

Deno.test("wire: the endpoint of a relay URL", () => {
  assertEquals(relayEndpoint("wss://Parol.Social/ws"), { host: "parol.social", port: 443 });
  assertEquals(relayEndpoint("wss://parol.social:443/ws"), { host: "parol.social", port: 443 });
  assertEquals(relayEndpoint("ws://relay.test/ws"), { host: "relay.test", port: 80 });
  assertEquals(relayEndpoint("ws://127.0.0.1:9000/ws"), { host: "127.0.0.1", port: 9000 });
  assertEquals(relayEndpoint("wss://[::1]:8443/ws"), { host: "[::1]", port: 8443 });
  // What the URL parser reads as the host is what the socket connects to.
  assertEquals(relayEndpoint("wss://relay.test\\@evil.test/ws").host, "relay.test");
  for (
    const url of [
      "https://relay.test/ws",
      "wss://user@relay.test/ws",
      "wss://user:pw@relay.test/ws",
      "relay.test:443",
      "",
    ]
  ) {
    assertThrows(() => relayEndpoint(url), Error, undefined, url);
  }
});

Deno.test("wire: relay frames", () => {
  const id = "AB".repeat(32);
  assertEquals(parseServerFrame('{"type":"challenge","nonce":"00ff"}'), {
    type: "challenge",
    nonce: "00ff",
  });
  // A relay that announces no profile is a pre-v0.11 `relay`.
  assertEquals(parseServerFrame('{"type":"registered"}'), { type: "registered", profile: "relay" });
  assertEquals(parseServerFrame(`{"type":"presence","peer_id":"${id}","online":true}`), {
    type: "presence",
    peerId: id.toLowerCase(),
    online: true,
  });
  assertEquals(parseServerFrame('{"type":"presence","peer_id":"xyz","online":true}'), null);
  assertEquals(parseServerFrame(`{"type":"rtc_offer","from":"${id}","payload":"{}"}`), {
    type: "signal",
    kind: "rtc_offer",
    from: id.toLowerCase(),
    payload: "{}",
  });
  assertEquals(
    parseServerFrame(`{"type":"rtc_offer","from":"${id}","payload":{"type":"offer"}}`),
    null,
  );
  assertEquals(parseServerFrame(`{"type":"error","code":"peer_offline","peer_id":"${id}"}`), {
    type: "error",
    code: "peer_offline",
    message: "",
    peerId: id.toLowerCase(),
  });
  assertEquals(parseServerFrame('{"type":"queued"}'), { type: "other", name: "queued" });
  assertEquals(parseServerFrame("nope"), null);
  assertEquals(parseServerFrame("[]"), null);
  assertEquals(parseSdpPayload('{"type":"offer","sdp":"v=0"}', "offer"), "v=0");
  assertEquals(parseSdpPayload('{"type":"answer","sdp":"v=0"}', "offer"), null);
  assertEquals(
    parseIcePayload('{"candidate":"candidate:1","sdpMid":"0","sdpMLineIndex":0}')?.sdpMid,
    "0",
  );
  assertEquals(parseIcePayload('{"sdpMid":"0"}'), null);
});

Deno.test("wire: data-channel frames, the initiator rule and peer ids", () => {
  const id = "0a".repeat(32);
  assertEquals(identityFrame(id), `{"type":"identity","peerId":"${id}"}`);
  assertEquals(chatFrame("00ff"), '{"type":"chat","payload":"00ff"}');
  assertEquals(parseDcFrame(identityFrame(id)), { type: "identity", peerId: id });
  assertEquals(parseDcFrame(chatFrame("00ff")), { type: "envelope", hex: "00ff" });
  assertEquals(parseDcFrame('{"type":"gossip","payload":"00"}'), { type: "other" });
  assertEquals(parseDcFrame("00FF"), { type: "envelope", hex: "00FF" }); // bare hex, like the desktop
  assertEquals(parseDcFrame("hello"), { type: "other" });
  assertEquals(parseDcFrame(new Uint8Array(2)), { type: "other" });
  assert(shouldInitiate("0a".repeat(32), "0B".repeat(32)));
  assert(!shouldInitiate("0b".repeat(32), "0A".repeat(32)));
  assert(!shouldInitiate(id, id.toUpperCase()));
  assert(isPeerId(id) && !isPeerId(id.slice(2)) && !isPeerId("g" + id.slice(1)));
});

Deno.test("wire: call signals have the shapes the desktop and the old PWA exchange", () => {
  const callId = "ab".repeat(16);
  assertEquals(
    callSignalJson({ action: "offer", callId, video: true, sdp: "v=0\r\n" }),
    `{"action":"offer","callId":"${callId}","withVideo":true,"sdp":"v=0\\r\\n"}`,
  );
  assertEquals(
    callSignalJson({ action: "hangup", callId }),
    `{"action":"hangup","callId":"${callId}"}`,
  );
  assertEquals(parseCallSignal(`{"action":"reject","callId":"${callId}"}`), {
    action: "reject",
    callId,
  });
  const ice = parseCallSignal(
    `{"action":"ice","callId":"${callId}","candidate":{"candidate":"candidate:1","sdpMid":"0","sdpMLineIndex":0}}`,
  );
  assertEquals(ice?.action, "ice");
  assertEquals(parseCallSignal(`{"action":"offer","callId":"${callId}"}`), null);
  assertEquals(parseCallSignal(`{"action":"dance","callId":"${callId}"}`), null);
  assertEquals(parseCallSignal(`{"action":"hangup","callId":"${"x".repeat(65)}"}`), null);
  assertEquals(parseCallSignal("[]"), null);
});

Deno.test("ice: the relay's HTTP base and its STUN list, hostile spellings included", () => {
  assertEquals(httpBase("wss://parol.example/ws"), "https://parol.example");
  assertEquals(httpBase("ws://127.0.0.1:9/ws/"), "http://127.0.0.1:9");
  assertEquals(httpBase("ws://h:1"), "http://h:1");
  assertEquals(httpBase("https://h/ws"), null);
  const { stun, profile } = stunUrisFromAnswer(JSON.stringify({
    username: "1700000000:u",
    credential: "c2VjcmV0",
    profile: "relay",
    uris: [
      "TURN:relay.example:3478",
      "Turn:relay.example:3478?transport=udp",
      "turns:relay.example:443?transport=tcp",
      " turn:relay.example:3478",
      "stun:relay.example:3478",
      "STUN:relay.example:3479",
      "stuns:relay.example:5349",
      "http://relay.example/",
      "",
      "stun:x turn:relay.example:3478",
      "stun:[2001:db8::1]:3478",
      42,
    ],
    iceServers: [{ urls: "turn:relay.example:3478", username: "u", credential: "c" }],
  }));
  assertEquals(stun, [
    "stun:relay.example:3478",
    "STUN:relay.example:3479",
    "stun:[2001:db8::1]:3478",
  ]);
  assertEquals(profile, "relay");
  assertEquals(stunUrisFromAnswer("garbage").stun, []);
  assertEquals(stunUrisFromAnswer("{}").stun, []);
});

Deno.test("ice: STUN is fetched from the relay's own origin, once, and a failure means none", async () => {
  const clock = new FakeClock();
  const urls: string[] = [];
  const ok = await fetchStun(
    (url) => {
      urls.push(url);
      return Promise.resolve({
        ok: true,
        status: 200,
        text: () => Promise.resolve('{"uris":["stun:a:1"]}'),
      });
    },
    clock,
    "wss://relay.example/ws",
  );
  assertEquals(ok, { url: "https://relay.example/turn-credentials", stun: ["stun:a:1"] });
  const refused = await fetchStun(
    () => Promise.resolve({ ok: false, status: 503, text: () => Promise.resolve("") }),
    clock,
    "wss://relay.example/ws",
  );
  assertEquals(refused?.stun, []);
  const broken = await fetchStun(
    () => Promise.reject(new Error("offline")),
    clock,
    "wss://relay.example/ws",
  );
  assertEquals(broken?.stun, []);
  // Never another host, whatever happens.
  assertEquals(urls, ["https://relay.example/turn-credentials"]);
  assertEquals(clock.pending, 0);
});

Deno.test("ice: TURN settings and the connection configuration", () => {
  const turn = validateTurn({
    uri: " turn:t.example:3478?transport=tcp ",
    username: " u ",
    password: " p ",
    relayOnly: true,
  });
  assertEquals(turn, {
    uri: "turn:t.example:3478?transport=tcp",
    username: "u",
    password: " p ",
    relayOnly: true,
  });
  for (
    const uri of [
      "turns:t.example",
      "stun:t.example",
      "turn:",
      "turn:a b",
      "turn:t.example?transport=sctp",
      "http://x",
    ]
  ) {
    assertThrows(() => validateTurn({ uri, username: "u", password: "p", relayOnly: false }));
  }
  assertEquals(peerConfig([], null), { iceServers: [], iceTransportPolicy: "all" });
  assertEquals(peerConfig(["stun:a:1"], { ...turn, relayOnly: false }), {
    iceServers: [{ urls: "stun:a:1" }, { urls: turn.uri, username: "u", credential: " p " }],
    iceTransportPolicy: "all",
  });
  assertEquals(peerConfig([], turn).iceTransportPolicy, "relay");
  assert(hasCandidates("v=0\r\na=candidate:1 1 udp 1 192.0.2.1 9 typ host\r\n"));
  assert(!hasCandidates("v=0\r\na=fingerprint:sha-256 AA\r\n"));
});

Deno.test("probe schedule: 15 s doubling to 5 min for waited-for contacts and 15 min idle", () => {
  const delays = (active: boolean) =>
    [0, 1, 2, 3, 4, 5, 6, 7].map((n) => probeDelay(DEFAULT_RECONNECT, n, active, 0) / 1000);
  assertEquals(delays(true), [15, 30, 60, 120, 240, 300, 300, 300]);
  assertEquals(delays(false), [15, 30, 60, 120, 240, 480, 900, 900]);
  assertEquals(probeDelay(DEFAULT_RECONNECT, 0, true, 1), 18_750); // a quarter of jitter at most
  assertEquals(probeDelay(DEFAULT_RECONNECT, 0, true, 7), 18_750);
});

Deno.test("probe schedule: due order, the shared budget and resets", () => {
  let now = 0;
  const s = new ProbeSchedule(DEFAULT_RECONNECT, now);
  const all = () => true;
  for (let i = 0; i < 20; i++) s.noteOffline(`p${String(i).padStart(2, "0")}`, now, 0);
  assertEquals(s.takeDue(now + 14_999, all, all, () => 0), []);
  now = 15_000;
  // Those the user waits for go first; the burst is 12.
  const first = s.takeDue(now, (p) => p === "p19", all, () => 0);
  assertEquals(first.length, 12);
  assertEquals(first[0], "p19");
  assertEquals(s.takeDue(now, all, all, () => 0), []);
  // One more token per minute; the next wake is not before the budget has one.
  assertEquals(s.nextWake(now, all, all), now + 60_000);
  now += 60_000;
  assertEquals(s.takeDue(now, all, all, () => 0).length, 1);
  // A contact with an attempt under way is skipped.
  assertEquals(s.nextWake(now, all, () => false), null);
  // A presence push clears; an explicit connect starts the backoff over.
  s.clear("p19");
  assert(!s.isScheduled("p19"));
  s.restart("p00", now);
  now += 15_000 + 60_000;
  assert(s.takeDue(now, all, (p) => p === "p00", () => 0).includes("p00"));
  assertEquals(s.size, 19);
  // An hour of probing stays far below the relay's 240 signaling frames an hour.
  assert(DEFAULT_RECONNECT.probeBurst + 3_600_000 / DEFAULT_RECONNECT.probeRefillMs <= 72);
});

Deno.test("signal budget: under the relay's caps per minute, per hour and per pair", () => {
  const b = new SignalBudget();
  let now = 0;
  let sent = 0;
  for (let i = 0; i < 100; i++) if (b.take(`p${i}`, now)) sent++;
  assertEquals(sent, SIGNAL_BUDGET.perMinute);
  assert(
    SIGNAL_BUDGET.perMinute < 60 && SIGNAL_BUDGET.perHour < 240 && SIGNAL_BUDGET.perPair10Min < 64,
  );
  now += 60_000;
  assert(b.take("p0", now));
  // Per pair: 58 in ten minutes, however slowly they come.
  const pair = new SignalBudget();
  let ok = 0;
  for (let i = 0; i < 70; i++) if (pair.take("same", i * 5_000)) ok++;
  assertEquals(ok, SIGNAL_BUDGET.perPair10Min);
  // Per hour.
  const hour = new SignalBudget();
  let total = 0;
  for (let i = 0; i < 400; i++) if (hour.take(`q${i}`, i * 9_000)) total++;
  assertEquals(total, SIGNAL_BUDGET.perHour);
});

Deno.test("memory storage: keys, the peer index, ordering and atomic-looking writes", async () => {
  const s = new MemoryStorage();
  await s.write([
    { op: "put", store: "messages", value: { id: 2, peerId: "b", text: "2" } },
    { op: "put", store: "messages", value: { id: 1, peerId: "a", text: "1" } },
    { op: "put", store: "messages", value: { id: 10, peerId: "a", text: "10" } },
    { op: "put", store: "settings", value: { key: "k", value: 1 } },
  ]);
  assertEquals((await s.getAll<{ id: number }>("messages")).map((m) => m.id), [1, 2, 10]);
  assertEquals((await s.getAllByPeer<{ id: number }>("messages", "a")).map((m) => m.id), [1, 10]);
  assertEquals(await s.maxKey("messages"), 10);
  assertEquals(await s.maxKey("outbox"), 0);
  // Values are copies: mutating a result does not change the store.
  const row = (await s.get<{ text: string }>("messages", 1))!;
  row.text = "changed";
  assertEquals((await s.get<{ text: string }>("messages", 1))!.text, "1");
  await s.write([{ op: "delete", store: "messages", key: 1 }]);
  assertEquals(await s.get("messages", 1), undefined);
  await s.destroy();
  assertEquals(await s.getAll("messages"), []);
});
