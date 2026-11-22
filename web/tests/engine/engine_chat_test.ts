// Text chat, the sender-side queue, take-back and edit, and session persistence.
import { assert, assertEquals, assertRejects } from "@std/assert";
import { MAX_TEXT_BYTES, QUEUE_MAX_AGE_MS, QUEUE_MAX_PER_PEER } from "../../src/engine/engine.ts";
import type { OutboxRow } from "../../src/engine/storage.ts";
import { EngineError } from "../../src/engine/types.ts";
import { chatFrame } from "../../src/engine/wire.ts";
import { type Device, withWorld, type World } from "./harness/world.ts";

async function texts(d: Device, peer: Device): Promise<string[]> {
  return (await d.engine.messages(peer.id)).map((m) => `${m.direction}:${m.state}:${m.text}`);
}

/** Take `d` off the network: its relay socket and connections go away. */
async function offline(w: World, d: Device): Promise<void> {
  w.relay.down = true;
  w.relay.socketOf(d.id)?.drop();
  for (const pc of d.pcs) pc.close();
  await w.settle();
}

Deno.test(
  "chat: text goes both ways as raw UTF-8 TEXT envelopes in chat frames",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b);
    const sent = await a.engine.sendText(b.id, "héllo wörld ✓");
    assertEquals(sent.state, "Sent");
    assertEquals(sent.direction, "Sent");
    await b.engine.sendText(a.id, "and back");
    await w.settle();
    assertEquals(await texts(b, a), [
      "Received:Received:héllo wörld ✓",
      "Sent:Sent:and back",
    ]);
    assertEquals(await texts(a, b), [
      "Sent:Sent:héllo wörld ✓",
      "Received:Received:and back",
    ]);
    // One Message event per message, with the final state.
    assertEquals(a.eventsOf("Message").map((e) => e.message.state), [
      "Sent",
      "Received",
    ]);
    // On the wire: JSON {"type":"chat","payload":<hex of a padded envelope>} and nothing in clear.
    const frames = a.pcs.at(-1)!.channels.flatMap((c) => c.sent).map((s) => JSON.parse(s));
    const last = frames.at(-1);
    assertEquals(Object.keys(last).sort(), ["payload", "type"]);
    assertEquals(last.type, "chat");
    assert(
      [256, 1024, 4096, 16384].includes(last.payload.length / 2),
      "padded to a bucket",
    );
    assert(!JSON.stringify(frames).includes("llo"));
  }),
);

Deno.test(
  "chat: sending needs a contact and a session; empty and oversized text is refused",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    const code = async (fn: () => Promise<unknown>) => (await assertRejects(fn, EngineError)).code;
    assertEquals(
      await code(() => a.engine.sendText(b.id, "x")),
      "UnknownContact",
    );
    await w.pair(a, b);
    assertEquals(await code(() => a.engine.sendText(b.id, "")), "Config");
    assertEquals(
      await code(() => a.engine.sendText(b.id, "x".repeat(MAX_TEXT_BYTES + 1))),
      "TooLong",
    );
    // The longest accepted text really fits an envelope.
    assertEquals(
      (await a.engine.sendText(b.id, "x".repeat(MAX_TEXT_BYTES))).state,
      "Sent",
    );
    await w.settle();
    assertEquals(
      (await b.engine.messages(a.id))[0].text.length,
      MAX_TEXT_BYTES,
    );
  }),
);

Deno.test(
  "queue: messages wait while the contact is away and flush in order when the channel verifies",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b);
    await b.engine.shutdown();
    w.devices = w.devices.filter((d) => d !== b);
    for (const pc of b.pcs) pc.close();
    await w.settle();
    assert(a.path(b) !== "Direct");

    const states: string[] = [];
    for (const text of ["one", "two", "three"]) {
      states.push((await a.engine.sendText(b.id, text)).state);
    }
    assertEquals(states, ["Queued", "Queued", "Queued"]);
    assertEquals(a.engine.snapshot().contacts[0].queued, 3);
    // Queued messages are plaintext at rest and nothing was encrypted for them yet.
    const outbox = await a.storage.getAll<OutboxRow>("outbox");
    assertEquals(outbox.map((e) => e.kind === "text" && e.text), [
      "one",
      "two",
      "three",
    ]);

    const back = await w.device("b", { storage: b.storage });
    await w.advance(60_000);
    assertEquals(a.path(back), "Direct");
    assertEquals(await texts(back, a), [
      "Received:Received:one",
      "Received:Received:two",
      "Received:Received:three",
    ]);
    assertEquals(await texts(a, back), [
      "Sent:Sent:one",
      "Sent:Sent:two",
      "Sent:Sent:three",
    ]);
    assertEquals(a.engine.snapshot().contacts[0].queued, 0);
    assertEquals((await a.storage.getAll("outbox")).length, 0);
    assertEquals(
      a.eventsOf("MessageState").map((e) => e.state),
      ["Sent", "Sent", "Sent"],
    );
  }),
);

Deno.test(
  "queue: it survives a restart of the sender, and so do the sessions on both sides",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b);
    await a.engine.sendText(b.id, "before");
    await w.settle();
    await offline(w, b);
    assertEquals((await a.engine.sendText(b.id, "held")).state, "Queued");
    // Both restart with fresh wasm instances: everything comes from storage.
    const a2 = await w.restart(a);
    assertEquals(a2.engine.snapshot().contacts[0].queued, 1);
    assertEquals((await a2.engine.messages(b.id)).at(-1)?.state, "Queued");
    w.relay.down = false;
    const b2 = await w.restart(b);
    await w.advance(90_000);
    assertEquals(a2.path(b2), "Direct");
    assertEquals(await texts(b2, a2), [
      "Received:Received:before",
      "Received:Received:held",
    ]);
    // The ratchets still agree in both directions.
    await b2.engine.sendText(a2.id, "reply");
    await a2.engine.sendText(b2.id, "again");
    await w.settle();
    assertEquals((await a2.engine.messages(b2.id)).map((m) => m.text), [
      "before",
      "held",
      "reply",
      "again",
    ]);
    assertEquals((await b2.engine.messages(a2.id)).map((m) => m.text), [
      "before",
      "held",
      "reply",
      "again",
    ]);
  }),
);

Deno.test(
  "queue: takeBack removes a queued message from the queue and the history",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b);
    await offline(w, b);
    const one = await a.engine.sendText(b.id, "keep");
    const two = await a.engine.sendText(b.id, "regret");
    await a.engine.takeBack(two.id);
    assertEquals(await texts(a, b), ["Sent:Queued:keep"]);
    assertEquals((await a.storage.getAll("outbox")).length, 1);
    assertEquals(a.eventsOf("MessageRemoved"), [{
      kind: "MessageRemoved",
      peerId: b.id,
      id: two.id,
    }]);
    assertEquals(
      (await assertRejects(() => a.engine.takeBack(two.id), EngineError)).code,
      "NotQueued",
    );
    w.relay.down = false;
    const b2 = await w.restart(b);
    await w.advance(90_000);
    assertEquals(await texts(b2, a), ["Received:Received:keep"]);
    // Once it left the device it cannot be taken back.
    assertEquals(
      (await assertRejects(() => a.engine.takeBack(one.id), EngineError)).code,
      "NotQueued",
    );
  }),
);

Deno.test(
  "queue: editQueued changes the text that is eventually sent, without touching the ratchet",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b);
    await offline(w, b);
    const m = await a.engine.sendText(b.id, "frist draft");
    const after = await a.engine.sendText(b.id, "second");
    const sessions = a.wasm.export_sessions();
    const edited = await a.engine.editQueued(m.id, "first draft");
    assertEquals(edited.text, "first draft");
    assertEquals(edited.state, "Queued");
    assert(edited.editedMs !== undefined);
    assertEquals(
      a.wasm.export_sessions(),
      sessions,
      "editing does not encrypt anything",
    );
    assertEquals(a.eventsOf("MessageEdited").length, 1);
    assertEquals(
      (await assertRejects(() => a.engine.editQueued(m.id, ""), EngineError))
        .code,
      "Config",
    );
    w.relay.down = false;
    const b2 = await w.restart(b);
    await w.advance(90_000);
    // Edited in place: it keeps its position in the conversation.
    assertEquals(await texts(b2, a), [
      "Received:Received:first draft",
      "Received:Received:second",
    ]);
    assertEquals(
      (await assertRejects(
        () => a.engine.editQueued(after.id, "x"),
        EngineError,
      )).code,
      "NotQueued",
    );
  }),
);

Deno.test(
  "queue: beyond 500 per contact the oldest is dropped; entries older than 30 days expire",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b);
    await offline(w, b);
    const first = await a.engine.sendText(b.id, "m0");
    for (let i = 1; i < QUEUE_MAX_PER_PEER; i++) {
      await a.engine.sendText(b.id, `m${i}`);
    }
    assertEquals(a.engine.snapshot().contacts[0].queued, QUEUE_MAX_PER_PEER);
    assertEquals(a.eventsOf("MessageState").length, 0);
    await a.engine.sendText(b.id, "one too many");
    assertEquals(a.engine.snapshot().contacts[0].queued, QUEUE_MAX_PER_PEER);
    assertEquals(a.eventsOf("MessageState"), [
      { kind: "MessageState", peerId: b.id, id: first.id, state: "Dropped" },
    ]);
    assertEquals((await a.engine.messages(b.id))[0].state, "Dropped");
    // 30 days later nothing is left to send.
    w.clock.jump(QUEUE_MAX_AGE_MS + 1);
    await w.advance(16_000);
    assertEquals(a.engine.snapshot().contacts[0].queued, 0);
    assert((await a.engine.messages(b.id)).every((m) => m.state === "Dropped"));
  }),
);

Deno.test(
  "receive: gossip frames, undecryptable envelopes and other senders' envelopes are ignored",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    const c = await w.device("c");
    await w.pair(a, b);
    await w.pair(a, c);
    const bToA = b.pcs.at(-1)!.channels[0];
    // The old PWA broadcast envelopes for other contacts as `gossip`.
    bToA.inject(
      JSON.stringify({
        type: "gossip",
        msgId: "1",
        from: b.id,
        to: c.id,
        payload: "00",
        ttl: 3,
      }),
    );
    bToA.inject(chatFrame("00".repeat(256)));
    bToA.inject("not json");
    // An envelope c encrypted for a, replayed on b's channel, is not accepted there: only
    // the session of the channel's own peer may decrypt.
    const forA = c.wasm.envelope_encode(
      a.id,
      0x01,
      new TextEncoder().encode("from c"),
      0n,
      null,
    );
    bToA.inject(chatFrame(forA));
    await w.settle();
    assertEquals(await a.engine.messages(b.id), []);
    assertEquals(await a.engine.messages(c.id), []);
    assertEquals(a.path(b), "Direct");
    // The same envelope on c's own channel is c's next message.
    c.pcs.at(-1)!.channels[0].inject(chatFrame(forA));
    await w.settle();
    assertEquals((await a.engine.messages(c.id)).map((m) => m.text), [
      "from c",
    ]);
  }),
);

Deno.test(
  "sessions: pairing a new contact, or an undecryptable envelope, leaves other sessions intact",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    const c = await w.device("c");
    await w.pair(a, b);
    await a.engine.sendText(b.id, "one");
    await b.engine.sendText(a.id, "two");
    await w.settle();
    // Pairing c (a new session, and a pairing's own messages on another channel) must not
    // cost a its session with b.
    await w.pair(a, c);
    // And an envelope that does not decrypt, on b's own channel (c's envelope for a, which
    // carries a ratchet key b's session has never seen).
    const forA = c.wasm.envelope_encode(a.id, 0x01, new TextEncoder().encode("x"), 0n, null);
    b.pcs.at(-1)!.channels[0].inject(chatFrame(forA));
    await w.settle();
    await a.engine.sendText(b.id, "three");
    await b.engine.sendText(a.id, "four");
    await w.settle();
    assertEquals((await a.engine.messages(b.id)).map((m) => m.text), [
      "one",
      "two",
      "three",
      "four",
    ]);
    assertEquals((await b.engine.messages(a.id)).map((m) => m.text), [
      "one",
      "two",
      "three",
      "four",
    ]);
    // What is persisted is the intact state too.
    const a2 = await w.restart(a);
    await w.advance(30_000);
    await b.engine.sendText(a2.id, "five");
    await w.settle();
    assertEquals((await a2.engine.messages(b.id)).at(-1)?.text, "five");
  }),
);

Deno.test(
  "receive: content that arrives before the binding verified is not delivered",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b);
    // On the next connection b's binding is lost, but b "sends" content anyway.
    let hold = true;
    w.rtc.dropFrame = (from, data) =>
      hold && b.pcs.includes(from) && JSON.parse(data).type === "chat";
    a.pcs.at(-1)!.close();
    await w.advance(16_000);
    const pc = b.pcs.at(-1)!;
    assertEquals(pc.connectionState, "connected");
    assert(a.path(b) !== "Direct");
    hold = false;
    const early = b.wasm.envelope_encode(
      a.id,
      0x01,
      new TextEncoder().encode("too early"),
      0n,
      null,
    );
    pc.channels[0].inject(chatFrame(early));
    await w.settle();
    assertEquals(await a.engine.messages(b.id), []);
    assert(a.logs.some((l) => l.includes("came before the binding")));
  }),
);

Deno.test(
  "storage: a failed write surfaces as an error and never as a sent message",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b);
    a.storage.failNextWrite = true;
    assertEquals(
      (await assertRejects(() => a.engine.sendText(b.id, "x"), EngineError))
        .code,
      "Storage",
    );
    await w.settle();
    assertEquals(await b.engine.messages(a.id), []);
    assertEquals((await a.engine.sendText(b.id, "y")).state, "Sent");
  }),
);

Deno.test(
  "privacy: no secret reaches the log or an event",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b);
    await a.engine.setTurnSettings({
      uri: "turn:turn.example:3478",
      username: "u",
      password: "hunter2-secret",
      relayOnly: false,
    });
    await w.settle();
    await a.engine.sendText(b.id, "plaintext-marker");
    await w.settle();
    const secret = (await a.storage.get<{ secretHex: string }>("identity", "self"))!
      .secretHex;
    const everything = JSON.stringify([
      a.logs,
      b.logs,
      a.eventsOf("Notice"),
      a.engine.snapshot(),
      a.engine.iceServers(),
    ]);
    for (
      const s of [
        secret,
        "hunter2-secret",
        "plaintext-marker",
        a.wasm.export_sessions().slice(80, 140),
      ]
    ) {
      assert(!everything.includes(s));
    }
    // The settings view can read it back; the snapshot only says it exists.
    assertEquals((await a.engine.turnSettings())?.password, "hunter2-secret");
    assertEquals(a.engine.snapshot().turnConfigured, true);
  }),
);
