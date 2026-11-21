// Identity, pairing (PNP-003) and the channel binding (PNP-001 §10.5.1), with real crypto.
import { assert, assertEquals, assertRejects } from "@std/assert";
import { parsePairingCode } from "../../src/engine/bytes.ts";
import { BINDING_TIMEOUT_MS } from "../../src/engine/engine.ts";
import { MemoryStorage } from "../../src/engine/storage.ts";
import { EngineError } from "../../src/engine/types.ts";
import { withWorld } from "./harness/world.ts";

Deno.test(
  "identity: created once, persisted, and the same after a restart",
  withWorld(async (w) => {
    const a = await w.device("a");
    assertEquals(a.id.length, 64);
    assertEquals(a.engine.publicKey.length, 64);
    const row = await a.storage.get<{ secretHex: string }>("identity", "self");
    assert(row && row.secretHex.length === 64);
    const again = await w.restart(a);
    assertEquals(again.id, a.id);
    assertEquals(again.engine.publicKey, a.engine.publicKey);
  }),
);

Deno.test(
  "identity: the relay registration is two register frames, the second signed",
  withWorld(async (w) => {
    const a = await w.device("a");
    assertEquals(a.engine.snapshot().relay, {
      kind: "Registered",
      profile: "signaling-only",
    });
    const registers = w.relay.framesFrom(a.id, "register");
    assertEquals(registers.length, 2);
    assertEquals(Object.keys(registers[0]).sort(), ["peer_id", "type"]);
    assertEquals(registers[1].pubkey, a.engine.publicKey);
    assertEquals((registers[1].signature as string).length, 128);
    assert(a.logs.includes("Registered with relay. Profile: signaling-only"));
  }),
);

Deno.test(
  "wipe: deletes the database and the next start has a new identity",
  withWorld(async (w) => {
    const a = await w.device("a");
    const storage = a.storage;
    await a.engine.wipe();
    assert(storage.destroyed);
    assertEquals(await storage.getAll("identity"), []);
    await assertRejects(() => a.engine.sendText(a.id, "x"), EngineError);
    w.devices = [];
    const fresh = await w.device("a", { storage: new MemoryStorage() });
    assert(fresh.id !== a.id);
  }),
);

Deno.test(
  "pairing: both sides get the contact, a verified channel and the right verification state",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    const { code, expiresAtMs } = await a.engine.createPairingCode();
    assert(/^[0-9a-f]{100,}$/.test(code));
    assertEquals(parsePairingCode(code)?.identityKey, a.engine.publicKey);
    // The window is the code's own lifetime: 1800 s from its (300 s floored) timestamp.
    const left = expiresAtMs - w.clock.now();
    assert(left > 1500_000 - 1 && left <= 1800_000, `window ${left}`);
    assert(a.engine.snapshot().pairingOpen);

    const contact = await b.engine.pairWithCode(code, { via: "scan" });
    assertEquals(contact.peerId, a.id);
    assertEquals(contact.identityKey, a.engine.publicKey);
    assertEquals(contact.verified, "in-person");
    await w.settle();

    assertEquals(b.path(a), "Direct");
    assertEquals(a.path(b), "Direct");
    const seen = a.engine.snapshot().contacts[0].contact;
    assertEquals(seen.peerId, b.id);
    // The presenter learns the scanner's identity key from the bootstrap envelope...
    assertEquals(seen.identityKey, b.engine.publicKey);
    // ...but cannot know how its code was obtained.
    assertEquals(seen.verified, "no");
    // The code is used up: the window closed with it.
    assert(!a.engine.snapshot().pairingOpen);
    assertEquals(a.eventsOf("Pairing").at(-1)?.pairing, null);
    for (const d of [a, b]) {
      assert(
        d.logs.some((l) => l.startsWith("[WebRTC] direct channel verified with ")),
      );
    }
    // Exactly one peer connection each, and nothing queued.
    assertEquals(w.rtc.open.length, 2);
    assertEquals((await b.storage.getAll("outbox")).length, 0);
  }),
);

Deno.test(
  "pairing: a pasted code proves nothing; comparing safety numbers sets 'compared'",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b, "paste");
    assertEquals(b.engine.snapshot().contacts[0].contact.verified, "no");
    const number = b.engine.safetyNumber(a.id);
    assertEquals(number, a.engine.safetyNumber(b.id));
    assert(/^(\d{10} ){5}\d{10}$/.test(number!));
    const c = await b.engine.setVerification(a.id, "compared");
    assertEquals(c.verified, "compared");
    assert(c.verifiedMs !== null);
    assertEquals((await b.engine.setVerification(a.id, "no")).verified, "no");
  }),
);

Deno.test(
  "pairing: rename is local and survives incoming traffic and a restart",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b, "scan");
    await b.engine.renameContact(a.id, "  Alice  ");
    await a.engine.sendText(b.id, "hello");
    await w.settle();
    const view = b.engine.snapshot().contacts[0];
    assertEquals(view.contact.name, "Alice");
    assertEquals(view.contact.identityKey, a.engine.publicKey);
    assertEquals(view.contact.verified, "in-person");
    assertEquals(view.unread, 1);
    const again = await w.restart(b);
    assertEquals(again.engine.snapshot().contacts[0].contact.name, "Alice");
    assertEquals(
      again.engine.snapshot().contacts[0].contact.verified,
      "in-person",
    );
  }),
);

Deno.test(
  "pairing: our own code, garbage and an expired code are refused with the right error",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    const { code } = await a.engine.createPairingCode();
    const err = async (c: string, d = b) =>
      (await assertRejects(
        () => d.engine.pairWithCode(c, { via: "paste" }),
        EngineError,
      )).code;
    assertEquals(await err(code, a), "OwnCode");
    assertEquals(await err("hello"), "InvalidCode");
    assertEquals(await err(a.id), "InvalidCode"); // a bare PeerId is not a code
    assertEquals(await err("ab".repeat(80)), "InvalidCode");
    // Quotes and whitespace around a pasted code are tolerated.
    await w.advance(1801_000);
    assertEquals(await err(` "${code}"\n`), "CodeExpired");
    assertEquals(b.engine.snapshot().contacts.length, 0);
  }),
);

Deno.test(
  "pairing: the window closes when the code expires, and strangers' offers are refused",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    const { code, expiresAtMs } = await a.engine.createPairingCode();
    // b scans in time (the session exists on b) but only offers after a's window closed.
    w.relay.swallow.add("rtc_offer");
    await b.engine.pairWithCode(code, { via: "paste" });
    await w.settle();
    await w.advance(expiresAtMs - w.clock.now() + 1);
    assert(!a.engine.snapshot().pairingOpen);
    assertEquals(a.engine.snapshot().pairing, null);
    assertEquals(a.eventsOf("Pairing").at(-1)?.pairing, null);
    w.relay.swallow.clear();
    b.engine.connect(a.id);
    await w.advance(60_000);
    assertEquals(a.engine.snapshot().contacts.length, 0);
    assert(
      a.logs.some((l) => l.includes("ignoring an offer from a non-contact")),
    );
    assert(b.path(a) !== "Direct");
  }),
);

Deno.test(
  "pairing: cancelPairing closes the window at once",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    const { code } = await a.engine.createPairingCode();
    await a.engine.cancelPairing();
    await b.engine.pairWithCode(code, { via: "paste" });
    await w.advance(30_000);
    assertEquals(a.engine.snapshot().contacts.length, 0);
  }),
);

Deno.test(
  "pairing: a bootstrap whose identity key does not hash to the signalling peer is refused",
  withWorld(async (w) => {
    const a = await w.device("a");
    const c = await w.device("c");
    // A relay presents c under another PeerId. c holds a's code, so its bootstrap envelope
    // would decrypt; accepting it would pair a with an identity the channel was not
    // signalled for.
    const shown = "ab".repeat(32);
    w.relay.alias.set(c.id, shown);
    const { code } = await a.engine.createPairingCode();
    await c.engine.pairWithCode(code, { via: "paste" });
    await w.advance(BINDING_TIMEOUT_MS + 1000);
    assertEquals(a.engine.snapshot().contacts.length, 0);
    assert(
      a.engine.snapshot().pairingOpen,
      "the code is still usable by its real holder",
    );
    assert(!a.wasm.has_session(c.id));
    assert(!a.wasm.has_session(shown));
  }),
);

Deno.test(
  "pairing: a shown code survives a reload within its lifetime, and works once",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    const { code, expiresAtMs } = await a.engine.createPairingCode();
    const stored = await a.storage.get<{ code: string; pendingHex: string }>(
      "identity",
      "pairing",
    );
    assertEquals(stored?.code, code);
    assert(/^01[0-9a-f]{128}$/.test(stored!.pendingHex));

    const again = await w.restart(a);
    assertEquals(again.engine.snapshot().pairing, { code, expiresAtMs });
    assert(again.engine.snapshot().pairingOpen);
    await b.engine.pairWithCode(code, { via: "paste" });
    await w.settle();
    assertEquals(again.path(b), "Direct");
    assertEquals(b.path(again), "Direct");
    assertEquals(again.engine.snapshot().contacts.map((v) => v.contact.peerId), [b.id]);
    // Used up: gone from the snapshot, from wasm memory and from storage.
    assertEquals(again.engine.snapshot().pairing, null);
    assertEquals(again.wasm.export_pending_bootstrap?.(), undefined);
    assertEquals(await again.storage.get("identity", "pairing"), undefined);
  }),
);

Deno.test(
  "pairing: a code that expired while the app was closed is not shown again",
  withWorld(async (w) => {
    const a = await w.device("a");
    const { expiresAtMs } = await a.engine.createPairingCode();
    await a.engine.shutdown();
    await w.advance(expiresAtMs - w.clock.now() + 1);
    const again = await w.restart(a);
    assertEquals(again.engine.snapshot().pairing, null);
    assertEquals(again.wasm.export_pending_bootstrap?.(), undefined);
    assertEquals(await again.storage.get("identity", "pairing"), undefined);
  }),
);

Deno.test(
  "pairing: cancelling or expiring clears the pending half from wasm memory and storage",
  withWorld(async (w) => {
    const a = await w.device("a");
    await a.engine.createPairingCode();
    assert(typeof a.wasm.export_pending_bootstrap?.() === "string");
    await a.engine.cancelPairing();
    await w.settle();
    assertEquals(a.wasm.export_pending_bootstrap?.(), undefined);
    assertEquals(await a.storage.get("identity", "pairing"), undefined);

    const { expiresAtMs } = await a.engine.createPairingCode();
    assert(await a.storage.get("identity", "pairing"));
    await w.advance(expiresAtMs - w.clock.now() + 1);
    assertEquals(a.engine.snapshot().pairing, null);
    assertEquals(a.wasm.export_pending_bootstrap?.(), undefined);
    assertEquals(await a.storage.get("identity", "pairing"), undefined);
  }),
);

Deno.test(
  "pairing: on a core that cannot export the pending half, a reload invalidates a shown code",
  withWorld(async (w) => {
    const older = { without: ["export_pending_bootstrap", "import_pending_bootstrap"] as const };
    const a = await w.device("a", older);
    const b = await w.device("b");
    const { code } = await a.engine.createPairingCode();
    assertEquals(await a.storage.get("identity", "pairing"), undefined);
    const again = await w.restart(a, older);
    assertEquals(again.engine.snapshot().pairing, null);
    assert(!again.engine.snapshot().pairingOpen);
    await b.engine.pairWithCode(code, { via: "paste" });
    await w.advance(30_000);
    assertEquals(again.engine.snapshot().contacts.length, 0);
  }),
);

Deno.test(
  "binding: a relay that swaps a fingerprint is caught on both sides and nothing is sent",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    w.relay.rewrite = (kind, _from, _to, payload) =>
      kind === "rtc_offer"
        ? payload.replace(/sha-256 [0-9A-F]{2}:[0-9A-F]{2}/, "sha-256 00:00")
        : payload;
    const { code } = await a.engine.createPairingCode();
    await b.engine.pairWithCode(code, { via: "paste" });
    await w.settle();
    for (const [d, other] of [[a, b], [b, a]] as const) {
      assertEquals(d.path(other), "BindingFailed");
      assert(
        d.notices().some((n) => n.includes("failed its end-to-end check")),
      );
      assert(!d.logs.some((l) => l.includes("direct channel verified")));
    }
    assertEquals(w.rtc.open.length, 0);
    // Content stays on the device.
    const m = await b.engine.sendText(a.id, "secret");
    assertEquals(m.state, "Queued");
    // The binding is rebuilt from the live descriptions on every attempt: an honest relay
    // later gets a verified channel and the message.
    w.relay.rewrite = null;
    await w.advance(20_000);
    assertEquals(b.path(a), "Direct");
    assertEquals((await a.engine.messages(b.id)).map((x) => x.text), [
      "secret",
    ]);
  }),
);

Deno.test(
  "binding: the local description is read live at binding time",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    // Like the interop driver: once the connection is up, the description a's binding is
    // built from names another fingerprint.
    const factory = a.platform.peerConnections;
    a.platform.peerConnections = (config) => {
      const pc = factory(config);
      const real = Object.getOwnPropertyDescriptor(pc, "localDescription");
      let value = real?.value ?? null;
      Object.defineProperty(pc, "localDescription", {
        configurable: true,
        get: () =>
          pc.connectionState === "connected" && value
            ? {
              type: value.type,
              sdp: value.sdp.replace(/sha-256 [0-9A-F:]{5}/, "sha-256 FF:FF"),
            }
            : value,
        set: (v) => (value = v),
      });
      return pc;
    };
    const { code } = await a.engine.createPairingCode();
    await b.engine.pairWithCode(code, { via: "paste" });
    await w.settle();
    assertEquals(b.path(a), "BindingFailed");
    assert(b.notices().some((n) => n.includes("failed its end-to-end check")));
  }),
);

Deno.test(
  "binding: no binding within 20 s closes the connection; only identity and binding crossed",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b);
    // From now on a's envelopes are lost: b never sees a binding on a new connection.
    w.rtc.dropFrame = (from, data) => a.pcs.includes(from) && JSON.parse(data).type === "chat";
    // The connection breaks; b (the scanner, so the offerer) reconnects.
    const first = b.pcs.at(-1)!;
    a.pcs.at(-1)!.close();
    await w.advance(16_000);
    const pc = b.pcs.at(-1)!;
    assert(pc !== first, "reconnected");
    assertEquals(pc.connectionState, "connected");
    // Open, but not presented as direct before the binding verifies (PNP-001-MUST-081).
    assertEquals(b.path(a), "Connecting");
    assertEquals((await b.engine.sendText(a.id, "waiting")).state, "Queued");
    // b sent its identity frame and its binding, and no content.
    assertEquals(
      pc.channels.flatMap((c) => c.sent).map((s) => JSON.parse(s).type),
      ["identity", "chat"],
    );
    await w.advance(BINDING_TIMEOUT_MS);
    assert(b.logs.some((l) => l.includes("no channel binding from")));
    assertEquals(pc.connectionState, "closed");
    assertEquals((await b.engine.messages(a.id))[0].state, "Queued");
  }),
);

for (const core of ["with remove_session", "without remove_session"] as const) {
  Deno.test(
    `contacts: removing one deletes its history, queue and session, and leaves the others (${core})`,
    withWorld(async (w) => {
      const older = core === "without remove_session";
      const a = await w.device("a", older ? { without: ["remove_session"] } : {});
      assertEquals(typeof a.wasm.remove_session, older ? "undefined" : "function");
      const b = await w.device("b");
      const c = await w.device("c");
      await w.pair(a, b);
      await w.pair(a, c);
      await a.engine.sendText(b.id, "to b");
      await b.engine.sendText(a.id, "from b");
      await a.engine.sendText(c.id, "to c");
      await w.settle();
      // Something still waiting for b.
      w.relay.socketOf(b.id)?.drop();
      for (const pc of b.pcs) pc.close();
      await w.settle();
      assertEquals((await a.engine.sendText(b.id, "waits")).state, "Queued");
      // A code on screen while the contact is removed.
      const shown = await a.engine.createPairingCode();

      await a.engine.removeContact(b.id);
      await w.settle();

      assertEquals(a.eventsOf("ContactRemoved"), [{ kind: "ContactRemoved", peerId: b.id }]);
      assertEquals(a.engine.snapshot().contacts.map((v) => v.contact.peerId), [c.id]);
      assertEquals(await a.engine.messages(b.id), []);
      assertEquals(a.wasm.has_session(b.id), false);
      assertEquals(a.wasm.has_session(c.id), true);
      assertEquals(a.wasm.get_peer_id(), a.id, "the identity is the same");
      assertEquals(await a.storage.get("contacts", b.id), undefined);
      assertEquals(await a.storage.get("contactState", b.id), undefined);
      assertEquals(await a.storage.getAllByPeer("messages", b.id), []);
      assertEquals(await a.storage.getAllByPeer("outbox", b.id), []);
      const saved = await a.storage.get<{ json: string }>("sessions", "blob");
      assertEquals(Object.keys(JSON.parse(saved!.json)), [c.id]);
      // With `remove_session` only that session goes and the shown code stays. Without it the
      // identity was reloaded, which drops the pending bootstrap: the code is closed.
      if (older) assertEquals(a.engine.snapshot().pairing, null);
      else assertEquals(a.engine.snapshot().pairing?.code, shown.code);

      // The other contact still works, both ways.
      await a.engine.sendText(c.id, "still here");
      await c.engine.sendText(a.id, "so am I");
      await w.settle();
      assertEquals((await a.engine.messages(c.id)).map((m) => m.text), [
        "to c",
        "still here",
        "so am I",
      ]);
      assertEquals((await c.engine.messages(a.id)).at(-2)?.text, "still here");

      // The removed contact is a stranger again: nothing it sends is accepted.
      const err = await assertRejects(() => a.engine.sendText(b.id, "x"), EngineError);
      assertEquals(err.code, "UnknownContact");
      const again = await assertRejects(() => a.engine.removeContact(b.id), EngineError);
      assertEquals(again.code, "UnknownContact");

      // And survives a restart.
      const a2 = await w.restart(a);
      assertEquals(a2.engine.snapshot().contacts.map((v) => v.contact.peerId), [c.id]);
      assertEquals(a2.wasm.has_session(b.id), false);
    }),
  );
}

Deno.test(
  "contacts: a removed contact can be added again with a new code",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b);
    await a.engine.removeContact(b.id);
    await b.engine.removeContact(a.id);
    await w.settle();
    await w.pair(a, b);
    await a.engine.sendText(b.id, "hello again");
    await w.settle();
    assertEquals((await b.engine.messages(a.id)).map((m) => m.text), ["hello again"]);
  }),
);
