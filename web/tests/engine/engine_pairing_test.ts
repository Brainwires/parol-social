// Identity, pairing (PNP-003) and the channel binding (PNP-001 §10.5.1), with real crypto.
import { assert, assertEquals, assertRejects } from "@std/assert";
import { BINDING_TIMEOUT_MS } from "../../src/engine/engine.ts";
import { MemoryStorage } from "../../src/engine/storage.ts";
import { EngineError } from "../../src/engine/types.ts";
import { chatFrame } from "../../src/engine/wire.ts";
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

/** Base45 (RFC 9285): what a QR code's alphanumeric mode holds. */
const BASE45 = /^[0-9A-Z $%*+\-./:]{100,}$/;

Deno.test(
  "pairing: both compare the verification code, then both have the contact and a verified channel",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    const { code, text, expiresAtMs } = await a.engine.createPairingCode();
    // PNP-003-MUST-007: the code is base45; as text it has no blanks.
    assert(BASE45.test(code), code);
    assertEquals(text, code.replaceAll(" ", "_"));
    // The window is the code's own lifetime: 1800 s from its (300 s floored) timestamp.
    const left = expiresAtMs - w.clock.now();
    assert(left > 1500_000 - 1 && left <= 1800_000, `window ${left}`);
    assert(a.engine.snapshot().pairingOpen);

    const contact = await b.engine.pairWithCode(code, { via: "scan" });
    assertEquals(contact.peerId, a.id);
    assertEquals(contact.identityKey, a.engine.publicKey);
    // Not a contact to talk to yet: it is being added.
    assertEquals(contact.pairing, "new");
    assertEquals(contact.verified, "no");
    await w.settle();

    // The code is used up: the window closed with it (PNP-003-MUST-009, -MUST-040).
    assert(!a.engine.snapshot().pairingOpen);
    assertEquals(a.eventsOf("Pairing").at(-1)?.pairing, null);
    // Both show the same verification code, as digits and as emoji (PNP-003-MUST-026, -027).
    const [shownA, shownB] = [a.engine.snapshot().sas!, b.engine.snapshot().sas!];
    assertEquals(shownA.peerId, b.id);
    assertEquals(shownB.peerId, a.id);
    assert(/^\d{6}$/.test(shownA.digits));
    assertEquals([...shownA.emoji].length, 5);
    assertEquals([shownA.digits, shownA.emoji], [shownB.digits, shownB.emoji]);
    // The channel's binding verified meanwhile, but the path is not usable before the
    // pairing completes, and nothing is a contact for good.
    for (const d of [a, b]) {
      assert(d.logs.some((l) => l.startsWith("[WebRTC] direct channel verified with ")));
    }
    assertEquals([a.path(b), b.path(a)], ["Connecting", "Connecting"]);
    assertEquals([a.contact(b)?.pairing, b.contact(a)?.pairing], ["new", "new"]);
    assertEquals((await b.storage.get<{ pairing?: string }>("contacts", a.id))?.pairing, "new");

    // One confirmation is not enough (PNP-003-MUST-029).
    await a.engine.confirmSas(b.id);
    await w.settle();
    assertEquals(a.engine.snapshot().sas?.confirmed, true);
    assertEquals(a.contact(b)?.pairing, "new");
    assertEquals(a.eventsOf("PairingComplete"), []);
    const twice = await assertRejects(() => a.engine.confirmSas(b.id), EngineError);
    assertEquals(twice.code, "NoPairing");

    await b.engine.confirmSas(a.id);
    await w.settle();
    for (const [d, other] of [[a, b], [b, a]] as const) {
      assertEquals(d.eventsOf("PairingComplete"), [
        { kind: "PairingComplete", peerId: other.id, sasVerified: true },
      ]);
      assertEquals(d.engine.snapshot().sas, null);
      assertEquals(d.path(other), "Direct");
      assertEquals(d.contact(other)?.pairing, undefined);
      assertEquals(d.contact(other)?.sasVerified, true);
      assertEquals(d.wasm.pairing_state(other.id), undefined);
      assertEquals(d.eventsOf("PairingFailed"), []);
    }
    // The presenter learns the scanner's identity key from the bootstrap envelope...
    assertEquals(a.contact(b)?.identityKey, b.engine.publicKey);
    // ...but cannot know how its code was obtained; the scanner used its camera.
    assertEquals(a.contact(b)?.verified, "no");
    assertEquals(b.contact(a)?.verified, "in-person");
    // Exactly one peer connection each, and nothing queued.
    assertEquals(w.rtc.open.length, 2);
    assertEquals((await b.storage.getAll("outbox")).length, 0);
    // The contact as stored: verified, and no longer marked as being added.
    const stored = await b.storage.get<{ pairing?: string; sasVerified?: boolean }>(
      "contacts",
      a.id,
    );
    assertEquals([stored?.pairing, stored?.sasVerified], [undefined, true]);

    // Content flows both ways under the new session, and survives a restart.
    await a.engine.sendText(b.id, "hello");
    await b.engine.sendText(a.id, "hi");
    await w.settle();
    assertEquals((await b.engine.messages(a.id)).map((m) => m.text), ["hello", "hi"]);
    const again = await w.restart(b);
    assertEquals(again.contact(a)?.sasVerified, true);
    assertEquals(again.contact(a)?.verified, "in-person");
    await w.advance(30_000);
    await a.engine.sendText(again.id, "after the restart");
    await w.advance(30_000);
    assertEquals((await again.engine.messages(a.id)).at(-1)?.text, "after the restart");
  }),
);

Deno.test(
  "pairing: nothing but the pairing crosses the channel until it completes; texts wait",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b", { media: true });
    const { text } = await a.engine.createPairingCode();
    await b.engine.pairWithCode(text, { via: "paste" });
    await w.settle();
    assert(a.engine.snapshot().sas && b.engine.snapshot().sas);

    // Typed while the verification code is on screen.
    assertEquals((await b.engine.sendText(a.id, "early")).state, "Queued");
    assertEquals((await a.engine.sendText(b.id, "early too")).state, "Queued");
    await w.settle();
    assertEquals(await a.engine.messages(b.id).then((m) => m.map((x) => x.direction)), ["Sent"]);
    const err = await assertRejects(() => b.engine.startCall(a.id, false), EngineError);
    assertEquals(err.code, "NotConnected");

    await w.confirmSas(a, b);
    await w.settle();
    assertEquals((await a.engine.messages(b.id)).map((m) => [m.text, m.state]), [
      ["early too", "Sent"],
      ["early", "Received"],
    ]);
    assertEquals((await b.engine.messages(a.id)).map((m) => [m.text, m.state]), [
      ["early", "Sent"],
      ["early too", "Received"],
    ]);
  }),
);

Deno.test(
  "pairing: a pasted code proves nothing; comparing safety numbers sets 'compared'",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b, "paste");
    assertEquals(b.contact(a)?.verified, "no");
    assertEquals(b.contact(a)?.sasVerified, true);
    const number = b.engine.safetyNumber(a.id);
    assertEquals(number, a.engine.safetyNumber(b.id));
    assert(/^(\d{10} ){5}\d{10}$/.test(number!));
    const c = await b.engine.setVerification(a.id, "compared");
    assertEquals(c.verified, "compared");
    assert(c.verifiedMs !== null);
    assertEquals((await b.engine.setVerification(a.id, "no")).verified, "no");
    // The confirmed verification code is not what `setVerification` takes back.
    assertEquals(b.contact(a)?.sasVerified, true);
  }),
);

Deno.test(
  "pairing: without the verification code on either device the contact is made, unverified",
  withWorld(async (w) => {
    const quiet = { config: { requestSas: false } };
    const a = await w.device("a", quiet);
    const b = await w.device("b", quiet);
    await w.pair(a, b, "paste");
    for (const [d, other] of [[a, b], [b, a]] as const) {
      assertEquals(d.eventsOf("Sas"), []);
      assertEquals(d.eventsOf("PairingComplete"), [
        { kind: "PairingComplete", peerId: other.id, sasVerified: false },
      ]);
      assertEquals(d.contact(other)?.sasVerified, undefined);
      assertEquals(d.contact(other)?.pairing, undefined);
    }
    await a.engine.sendText(b.id, "hello");
    await w.settle();
    assertEquals((await b.engine.messages(a.id)).map((m) => m.text), ["hello"]);
  }),
);

Deno.test(
  "pairing: one device asking for the verification code is enough for both to show it",
  withWorld(async (w) => {
    for (const asks of ["presenter", "scanner"] as const) {
      const a = await w.device(`a-${asks}`, { config: { requestSas: asks === "presenter" } });
      const b = await w.device(`b-${asks}`, { config: { requestSas: asks === "scanner" } });
      const { code } = await a.engine.createPairingCode();
      await b.engine.pairWithCode(code, { via: "scan" });
      await w.settle();
      assertEquals(a.engine.snapshot().sas?.digits, b.engine.snapshot().sas?.digits, asks);
      assert(a.engine.snapshot().sas !== null, asks);
      await w.confirmSas(a, b);
      await w.settle();
      assertEquals([a.contact(b)?.sasVerified, b.contact(a)?.sasVerified], [true, true], asks);
      assertEquals([a.path(b), b.path(a)], ["Direct", "Direct"], asks);
    }
  }),
);

Deno.test(
  "pairing: codes that differ end it; neither device keeps the contact or a session",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    const { code } = await a.engine.createPairingCode();
    await b.engine.pairWithCode(code, { via: "scan" });
    await w.settle();
    await b.engine.sendText(a.id, "never sent");
    assert(a.engine.snapshot().sas && b.engine.snapshot().sas);

    await b.engine.rejectSas(a.id);
    await w.settle();
    // The one who said no, and the one whose connection went with it (PNP-003 §4).
    assertEquals(b.eventsOf("PairingFailed"), [
      { kind: "PairingFailed", peerId: a.id, reason: "SasRejected" },
    ]);
    assertEquals(a.eventsOf("PairingFailed"), [
      { kind: "PairingFailed", peerId: b.id, reason: "ConnectionLost" },
    ]);
    for (const [d, other] of [[a, b], [b, a]] as const) {
      assertEquals(d.engine.snapshot().contacts, []);
      assertEquals(d.engine.snapshot().sas, null);
      assertEquals(d.eventsOf("ContactRemoved"), [{ kind: "ContactRemoved", peerId: other.id }]);
      assertEquals(d.eventsOf("PairingComplete"), []);
      assertEquals(d.wasm.has_session(other.id), false);
      assertEquals(d.wasm.pairing_state(other.id), undefined);
      assertEquals(await d.storage.getAll("contacts"), []);
      assertEquals(await d.storage.getAll("contactState"), []);
      assertEquals(await d.storage.getAll("outbox"), []);
      assertEquals(await d.storage.getAll("messages"), []);
      const saved = await d.storage.get<{ json: string }>("sessions", "blob");
      assertEquals(saved?.json ?? "", "");
    }
    assertEquals(w.rtc.open.length, 0);
    // Nothing comes back by itself, and nothing reconnects.
    await w.advance(120_000);
    assertEquals(w.rtc.open.length, 0);
    const gone = await assertRejects(() => a.engine.confirmSas(b.id), EngineError);
    assertEquals(gone.code, "NoPairing");

    // A new code works, and this time the codes are confirmed.
    await w.pair(a, b, "scan");
    assertEquals(b.contact(a)?.sasVerified, true);
  }),
);

Deno.test(
  "pairing: a verification code nobody answers times out on both devices",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    const { code } = await a.engine.createPairingCode();
    await b.engine.pairWithCode(code, { via: "scan" });
    await w.settle();
    assert(a.engine.snapshot().sas && b.engine.snapshot().sas);
    await w.advance(9 * 60_000);
    assert(a.engine.snapshot().sas && b.engine.snapshot().sas);
    // PNP-003 §4: SAS_PENDING lasts 10 minutes.
    await w.advance(90_000);
    for (const d of [a, b]) {
      assertEquals(d.engine.snapshot().contacts, []);
      assertEquals(d.engine.snapshot().sas, null);
      assertEquals(d.eventsOf("PairingFailed").length, 1);
      assertEquals(await d.storage.getAll("contacts"), []);
    }
    assert(
      [a, b].some((d) => d.eventsOf("PairingFailed")[0].reason === "Timeout"),
      "one of them timed out first",
    );
  }),
);

Deno.test(
  "pairing: a scanned code whose owner never answers is given up after five minutes",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    const { code } = await a.engine.createPairingCode();
    // b's offers never arrive.
    w.relay.swallow.add("rtc_offer");
    await b.engine.pairWithCode(code, { via: "paste" });
    await w.settle();
    assertEquals(b.contact(a)?.pairing, "new");
    // PNP-003 §4: SECRET_SHARED lasts 5 minutes.
    await w.advance(5 * 60_000 + 30_000);
    assertEquals(b.eventsOf("PairingFailed"), [
      { kind: "PairingFailed", peerId: a.id, reason: "Timeout" },
    ]);
    assertEquals(b.engine.snapshot().contacts, []);
    assertEquals(b.wasm.has_session(a.id), false);
    // It no longer offers to someone who is not a contact.
    w.relay.swallow.clear();
    const offers = w.relay.framesFrom(b.id, "rtc_offer").length;
    await w.advance(10 * 60_000);
    assertEquals(w.relay.framesFrom(b.id, "rtc_offer").length, offers);
    assertEquals(a.engine.snapshot().contacts, []);
  }),
);

Deno.test(
  "pairing: stopping while the devices reach each other removes what was begun",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    const { code } = await a.engine.createPairingCode();
    w.relay.swallow.add("rtc_offer");
    await b.engine.pairWithCode(code, { via: "paste" });
    await w.settle();
    await b.engine.stopPairing(a.id);
    await w.settle();
    assertEquals(b.eventsOf("PairingFailed"), [
      { kind: "PairingFailed", peerId: a.id, reason: "Cancelled" },
    ]);
    assertEquals(b.engine.snapshot().contacts, []);
    assertEquals(await b.storage.getAll("contacts"), []);
    assertEquals(b.wasm.has_session(a.id), false);
    // Stopping what is not under way does nothing.
    await b.engine.stopPairing(a.id);
    assertEquals(b.eventsOf("PairingFailed").length, 1);
  }),
);

Deno.test(
  "pairing: a restart in the middle removes the half-made contact and its session",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    const { code } = await a.engine.createPairingCode();
    await b.engine.pairWithCode(code, { via: "scan" });
    await w.settle();
    await b.engine.sendText(a.id, "typed while adding");
    assert(a.engine.snapshot().sas && b.engine.snapshot().sas);
    // On record while it is under way: the contact, marked, and the bootstrap session.
    assertEquals((await b.storage.get<{ pairing?: string }>("contacts", a.id))?.pairing, "new");
    const before = await b.storage.get<{ json: string }>("sessions", "blob");
    assertEquals(Object.keys(JSON.parse(before!.json)), [a.id]);

    // The scanner's page is reloaded; the presenter's a little later.
    const b2 = await w.restart(b);
    assertEquals(b2.engine.snapshot().contacts, []);
    assertEquals(b2.engine.snapshot().sas, null);
    assertEquals(b2.wasm.has_session(a.id), false);
    assertEquals(await b2.storage.getAll("contacts"), []);
    assertEquals(await b2.storage.getAll("contactState"), []);
    assertEquals(await b2.storage.getAll("outbox"), []);
    assertEquals(await b2.storage.getAll("messages"), []);
    assertEquals((await b2.storage.get<{ json: string }>("sessions", "blob"))?.json, "");
    assert(b2.logs.some((l) => l.includes("an unfinished pairing")));

    // The presenter lost the connection its pairing was on: over there too (PNP-003 §4).
    await w.settle();
    assertEquals(a.eventsOf("PairingFailed"), [
      { kind: "PairingFailed", peerId: b.id, reason: "ConnectionLost" },
    ]);
    assertEquals(a.engine.snapshot().contacts, []);
    assertEquals(await a.storage.getAll("contacts"), []);

    // The other way round: this time the presenter's page is reloaded.
    const { code: next } = await a.engine.createPairingCode();
    await b2.engine.pairWithCode(next, { via: "scan" });
    await w.settle();
    assert(a.engine.snapshot().sas && b2.engine.snapshot().sas);
    assertEquals((await a.storage.get<{ pairing?: string }>("contacts", b.id))?.pairing, "new");
    const a2 = await w.restart(a);
    assertEquals(a2.engine.snapshot().contacts, []);
    assertEquals(a2.engine.snapshot().sas, null);
    assertEquals(a2.wasm.has_session(b.id), false);
    assertEquals(await a2.storage.getAll("contacts"), []);
    // The used code did not come back with the reload.
    assertEquals(a2.engine.snapshot().pairing, null);
    assertEquals(await a2.storage.get("identity", "pairing"), undefined);
    await w.settle();
    assertEquals(b2.engine.snapshot().contacts, []);
    assertEquals(b2.eventsOf("PairingFailed").map((e) => e.reason), ["ConnectionLost"]);

    // Starting over works.
    await w.pair(a2, b2, "scan");
    assertEquals(b2.contact(a2)?.sasVerified, true);
  }),
);

Deno.test(
  "pairing: a restart while adding an existing contact again keeps the contact, without a session",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    await w.pair(a, b, "scan");
    await b.engine.renameContact(a.id, "Alice");
    await a.engine.sendText(b.id, "before");
    await w.settle();

    // b adds a again with a new code, and the page goes away before the codes are compared.
    const { code } = await a.engine.createPairingCode();
    const again = await b.engine.pairWithCode(code, { via: "paste" });
    assertEquals(again.pairing, "again");
    await w.settle();
    assert(b.engine.snapshot().sas, "the verification code is asked for again");
    assertEquals((await b.engine.sendText(a.id, "typed while adding")).state, "Queued");
    const b2 = await w.restart(b);

    const kept = b2.contact(a)!;
    assertEquals([kept.name, kept.pairing, kept.sasVerified], ["Alice", undefined, true]);
    assertEquals(kept.verified, "in-person");
    assertEquals(b2.wasm.has_session(a.id), false);
    // The history stays; what was waiting for the lost session is dropped, not left queued.
    assertEquals((await b2.engine.messages(a.id)).map((m) => [m.text, m.state]), [
      ["before", "Received"],
      ["typed while adding", "Dropped"],
    ]);
    assertEquals(await b2.storage.getAll("outbox"), []);
    const err = await assertRejects(() => b2.engine.sendText(a.id, "x"), EngineError);
    assertEquals(err.code, "NoSession");
  }),
);

Deno.test(
  "pairing: our own code, garbage and an expired code are refused with the right error",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    const { code, text } = await a.engine.createPairingCode();
    const err = async (c: string, d = b) =>
      (await assertRejects(
        () => d.engine.pairWithCode(c, { via: "paste" }),
        EngineError,
      )).code;
    assertEquals(await err(code, a), "OwnCode");
    assertEquals(await err(text, a), "OwnCode");
    assertEquals(await err("hello"), "InvalidCode");
    assertEquals(await err(""), "InvalidCode");
    assertEquals(await err(a.id), "InvalidCode"); // a bare PeerId is not a code
    assertEquals(await err("ab".repeat(80)), "InvalidCode");
    assertEquals(await err(text.slice(0, text.length - 20)), "InvalidCode");
    // PNP-003-MUST-011: 30 minutes after its timestamp a code is refused. Quotes and
    // whitespace around a pasted code are tolerated.
    await w.advance(1801_000);
    assertEquals(await err(` "${text}"\n`), "CodeExpired");
    assertEquals(await err(code), "CodeExpired");
    // Nothing was begun for any of them.
    assertEquals(b.engine.snapshot().contacts.length, 0);
    assertEquals(b.wasm.has_session(a.id), false);
    assertEquals(b.eventsOf("PairingFailed"), []);
  }),
);

Deno.test(
  "pairing: the window closes when the code expires, and strangers' offers are refused",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    const { code, expiresAtMs } = await a.engine.createPairingCode();
    // b takes the code a minute before it expires, but its offers only arrive afterwards.
    await w.advance(expiresAtMs - w.clock.now() - 60_000);
    w.relay.swallow.add("rtc_offer");
    await b.engine.pairWithCode(code, { via: "paste" });
    await w.settle();
    await w.advance(61_000);
    assert(!a.engine.snapshot().pairingOpen);
    assertEquals(a.engine.snapshot().pairing, null);
    assertEquals(a.eventsOf("Pairing").at(-1)?.pairing, null);
    assertEquals(a.wasm.export_pending_bootstrap?.(), undefined);
    w.relay.swallow.clear();
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
    assert(a.logs.some((l) => l.includes("ignoring an offer from a non-contact")));
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
    assertEquals(a.wasm.pairing_state(shown), undefined);
    assertEquals(a.eventsOf("Sas"), []);
  }),
);

Deno.test(
  "pairing: the holder of a code who sends something else than the handshake is not added",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    const { code } = await a.engine.createPairingCode();
    // Nothing b's engine sends on the channel arrives...
    w.rtc.dropFrame = (from, data) => b.pcs.includes(from) && JSON.parse(data).type === "chat";
    await b.engine.pairWithCode(code, { via: "paste" });
    await w.settle();
    // ...and what a gets instead as b's first envelope is content under the bootstrap
    // session, not its BootstrapHandshake (what a client of the older pairing sent):
    // PNP-003-MUST-022.
    const content = b.wasm.envelope_encode(
      a.id,
      0x01,
      new TextEncoder().encode("hello"),
      BigInt(Math.floor(w.clock.now() / 1000)),
      b.engine.publicKey,
    );
    b.pcs.at(-1)!.channels[0].inject(chatFrame(content));
    await w.settle();
    assertEquals(a.engine.snapshot().contacts, []);
    assertEquals(a.eventsOf("PairingFailed"), [
      { kind: "PairingFailed", peerId: b.id, reason: "Failed" },
    ]);
    assertEquals(a.eventsOf("ContactAdded"), []);
    assertEquals(a.eventsOf("Message"), []);
    assertEquals(a.wasm.has_session(b.id), false);
    // The code is spent all the same: one try per code (PNP-003-MUST-040).
    assert(!a.engine.snapshot().pairingOpen);
    assertEquals(await a.storage.getAll("contacts"), []);
  }),
);

Deno.test(
  "pairing: a relay between the two devices is caught by the binding and no contact is made",
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
    for (const d of [a, b]) {
      assert(d.notices().some((n) => n.includes("failed its end-to-end check")));
      assert(!d.logs.some((l) => l.includes("direct channel verified")));
      assertEquals(d.engine.snapshot().contacts, []);
      assertEquals(d.eventsOf("PairingFailed").map((e) => e.reason), ["ConnectionLost"]);
      assertEquals(await d.storage.getAll("contacts"), []);
    }
    assertEquals(w.rtc.open.length, 0);
    assertEquals(a.wasm.has_session(b.id), false);
    assertEquals(b.wasm.has_session(a.id), false);
    // With an honest relay a new code pairs them.
    w.relay.rewrite = null;
    await w.pair(a, b);
  }),
);

Deno.test(
  "pairing: a shown code survives a reload within its lifetime, and works once",
  withWorld(async (w) => {
    const a = await w.device("a");
    const b = await w.device("b");
    const { code, text, expiresAtMs } = await a.engine.createPairingCode();
    const stored = await a.storage.get<{ code: string; text: string; pendingHex: string }>(
      "identity",
      "pairing",
    );
    assertEquals([stored?.code, stored?.text], [code, text]);
    assert(/^01[0-9a-f]{128}$/.test(stored!.pendingHex));

    const again = await w.restart(a);
    assertEquals(again.engine.snapshot().pairing, { code, text, expiresAtMs });
    assert(again.engine.snapshot().pairingOpen);
    await b.engine.pairWithCode(text, { via: "paste" });
    await w.settle();
    // Used up as soon as b's handshake arrived: gone from the snapshot, from wasm memory and
    // from storage, before the verification code is even answered.
    assertEquals(again.engine.snapshot().pairing, null);
    assertEquals(again.wasm.export_pending_bootstrap?.(), undefined);
    assertEquals(await again.storage.get("identity", "pairing"), undefined);
    await w.confirmSas(again, b);
    await w.settle();
    assertEquals(again.path(b), "Direct");
    assertEquals(b.path(again), "Direct");
    assertEquals(again.engine.snapshot().contacts.map((v) => v.contact.peerId), [b.id]);
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
    await w.pair(a, b);
    // From the next connection on, the relay sits in between.
    w.relay.rewrite = (kind, _from, _to, payload) =>
      kind === "rtc_offer"
        ? payload.replace(/sha-256 [0-9A-F]{2}:[0-9A-F]{2}/, "sha-256 00:00")
        : payload;
    a.pcs.at(-1)!.close();
    await w.advance(16_000);
    for (const [d, other] of [[a, b], [b, a]] as const) {
      assertEquals(d.path(other), "BindingFailed");
      assert(
        d.notices().some((n) => n.includes("failed its end-to-end check")),
      );
    }
    assertEquals(w.rtc.open.length, 0);
    // The contact stays (it was made before), and content stays on the device.
    assertEquals(b.engine.snapshot().contacts.length, 1);
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
    await w.pair(a, b);
    // Like the interop driver: once a connection is up, the description a's binding is
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
    a.pcs.at(-1)!.close();
    await w.advance(16_000);
    assertEquals(b.path(a), "BindingFailed");
    assert(b.notices().some((n) => n.includes("failed its end-to-end check")));
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
