import { assertEquals, assertRejects } from "@std/assert";
import { EngineError } from "../../src/engine/types.ts";
import { hrefOf, isLabHash, parseRoute } from "../../src/router.ts";
import { captionOf, threadItems } from "../../src/screens/thread.ts";
import { createFakeStore, FAKE_PEERS } from "../../src/state/fake.ts";
import {
  callEndWords,
  type ContactView,
  isOnline,
  lineState,
  type PathState,
  sortContacts,
} from "../../src/state/model.ts";
import { contactOf, messagesOf } from "../../src/state/store.ts";

Deno.test("lineState: one variant per path state; being offline ourselves wins", () => {
  const expected: Record<PathState, string> = {
    Unknown: "waiting",
    Offline: "waiting",
    Connecting: "connecting",
    Direct: "open",
    NoDirectPath: "no-path",
    BindingFailed: "blocked",
  };
  for (const [path, line] of Object.entries(expected)) {
    assertEquals(lineState(path as PathState, true), line);
    assertEquals(lineState(path as PathState, false), "self-offline");
  }
});

Deno.test("isOnline: who is listed under Online now", () => {
  assertEquals(
    (["Unknown", "Offline", "Connecting", "Direct", "NoDirectPath", "BindingFailed"] as const)
      .filter(isOnline),
    ["Connecting", "Direct", "NoDirectPath", "BindingFailed"],
  );
});

Deno.test("sortContacts: online first, then by last activity, newest first", () => {
  const view = (name: string, path: PathState, lastActivityMs: number): ContactView => ({
    contact: {
      peerId: name,
      name,
      identityKey: null,
      addedMs: 0,
      verified: "no",
      verifiedMs: null,
    },
    path,
    queued: 0,
    unread: 0,
    lastActivityMs,
  });
  const sorted = sortContacts([
    view("away-old", "Offline", 10),
    view("online-old", "Direct", 20),
    view("away-new", "Unknown", 90),
    view("online-new", "NoDirectPath", 80),
    view("b-tie", "Offline", 5),
    view("a-tie", "Offline", 5),
  ]);
  assertEquals(sorted.map((v) => v.contact.name), [
    "online-new",
    "online-old",
    "away-new",
    "away-old",
    "a-tie",
    "b-tie",
  ]);
});

Deno.test("callEndWords: one wording per way a call ends", () => {
  assertEquals(callEndWords({ kind: "HungUp" }, false), "youEnded");
  assertEquals(callEndWords({ kind: "RemoteHungUp" }, true), "theyEnded");
  // The engine's names: we declined is `Declined`, they declined is `Rejected`.
  assertEquals(callEndWords({ kind: "Declined" }, true), "youDeclined");
  assertEquals(callEndWords({ kind: "Rejected" }, false), "theyDeclined");
  assertEquals(callEndWords({ kind: "NoAnswer" }, false), "noAnswer");
  assertEquals(callEndWords({ kind: "NoAnswer" }, true), "missed");
  assertEquals(callEndWords({ kind: "Failed", reason: "x" }, false), "failed");
});

const queued = (store: ReturnType<typeof createFakeStore>, peer: string) =>
  contactOf(store, peer)?.queued;

Deno.test("fake store: a message on an open line is delivered, otherwise it waits", async () => {
  const store = createFakeStore();
  await store.send(FAKE_PEERS.mira, "hello");
  assertEquals(messagesOf(store, FAKE_PEERS.mira).at(-1)?.state, "Sent");
  await store.send(FAKE_PEERS.tomasz, "hello");
  assertEquals(messagesOf(store, FAKE_PEERS.tomasz).at(-1)?.state, "Queued");
  assertEquals(queued(store, FAKE_PEERS.tomasz), 4);
});

Deno.test("fake store: when the line opens, what waited is delivered", () => {
  const store = createFakeStore();
  store.setPath(FAKE_PEERS.tomasz, "Direct");
  assertEquals(queued(store, FAKE_PEERS.tomasz), 0);
  // Other contacts are untouched.
  assertEquals(queued(store, FAKE_PEERS.kofi), 2);
});

Deno.test("fake store: offline ourselves, even a direct contact's message waits", async () => {
  const store = createFakeStore();
  store.setSelfOnline(false);
  assertEquals(store.relay.value.kind, "Disconnected");
  await store.send(FAKE_PEERS.mira, "later");
  assertEquals(messagesOf(store, FAKE_PEERS.mira).at(-1)?.state, "Queued");
  store.setSelfOnline(true);
  assertEquals(queued(store, FAKE_PEERS.mira), 0);
});

Deno.test("fake store: take back and edit only touch messages still on this device", async () => {
  const store = createFakeStore();
  const [delivered, held] = messagesOf(store, FAKE_PEERS.tomasz).filter((m) =>
    m.direction === "Sent"
  );
  // As the engine: a message that has left the device rejects with `NotQueued`.
  const gone = await assertRejects(() => store.takeBack(delivered.id), EngineError);
  assertEquals(gone.code, "NotQueued");
  await assertRejects(() => store.edit(delivered.id, "changed"), EngineError);
  assertEquals(messagesOf(store, FAKE_PEERS.tomasz).find((m) => m.id === delivered.id), delivered);

  await store.edit(held.id, "changed");
  assertEquals(messagesOf(store, FAKE_PEERS.tomasz).find((m) => m.id === held.id)?.text, "changed");
  await store.takeBack(held.id);
  assertEquals(messagesOf(store, FAKE_PEERS.tomasz).some((m) => m.id === held.id), false);
});

Deno.test("fake store: calls only start on an open line", async () => {
  const store = createFakeStore();
  await store.startCall(FAKE_PEERS.tomasz, false);
  assertEquals(store.call.value, null);
  await store.startCall(FAKE_PEERS.mira, true);
  assertEquals(store.call.value?.state.kind, "Outgoing");
  store.setPath(FAKE_PEERS.mira, "Offline");
  assertEquals(store.call.value, null);
});

Deno.test("fake store: retry shows the attempt, then the same reason", async () => {
  const store = createFakeStore({ retryDelayMs: 5 });
  const path = () => contactOf(store, FAKE_PEERS.kofi)?.path;
  store.connect(FAKE_PEERS.kofi);
  assertEquals(path(), "Connecting");
  await new Promise((done) => setTimeout(done, 30));
  assertEquals(path(), "NoDirectPath");
});

Deno.test("fake store: a scanned code is verified in person, a pasted one is not", async () => {
  const store = createFakeStore({ empty: true });
  const scanned = await store.pair("ab".repeat(40), "scan");
  assertEquals(scanned.verified, "in-person");
  const pasted = await store.pair("cd".repeat(40), "paste");
  assertEquals(pasted.verified, "no");
  await store.setCompared(pasted.peerId, true);
  assertEquals(contactOf(store, pasted.peerId)?.contact.verified, "compared");
  // Comparing numbers never undoes having met.
  await store.setCompared(scanned.peerId, false);
  assertEquals(contactOf(store, scanned.peerId)?.contact.verified, "in-person");
  const bad = await assertRejects(() => store.pair("zz", "paste"), EngineError);
  assertEquals(bad.code, "InvalidCode");
});

Deno.test("fake store: a verification code on screen, confirmed or refused", async () => {
  const store = createFakeStore({ empty: true });
  const code = await store.createPairingCode();
  assertEquals(code.text, code.code);
  assertEquals(store.sas.value, null);
  const sas = { peerId: "5a".repeat(32), digits: "042917", emoji: "abcde", confirmed: false };
  store.setSas(sas);
  await store.confirmSas("00".repeat(32));
  assertEquals(store.sas.value, sas);
  await store.confirmSas(sas.peerId);
  assertEquals(store.sas.value?.confirmed, true);
  await store.rejectSas(sas.peerId);
  assertEquals(store.sas.value, null);
  store.setSas(sas);
  await store.stopPairing(sas.peerId);
  assertEquals(store.sas.value, null);
});

Deno.test("thread: bubble kinds, groups and the single caption", () => {
  const store = createFakeStore();
  const items = threadItems(messagesOf(store, FAKE_PEERS.tomasz));
  assertEquals(items.map((i) => i.kind), ["received", "delivered", "held", "held", "held"]);
  assertEquals(items.map((i) => i.groupStart), [true, true, false, false, false]);
  assertEquals(items.map((i) => i.groupEnd), [true, false, false, false, true]);
  assertEquals(captionOf(items), { after: 4, caption: "waiting" });

  const mira = threadItems(messagesOf(store, FAKE_PEERS.mira));
  assertEquals(captionOf(mira), { after: 4, caption: "delivered" });
  assertEquals(captionOf(threadItems([])), null);
});

Deno.test("thread: a delivered message stays outlined until its turn in the fill", () => {
  const store = createFakeStore();
  store.setPath(FAKE_PEERS.tomasz, "Direct");
  const messages = messagesOf(store, FAKE_PEERS.tomasz);
  const lastTwo = new Set(messages.slice(-2).map((m) => m.id));
  const items = threadItems(messages, lastTwo);
  assertEquals(items.map((i) => i.kind), ["received", "delivered", "delivered", "held", "held"]);
  assertEquals(captionOf(items)?.caption, "waiting");
});

Deno.test("router: hash routes", () => {
  assertEquals(parseRoute(""), { name: "list" });
  assertEquals(parseRoute("#/"), { name: "list" });
  assertEquals(parseRoute("#/add"), { name: "add" });
  assertEquals(parseRoute("#/settings"), { name: "settings" });
  assertEquals(parseRoute("#/c/A1b2"), { name: "conversation", peerId: "a1b2" });
  assertEquals(parseRoute("#/c/not-hex"), { name: "list" });
  assertEquals(hrefOf({ name: "conversation", peerId: "a1b2" }), "#/c/a1b2");
  assertEquals(hrefOf({ name: "add" }), "#/add");
});

Deno.test("router: everything under #/lab is the lab's own world", () => {
  assertEquals(parseRoute("#/lab"), { name: "lab" });
  assertEquals(parseRoute("#/lab/"), { name: "list" });
  assertEquals(parseRoute("#/lab/c/a1b2"), { name: "conversation", peerId: "a1b2" });
  assertEquals(parseRoute("#/lab/settings"), { name: "settings" });
  assertEquals(isLabHash("#/lab"), true);
  assertEquals(isLabHash("#/lab/add"), true);
  assertEquals(isLabHash("#/"), false);
  assertEquals(isLabHash("#/labyrinth"), false);
});
