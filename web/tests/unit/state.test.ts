import { assertEquals } from "@std/assert";
import { parseRoute } from "../../src/router.ts";
import { captionOf, threadItems } from "../../src/screens/thread.ts";
import { createFakeStore, FAKE_PEERS } from "../../src/state/fake.ts";
import { isOnline, lineState, type PathState } from "../../src/state/model.ts";
import { messagesOf, waitingCount } from "../../src/state/store.ts";

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

Deno.test("fake store: a message on an open line is delivered, otherwise it waits", () => {
  const store = createFakeStore();
  store.send(FAKE_PEERS.mira, "hello");
  assertEquals(messagesOf(store, FAKE_PEERS.mira).at(-1)?.state, "Sent");
  store.send(FAKE_PEERS.tomasz, "hello");
  assertEquals(messagesOf(store, FAKE_PEERS.tomasz).at(-1)?.state, "Queued");
  assertEquals(waitingCount(messagesOf(store, FAKE_PEERS.tomasz)), 4);
});

Deno.test("fake store: when the line opens, what waited is delivered", () => {
  const store = createFakeStore();
  store.setPath(FAKE_PEERS.tomasz, "Direct");
  assertEquals(waitingCount(messagesOf(store, FAKE_PEERS.tomasz)), 0);
  // Other contacts are untouched.
  assertEquals(waitingCount(messagesOf(store, FAKE_PEERS.kofi)), 2);
});

Deno.test("fake store: offline ourselves, even a direct contact's message waits", () => {
  const store = createFakeStore();
  store.setSelfOnline(false);
  assertEquals(store.relay.value.kind, "Disconnected");
  store.send(FAKE_PEERS.mira, "later");
  assertEquals(messagesOf(store, FAKE_PEERS.mira).at(-1)?.state, "Queued");
  store.setSelfOnline(true);
  assertEquals(waitingCount(messagesOf(store, FAKE_PEERS.mira)), 0);
});

Deno.test("fake store: take back and edit only touch messages still on this device", () => {
  const store = createFakeStore();
  const [delivered, held] = messagesOf(store, FAKE_PEERS.tomasz).filter((m) =>
    m.direction === "Sent"
  );
  store.takeBack(FAKE_PEERS.tomasz, delivered.id);
  store.edit(FAKE_PEERS.tomasz, delivered.id, "changed");
  assertEquals(messagesOf(store, FAKE_PEERS.tomasz).find((m) => m.id === delivered.id), delivered);

  store.edit(FAKE_PEERS.tomasz, held.id, "changed");
  assertEquals(messagesOf(store, FAKE_PEERS.tomasz).find((m) => m.id === held.id)?.body, {
    kind: "text",
    text: "changed",
  });
  store.takeBack(FAKE_PEERS.tomasz, held.id);
  assertEquals(messagesOf(store, FAKE_PEERS.tomasz).some((m) => m.id === held.id), false);
});

Deno.test("fake store: calls only start on an open line", () => {
  const store = createFakeStore();
  store.startCall(FAKE_PEERS.tomasz, "voice");
  assertEquals(store.call.value, null);
  store.startCall(FAKE_PEERS.mira, "video");
  assertEquals(store.call.value?.state.kind, "Outgoing");
  store.setPath(FAKE_PEERS.mira, "Offline");
  assertEquals(store.call.value, null);
});

Deno.test("fake store: retry shows the attempt, then the same reason", async () => {
  const store = createFakeStore({ retryDelayMs: 5 });
  const path = () => store.contacts.value.find((c) => c.peerId === FAKE_PEERS.kofi)?.path;
  store.retryPath(FAKE_PEERS.kofi);
  assertEquals(path(), "Connecting");
  await new Promise((done) => setTimeout(done, 30));
  assertEquals(path(), "NoDirectPath");
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
  assertEquals(parseRoute("#/lab"), { name: "lab" });
  assertEquals(parseRoute("#/c/A1b2"), { name: "conversation", peerId: "a1b2" });
  assertEquals(parseRoute("#/c/not-hex"), { name: "list" });
});
