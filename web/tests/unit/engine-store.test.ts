// The store adapter over the engine, against a scripted engine: what the screens read after
// each event, and what each intent asks of the engine.
import { assert, assertEquals, assertRejects } from "@std/assert";
import {
  type AppEvent,
  type CallInfo,
  type ChatMessage,
  type Contact,
  type ContactView,
  EngineError,
  type Snapshot,
  type TransferInfo,
  type TurnSettings,
} from "../../src/engine/types.ts";
import type { FileSource } from "../../src/engine/platform.ts";
import {
  createEngineStore,
  ENDED_CALL_MS,
  type EnginePort,
  type EngineStore,
  StartError,
  type StoreEnv,
} from "../../src/state/engine-store.ts";
import type { SaveOutcome } from "../../src/state/save-file.ts";

const ALICE = "a1".repeat(32);
const BOB = "b2".repeat(32);

function contact(peerId: string, name: string): Contact {
  return { peerId, name, identityKey: null, addedMs: 1, verified: "no", verifiedMs: null };
}

function message(id: number, peerId: string, text: string, sent = false): ChatMessage {
  return {
    id,
    peerId,
    direction: sent ? "Sent" : "Received",
    text,
    timestampMs: id,
    state: sent ? "Queued" : "Received",
  };
}

function transfer(
  id: string,
  peerId: string,
  createdMs: number,
  extra: Partial<TransferInfo> = {},
): TransferInfo {
  return {
    id,
    peerId,
    direction: "Received",
    name: `${id}.pdf`,
    size: 1000,
    mime: "application/pdf",
    state: { kind: "Offered" },
    bytesDone: 0,
    pending: false,
    createdMs,
    available: false,
    ...extra,
  };
}

/** A scripted engine: tests change `snap` and `history`, then `emit`. */
class FakeEngine implements EnginePort {
  readonly peerId = "ee".repeat(32);
  snap: Snapshot = {
    peerId: this.peerId,
    publicKey: "",
    relay: { kind: "Connecting" },
    contacts: [],
    pairingOpen: false,
    pairing: null,
    turnConfigured: false,
    relayOnly: false,
    call: null,
  };
  history = new Map<string, ChatMessage[]>();
  files = new Map<string, TransferInfo[]>();
  blobs = new Map<string, Blob>();
  persist = true;
  turn: TurnSettings | null = null;
  calls: string[] = [];
  stopped = false;
  wiped = false;
  private listeners = new Set<(event: AppEvent) => void>();

  emit(event: AppEvent): void {
    for (const listener of this.listeners) listener(event);
  }
  view(peerId: string, name: string, extra: Partial<ContactView> = {}): void {
    const views = this.snap.contacts.filter((v) => v.contact.peerId !== peerId);
    this.snap = {
      ...this.snap,
      contacts: [...views, {
        contact: contact(peerId, name),
        path: "Unknown",
        queued: 0,
        unread: 0,
        lastActivityMs: 1,
        ...extra,
      }],
    };
  }

  subscribe(listener: (event: AppEvent) => void) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
  snapshot = () => this.snap;
  messages = (peerId: string) => Promise.resolve(this.history.get(peerId) ?? []);
  createPairingCode() {
    this.calls.push("createPairingCode");
    return Promise.resolve({ code: "c0de", expiresAtMs: 1 });
  }
  cancelPairing() {
    this.calls.push("cancelPairing");
    return Promise.resolve();
  }
  pairWithCode(code: string, how: { via: "scan" | "paste" }) {
    this.calls.push(`pair:${code}:${how.via}`);
    return Promise.resolve(contact(ALICE, "New contact"));
  }
  sendText(peerId: string, text: string) {
    if (text === "too long") return Promise.reject(new EngineError("TooLong", "too long"));
    this.calls.push(`send:${peerId.slice(0, 2)}:${text}`);
    return Promise.resolve(message(99, peerId, text, true));
  }
  takeBack(id: number) {
    this.calls.push(`takeBack:${id}`);
    return Promise.resolve();
  }
  editQueued(id: number, text: string) {
    this.calls.push(`edit:${id}:${text}`);
    return Promise.resolve(message(id, ALICE, text, true));
  }
  markRead(peerId: string) {
    this.calls.push(`markRead:${peerId.slice(0, 2)}`);
    return Promise.resolve();
  }
  renameContact(peerId: string, name: string) {
    this.calls.push(`rename:${name}`);
    return Promise.resolve(contact(peerId, name));
  }
  setVerification(peerId: string, verified: "compared" | "no") {
    this.calls.push(`verify:${verified}`);
    return Promise.resolve(contact(peerId, "x"));
  }
  safetyNumber = () => "1".repeat(60);
  removeContact(peerId: string) {
    this.calls.push(`remove:${peerId.slice(0, 2)}`);
    return Promise.resolve();
  }
  connect(peerId: string) {
    this.calls.push(`connect:${peerId.slice(0, 2)}`);
  }
  startCall(peerId: string, video: boolean) {
    this.calls.push(`startCall:${video}`);
    return Promise.resolve(call("Outgoing", peerId));
  }
  acceptCall(callId: string) {
    this.calls.push(`accept:${callId}`);
    return Promise.resolve(call("Connecting"));
  }
  rejectCall(callId: string) {
    this.calls.push(`reject:${callId}`);
    return Promise.resolve();
  }
  hangup(callId: string) {
    this.calls.push(`hangup:${callId}`);
    return Promise.resolve();
  }
  callMedia: EnginePort["callMedia"] = () => ({ local: null, remote: null });
  setMuted(_callId: string, muted: boolean) {
    this.calls.push(`mute:${muted}`);
  }
  setCameraOff(_callId: string, off: boolean) {
    this.calls.push(`camera:${off}`);
  }
  replaceCamera() {
    this.calls.push("replaceCamera");
    return Promise.resolve();
  }
  turnSettings = () => Promise.resolve(this.turn ? { ...this.turn } : null);
  setTurnSettings(settings: TurnSettings | null) {
    if (settings && !settings.uri.startsWith("turn:")) {
      return Promise.reject(new EngineError("Config", "bad"));
    }
    this.turn = settings;
    return Promise.resolve();
  }
  offerFile(peerId: string, file: FileSource) {
    this.calls.push(`offer:${peerId.slice(0, 2)}:${file.name}`);
    if (file.size === 0) return Promise.reject(new EngineError("Transfer", "empty"));
    return Promise.resolve(transfer("new", peerId, 5, { direction: "Sent", name: file.name }));
  }
  acceptTransfer(id: string) {
    this.calls.push(`acceptTransfer:${id}`);
    return Promise.resolve(transfer(id, ALICE, 1, { state: { kind: "Waiting" } }));
  }
  declineTransfer(id: string) {
    this.calls.push(`declineTransfer:${id}`);
    return Promise.resolve(transfer(id, ALICE, 1, { state: { kind: "Declined" } }));
  }
  cancelTransfer(id: string) {
    this.calls.push(`cancelTransfer:${id}`);
    return Promise.resolve(
      transfer(id, ALICE, 1, { state: { kind: "Cancelled", byPeer: false, reason: "User" } }),
    );
  }
  transfers = (peerId?: string) => Promise.resolve(peerId ? this.files.get(peerId) ?? [] : []);
  transferFile(id: string) {
    this.calls.push(`transferFile:${id}`);
    return Promise.resolve(this.blobs.get(id) ?? null);
  }
  removeTransfer(id: string) {
    this.calls.push(`removeTransfer:${id}`);
    return Promise.resolve();
  }
  receivedFilesPersist = () => this.persist;
  shutdown() {
    this.stopped = true;
    return Promise.resolve();
  }
  wipe() {
    this.wiped = true;
    return Promise.resolve();
  }
}

function call(kind: "Outgoing" | "Incoming" | "Connecting" | "Active", peerId = ALICE): CallInfo {
  return {
    callId: "ca11",
    peerId,
    video: true,
    incoming: kind === "Incoming",
    state: { kind },
    muted: false,
    cameraOff: false,
  };
}

interface Harness {
  /** What `saveFile` was asked to save: the name and the blob it got. */
  saved: Array<{ name: string; blob: Blob | null }>;
  /** What the next `saveFile` returns. */
  saveOutcome: SaveOutcome;
  /** Every `keepPlaying` call: the streams that may go on playing. */
  kept: Array<readonly unknown[]>;
  /** What the screens were shown (`callMedia`) at the moment of each of those calls. */
  shownWhenKept: unknown[];
  store: EngineStore;
  engine: FakeEngine;
  /** What `prepared.start()` does next. */
  starts: Array<() => Promise<EnginePort>>;
  timers: Array<{ fn: () => void; ms: number; live: boolean }>;
  reloads: number;
  cleared: number;
  askedToTakeOver: number;
  handOver(): void;
  events: AppEvent[];
  engines: Array<EnginePort | null>;
  takeoverFlag: boolean;
  /** Run the timers that are due, as a clock would. */
  runTimers(): Promise<void>;
}

function harness(options: { hasIdentity?: boolean; prepare?: () => never } = {}): Harness {
  const engine = new FakeEngine();
  let handOver = () => {};
  const h: Harness = {
    saved: [],
    saveOutcome: "saved",
    kept: [],
    shownWhenKept: [],
    engine,
    starts: [],
    timers: [],
    reloads: 0,
    cleared: 0,
    askedToTakeOver: 0,
    handOver: () => handOver(),
    events: [],
    engines: [],
    takeoverFlag: false,
    async runTimers() {
      for (const timer of h.timers.splice(0)) if (timer.live) timer.fn();
      await new Promise((done) => setTimeout(done, 0));
    },
    store: undefined as unknown as EngineStore,
  };
  const env: StoreEnv = {
    prepare() {
      options.prepare?.();
      return Promise.resolve({
        hasIdentity: options.hasIdentity ?? true,
        start: () => (h.starts.shift() ?? (() => Promise.resolve(engine)))(),
      });
    },
    tabs: {
      askToTakeOver: () => void h.askedToTakeOver++,
      onAskedToHandOver: (handler) => (handOver = handler),
    },
    takeoverOnStart: {
      set: () => void (h.takeoverFlag = true),
      take() {
        const wanted = h.takeoverFlag;
        h.takeoverFlag = false;
        return wanted;
      },
    },
    reload: () => void h.reloads++,
    clearPreferences: () => void h.cleared++,
    setTimeout(fn, ms) {
      const timer = { fn, ms, live: true };
      h.timers.push(timer);
      return timer;
    },
    clearTimeout(handle) {
      if (handle) (handle as { live: boolean }).live = false;
    },
    keepPlaying(streams) {
      h.kept.push(streams);
      h.shownWhenKept.push(h.store.callMedia.value);
    },
    async saveFile(name, getBlob) {
      h.saved.push({ name, blob: await getBlob() });
      return h.saveOutcome;
    },
    onEngine: (started) => void h.engines.push(started),
    onEvent: (event) => void h.events.push(event),
  };
  h.store = createEngineStore(env);
  return h;
}

const busy = () => Promise.reject(new EngineError("Busy", "another tab"));

Deno.test("store: an existing identity starts the engine and shows what it holds", async () => {
  const h = harness();
  h.engine.view(ALICE, "Alice", { path: "Direct", unread: 2 });
  h.engine.history.set(ALICE, [message(1, ALICE, "hello")]);
  h.engine.snap = { ...h.engine.snap, relay: { kind: "Registered", profile: "signaling-only" } };
  assertEquals(h.store.phase.value.kind, "loading");
  await h.store.start();
  assertEquals(h.store.phase.value.kind, "ready");
  assertEquals(h.store.selfOnline.value, true);
  assertEquals(h.store.contacts.value.map((v) => [v.contact.name, v.path, v.unread]), [
    ["Alice", "Direct", 2],
  ]);
  assertEquals(h.store.messages.value.get(ALICE)?.map((m) => m.text), ["hello"]);
  assertEquals(h.engines, [h.engine]);
});

Deno.test("store: with nothing on the device, first run waits for Start", async () => {
  const h = harness({ hasIdentity: false });
  let started = 0;
  h.starts.push(() => {
    started++;
    return Promise.resolve(h.engine);
  });
  await h.store.start();
  assertEquals(h.store.phase.value.kind, "first-run");
  assertEquals(started, 0, "no identity is made before the person asks");
  await h.store.begin();
  assertEquals(started, 1);
  assertEquals(h.store.phase.value.kind, "ready");
});

Deno.test("store: what could not start says which part", async () => {
  const core = harness({
    prepare: () => {
      throw new StartError("core");
    },
  });
  await core.store.start();
  assertEquals(core.store.phase.value, { kind: "failed", reason: "core" });

  const storage = harness();
  storage.starts.push(() => Promise.reject(new EngineError("Storage", "no database")));
  await storage.store.start();
  assertEquals(storage.store.phase.value, { kind: "failed", reason: "storage" });
});

Deno.test("store: messages follow the engine's events", async () => {
  const h = harness();
  h.engine.view(ALICE, "Alice");
  await h.store.start();
  const thread = () => h.store.messages.value.get(ALICE)?.map((m) => `${m.text}:${m.state}`);

  h.engine.emit({ kind: "Message", message: message(1, ALICE, "one", true) });
  h.engine.emit({ kind: "Message", message: message(2, ALICE, "two", true) });
  assertEquals(thread(), ["one:Queued", "two:Queued"]);
  h.engine.emit({ kind: "MessageEdited", message: { ...message(2, ALICE, "TWO", true) } });
  h.engine.emit({ kind: "MessageState", peerId: ALICE, id: 1, state: "Sent" });
  assertEquals(thread(), ["one:Sent", "TWO:Queued"]);
  h.engine.emit({ kind: "MessageRemoved", peerId: ALICE, id: 2 });
  assertEquals(thread(), ["one:Sent"]);
  // Every event reaches the page's hook after the store applied it.
  assertEquals(h.events.map((e) => e.kind), [
    "Message",
    "Message",
    "MessageEdited",
    "MessageState",
    "MessageRemoved",
  ]);
});

Deno.test("store: a message that arrives while history loads is kept once", async () => {
  const h = harness();
  h.engine.view(ALICE, "Alice");
  let release: (list: ChatMessage[]) => void = () => {};
  h.engine.messages = () => new Promise((resolve) => (release = resolve));
  const starting = h.store.start();
  await new Promise((done) => setTimeout(done, 0));
  // It arrives, and is in what storage returns as well.
  h.engine.emit({ kind: "Message", message: message(2, ALICE, "new") });
  release([message(1, ALICE, "old"), message(2, ALICE, "new")]);
  await starting;
  assertEquals(h.store.messages.value.get(ALICE)?.map((m) => m.text), ["old", "new"]);
});

Deno.test("store: contacts, the line and pairing come from the snapshot on every event", async () => {
  const h = harness();
  await h.store.start();
  assertEquals(h.store.selfOnline.value, false);
  h.engine.snap = { ...h.engine.snap, relay: { kind: "Registered", profile: "relay" } };
  h.engine.emit({ kind: "Relay", state: h.engine.snap.relay });
  assertEquals(h.store.selfOnline.value, true);

  h.engine.view(BOB, "Bob", { path: "NoDirectPath", queued: 3 });
  h.engine.emit({ kind: "ContactAdded", contact: contact(BOB, "Bob") });
  assertEquals(h.store.contacts.value.map((v) => [v.contact.name, v.path, v.queued]), [
    ["Bob", "NoDirectPath", 3],
  ]);

  h.engine.snap = { ...h.engine.snap, pairing: { code: "abcd", expiresAtMs: 5 } };
  h.engine.emit({ kind: "Pairing", pairing: h.engine.snap.pairing });
  assertEquals(h.store.pairing.value, { code: "abcd", expiresAtMs: 5 });
  h.engine.snap = { ...h.engine.snap, pairing: null };
  h.engine.emit({ kind: "Pairing", pairing: null });
  assertEquals(h.store.pairing.value, null);

  h.engine.history.set(BOB, []);
  h.engine.emit({ kind: "Message", message: message(1, BOB, "hi") });
  h.engine.snap = { ...h.engine.snap, contacts: [] };
  h.engine.emit({ kind: "ContactRemoved", peerId: BOB });
  assertEquals(h.store.contacts.value, []);
  assertEquals(h.store.messages.value.has(BOB), false);
});

Deno.test("store: intents become engine commands; a refusal reaches the screen", async () => {
  const h = harness();
  h.engine.view(ALICE, "Alice");
  await h.store.start();
  await h.store.send(ALICE, "hello");
  await h.store.takeBack(7);
  await h.store.edit(8, "changed");
  h.store.connect(ALICE);
  h.store.markRead(ALICE);
  await h.store.createPairingCode();
  await h.store.cancelPairing();
  await h.store.pair("c0de", "scan");
  await h.store.rename(ALICE, "Ally");
  await h.store.setCompared(ALICE, true);
  await h.store.setCompared(ALICE, false);
  await h.store.removeContact(ALICE);
  assertEquals(h.engine.calls, [
    "send:a1:hello",
    "takeBack:7",
    "edit:8:changed",
    "connect:a1",
    "markRead:a1",
    "createPairingCode",
    "cancelPairing",
    "pair:c0de:scan",
    "rename:Ally",
    "verify:compared",
    "verify:no",
    "remove:a1",
  ]);
  const refused = await assertRejects(() => h.store.send(ALICE, "too long"), EngineError);
  assertEquals(refused.code, "TooLong");
  assertEquals(h.store.safetyNumber(ALICE), "1".repeat(60));
});

Deno.test("store: a call from ringing to how it ended", async () => {
  const h = harness();
  h.engine.view(ALICE, "Alice");
  await h.store.start();

  h.engine.snap = { ...h.engine.snap, call: call("Incoming") };
  h.engine.emit({ kind: "Call", call: call("Incoming") });
  assertEquals(h.store.call.value?.state.kind, "Incoming");
  await h.store.acceptCall();
  h.engine.snap = { ...h.engine.snap, call: call("Active") };
  h.engine.emit({ kind: "Call", call: call("Active") });
  h.store.setMuted(true);
  h.store.setCameraOff(true);
  await h.store.hangup();
  assertEquals(h.engine.calls, ["accept:ca11", "mute:true", "camera:true", "hangup:ca11"]);

  // Over: the snapshot has no call, but the screen still says how it ended, for a moment.
  const ended: CallInfo = {
    ...call("Active"),
    state: { kind: "Ended", end: { kind: "RemoteHungUp" } },
  };
  h.engine.snap = { ...h.engine.snap, call: null };
  h.engine.emit({ kind: "Call", call: ended });
  assertEquals(h.store.call.value, ended);
  assertEquals(h.timers.at(-1)?.ms, ENDED_CALL_MS);
  await h.store.hangup();
  assertEquals(h.engine.calls.length, 4, "an ended call is not hung up again");
  await h.runTimers();
  assertEquals(h.store.call.value, null);

  // A call this device declined needs no words.
  h.engine.emit({ kind: "Call", call: call("Incoming") });
  await h.store.declineCall();
  h.engine.emit({
    kind: "Call",
    call: { ...call("Incoming"), state: { kind: "Ended", end: { kind: "Declined" } } },
  });
  assertEquals(h.store.call.value, null);

  // "Close" does not wait for the timer.
  h.engine.emit({ kind: "Call", call: ended });
  h.store.dismissCall();
  assertEquals(h.store.call.value, null);
});

Deno.test("store: the call's streams stop playing in the turn the call ends or its capture changes", async () => {
  const h = harness();
  h.engine.view(ALICE, "Alice");
  await h.store.start();
  const local = { id: "local" } as unknown as MediaStream;
  const remote = { id: "remote" } as unknown as MediaStream;
  const streams: { local: MediaStream | null; remote: MediaStream | null } = {
    local,
    remote: null,
  };
  h.engine.callMedia = () => streams;

  h.engine.emit({ kind: "Call", call: call("Active") });
  h.engine.emit({ kind: "CallMedia", callId: "ca11" });
  assertEquals(h.kept, [[local, null]]);
  assertEquals(h.store.callMedia.value, { local, remote: null });

  // The camera was switched: only the new capture may go on playing, and the page hears
  // that before the screens see the new streams.
  const other = { id: "other" } as unknown as MediaStream;
  streams.local = other;
  streams.remote = remote;
  h.kept.length = h.shownWhenKept.length = 0;
  h.engine.emit({ kind: "CallMedia", callId: "ca11" });
  assertEquals(h.kept, [[other, remote]]);
  assertEquals(h.shownWhenKept, [{ local, remote: null }]);
  assertEquals(h.store.callMedia.value, { local: other, remote });

  // The call ends: nothing plays any more by the time the event has been handled, which is
  // before the engine releases the capture and the connection.
  h.kept.length = h.shownWhenKept.length = 0;
  h.engine.emit({
    kind: "Call",
    call: { ...call("Active"), state: { kind: "Ended", end: { kind: "RemoteHungUp" } } },
  });
  assertEquals(h.kept, [[]]);
  assertEquals(h.shownWhenKept, [{ local: other, remote }]);
  assertEquals(h.store.callMedia.value, { local: null, remote: null });

  // Handing over to another tab stops the playing as well, before the engine shuts down.
  h.engine.emit({ kind: "Call", call: call("Active") });
  h.kept.length = 0;
  h.handOver();
  assertEquals(h.kept, [[]]);
});

Deno.test("store: the relay server's password goes in and never comes back", async () => {
  const h = harness();
  await h.store.start();
  assertEquals(h.store.turn.value, null);
  await h.store.setTurn({
    uri: " turn:turn.example.org:3478 ",
    username: "me",
    password: "s3cret",
    relayOnly: true,
  });
  assertEquals(h.engine.turn?.password, "s3cret");
  assertEquals(h.store.turn.value, {
    uri: "turn:turn.example.org:3478",
    username: "me",
    relayOnly: true,
  });
  assert(!JSON.stringify(h.store.turn.value).includes("s3cret"));

  // An empty password field keeps the saved one.
  await h.store.setTurn({
    uri: "turn:turn.example.org:3478",
    username: "me",
    password: "",
    relayOnly: false,
  });
  assertEquals(h.engine.turn, {
    uri: "turn:turn.example.org:3478",
    username: "me",
    password: "s3cret",
    relayOnly: false,
  });
  await assertRejects(
    () => h.store.setTurn({ uri: "https://x", username: "", password: "", relayOnly: false }),
    EngineError,
  );
  await h.store.setTurn(null);
  assertEquals(h.store.turn.value, null);
});

Deno.test("store: notices; a failed security check is left to the conversation's line", async () => {
  const h = harness();
  await h.store.start();
  h.engine.emit({ kind: "Notice", code: "BindingFailed", peerId: ALICE, text: "x" });
  assertEquals(h.store.notice.value, null);
  h.engine.emit({ kind: "Notice", code: "TurnUnusable", text: "x" });
  assertEquals(h.store.notice.value, { code: "TurnUnusable", peerId: undefined });
  h.store.dismissNotice();
  assertEquals(h.store.notice.value, null);
});

Deno.test("store: another tab has ParolNet; 'Use it here' takes it over", async () => {
  const h = harness();
  h.starts.push(busy, busy);
  await h.store.start();
  assertEquals(h.store.phase.value, { kind: "other-tab", moved: false });
  assertEquals(h.askedToTakeOver, 0, "nothing is taken without being asked");

  h.store.takeOver();
  assertEquals(h.askedToTakeOver, 1);
  // The other tab has not let go yet; then it has.
  await h.runTimers();
  assertEquals(h.store.phase.value.kind, "other-tab");
  await h.runTimers();
  assertEquals(h.store.phase.value.kind, "ready");
});

Deno.test("store: asked to hand over, the running tab stops and says where it went", async () => {
  const h = harness();
  await h.store.start();
  h.engine.emit({ kind: "Call", call: call("Active") });
  h.handOver();
  assertEquals(h.engine.stopped, true);
  assertEquals(h.store.phase.value, { kind: "other-tab", moved: true });
  assertEquals(h.store.call.value, null);
  assertEquals(h.engines, [h.engine, null]);
  await assertRejects(() => h.store.send(ALICE, "x"), EngineError);

  // "Use it here" in a tab that ran an engine: reload, and take over once loaded.
  h.store.takeOver();
  assertEquals(h.reloads, 1);
  assertEquals(h.takeoverFlag, true);
});

Deno.test("store: a tab reloaded to take over does so without another click", async () => {
  const h = harness();
  h.takeoverFlag = true;
  h.starts.push(busy);
  await h.store.start();
  assertEquals(h.askedToTakeOver, 1);
  await h.runTimers();
  assertEquals(h.store.phase.value.kind, "ready");
  assertEquals(h.takeoverFlag, false);
});

Deno.test("store: delete all data wipes the engine and the preferences, then starts over", async () => {
  const h = harness();
  await h.store.start();
  await h.store.wipe();
  assertEquals(h.engine.wiped, true);
  assertEquals(h.cleared, 1);
  assertEquals(h.reloads, 1);
});

Deno.test("store: transfers load per conversation and follow Transfer / TransferRemoved", async () => {
  const h = harness();
  h.engine.view(ALICE, "Alice");
  h.engine.view(BOB, "Bob");
  h.engine.files.set(ALICE, [transfer("t1", ALICE, 10), transfer("t2", ALICE, 20)]);
  h.engine.persist = false;
  await h.store.start();
  const ids = (peer: string) =>
    h.store.transfers.value.get(peer)?.map((t) => `${t.id}:${t.state.kind}`);
  assertEquals(ids(ALICE), ["t1:Offered", "t2:Offered"]);
  assertEquals(ids(BOB), []);
  assertEquals(h.store.filesPersist.value, false);

  // A change replaces the transfer in place; a new one goes in by time.
  h.engine.emit({
    kind: "Transfer",
    transfer: transfer("t1", ALICE, 10, { state: { kind: "Active" }, bytesDone: 400 }),
  });
  h.engine.emit({ kind: "Transfer", transfer: transfer("t0", ALICE, 5) });
  h.engine.emit({ kind: "Transfer", transfer: transfer("b1", BOB, 1) });
  assertEquals(ids(ALICE), ["t0:Offered", "t1:Active", "t2:Offered"]);
  assertEquals(h.store.transfers.value.get(ALICE)?.[1].bytesDone, 400);
  assertEquals(ids(BOB), ["b1:Offered"]);

  h.engine.emit({ kind: "TransferRemoved", peerId: ALICE, id: "t2" });
  assertEquals(ids(ALICE), ["t0:Offered", "t1:Active"]);

  // Removing a contact takes its transfers with it.
  h.engine.snap = { ...h.engine.snap, contacts: h.engine.snap.contacts.slice(1) };
  h.engine.emit({ kind: "ContactRemoved", peerId: ALICE });
  assertEquals(h.store.transfers.value.has(ALICE), false);
  assertEquals(h.events.map((e) => e.kind).filter((k) => k.startsWith("Transfer")), [
    "Transfer",
    "Transfer",
    "Transfer",
    "TransferRemoved",
  ]);
});

Deno.test("store: a transfer event delivered while the list loads wins over the list", async () => {
  const h = harness();
  h.engine.view(ALICE, "Alice");
  let release: (list: TransferInfo[]) => void = () => {};
  h.engine.transfers = () => new Promise((resolve) => (release = resolve));
  const starting = h.store.start();
  await new Promise((done) => setTimeout(done, 0));
  h.engine.emit({
    kind: "Transfer",
    transfer: transfer("t1", ALICE, 10, { state: { kind: "Waiting" } }),
  });
  h.engine.emit({ kind: "TransferRemoved", peerId: ALICE, id: "t3" });
  release([transfer("t1", ALICE, 10), transfer("t2", ALICE, 20), transfer("t3", ALICE, 30)]);
  await starting;
  assertEquals(
    h.store.transfers.value.get(ALICE)?.map((t) => `${t.id}:${t.state.kind}`),
    ["t1:Waiting", "t2:Offered"],
  );
});

Deno.test("store: transfer intents become engine commands", async () => {
  const h = harness();
  h.engine.view(ALICE, "Alice");
  await h.store.start();
  const file = new File(["hello"], "notes.txt", { type: "text/plain" });
  const offered = await h.store.offerFile(ALICE, file);
  assertEquals(offered.name, "notes.txt");
  await h.store.acceptTransfer("t1");
  await h.store.declineTransfer("t2");
  await h.store.cancelTransfer("t3");
  await h.store.removeTransfer("t4");
  assertEquals(h.engine.calls, [
    "offer:a1:notes.txt",
    "acceptTransfer:t1",
    "declineTransfer:t2",
    "cancelTransfer:t3",
    "removeTransfer:t4",
  ]);
  // A file the engine cannot offer is refused with its code, for the screen to word.
  const error = await assertRejects(
    () => h.store.offerFile(ALICE, new File([], "empty.txt")),
    EngineError,
  );
  assertEquals(error.code, "Transfer");
});

Deno.test("store: saving hands the engine's blob, under the transfer's name, to the saver", async () => {
  const h = harness();
  h.engine.view(ALICE, "Alice");
  h.engine.files.set(ALICE, [
    transfer("t1", ALICE, 1, { name: "report.pdf", state: { kind: "Complete" }, available: true }),
  ]);
  const blob = new Blob(["%PDF"], { type: "application/pdf" });
  h.engine.blobs.set("t1", blob);
  await h.store.start();
  await h.store.saveTransfer("t1");
  assertEquals(h.saved.length, 1);
  assertEquals(h.saved[0].name, "report.pdf");
  assert(h.saved[0].blob === blob, "the engine's own blob, type and all");

  // Closing the save dialog is not a problem; a file no longer on this device is.
  h.saveOutcome = "cancelled";
  await h.store.saveTransfer("t1");
  h.saveOutcome = "missing";
  const missing = await assertRejects(() => h.store.saveTransfer("t1"), EngineError);
  assertEquals(missing.code, "UnknownTransfer");
  const unknown = await assertRejects(() => h.store.saveTransfer("nope"), EngineError);
  assertEquals(unknown.code, "UnknownTransfer");
});
