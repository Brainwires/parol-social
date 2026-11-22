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
  type TurnSettings,
} from "../../src/engine/types.ts";
import {
  createEngineStore,
  type DeviceVault,
  ENDED_CALL_MS,
  type EnginePort,
  type EngineStore,
  type Locked,
  StartError,
  type StoreEnv,
  type Unlocked,
} from "../../src/state/engine-store.ts";
import { BackupError } from "../../src/engine/backup.ts";
import { VaultError } from "../../src/engine/vault.ts";

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
  /** What `prepare` gives once storage can be read. */
  unlocked: Unlocked;
}

function harness(
  options: {
    hasIdentity?: boolean;
    prepare?: () => never;
    device?: DeviceVault;
    /** Start locked: `unlock` gets what the person typed. */
    locked?: Locked["locked"];
  } = {},
): Harness {
  const engine = new FakeEngine();
  let handOver = () => {};
  const h: Harness = {
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
    unlocked: {
      hasIdentity: options.hasIdentity ?? true,
      device: options.device,
      start: () => (h.starts.shift() ?? (() => Promise.resolve(engine)))(),
    },
  };
  const env: StoreEnv = {
    prepare() {
      options.prepare?.();
      if (options.locked) return Promise.resolve({ locked: options.locked });
      return Promise.resolve(h.unlocked);
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

Deno.test("store: switching the camera off lets the self view go before the track is disabled", async () => {
  const h = harness();
  h.engine.view(ALICE, "Alice");
  await h.store.start();
  const local = { id: "local" } as unknown as MediaStream;
  const remote = { id: "remote" } as unknown as MediaStream;
  h.engine.callMedia = () => ({ local, remote });
  h.engine.emit({ kind: "Call", call: call("Active") });
  h.engine.emit({ kind: "CallMedia", callId: "ca11" });

  // What had been allowed to play at the moment the engine was told.
  const allowedWhenTold: Array<readonly unknown[] | undefined> = [];
  const tell = h.engine.setCameraOff.bind(h.engine);
  h.engine.setCameraOff = (callId, off) => {
    allowedWhenTold.push(h.kept.at(-1));
    tell(callId, off);
  };
  h.kept.length = 0;
  h.store.setCameraOff(true);
  // Off: only their video may play by the time the camera's track is switched off.
  assertEquals(h.kept, [[remote]]);
  assertEquals(allowedWhenTold, [[remote]]);
  h.store.setCameraOff(false);
  assertEquals(h.kept.at(-1), [local, remote]);
  assertEquals(h.engine.calls.slice(-2), ["camera:true", "camera:false"]);
});

/** A scripted protected storage: one passphrase, a count of what was asked of it. */
function fakeDevice(passphrase: string | null = null) {
  const device = {
    passphrase,
    asked: [] as string[],
    restored: null as Uint8Array | null,
    lastMs: null as number | null,
    hasPassphrase: () => device.passphrase !== null,
    setPassphrase(next: string) {
      if (next.length < 8) return Promise.reject(new VaultError("Weak", "short"));
      device.passphrase = next;
      return Promise.resolve();
    },
    changePassphrase(current: string, next: string) {
      if (current !== device.passphrase) {
        return Promise.reject(new VaultError("WrongPassphrase", "wrong"));
      }
      device.passphrase = next;
      return Promise.resolve();
    },
    removePassphrase(current: string) {
      if (current !== device.passphrase) {
        return Promise.reject(new VaultError("WrongPassphrase", "wrong"));
      }
      device.passphrase = null;
      return Promise.resolve();
    },
    backup(typed: string, options: { history: boolean; peerId: string }) {
      device.asked.push(`backup:${typed}:${options.history}:${options.peerId.slice(0, 2)}`);
      return Promise.resolve({ bytes: new Uint8Array([1, 2, 3]), madeMs: 777 });
    },
    restore(file: Uint8Array, typed: string) {
      if (typed !== "of the backup") {
        return Promise.reject(new BackupError("WrongPassphrase", "wrong"));
      }
      device.restored = file;
      return Promise.resolve();
    },
    lastBackupMs: () => Promise.resolve(device.lastMs),
  };
  return device;
}

Deno.test("store: locked with a passphrase, nothing starts until it is typed", async () => {
  let retryAt = 0;
  let wiped = 0;
  // deno-lint-ignore prefer-const
  let h: Harness;
  const device = fakeDevice("the right one");
  let started = 0;
  const door: Locked["locked"] = {
    retryAtMs: () => Promise.resolve(retryAt),
    unlock(passphrase) {
      if (retryAt > 0) return Promise.reject(new VaultError("TooSoon", "wait", retryAt));
      if (passphrase !== "the right one") {
        retryAt = 5000;
        return Promise.reject(new VaultError("WrongPassphrase", "wrong"));
      }
      return Promise.resolve(h.unlocked);
    },
    destroy: () => Promise.resolve(void wiped++),
  };
  h = harness({ locked: door, device });
  h.starts.push(() => {
    started++;
    return Promise.resolve(h.engine);
  });
  await h.store.start();
  assertEquals(h.store.phase.value, { kind: "locked", retryAtMs: 0 });
  assertEquals(started, 0);
  assertEquals(h.engines, []);

  // A wrong passphrase: still locked, and the screen learns how long to wait.
  const wrong = await assertRejects(() => h.store.unlock("a guess"), VaultError);
  assertEquals(wrong.code, "WrongPassphrase");
  assertEquals(h.store.phase.value, { kind: "locked", retryAtMs: 5000 });
  assertEquals(
    (await assertRejects(() => h.store.unlock("the right one"), VaultError)).code,
    "TooSoon",
  );
  assertEquals(started, 0);

  retryAt = 0;
  await h.store.unlock("the right one");
  assertEquals(h.store.phase.value.kind, "ready");
  assertEquals(started, 1);
  assertEquals(h.store.passphraseSet.value, true);

  // "Lock now": the engine stops and the page starts over, at the passphrase.
  h.store.lock();
  await new Promise((done) => setTimeout(done, 0));
  assertEquals(h.engine.stopped, true);
  assertEquals(h.reloads, 1);
  assertEquals(wiped, 0);
});

Deno.test("store: a forgotten passphrase leaves one way on: delete everything", async () => {
  let wiped = 0;
  const h = harness({
    locked: {
      retryAtMs: () => Promise.resolve(0),
      unlock: () => Promise.reject(new VaultError("WrongPassphrase", "wrong")),
      destroy: () => Promise.resolve(void wiped++),
    },
  });
  await h.store.start();
  await h.store.forget();
  assertEquals([wiped, h.cleared, h.reloads], [1, 1, 1]);
});

Deno.test("store: setting, changing and removing the passphrase", async () => {
  const device = fakeDevice();
  const h = harness({ device });
  await h.store.start();
  assertEquals(h.store.passphraseSet.value, false);
  // Without a passphrase there is nothing to lock.
  h.store.lock();
  await new Promise((done) => setTimeout(done, 0));
  assertEquals(h.reloads, 0);

  assertEquals(
    (await assertRejects(() => h.store.setPassphrase("short"), VaultError)).code,
    "Weak",
  );
  assertEquals(h.store.passphraseSet.value, false);
  await h.store.setPassphrase("long enough");
  assertEquals(h.store.passphraseSet.value, true);
  await assertRejects(() => h.store.changePassphrase("not it", "another one"), VaultError);
  await h.store.changePassphrase("long enough", "another one");
  assertEquals(device.passphrase, "another one");
  await assertRejects(() => h.store.removePassphrase("long enough"), VaultError);
  assertEquals(h.store.passphraseSet.value, true);
  await h.store.removePassphrase("another one");
  assertEquals(h.store.passphraseSet.value, false);
  // The engine ran through all of it.
  assertEquals(h.engine.stopped, false);
});

Deno.test("store: a backup is made of this identity and its date is shown", async () => {
  const device = fakeDevice();
  device.lastMs = 123;
  const h = harness({ device });
  await h.store.start();
  await new Promise((done) => setTimeout(done, 0));
  assertEquals(h.store.lastBackupMs.value, 123);
  const file = await h.store.makeBackup("for the file", { history: true });
  assertEquals([...file.bytes], [1, 2, 3]);
  assertEquals(device.asked, ["backup:for the file:true:ee"]);
  assertEquals(h.store.lastBackupMs.value, 777);
});

Deno.test("store: restoring replaces what is here and starts over; a wrong passphrase changes nothing", async () => {
  const device = fakeDevice();
  const h = harness({ device });
  await h.store.start();
  const file = new Uint8Array([9, 9]);
  const wrong = await assertRejects(() => h.store.restore(file, "a guess"), BackupError);
  assertEquals(wrong.code, "WrongPassphrase");
  assertEquals([device.restored, h.reloads, h.store.phase.value.kind], [null, 0, "ready"]);
  await h.store.restore(file, "of the backup");
  assertEquals(device.restored, file);
  assertEquals(h.reloads, 1);
  // The engine that ran on the old rows is let go of.
  assertEquals(h.engines.at(-1), null);
});

Deno.test("store: a backup can be restored on first run, before any identity is made", async () => {
  const device = fakeDevice();
  const h = harness({ device, hasIdentity: false });
  let started = 0;
  h.starts.push(() => Promise.resolve((started++, h.engine)));
  await h.store.start();
  assertEquals(h.store.phase.value.kind, "first-run");
  await h.store.restore(new Uint8Array([1]), "of the backup");
  assertEquals([started, h.reloads], [0, 1]);
});
