// The real AppStore: an adapter over the engine (src/engine). It keeps one set of signals in
// step with `engine.snapshot()` and the engine's events, and turns the screens' intents into
// engine commands. Everything it needs from the page comes in through `StoreEnv`, so it runs
// in unit tests against a fake engine.
import { batch, signal } from "denext/signals";
import type { Engine } from "../engine/engine.ts";
import { type AppEvent, EngineError } from "../engine/types.ts";
import type { CallInfo, ChatMessage, ContactView, PairingCode, RelayState } from "./model.ts";
import type { AppStore, CallMediaStreams, Notice, Phase, TurnView } from "./store.ts";

/** The part of the engine the store uses. `Engine` satisfies it. */
export type EnginePort = Pick<
  Engine,
  | "peerId"
  | "subscribe"
  | "snapshot"
  | "createPairingCode"
  | "pairWithCode"
  | "sendText"
  | "takeBack"
  | "editQueued"
  | "messages"
  | "markRead"
  | "renameContact"
  | "setVerification"
  | "safetyNumber"
  | "removeContact"
  | "connect"
  | "startCall"
  | "acceptCall"
  | "rejectCall"
  | "hangup"
  | "callMedia"
  | "setMuted"
  | "setCameraOff"
  | "replaceCamera"
  | "turnSettings"
  | "setTurnSettings"
  | "shutdown"
  | "wipe"
>;

/** Why the app could not start. */
export class StartError extends Error {
  constructor(readonly reason: "core" | "storage") {
    super(reason);
    this.name = "StartError";
  }
}

export interface Prepared {
  /** This device already has an identity (otherwise: the first-run screen). */
  hasIdentity: boolean;
  /** Start the engine; creates the identity when there is none. May reject with `Busy`. */
  start(): Promise<EnginePort>;
}

/** What the store needs from the page. */
export interface StoreEnv {
  /** Load the encryption core and open storage. Rejects with a `StartError`. */
  prepare(): Promise<Prepared>;
  /** The other tabs of this app, or null where tabs cannot talk to each other. */
  tabs: {
    /** Ask the tab that runs ParolNet to hand over. */
    askToTakeOver(): void;
    onAskedToHandOver(handler: () => void): void;
  } | null;
  /** Survives a reload of this tab: "take over as soon as you start". */
  takeoverOnStart: { set(): void; take(): boolean };
  reload(): void;
  /** Forget what the app keeps outside the engine's database (preferences). */
  clearPreferences(): void;
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
  /** The engine started (or stopped: null). For lifecycle listeners and test hooks. */
  onEngine?(engine: EnginePort | null): void;
  /** Every engine event, after the store has applied it. For notifications. */
  onEvent?(event: AppEvent, store: AppStore): void;
}

/** How long an ended call stays on screen saying how it ended. */
export const ENDED_CALL_MS = 6000;
const TAKEOVER_RETRY_MS = 300;
const TAKEOVER_TRIES = 20;

const NO_MEDIA: CallMediaStreams = { local: null, remote: null };

function notReady(): never {
  throw new EngineError("Stopped", "ParolNet is not running in this tab");
}

export interface EngineStore extends AppStore {
  /** Begin loading. Call once. */
  start(): Promise<void>;
}

export function createEngineStore(env: StoreEnv): EngineStore {
  const phase = signal<Phase>({ kind: "loading" });
  const relay = signal<RelayState>({ kind: "Connecting" });
  const selfOnline = signal(false);
  const contacts = signal<readonly ContactView[]>([]);
  const messages = signal<ReadonlyMap<string, readonly ChatMessage[]>>(new Map());
  const call = signal<CallInfo | null>(null);
  const callMedia = signal<CallMediaStreams>(NO_MEDIA);
  const pairing = signal<PairingCode | null>(null);
  const turn = signal<TurnView | null>(null);
  const notice = signal<Notice | null>(null);

  let prepared: Prepared | null = null;
  let engine: EnginePort | null = null;
  let unsubscribe: (() => void) | null = null;
  let endedTimer: unknown = null;

  const live = (): EnginePort => engine ?? notReady();

  function thread(peerId: string, change: (list: readonly ChatMessage[]) => ChatMessage[]): void {
    const next = new Map(messages.value);
    next.set(peerId, change(next.get(peerId) ?? []));
    messages.value = next;
  }

  /** Everything the snapshot carries. */
  function sync(): void {
    if (!engine) return;
    const snap = engine.snapshot();
    batch(() => {
      relay.value = snap.relay;
      selfOnline.value = snap.relay.kind === "Registered";
      contacts.value = snap.contacts;
      pairing.value = snap.pairing;
      // An ended call is not in the snapshot; it stays until its timer or `dismissCall`.
      if (snap.call) call.value = snap.call;
    });
  }

  function syncMedia(callId: string): void {
    const media = engine?.callMedia(callId);
    callMedia.value = media
      ? { local: media.local as MediaStream | null, remote: media.remote as MediaStream | null }
      : NO_MEDIA;
  }

  async function syncTurn(): Promise<void> {
    const settings = await engine?.turnSettings();
    turn.value = settings
      ? { uri: settings.uri, username: settings.username, relayOnly: settings.relayOnly }
      : null;
  }

  function onCall(info: CallInfo): void {
    env.clearTimeout(endedTimer);
    if (info.state.kind !== "Ended") {
      call.value = info;
      return;
    }
    // Say how it ended for a moment. A call we declined ourselves needs no words.
    callMedia.value = NO_MEDIA;
    if (info.state.end.kind === "Declined") {
      call.value = null;
      return;
    }
    call.value = info;
    endedTimer = env.setTimeout(() => {
      if (call.value?.callId === info.callId) call.value = null;
    }, ENDED_CALL_MS);
  }

  function onEvent(event: AppEvent): void {
    switch (event.kind) {
      case "Message":
        thread(event.message.peerId, (list) => [...list, event.message]);
        break;
      case "MessageState":
        thread(
          event.peerId,
          (list) => list.map((m) => (m.id === event.id ? { ...m, state: event.state } : m)),
        );
        break;
      case "MessageEdited":
        thread(
          event.message.peerId,
          (list) => list.map((m) => (m.id === event.message.id ? event.message : m)),
        );
        break;
      case "MessageRemoved":
        thread(event.peerId, (list) => list.filter((m) => m.id !== event.id));
        break;
      case "ContactRemoved": {
        const next = new Map(messages.value);
        next.delete(event.peerId);
        messages.value = next;
        break;
      }
      case "Call":
        onCall(event.call);
        break;
      case "CallMedia":
        syncMedia(event.callId);
        break;
      case "Notice":
        // A failed security check is already what the conversation's line and panel say.
        if (event.code !== "BindingFailed") {
          notice.value = { code: event.code, peerId: event.peerId };
        }
        break;
    }
    sync();
    env.onEvent?.(event, store);
  }

  async function attach(started: EnginePort): Promise<void> {
    engine = started;
    unsubscribe = started.subscribe(onEvent);
    sync();
    // Every thread, so the list can show the last message of each. `messages()` runs in the
    // engine's own order, so what it returns already reflects every event delivered before
    // it; a message that arrived meanwhile is in both and is kept once.
    for (const view of started.snapshot().contacts) {
      const peer = view.contact.peerId;
      const stored = await started.messages(peer);
      if (engine !== started) return;
      const have = new Set(stored.map((m) => m.id));
      thread(peer, (list) => [...stored, ...list.filter((m) => !have.has(m.id))]);
    }
    await syncTurn();
    sync();
    phase.value = { kind: "ready" };
    env.onEngine?.(started);
  }

  function detach(): void {
    unsubscribe?.();
    unsubscribe = null;
    engine = null;
    env.clearTimeout(endedTimer);
    batch(() => {
      call.value = null;
      callMedia.value = NO_MEDIA;
      pairing.value = null;
    });
    env.onEngine?.(null);
  }

  /** Start the engine. Returns false when another tab holds it. */
  async function launch(): Promise<boolean> {
    if (!prepared) return false;
    let started: EnginePort;
    try {
      started = await prepared.start();
    } catch (error) {
      if (error instanceof EngineError && error.code === "Busy") {
        phase.value = { kind: "other-tab", moved: false };
        return false;
      }
      phase.value = { kind: "failed", reason: "storage" };
      return false;
    }
    await attach(started);
    return true;
  }

  let takingOver = false;
  function takeOver(): void {
    const now = phase.value;
    if (now.kind !== "other-tab" || takingOver) return;
    if (now.moved) {
      // This tab ran an engine before: start clean, and take over once loaded.
      env.takeoverOnStart.set();
      env.reload();
      return;
    }
    takingOver = true;
    env.tabs?.askToTakeOver();
    let tries = 0;
    const attempt = async () => {
      if (await launch() || ++tries >= TAKEOVER_TRIES || phase.value.kind !== "other-tab") {
        takingOver = false;
        return;
      }
      env.setTimeout(() => void attempt(), TAKEOVER_RETRY_MS);
    };
    env.setTimeout(() => void attempt(), TAKEOVER_RETRY_MS);
  }

  env.tabs?.onAskedToHandOver(() => {
    const running = engine;
    if (!running) return;
    detach();
    phase.value = { kind: "other-tab", moved: true };
    void running.shutdown();
  });

  const store: EngineStore = {
    phase,
    relay,
    selfOnline,
    contacts,
    messages,
    call,
    callMedia,
    pairing,
    turn,
    notice,

    async start() {
      try {
        prepared = await env.prepare();
      } catch (error) {
        phase.value = {
          kind: "failed",
          reason: error instanceof StartError ? error.reason : "core",
        };
        return;
      }
      const wantsTakeover = env.takeoverOnStart.take();
      if (!prepared.hasIdentity) {
        phase.value = { kind: "first-run" };
        return;
      }
      if (!(await launch()) && wantsTakeover) takeOver();
    },

    async begin() {
      if (phase.value.kind !== "first-run") return;
      await launch();
    },

    takeOver,

    async send(peerId, text) {
      await live().sendText(peerId, text);
    },
    takeBack: (messageId) => live().takeBack(messageId),
    async edit(messageId, text) {
      await live().editQueued(messageId, text);
    },
    connect(peerId) {
      engine?.connect(peerId);
    },
    markRead(peerId) {
      void engine?.markRead(peerId).catch(() => {});
    },

    createPairingCode: () => live().createPairingCode(),
    pair: (code, via) => live().pairWithCode(code, { via }),
    async rename(peerId, name) {
      await live().renameContact(peerId, name);
    },
    async setCompared(peerId, compared) {
      await live().setVerification(peerId, compared ? "compared" : "no");
    },
    safetyNumber: (peerId) => engine?.safetyNumber(peerId) ?? null,
    removeContact: (peerId) => live().removeContact(peerId),

    async startCall(peerId, video) {
      await live().startCall(peerId, video);
    },
    async acceptCall() {
      const current = call.value;
      if (current) await live().acceptCall(current.callId);
    },
    async declineCall() {
      const current = call.value;
      if (current) await live().rejectCall(current.callId);
    },
    async hangup() {
      const current = call.value;
      if (current && current.state.kind !== "Ended") await live().hangup(current.callId);
    },
    setMuted(muted) {
      const current = call.value;
      if (current) engine?.setMuted(current.callId, muted);
    },
    setCameraOff(off) {
      const current = call.value;
      if (current) engine?.setCameraOff(current.callId, off);
    },
    async replaceCamera(stream) {
      const current = call.value;
      if (!current || !engine) {
        for (const track of stream.getTracks()) track.stop();
        return;
      }
      await engine.replaceCamera(current.callId, stream);
    },
    dismissCall() {
      if (call.value?.state.kind === "Ended") {
        env.clearTimeout(endedTimer);
        call.value = null;
      }
    },

    async setTurn(settings) {
      const running = live();
      if (settings === null) {
        await running.setTurnSettings(null);
      } else {
        // An empty password field means "the one already saved": it is never shown back.
        const password = settings.password || (await running.turnSettings())?.password || "";
        await running.setTurnSettings({
          uri: settings.uri.trim(),
          username: settings.username,
          password,
          relayOnly: settings.relayOnly,
        });
      }
      await syncTurn();
      if (notice.value?.code === "TurnUnusable") notice.value = null;
    },
    dismissNotice() {
      notice.value = null;
    },

    async wipe() {
      const running = live();
      detach();
      await running.wipe();
      env.clearPreferences();
      env.reload();
    },
  };
  return store;
}
