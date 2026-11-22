// The real AppStore: an adapter over the engine (src/engine). It keeps one set of signals in
// step with `engine.snapshot()` and the engine's events, and turns the screens' intents into
// engine commands. Everything it needs from the page comes in through `StoreEnv`, so it runs
// in unit tests against a fake engine.
import { batch, signal } from "denext/signals";
import type { Engine } from "../engine/engine.ts";
import { type AppEvent, EngineError } from "../engine/types.ts";
import type {
  CallInfo,
  ChatMessage,
  ContactView,
  PairingCode,
  RelayState,
  SasCheck,
  TransferInfo,
} from "./model.ts";
import { saveFile as saveWithBrowser, type SaveOutcome } from "./save-file.ts";
import type { AppStore, BackupFile, CallMediaStreams, Notice, Phase, TurnView } from "./store.ts";

/** The part of the engine the store uses. `Engine` satisfies it. */
export type EnginePort = Pick<
  Engine,
  | "peerId"
  | "subscribe"
  | "snapshot"
  | "createPairingCode"
  | "cancelPairing"
  | "pairWithCode"
  | "confirmSas"
  | "rejectSas"
  | "stopPairing"
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
  | "offerFile"
  | "acceptTransfer"
  | "declineTransfer"
  | "cancelTransfer"
  | "transfers"
  | "transferFile"
  | "removeTransfer"
  | "receivedFilesPersist"
>;

/** Why the app could not start. */
export class StartError extends Error {
  constructor(readonly reason: "core" | "storage") {
    super(reason);
    this.name = "StartError";
  }
}

/**
 * This device's protected storage, apart from the engine that runs on it. Rejections are
 * `VaultError`s (the lock) and `BackupError`s (the file).
 */
export interface DeviceVault {
  hasPassphrase(): boolean;
  setPassphrase(next: string): Promise<void>;
  changePassphrase(current: string, next: string): Promise<void>;
  removePassphrase(current: string): Promise<void>;
  backup(
    passphrase: string,
    options: { history: boolean; peerId: string },
  ): Promise<BackupFile>;
  /** Replace everything stored by the backup's contents. The page must reload afterwards. */
  restore(file: Uint8Array, passphrase: string): Promise<void>;
  lastBackupMs(): Promise<number | null>;
}

/** Storage that can be read: either it has no passphrase, or it was typed. */
export interface Unlocked {
  locked?: undefined;
  /** This device already has an identity (otherwise: the first-run screen). */
  hasIdentity: boolean;
  /** Start the engine; creates the identity when there is none. May reject with `Busy`. */
  start(): Promise<EnginePort>;
  /** Absent only where the storage is not a protected one (tests). */
  device?: DeviceVault;
}

/** Storage locked with a passphrase. */
export interface Locked {
  locked: {
    /** When the next passphrase may be tried (0: now). */
    retryAtMs(): Promise<number>;
    /** Rejects with a `VaultError`: `WrongPassphrase` or `TooSoon`. */
    unlock(passphrase: string): Promise<Unlocked>;
    /** Delete the database, keys and all. */
    destroy(): Promise<void>;
  };
}

export type Prepared = Unlocked | Locked;

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
  /**
   * Stop playing, now, every call stream that is not one of `streams`. Called in the same
   * turn in which a call ends or its capture changes, before the engine releases the media
   * (src/platform/playback.ts says why it cannot wait for the screen to render).
   */
  keepPlaying?(streams: readonly (MediaStream | null)[]): void;
  /**
   * Hand a file to the person (src/state/save-file.ts; the default is the browser's save
   * dialog or a download). Tests replace it.
   */
  saveFile?(name: string, getBlob: () => Promise<Blob | null>): Promise<SaveOutcome>;
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
  const transfers = signal<ReadonlyMap<string, readonly TransferInfo[]>>(new Map());
  const filesPersist = signal(true);
  const call = signal<CallInfo | null>(null);
  const callMedia = signal<CallMediaStreams>(NO_MEDIA);
  const pairing = signal<PairingCode | null>(null);
  const sas = signal<SasCheck | null>(null);
  const turn = signal<TurnView | null>(null);
  const notice = signal<Notice | null>(null);

  const passphraseSet = signal(false);
  const lastBackupMs = signal<number | null>(null);

  let prepared: Unlocked | null = null;
  let locked: Locked["locked"] | null = null;
  let wantsTakeover = false;
  let engine: EnginePort | null = null;
  let unsubscribe: (() => void) | null = null;
  let endedTimer: unknown = null;

  const live = (): EnginePort => engine ?? notReady();
  const device = (): DeviceVault => prepared?.device ?? notReady();

  /** Storage can be read: first run, or start the engine. */
  async function proceed(unlocked: Unlocked): Promise<void> {
    prepared = unlocked;
    locked = null;
    passphraseSet.value = unlocked.device?.hasPassphrase() ?? false;
    void unlocked.device?.lastBackupMs().then((ms) => (lastBackupMs.value = ms)).catch(() => {});
    if (!unlocked.hasIdentity) {
      phase.value = { kind: "first-run" };
      return;
    }
    if (!(await launch()) && wantsTakeover) takeOver();
  }

  function thread(peerId: string, change: (list: readonly ChatMessage[]) => ChatMessage[]): void {
    const next = new Map(messages.value);
    next.set(peerId, change(next.get(peerId) ?? []));
    messages.value = next;
  }

  /** Oldest first, as the engine lists them. */
  const byCreation = (a: TransferInfo, b: TransferInfo) => a.createdMs - b.createdMs;

  function transferThread(
    peerId: string,
    change: (list: readonly TransferInfo[]) => TransferInfo[],
  ): void {
    const next = new Map(transfers.value);
    next.set(peerId, change(next.get(peerId) ?? []).sort(byCreation));
    transfers.value = next;
  }

  /** Ids removed since this engine started, so a list loaded meanwhile does not bring one back. */
  const removedTransfers = new Set<string>();

  /** Everything the snapshot carries. */
  function sync(): void {
    if (!engine) return;
    const snap = engine.snapshot();
    batch(() => {
      relay.value = snap.relay;
      selfOnline.value = snap.relay.kind === "Registered";
      contacts.value = snap.contacts;
      pairing.value = snap.pairing;
      // A new object at every snapshot: keep the one on screen while nothing changed.
      const shown = sas.value;
      const next = snap.sas;
      if (
        shown?.peerId !== next?.peerId || shown?.digits !== next?.digits ||
        shown?.confirmed !== next?.confirmed
      ) sas.value = next;
      // An ended call is not in the snapshot; it stays until its timer or `dismissCall`.
      if (snap.call) call.value = snap.call;
    });
  }

  function syncMedia(callId: string): void {
    const media = engine?.callMedia(callId);
    const next = media
      ? { local: media.local as MediaStream | null, remote: media.remote as MediaStream | null }
      : NO_MEDIA;
    // A stream the call no longer has (the camera was switched) stops playing here, before
    // the engine stops its tracks.
    env.keepPlaying?.([next.local, next.remote]);
    callMedia.value = next;
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
    // Nothing plays the call's streams by the time this returns: the engine releases the
    // capture and the connection next.
    env.keepPlaying?.([]);
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
        const files = new Map(transfers.value);
        files.delete(event.peerId);
        batch(() => {
          messages.value = next;
          transfers.value = files;
        });
        break;
      }
      case "Transfer": {
        const info = event.transfer;
        removedTransfers.delete(info.id);
        transferThread(info.peerId, (list) => [...list.filter((t) => t.id !== info.id), info]);
        break;
      }
      case "TransferRemoved":
        removedTransfers.add(event.id);
        transferThread(event.peerId, (list) => list.filter((t) => t.id !== event.id));
        break;
      case "Call":
        onCall(event.call);
        break;
      case "CallMedia":
        syncMedia(event.callId);
        break;
      case "PairingFailed":
        // What the person stopped themselves needs no words.
        if (event.reason !== "Cancelled") {
          notice.value = { code: "Pairing", peerId: event.peerId, pairing: event.reason };
        }
        break;
      case "PairingComplete":
        if (notice.value?.code === "Pairing") notice.value = null;
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
      // The same for its file transfers; one an event delivered meanwhile is newer, so the
      // event's copy wins, and one removed meanwhile stays removed.
      const files = await started.transfers(peer);
      if (engine !== started) return;
      transferThread(peer, (live) => {
        const fresh = new Set(live.map((t) => t.id));
        return [
          ...files.filter((t) => !fresh.has(t.id) && !removedTransfers.has(t.id)),
          ...live,
        ];
      });
    }
    filesPersist.value = started.receivedFilesPersist();
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
    env.keepPlaying?.([]);
    batch(() => {
      call.value = null;
      callMedia.value = NO_MEDIA;
      pairing.value = null;
      sas.value = null;
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
    transfers,
    filesPersist,
    call,
    callMedia,
    pairing,
    sas,
    turn,
    notice,

    passphraseSet,
    lastBackupMs,

    async start() {
      let opened: Prepared;
      try {
        opened = await env.prepare();
      } catch (error) {
        phase.value = {
          kind: "failed",
          reason: error instanceof StartError ? error.reason : "core",
        };
        return;
      }
      wantsTakeover = env.takeoverOnStart.take();
      if (opened.locked) {
        locked = opened.locked;
        phase.value = { kind: "locked", retryAtMs: await locked.retryAtMs().catch(() => 0) };
        return;
      }
      await proceed(opened);
    },

    async unlock(passphrase) {
      const door = locked;
      if (!door || phase.value.kind !== "locked") return;
      let unlocked: Unlocked;
      try {
        unlocked = await door.unlock(passphrase);
      } catch (error) {
        if (error instanceof StartError) {
          phase.value = { kind: "failed", reason: error.reason };
          return;
        }
        // A wrong passphrase: the screen says so, and how long the next try has to wait.
        phase.value = { kind: "locked", retryAtMs: await door.retryAtMs().catch(() => 0) };
        throw error;
      }
      await proceed(unlocked);
    },

    async forget() {
      const door = locked;
      if (!door) return;
      await door.destroy();
      env.clearPreferences();
      env.reload();
    },

    lock() {
      // The keys exist only in this page: a reload ends at the passphrase.
      if (!passphraseSet.value) return;
      const running = engine;
      if (running) detach();
      void (running ? running.shutdown() : Promise.resolve()).finally(() => env.reload());
    },

    async setPassphrase(next) {
      await device().setPassphrase(next);
      passphraseSet.value = true;
    },
    async changePassphrase(current, next) {
      await device().changePassphrase(current, next);
    },
    async removePassphrase(current) {
      await device().removePassphrase(current);
      passphraseSet.value = false;
    },

    async makeBackup(passphrase, options) {
      const file = await device().backup(passphrase, {
        history: options.history,
        peerId: live().peerId,
      });
      lastBackupMs.value = file.madeMs;
      return file;
    },

    async restore(file, passphrase) {
      // Rejects before anything is written when the file or the passphrase is wrong.
      await device().restore(file, passphrase);
      // The database now holds the backup; an engine still running holds the old state and
      // can no longer write. Start over from what was restored.
      if (engine) detach();
      env.reload();
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

    offerFile: (peerId, file) => live().offerFile(peerId, file),
    async acceptTransfer(id) {
      await live().acceptTransfer(id);
    },
    async declineTransfer(id) {
      await live().declineTransfer(id);
    },
    async cancelTransfer(id) {
      await live().cancelTransfer(id);
    },
    async saveTransfer(id) {
      const running = live();
      const info = [...transfers.value.values()].flat().find((t) => t.id === id);
      if (!info) throw new EngineError("UnknownTransfer", "no such transfer");
      const save = env.saveFile ?? saveWithBrowser;
      const outcome = await save(info.name, () => running.transferFile(id));
      if (outcome === "missing") {
        throw new EngineError("UnknownTransfer", "the file is no longer on this device");
      }
    },
    removeTransfer: (id) => live().removeTransfer(id),

    createPairingCode: () => live().createPairingCode(),
    cancelPairing: () => engine?.cancelPairing() ?? Promise.resolve(),
    pair: (code, via) => live().pairWithCode(code, { via }),
    confirmSas: (peerId) => live().confirmSas(peerId),
    rejectSas: (peerId) => live().rejectSas(peerId),
    stopPairing: (peerId) => live().stopPairing(peerId),
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
      if (!current || !engine) return;
      // The self view lets its stream go before the camera track is switched off, never
      // after: detaching a stream whose track was just disabled can freeze the page in
      // WebKit on Linux (tests/e2e/repro, `camera-off` against `camera-off-detach-first`).
      // Switching it back on allows the stream again; the screen attaches it once the
      // engine has said the camera is on.
      const media = callMedia.value;
      env.keepPlaying?.(off ? [media.remote] : [media.local, media.remote]);
      engine.setCameraOff(current.callId, off);
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
