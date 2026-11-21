// The store the screens read and act on. Screens only know this interface. The real one
// (./engine-store.ts) is an adapter over the engine; the state lab runs on a made-up one
// (./fake.ts). Everything readable is a signal; everything else is an intent. Intents that
// touch the engine are asynchronous and reject with an `EngineError` (its `code` says why).
import type { ReadonlySignal } from "denext/signals";
import type {
  CallInfo,
  ChatMessage,
  Contact,
  ContactView,
  NoticeCode,
  PairingCode,
  PathState,
  RelayState,
} from "./model.ts";

/** Where the app is in its own life. Everything but `ready` is a full screen. */
export type Phase =
  /** Loading the encryption core and opening this device's storage. */
  | { kind: "loading" }
  /** Nothing on this device yet: the first-run screen. */
  | { kind: "first-run" }
  /** Another tab runs ParolNet (`moved`: this tab ran it until the other took over). */
  | { kind: "other-tab"; moved: boolean }
  /** It could not start: the core did not load, or storage is unavailable. */
  | { kind: "failed"; reason: "core" | "storage" }
  | { kind: "ready" };

/** Something the app has to say on its own; shown as a panel until dismissed. */
export interface Notice {
  code: NoticeCode;
  /** The contact it is about, when there is one. */
  peerId?: string;
}

/** The streams of the current call, for the media elements. */
export interface CallMediaStreams {
  local: MediaStream | null;
  remote: MediaStream | null;
}

/** The person's own relay server, as the settings show it: never the password. */
export interface TurnView {
  uri: string;
  username: string;
  relayOnly: boolean;
}

export interface TurnInput {
  uri: string;
  username: string;
  /** Empty keeps the saved password. */
  password: string;
  relayOnly: boolean;
}

export interface AppStore {
  readonly phase: ReadonlySignal<Phase>;
  /** The home relay connection. */
  readonly relay: ReadonlySignal<RelayState>;
  /** False when this device has no network or no relay: "You are offline". */
  readonly selfOnline: ReadonlySignal<boolean>;
  /** People, in the order they were added, each with its live state. */
  readonly contacts: ReadonlySignal<readonly ContactView[]>;
  /** Messages by contact, oldest first. */
  readonly messages: ReadonlySignal<ReadonlyMap<string, readonly ChatMessage[]>>;
  /** The current call; an ended one stays for a moment so the screen can say how it ended. */
  readonly call: ReadonlySignal<CallInfo | null>;
  readonly callMedia: ReadonlySignal<CallMediaStreams>;
  /** The code this device is showing, while it can still be used. */
  readonly pairing: ReadonlySignal<PairingCode | null>;
  /** The person's own relay server: null when none is set. */
  readonly turn: ReadonlySignal<TurnView | null>;
  readonly notice: ReadonlySignal<Notice | null>;

  /** First run: make this device's identity and start. */
  begin(): Promise<void>;
  /** Another tab has ParolNet: run it in this one instead. */
  takeOver(): void;

  /** Send a text; it goes at once on an open line, otherwise it waits on this device. */
  send(peerId: string, text: string): Promise<void>;
  /** Remove a message that is still on this device. */
  takeBack(messageId: number): Promise<void>;
  /** Change the text of a message that is still on this device. */
  edit(messageId: number, text: string): Promise<void>;
  /** Try to build the direct path now (the conversation was opened, or "Try again"). */
  connect(peerId: string): void;
  markRead(peerId: string): void;

  /** A fresh code to show; the previous one stops working. */
  createPairingCode(): Promise<PairingCode>;
  /** Add the contact whose code this is. `via` says whether it was scanned or pasted. */
  pair(code: string, via: "scan" | "paste"): Promise<Contact>;
  rename(peerId: string, name: string): Promise<void>;
  /** The person compared safety numbers (`true`), or takes that back. */
  setCompared(peerId: string, compared: boolean): Promise<void>;
  /** 60 digits, or null when it cannot be computed. */
  safetyNumber(peerId: string): string | null;
  /** Remove a contact with its history and what was waiting for it. */
  removeContact(peerId: string): Promise<void>;

  startCall(peerId: string, video: boolean): Promise<void>;
  acceptCall(): Promise<void>;
  declineCall(): Promise<void>;
  hangup(): Promise<void>;
  setMuted(muted: boolean): void;
  setCameraOff(off: boolean): void;
  /** Send this capture's video instead; the call takes the stream over. */
  replaceCamera(stream: MediaStream): Promise<void>;
  /** Stop showing how the last call ended. */
  dismissCall(): void;

  setTurn(settings: TurnInput | null): Promise<void>;
  dismissNotice(): void;
  /** Delete everything on this device and start over. */
  wipe(): Promise<void>;
}

/** What the state lab can flip on a fake store. The real store has no such controls. */
export interface FakeControls {
  setPath(peerId: string, path: PathState): void;
  setSelfOnline(online: boolean): void;
  /** Put a call on screen in any state (null: no call). */
  setCall(call: CallInfo | null): void;
  /** Remove every contact and message: the empty state. */
  clear(): void;
  reset(): void;
}

export function messagesOf(store: AppStore, peerId: string): readonly ChatMessage[] {
  return store.messages.value.get(peerId) ?? [];
}

export function contactOf(store: AppStore, peerId: string): ContactView | undefined {
  return store.contacts.value.find((c) => c.contact.peerId === peerId);
}

/** The name to show for a contact id (an empty string when it is unknown). */
export function nameOf(store: AppStore, peerId: string): string {
  return contactOf(store, peerId)?.contact.name ?? "";
}
