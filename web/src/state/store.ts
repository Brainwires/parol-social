// The store the screens read and act on. Screens only know this interface; today a fake
// (./fake.ts) implements it in memory, later the real services (relay, WebRTC, the wasm core,
// IndexedDB) do. Everything readable is a signal; everything else is an intent.
import type { ReadonlySignal } from "denext/signals";
import type {
  ActiveCall,
  CallMedia,
  ChatMessage,
  Contact,
  PathState,
  RelayState,
} from "./model.ts";

export interface AppStore {
  /** The home relay connection. */
  readonly relay: ReadonlySignal<RelayState>;
  /** False when this device has no network or no relay: "You are offline". */
  readonly selfOnline: ReadonlySignal<boolean>;
  /** People and groups, in the order they were added. */
  readonly contacts: ReadonlySignal<readonly Contact[]>;
  /** Messages by contact, oldest first. */
  readonly messages: ReadonlySignal<ReadonlyMap<string, readonly ChatMessage[]>>;
  readonly call: ReadonlySignal<ActiveCall | null>;

  /** Queue a text message; it is sent at once on an open line, otherwise it waits here. */
  send(peerId: string, text: string): void;
  /** Remove a message that is still on this device. */
  takeBack(peerId: string, messageId: number): void;
  /** Change the text of a message that is still on this device. */
  edit(peerId: string, messageId: number, text: string): void;
  /** Try to build the direct path again (after "no direct path" or a failed check). */
  retryPath(peerId: string): void;
  addContact(name: string, code: string): Contact;
  startCall(peerId: string, media: CallMedia): void;
  endCall(): void;
}

/** What the state lab can flip on a fake store. The real store has no such controls. */
export interface FakeControls {
  setPath(peerId: string, path: PathState): void;
  setSelfOnline(online: boolean): void;
  /** Remove every contact and message: the empty state. */
  clear(): void;
  reset(): void;
}

export function messagesOf(store: AppStore, peerId: string): readonly ChatMessage[] {
  return store.messages.value.get(peerId) ?? [];
}

/** How many of our messages to this contact are still on this device. */
export function waitingCount(messages: readonly ChatMessage[]): number {
  return messages.filter((m) => m.direction === "Sent" && m.state === "Queued").length;
}
