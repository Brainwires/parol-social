// The app's data model: the engine's own vocabulary (src/engine/types.ts, which mirrors the
// Rust core by name), plus the few things only the interface knows. One vocabulary drives this
// UI and the GPUI desktop app.
import type {
  CallEnd,
  ChatMessage as EngineMessage,
  ContactView,
  PathState,
} from "../engine/types.ts";

export type {
  CallEnd,
  CallInfo,
  CallState,
  Contact,
  ContactView,
  DeliveryState,
  Direction,
  NoticeCode,
  PairingCode,
  PathState,
  RelayState,
  Verification,
} from "../engine/types.ts";

/**
 * What a bubble can carry besides text. The engine sends text only in this phase; the state
 * lab's made-up conversations use these to show the one form files and call invitations share.
 */
export type Attachment =
  | { kind: "file"; name: string; bytes: number }
  | { kind: "call"; media: "voice" | "video" };

/** A message as the screens show it: the engine's, optionally with a lab attachment. */
export interface ChatMessage extends EngineMessage {
  readonly attachment?: Attachment;
}

/** The contact is reachable by the relay: listed under "Online now". */
export function isOnline(path: PathState): boolean {
  return path === "Connecting" || path === "Direct" || path === "NoDirectPath" ||
    path === "BindingFailed";
}

/** Which variant of the line a conversation shows. */
export type LineState = "open" | "waiting" | "connecting" | "no-path" | "blocked" | "self-offline";

/**
 * The line of a conversation. Being offline ourselves wins: nothing else can be known then.
 * `Unknown` reads as waiting: messages are held on this device either way.
 */
export function lineState(path: PathState, selfOnline: boolean): LineState {
  if (!selfOnline) return "self-offline";
  switch (path) {
    case "Direct":
      return "open";
    case "Connecting":
      return "connecting";
    case "NoDirectPath":
      return "no-path";
    case "BindingFailed":
      return "blocked";
    case "Unknown":
    case "Offline":
      return "waiting";
  }
}

/** The list's order: who is online first, then by last activity, newest first. */
export function sortContacts(contacts: readonly ContactView[]): ContactView[] {
  return [...contacts].sort((a, b) =>
    Number(isOnline(b.path)) - Number(isOnline(a.path)) ||
    b.lastActivityMs - a.lastActivityMs ||
    a.contact.name.localeCompare(b.contact.name)
  );
}

/** How a call ended, as the interface words it (one message per engine `CallEnd`). */
export type CallEndWords =
  | "youEnded"
  | "theyEnded"
  | "youDeclined"
  | "theyDeclined"
  | "noAnswer"
  | "missed"
  | "failed";

export function callEndWords(end: CallEnd, incoming: boolean): CallEndWords {
  switch (end.kind) {
    case "HungUp":
      return "youEnded";
    case "RemoteHungUp":
      return "theyEnded";
    case "Declined":
      return "youDeclined";
    case "Rejected":
      return "theyDeclined";
    case "NoAnswer":
      // We did not pick up, or they did not.
      return incoming ? "missed" : "noAnswer";
    case "Failed":
      return "failed";
  }
}
