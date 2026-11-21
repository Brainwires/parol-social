// The app's data model. The enums mirror the Rust core (crates/parolnet-app/src/lib.rs and
// call.rs) by name, so the same events can drive this UI and the GPUI desktop app.

/** The direct path to a contact (`PathState` in the core). */
export type PathState =
  | "Unknown" // No presence information yet.
  | "Offline" // The contact is away (or does not watch us back yet).
  | "Connecting" // Setting up the direct connection.
  | "Direct" // The data channel is open.
  | "NoDirectPath" // Online, but the two networks would not connect directly.
  | "BindingFailed"; // The last connection failed its end-to-end check (PNP-001 §10.5.1).

/** Where a message is (`DeliveryState` in the core). */
export type DeliveryState =
  | "Queued" // Waiting on this device.
  | "Sent" // Handed to the contact's device.
  | "Received" // A message we received.
  | "Dropped"; // Dropped from the queue before it could be sent.

export type Direction = "Sent" | "Received";

/** The home relay connection (`RelayState` in the core). */
export type RelayState =
  | { kind: "Connecting" }
  | { kind: "Registered"; profile: string }
  | { kind: "Disconnected"; reason: string };

export type CallEnd = "HungUp" | "RemoteHungUp" | "Declined" | "RemoteDeclined" | "Failed";

/** `CallState` in the core. */
export type CallState =
  | { kind: "Outgoing" }
  | { kind: "Incoming" }
  | { kind: "Connecting" }
  | { kind: "Active" }
  | { kind: "Ended"; end: CallEnd };

export type CallMedia = "voice" | "video";

export interface ActiveCall {
  peerId: string;
  media: CallMedia;
  state: CallState;
}

export interface Contact {
  /** SHA-256 of the contact's Ed25519 public key, hex. Groups use their group id. */
  peerId: string;
  name: string;
  kind: "person" | "group";
  path: PathState;
}

/** What a bubble carries. Text, files and call invitations share one form. */
export type MessageBody =
  | { kind: "text"; text: string }
  | { kind: "file"; name: string; bytes: number }
  | { kind: "call"; media: CallMedia };

export interface ChatMessage {
  id: number;
  peerId: string;
  direction: Direction;
  body: MessageBody;
  timestampMs: number;
  state: DeliveryState;
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

/** The plain text of a message, for previews. */
export function previewText(body: MessageBody): string | null {
  return body.kind === "text" ? body.text : body.kind === "file" ? body.name : null;
}
