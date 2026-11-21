// The engine's public vocabulary. The names and meanings mirror the native core
// (crates/parolnet-app/src/lib.rs and call.rs) so one UI vocabulary serves web and desktop.

/** The direct path to a contact (`PathState` in the native core). */
export type PathState =
  /** No presence information yet. */
  | "Unknown"
  /** The relay says the contact is offline (or does not watch us back yet). */
  | "Offline"
  /** Setting up the WebRTC connection. */
  | "Connecting"
  /** The data channel is open and its channel binding verified (PNP-001 §10.5.1). */
  | "Direct"
  /** The contact is online but no path could be built (either side can add a TURN server). */
  | "NoDirectPath"
  /** The last direct connection failed its end-to-end check. Retried with backoff. */
  | "BindingFailed";

/** Where a message is (`DeliveryState` in the native core). */
export type DeliveryState =
  /** Waiting on this device for the contact's verified data channel. */
  | "Queued"
  /** Handed to the contact's data channel. */
  | "Sent"
  /** A message we received. */
  | "Received"
  /** Dropped from the queue (limits, age, or it could not be encrypted) before it was sent. */
  | "Dropped";

export type Direction = "Sent" | "Received";

/** The home relay connection (`RelayState` in the native core). */
export type RelayState =
  | { kind: "Connecting" }
  /** Registered; `profile` is `signaling-only` or `relay`. */
  | { kind: "Registered"; profile: string }
  | { kind: "Disconnected"; reason: string };

/**
 * How far the user checked that a contact is who they think:
 * - `in-person`: we scanned their code with the camera;
 * - `compared`: the user compared safety numbers out of band;
 * - `no`: neither (a pasted code, or they scanned ours).
 */
export type Verification = "in-person" | "compared" | "no";

export interface Contact {
  /** SHA-256 of the contact's Ed25519 identity key, 64 lower-case hex characters. */
  readonly peerId: string;
  /** Local only; never sent anywhere. */
  readonly name: string;
  /** The contact's Ed25519 identity key (hex) at pairing time; the trust anchor. */
  readonly identityKey: string | null;
  readonly addedMs: number;
  readonly verified: Verification;
  readonly verifiedMs: number | null;
}

export interface ChatMessage {
  readonly id: number;
  readonly peerId: string;
  readonly direction: Direction;
  readonly text: string;
  readonly timestampMs: number;
  readonly state: DeliveryState;
  /** Set when the text of a still-queued message was changed. */
  readonly editedMs?: number;
}

/** A contact with its live state (`ContactView`). */
export interface ContactView {
  readonly contact: Contact;
  readonly path: PathState;
  /** Messages for this contact still waiting on this device. */
  readonly queued: number;
  readonly unread: number;
  readonly lastActivityMs: number;
}

/** The pairing code this device is showing, while it can still be used. */
export interface PairingCode {
  /** Lower-case hex of the PNP-003 payload; the QR code encodes the same text. */
  readonly code: string;
  /** When a scanner stops accepting it (the code's own lifetime, 1800 s from its timestamp). */
  readonly expiresAtMs: number;
}

/** Why a call ended (`CallEnd`). */
export type CallEnd =
  | { kind: "HungUp" }
  | { kind: "RemoteHungUp" }
  | { kind: "Declined" }
  | { kind: "Rejected" }
  | { kind: "NoAnswer" }
  | { kind: "Failed"; reason: string };

/** Where a call is (`CallState`). */
export type CallState =
  | { kind: "Outgoing" }
  | { kind: "Incoming" }
  | { kind: "Connecting" }
  | { kind: "Active" }
  | { kind: "Ended"; end: CallEnd };

/** A call as the UI shows it (`CallInfo`). */
export interface CallInfo {
  /** 32 hex digits. */
  readonly callId: string;
  readonly peerId: string;
  /** Video was offered. */
  readonly video: boolean;
  readonly incoming: boolean;
  readonly state: CallState;
  /** Our microphone is muted. */
  readonly muted: boolean;
  /** Our camera is switched off (the track stays; no renegotiation). */
  readonly cameraOff: boolean;
}

/** A consistent picture of the engine's state (`Snapshot`). Immutable. */
export interface Snapshot {
  readonly peerId: string;
  readonly publicKey: string;
  readonly relay: RelayState;
  readonly contacts: readonly ContactView[];
  readonly pairingOpen: boolean;
  /** The code being shown, if one is still valid. */
  readonly pairing: PairingCode | null;
  /** The user configured their own TURN server (its credential is never in a snapshot). */
  readonly turnConfigured: boolean;
  /** Connections use that TURN server only. */
  readonly relayOnly: boolean;
  /** The current call, if any. */
  readonly call: CallInfo | null;
}

/** What the engine reports to the UI (`AppEvent`, plus the web-only kinds marked below). */
export type AppEvent =
  | { kind: "Relay"; state: RelayState }
  | { kind: "ContactAdded"; contact: Contact }
  | { kind: "ContactUpdated"; contact: Contact }
  | { kind: "Path"; peerId: string; state: PathState }
  | { kind: "Message"; message: ChatMessage }
  | { kind: "MessageState"; peerId: string; id: number; state: DeliveryState }
  /** Web-only: a queued message's text was changed (`editQueued`). */
  | { kind: "MessageEdited"; message: ChatMessage }
  /** Web-only: a queued message was taken back (`takeBack`). */
  | { kind: "MessageRemoved"; peerId: string; id: number }
  /** Web-only: the pairing window opened or closed. */
  | { kind: "Pairing"; pairing: PairingCode | null }
  /** Web-only: unread count or last activity of a contact changed. */
  | {
    kind: "ContactActivity";
    peerId: string;
    unread: number;
    lastActivityMs: number;
  }
  /** Something the user should know (a failed pairing, a refused connection). */
  | { kind: "Notice"; text: string }
  | { kind: "Call"; call: CallInfo }
  /** Web-only: the local or remote stream of a call changed (see `Engine.callMedia`). */
  | { kind: "CallMedia"; callId: string };

/** The user's own TURN server. The only TURN server the engine ever uses. */
export interface TurnSettings {
  /** `turn:host[:port]`, optionally `?transport=udp` or `?transport=tcp`. */
  uri: string;
  username: string;
  password: string;
  /** Use the TURN server for every connection and nothing else. */
  relayOnly: boolean;
}

export type EngineErrorCode =
  | "Storage"
  | "InvalidCode"
  | "CodeExpired"
  | "OwnCode"
  | "NoSession"
  | "UnknownContact"
  | "Crypto"
  | "Config"
  | "NotConnected"
  | "Busy"
  | "UnknownCall"
  | "UnknownMessage"
  | "NotQueued"
  | "TooLong"
  | "Media"
  | "Stopped";

/**
 * Every error the engine throws. Messages never contain key material, session state,
 * plaintext or a TURN credential; peer ids appear only in their 8-character short form.
 */
export class EngineError extends Error {
  readonly code: EngineErrorCode;
  constructor(code: EngineErrorCode, message: string) {
    super(message);
    this.name = "EngineError";
    this.code = code;
  }
}

/** Short display form of a peer id. */
export function shortId(peerId: string): string {
  return peerId.slice(0, 8);
}

export function isOver(call: CallInfo): boolean {
  return call.state.kind === "Ended";
}
