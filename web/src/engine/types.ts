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
  /**
   * Both people confirmed the verification code (the SAS of PNP-003 §5.5) when they paired.
   * Kept across later pairings with the same identity.
   */
  readonly sasVerified?: boolean;
  /**
   * A pairing with this contact is under way: `new` when the pairing added the contact (it
   * goes again if the pairing does not complete), `again` when it was a contact before.
   * Until it completes nothing but the pairing itself is sent to it.
   */
  readonly pairing?: PairingMark;
  /** Web-only: restored from a backup, and no connection has passed its check since. */
  readonly restoredMs?: number;
}

/** See `Contact.pairing` (`PairingMark` in the native core). */
export type PairingMark = "new" | "again";

/** Whether the person checked this contact one way or another. */
export function isVerified(contact: Contact): boolean {
  return contact.verified !== "no" || contact.sasVerified === true;
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
  /** What the QR code encodes: base45 of the PNP-003 payload (it has blanks in it). */
  readonly code: string;
  /** The same code for copying as text: no blanks. `pairWithCode` takes both forms. */
  readonly text: string;
  /** When a scanner stops accepting it (the code's own lifetime, 1800 s from its timestamp). */
  readonly expiresAtMs: number;
}

/**
 * The verification code of a pairing under way (the Short Authentication String of PNP-003
 * §5.5). Both devices show the same one unless someone sits between them; the two people
 * compare it by voice or in person and each says whether it matches.
 */
export interface SasCheck {
  readonly peerId: string;
  /** Six decimal digits. */
  readonly digits: string;
  /** The same value as five emoji. */
  readonly emoji: string;
  /** This device's user said it matches; the contact's answer is awaited. */
  readonly confirmed: boolean;
}

/**
 * Why a pairing ended without a contact:
 * - `SasRejected`: this device's user said the verification codes differ;
 * - `SasMismatch`: the contact's confirmation did not fit the code shown here;
 * - `Timeout`: the contact did not answer, or a code was not compared, in time;
 * - `ConnectionLost`: the connection was lost while pairing;
 * - `Cancelled`: this device's user stopped it (`stopPairing`, or the contact was removed);
 * - `Failed`: anything else (a proof that did not verify, a malformed message).
 */
export type PairingFailure =
  | "Cancelled"
  | "SasRejected"
  | "SasMismatch"
  | "Timeout"
  | "ConnectionLost"
  | "Failed";

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

/** Why a transfer was cancelled (PNP-010 §4.4; `CancelReason` in the native core). */
export type CancelReason =
  /** The user cancelled. */
  | "User"
  /** The sender can no longer read the file. */
  | "Unavailable"
  /** A record or the final hash did not verify. */
  | "Integrity"
  /** The receiver could not store the file. */
  | "Storage"
  /** A limit of the side that cancelled. */
  | "Limit"
  | "Other";

/** Where a file transfer is (`TransferState`). */
export type TransferState =
  /** Offered; the receiver has not answered. */
  | { kind: "Offered" }
  /** Accepted, and waiting for a direct connection or for its turn. */
  | { kind: "Waiting" }
  /** Records are flowing. */
  | { kind: "Active" }
  /** The whole file arrived and verified. */
  | { kind: "Complete" }
  | { kind: "Declined" }
  | { kind: "Cancelled"; byPeer: boolean; reason: CancelReason };

/** A file transfer as the UI shows it (`TransferInfo`). */
export interface TransferInfo {
  /** 32 hex digits. */
  readonly id: string;
  readonly peerId: string;
  /** `Sent`: this device offers the file. `Received`: it was offered to us. */
  readonly direction: Direction;
  /** Safe to show and to use as a file name: never a path. */
  readonly name: string;
  readonly size: number;
  /** The sender's claim; may be empty. */
  readonly mime: string;
  readonly state: TransferState;
  readonly bytesDone: number;
  /** Our latest message about it (offer, answer, cancel) still waits on this device. */
  readonly pending: boolean;
  readonly createdMs: number;
  /** Web-only: a received, complete file is on this device and can be saved (`transferFile`). */
  readonly available: boolean;
}

export function transferOver(t: TransferInfo): boolean {
  return t.state.kind === "Complete" || t.state.kind === "Declined" ||
    t.state.kind === "Cancelled";
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
  /** The verification code to compare, while a pairing waits for it (the oldest, if several). */
  readonly sas: SasCheck | null;
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
  /** A pairing shows its verification code, or the user confirmed it (`SasVerification`). */
  | { kind: "Sas"; sas: SasCheck }
  /** The pairing with a contact completed; `sasVerified`: both confirmed the code. */
  | { kind: "PairingComplete"; peerId: string; sasVerified: boolean }
  /** A pairing was aborted. A contact it had added is gone (`ContactRemoved` came first). */
  | { kind: "PairingFailed"; peerId: string; reason: PairingFailure }
  /** Web-only: unread count or last activity of a contact changed. */
  | {
    kind: "ContactActivity";
    peerId: string;
    unread: number;
    lastActivityMs: number;
  }
  /** Web-only: a contact and everything kept about it was removed (`removeContact`). */
  | { kind: "ContactRemoved"; peerId: string }
  /**
   * Something the user should know. `code` says which, so a UI can use its own words;
   * `text` is the English sentence. `peerId` is set when it is about one contact.
   */
  | { kind: "Notice"; code: NoticeCode; text: string; peerId?: string }
  | { kind: "Call"; call: CallInfo }
  /** A file transfer appeared, changed state or moved on. */
  | { kind: "Transfer"; transfer: TransferInfo }
  /** Web-only: a finished transfer was removed from the conversation (`removeTransfer`). */
  | { kind: "TransferRemoved"; peerId: string; id: string }
  /** Web-only: the local or remote stream of a call changed (see `Engine.callMedia`). */
  | { kind: "CallMedia"; callId: string };

/**
 * What a `Notice` is about:
 * - `Storage`: a write to this device's storage failed;
 * - `BindingFailed`: a direct connection failed its end-to-end check and was closed;
 * - `TurnUnusable`: relay-only is on and the user's TURN server gave no path;
 * - `Transfer`: a file transfer was stopped because what arrived did not verify.
 */
export type NoticeCode = "Storage" | "BindingFailed" | "TurnUnusable" | "Transfer";

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
  | "NoPairing"
  | "Crypto"
  | "Config"
  | "NotConnected"
  | "Busy"
  | "UnknownCall"
  | "UnknownTransfer"
  | "Transfer"
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
