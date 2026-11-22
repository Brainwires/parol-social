// The backup file: one device's identity, contacts, sessions and settings (and, if asked,
// its history) encrypted under a passphrase. docs/web-port/backup.md is the format's
// specification; this is its only implementation so far.
//
//   "PNBACKUP" | version (1 byte) | header length (4 bytes, big-endian) | header | ciphertext
//
// The header is JSON and names everything needed to derive the key. Everything before the
// ciphertext is its associated data, so no byte of the file can change unnoticed.
import { fromUtf8, isHex, toHex, utf8 } from "./bytes.ts";
import type { StoreName } from "./platform.ts";
import type {
  ContactRow,
  ContactStateRow,
  IdentityRow,
  MessageRow,
  OutboxRow,
  SessionsRow,
  SettingRow,
} from "./storage.ts";
import {
  checkKdf,
  hexBytes,
  KDF_DEFAULT,
  type KdfParams,
  MIN_PASSPHRASE,
  passphraseKey,
  type VaultCrypto,
  VaultError,
} from "./vault.ts";

export const BACKUP_MAGIC = "PNBACKUP";
export const BACKUP_VERSION = 1;
/** The file name's ending, and what the file chooser offers. */
export const BACKUP_EXTENSION = ".pnbackup";
/** The plaintext is padded to a multiple of this many bytes. */
const BACKUP_PAD = 4096;
/** Larger files are refused before anything is derived (history is text: this is ample). */
export const BACKUP_MAX_BYTES = 256 * 1024 * 1024;

/**
 * Settings that belong to the person rather than to the device, and so go into a backup.
 * Everything else in the `settings` store stays behind (the date of the last backup, for
 * one), as do the preferences the app keeps outside the database (theme, language, chosen
 * camera, the address of the app's server).
 */
export const BACKUP_SETTINGS: readonly string[] = ["turn"];

export interface BackupHeader {
  kdf: KdfParams;
  /** 16 bytes, hex. */
  salt: string;
  /** 12 bytes, hex. */
  nonce: string;
  cipher: "AES-256-GCM";
}

export interface BackupContents {
  version: typeof BACKUP_VERSION;
  createdMs: number;
  /** The identity's PeerId, so a restore can say whose backup this is. */
  peerId: string;
  identity: { secretHex: string };
  /** The wasm core's `export_sessions()` JSON; "" when there are none. */
  sessions: string;
  contacts: ContactRow[];
  settings: SettingRow[];
  /** Null unless the person asked for the history. */
  history: null | {
    messages: MessageRow[];
    outbox: OutboxRow[];
    contactState: ContactStateRow[];
  };
}

export type BackupErrorCode =
  /** Not a ParolNet backup file. */
  | "NotABackup"
  /** Written by a newer version of the format than this code reads. */
  | "Newer"
  /** The passphrase is wrong, or the file was changed or damaged: the two look the same. */
  | "WrongPassphrase"
  /** It decrypted, but what is inside is not a backup this code can use. */
  | "Invalid"
  /** The passphrase is too short to make a backup with. */
  | "Weak"
  /** There is no identity on this device to back up. */
  | "Empty";

/** Every error of this module. Its message never contains a passphrase or a row. */
export class BackupError extends Error {
  constructor(readonly code: BackupErrorCode, message: string) {
    super(message);
    this.name = "BackupError";
  }
}

const buf = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => bytes as Uint8Array<ArrayBuffer>;

/** What a backup of these rows holds. Throws `Empty` when there is no identity. */
export function collectBackup(
  rows: Record<StoreName, unknown[]>,
  options: { history: boolean; peerId: string; now: number },
): BackupContents {
  const identity = (rows.identity as IdentityRow[]).find((row) => row.id === "self");
  if (!identity) throw new BackupError("Empty", "there is no identity on this device");
  const sessions = (rows.sessions as SessionsRow[]).find((row) => row.id === "blob");
  return {
    version: BACKUP_VERSION,
    createdMs: options.now,
    peerId: options.peerId,
    identity: { secretHex: identity.secretHex },
    sessions: sessions?.json ?? "",
    contacts: rows.contacts as ContactRow[],
    settings: (rows.settings as SettingRow[]).filter((row) => BACKUP_SETTINGS.includes(row.key)),
    history: options.history
      ? {
        messages: rows.messages as MessageRow[],
        outbox: rows.outbox as OutboxRow[],
        contactState: rows.contactState as ContactStateRow[],
      }
      : null,
  };
}

/**
 * The rows a device has after restoring `contents`: its identity and sessions, its contacts
 * (each marked `restoredMs`, until its connection has proven that the sessions still fit),
 * its settings, and the history if the backup has one. No pairing code, no queue otherwise.
 */
export function restoredRows(
  contents: BackupContents,
  now: number,
): Record<StoreName, unknown[]> {
  const contacts = contents.contacts.map((row) => ({ ...row, restoredMs: now }));
  const state = new Map(
    (contents.history?.contactState ?? []).map((row) => [row.peerId, row]),
  );
  return {
    identity: [{ id: "self", secretHex: contents.identity.secretHex } satisfies IdentityRow],
    sessions: contents.sessions === ""
      ? []
      : [{ id: "blob", json: contents.sessions } satisfies SessionsRow],
    contacts,
    contactState: contacts.map((row) =>
      state.get(row.peerId) ??
        { peerId: row.peerId, lastActivityMs: row.addedMs, unread: 0 } satisfies ContactStateRow
    ),
    messages: contents.history?.messages ?? [],
    outbox: contents.history?.outbox ?? [],
    settings: contents.settings.filter((row) => BACKUP_SETTINGS.includes(row.key)),
  };
}

function prefix(header: Uint8Array): Uint8Array {
  const out = new Uint8Array(BACKUP_MAGIC.length + 5 + header.length);
  out.set(utf8(BACKUP_MAGIC));
  out[BACKUP_MAGIC.length] = BACKUP_VERSION;
  new DataView(out.buffer).setUint32(BACKUP_MAGIC.length + 1, header.length);
  out.set(header, BACKUP_MAGIC.length + 5);
  return out;
}

/** The file for `contents`, encrypted under `passphrase`. */
export async function encodeBackup(
  crypto: VaultCrypto,
  passphrase: string,
  contents: BackupContents,
  kdf: KdfParams = KDF_DEFAULT,
): Promise<Uint8Array> {
  if ([...passphrase.normalize("NFKC")].length < MIN_PASSPHRASE) {
    throw new BackupError("Weak", `a passphrase needs at least ${MIN_PASSPHRASE} characters`);
  }
  const salt = crypto.random(16);
  const nonce = crypto.random(12);
  const header: BackupHeader = {
    kdf: { ...kdf },
    salt: toHex(salt),
    nonce: toHex(nonce),
    cipher: "AES-256-GCM",
  };
  const head = prefix(utf8(JSON.stringify(header)));
  const key = await passphraseKey(crypto, passphrase, salt, kdf);
  const text = utf8(JSON.stringify(contents));
  const plain = new Uint8Array(Math.ceil((text.length + 1) / BACKUP_PAD) * BACKUP_PAD).fill(0x20);
  plain.set(text);
  text.fill(0);
  try {
    const sealed = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: buf(nonce), additionalData: buf(head) },
        key,
        buf(plain),
      ),
    );
    const file = new Uint8Array(head.length + sealed.length);
    file.set(head);
    file.set(sealed, head.length);
    return file;
  } finally {
    plain.fill(0);
  }
}

const isPeerId = (value: unknown): value is string =>
  typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

/** Throws `Invalid` unless `value` is a backup this code can restore. */
function checkContents(value: unknown): asserts value is BackupContents {
  const bad = (what: string): never => {
    throw new BackupError("Invalid", `the backup's ${what} cannot be used`);
  };
  if (!isObject(value) || value.version !== BACKUP_VERSION) return bad("contents");
  const identity = value.identity;
  if (
    !isObject(identity) || typeof identity.secretHex !== "string" ||
    identity.secretHex.length !== 64 || !isHex(identity.secretHex)
  ) {
    return bad("identity");
  }
  if (!isPeerId(value.peerId) || typeof value.createdMs !== "number") return bad("contents");
  if (typeof value.sessions !== "string") return bad("sessions");
  if (value.sessions !== "") {
    try {
      if (!isObject(JSON.parse(value.sessions))) return bad("sessions");
    } catch {
      return bad("sessions");
    }
  }
  if (!Array.isArray(value.contacts) || !Array.isArray(value.settings)) return bad("contacts");
  for (const row of value.contacts) {
    if (
      !isObject(row) || !isPeerId(row.peerId) || typeof row.name !== "string" ||
      typeof row.addedMs !== "number" ||
      !["in-person", "compared", "no"].includes(row.verified as string) ||
      !(row.identityKey === null || typeof row.identityKey === "string")
    ) {
      return bad("contacts");
    }
  }
  for (const row of value.settings) {
    if (!isObject(row) || typeof row.key !== "string") return bad("settings");
  }
  const history = value.history;
  if (history === null) return;
  if (
    !isObject(history) || !Array.isArray(history.messages) || !Array.isArray(history.outbox) ||
    !Array.isArray(history.contactState)
  ) {
    return bad("history");
  }
  const known = new Set((value.contacts as ContactRow[]).map((row) => row.peerId));
  for (const row of [...history.messages, ...history.outbox]) {
    if (!isObject(row) || !Number.isInteger(row.id) || !known.has(row.peerId as string)) {
      return bad("history");
    }
  }
  for (const row of history.messages) {
    if (typeof row.text !== "string" || typeof row.timestampMs !== "number") return bad("history");
  }
  for (const row of history.contactState) {
    if (
      !isObject(row) || !known.has(row.peerId as string) ||
      typeof row.lastActivityMs !== "number" || typeof row.unread !== "number"
    ) {
      return bad("history");
    }
  }
}

/** Read the part of a file that is not encrypted. Throws `NotABackup` or `Newer`. */
export function backupHeader(file: Uint8Array): { header: BackupHeader; head: Uint8Array } {
  const magic = utf8(BACKUP_MAGIC);
  const fixed = magic.length + 5;
  const notOne = () => new BackupError("NotABackup", "that file is not a ParolNet backup");
  if (file.length < fixed || file.length > BACKUP_MAX_BYTES) throw notOne();
  for (let i = 0; i < magic.length; i++) if (file[i] !== magic[i]) throw notOne();
  if (file[magic.length] !== BACKUP_VERSION) {
    if (file[magic.length] > BACKUP_VERSION) {
      throw new BackupError("Newer", "that backup was made by a newer ParolNet");
    }
    throw notOne();
  }
  const length = new DataView(file.buffer, file.byteOffset).getUint32(magic.length + 1);
  if (length > 4096 || fixed + length + 16 > file.length) throw notOne();
  const head = file.subarray(0, fixed + length);
  let header: BackupHeader;
  try {
    header = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(file.subarray(fixed, fixed + length)),
    );
    if (!isObject(header) || header.cipher !== "AES-256-GCM") throw notOne();
    checkKdf(header.kdf);
    hexBytes(header.salt, 16);
    hexBytes(header.nonce, 12);
  } catch (error) {
    // Settings beyond what this app derives with are a newer format's, not damage.
    if (error instanceof VaultError && error.code === "Unsupported") {
      throw new BackupError("Newer", "that backup needs a newer ParolNet");
    }
    throw notOne();
  }
  return { header, head };
}

/**
 * Decrypt and check a backup file. Throws `NotABackup`, `Newer`, `WrongPassphrase` (also
 * for a file that was changed) or `Invalid`. Nothing is written anywhere.
 */
export async function decodeBackup(
  crypto: VaultCrypto,
  passphrase: string,
  file: Uint8Array,
): Promise<BackupContents> {
  const { header, head } = backupHeader(file);
  const key = await passphraseKey(crypto, passphrase, hexBytes(header.salt, 16), header.kdf);
  let plain: Uint8Array;
  try {
    plain = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: buf(hexBytes(header.nonce, 12)), additionalData: buf(head) },
        key,
        buf(file.subarray(head.length)),
      ),
    );
  } catch {
    throw new BackupError(
      "WrongPassphrase",
      "the passphrase is wrong, or the file was changed",
    );
  }
  let contents: unknown;
  try {
    contents = JSON.parse(fromUtf8(plain));
  } catch {
    throw new BackupError("Invalid", "the backup's contents cannot be read");
  } finally {
    plain.fill(0);
  }
  checkContents(contents);
  return contents;
}
