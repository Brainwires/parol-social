# Web port: the backup file

"Back up this device" (Settings, You) writes one file that holds a person's identity, their
contacts and their settings, encrypted under a passphrase they type twice. "Restore from a
backup" (first run, and Settings) reads it back. This document specifies the file, **format
version 1**, and says what a restore does.

Code: `web/src/engine/backup.ts`. Tests: `web/tests/engine/backup_test.ts`; in real browsers,
`web/tests/e2e/real.flows.ts` ("back up this device, delete all data, restore…").

## The file

Name: `parolnet-backup-YYYY-MM-DD.pnbackup` (the device's own date). Media type
`application/octet-stream`.

```
offset  size  field
0       8     magic: the ASCII bytes "PNBACKUP"
8       1     format version: 1
9       4     header length H, unsigned, big-endian (at most 4096)
13      H     header: UTF-8 JSON
13+H    …     ciphertext: AES-256-GCM, the 16-byte tag last
```

### Header

```json
{"kdf":{"alg":"argon2id","version":19,"memoryKiB":65536,"passes":3,"lanes":1},
 "salt":"<32 hex digits>","nonce":"<24 hex digits>","cipher":"AES-256-GCM"}
```

The header says everything needed to derive the key and nothing about the contents: no date,
no peer id, no count. **The header is authenticated**: the associated data of the ciphertext
is every byte of the file before it (magic, version, length and the header exactly as
written). Changing any of them, including the cost parameters, makes decryption fail.

### Key

`key = Argon2id(passphrase, salt)`, 32 bytes, with the header's parameters: the same function,
defaults, passphrase handling (Unicode NFKC, UTF-8, at least 8 characters) and limits as the
passphrase lock ([at-rest.md](at-rest.md), "The passphrase's key"). The salt (16 bytes) and
the nonce (12 bytes) are random and new for every file. The backup's passphrase is its own:
it has nothing to do with a passphrase that locks the device, and the two may differ.

A reader refuses, before deriving anything: a file without the magic or shorter than a header
(`NotABackup`); a version byte above 1, or parameters beyond what version 1 allows (`Newer`:
"made by a newer version of ParolNet"); a file over 256 MiB.

### Plaintext

UTF-8 JSON, padded with spaces to a multiple of 4096 bytes (so the file's size says little
about how many contacts it holds), not compressed:

```json
{
  "version": 1,
  "createdMs": 1795300000000,
  "peerId": "<64 hex: the identity's PeerId>",
  "identity": { "secretHex": "<64 hex: the Ed25519 secret>" },
  "sessions": "<the wasm core's export_sessions() JSON, or \"\">",
  "contacts": [
    { "peerId": "…", "name": "…", "identityKey": "<hex> | null", "addedMs": 0,
      "verified": "in-person | compared | no", "verifiedMs": null }
  ],
  "settings": [ { "key": "turn", "value": { "uri": "…", "username": "…", "password": "…", "relayOnly": false } } ],
  "history": null
}
```

With "Include message history" ticked (off by default), `history` is

```json
{ "messages": [ <rows of the `messages` store> ],
  "outbox":   [ <rows of the `outbox` store: what was waiting to be sent> ],
  "contactState": [ { "peerId": "…", "lastActivityMs": 0, "unread": 0 } ] }
```

The rows are the engine's own ([engine.md](engine.md), "Storage schema").

**What is in a backup:** the identity; every contact with its name and verification state; the
ratchet sessions; the person's own relay (TURN) server, password included; optionally the
history and the queue.

**What is not:** the pairing code on screen and its pending secret; settings that belong to the
device (the date of the last backup); the preferences kept outside the database (theme,
language, chosen devices, a custom address of the app's server); the storage keys and any
passphrase lock (a restored device is sealed under its own keys, and locked only if that
device has a passphrase).

After decryption the contents are checked (version, a 32-byte identity secret, well-formed
contacts, history rows that belong to listed contacts). Contents that fail are `Invalid`, and
nothing is written.

### Errors a reader distinguishes

| Code | Meaning | What the app says |
|---|---|---|
| `NotABackup` | no magic, truncated before the ciphertext, a header that does not parse | "That file is not a ParolNet backup." |
| `Newer` | version byte above 1, or key-derivation settings outside version 1 | "That backup was made by a newer version of ParolNet. Update the app, then try again." |
| `WrongPassphrase` | the tag does not verify | "The passphrase is wrong, or the file is damaged." (the two cannot be told apart) |
| `Invalid` | decrypted, but not a usable backup | "That backup cannot be used. What is inside it is incomplete." |

A later format gets a new version byte. Version 1 readers refuse it by that byte alone.

## Making one

The person types a passphrase twice and chooses whether to include the history. The rows are
read in one transaction, so the sessions and the history in a file belong to the same moment.
The file is built in memory and offered as a link ("Save the backup file", an `<a download>`
on a `blob:` URL) that the person presses: a user-initiated download, which Chromium, Firefox
and WebKit all allow under the app's Content-Security-Policy. Nothing is uploaded anywhere.

Settings shows the date of the last backup made on this device. Once there is a first contact
and no backup has been made, the conversation list suggests one in a line with "Back up" and
"Not now"; it blocks nothing and "Not now" puts it away on that device.

## Restoring

- **On first run** ("Restore from a backup" under Start): file, passphrase, Restore.
- **In Settings**: the same, and because it replaces the identity on the device, the person
  first types the word "replace".

The file is decrypted and checked in full before anything on the device is touched; a wrong
passphrase or a bad file changes nothing. Then **every row the engine keeps is replaced in one
transaction** (identity, sessions, contacts, contact state, messages, queue, settings), the
storage refuses any further write from an engine still running on the old state, and the page
reloads into the restored identity. The storage keys and a passphrase lock on the device stay
as they were.

### One identity, one device

A backup restored on a second device while the first still runs gives two devices one identity.
The relay registers one connection per identity, so each device's registration takes the
other's place and each sees itself disconnected in turn; and the two would fork every ratchet.
The app says so in one sentence where a backup is made and where it is restored: "Use a backup
on one device at a time: two devices with the same identity keep cutting each other off."
Nothing enforces it.

### Sessions in a backup go stale

A Double Ratchet session moves forward every time either side sends, and every new connection
between two contacts sends a channel-binding envelope each way. So the sessions in a backup
match the contact's device only if nothing at all passed between the two since the backup was
made, which in practice means: a backup restored right away (a browser reset, a move to a new
device the same day with the old one switched off). Otherwise the restored device can usually
still read what the contact sends, but the contact cannot read what the restored device sends,
its end-to-end check of the connection fails, and it closes the connection.

**Decision: sessions are included, and a restore marks every contact.** Including them costs
nothing when they are stale and saves re-adding every contact when they are not. Each restored
contact row carries `restoredMs`. For a marked contact:

- the conversation says, under its header: "{name} came back from a backup. If this
  conversation does not connect, add each other again.";
- if the connection fails its check (the line reads "Blocked for your safety"), the panel says
  what happened instead of the general explanation: "This conversation no longer matches
  {name}'s device. Your backup is older than your last conversation with {name}, so the two
  devices cannot read each other. Remove this contact and add each other again." with
  "Remove contact";
- the mark is removed once a verified connection to the contact has stayed open for 10 seconds
  (`RESTORED_PROVEN_MS`: a contact that could not read our binding closes the connection at
  once, so a connection that lasts is the proof), or when the contact is added again.

The other person's device, which restored nothing, sees the general "This connection did not
pass its security check" panel; its explanation now ends with "This also happens after one of
you restored an older backup. If it keeps failing, remove this contact and add each other
again." Neither side is left with silence.

Queued messages that came back with a history stay queued and go out once a line opens.

## Not in version 1

- No desktop reader or writer: the desktop app keeps its data in SQLCipher and has no import
  of this file yet. The format is specified so that it can.
- No partial restore (contacts only, say), and no merge: a restore replaces.
- No scheduled or automatic backups: making one is always the person's act.
