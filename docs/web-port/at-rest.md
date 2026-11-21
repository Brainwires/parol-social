# Web port: encryption at rest and the passphrase lock

What the web app keeps on a device (identity, sessions, contacts, history, queue, settings) is
encrypted before it reaches IndexedDB. This document is the design: the keys, the form of a
stored row, what stays readable, the optional passphrase, the migration from the plaintext
database of the first release, and what all of it does and does not protect against. The
backup file has its own document: [backup.md](backup.md).

Code: `web/src/engine/vault.ts` (keys, sealing, the lock), `sealed-storage.ts` (the engine's
`Storage` on top), `storage.ts` (IndexedDB and the in-memory stand-in, both of which keep rows
exactly as given). Tests: `web/tests/engine/vault_test.ts`, and in real browsers
`web/tests/e2e/real.flows.ts` ("at rest…", "locked and the passphrase forgotten…", "a database
of the earlier version…").

## What it protects, plainly

| Someone who… | Without a passphrase | With a passphrase |
|---|---|---|
| reads the database through the page's own exports, another origin, or a backup tool that copies IndexedDB rows as data | sees ciphertext; the key is an object that cannot be exported | sees ciphertext |
| copies the browser profile from the disk (a seized or stolen device, malware with file access, a disk image) | **partly protected, depending on the browser.** The key is in the same profile. Browsers store a non-extractable key's bytes in their own files, some of them wrapped with an operating-system secret, some not. Assume a determined attacker with the whole profile, and the login session where one is needed, can recover it | protected by the passphrase: the profile holds no key, only one wrapped under Argon2id of the passphrase. Its strength is the passphrase's strength |
| can open the browser on the unlocked device | opens ParolNet | is asked for the passphrase |
| runs script in the app's origin (a compromised server serving a changed app, an XSS, a malicious extension with page access) | **not protected.** Such script can use the key to decrypt everything, with or without a passphrase once the app is unlocked. The strict Content-Security-Policy and the service worker are the defences there, not this | not protected once unlocked; while locked, the script can still wait for the passphrase to be typed |
| has an old copy of the profile and later learns nothing new | cannot read rows written after a change of lock state: setting, changing or removing the passphrase makes new keys and seals every row again | the same |

Two more limits:

- **Deleted is not erased.** Browsers keep IndexedDB in log-structured files. After the
  migration, or after a change of keys, the old rows (plaintext, in the migration's case) can
  stay in those files until the browser compacts them. A page cannot force that. An identity
  that existed before this release was on the disk in plaintext for as long as it existed.
- **Memory.** JavaScript strings cannot be wiped: a passphrase typed into a field, a decrypted
  row, and the identity secret handed to the wasm core live until the garbage collector takes
  them. Buffers the code owns (stretched key bytes, unwrapped key bytes, padded plaintext) are
  overwritten after use.

The passphrase is what protects a seized device. Without it, encryption at rest is a
substantial obstacle to casual copying and nothing more, and the app's settings say so in
those words.

## Keys

```
no passphrase                              with a passphrase
─────────────                              ─────────────────
generateKey (browser)                      64 random bytes
  enc  AES-256-GCM   extractable: false      enc = bytes 0..31   imported, extractable: false
  mac  HMAC-SHA-256  extractable: false      mac = bytes 32..63  imported, extractable: false
        │                                          │
stored as CryptoKey objects                 stored only as AES-256-GCM( KEK, 64 bytes )
in the `vault` store                        KEK = Argon2id( NFKC(passphrase), salt )
```

- **`enc`** seals every row. **`mac`** turns every text key (a peer id, `"self"`, a setting's
  name) into an opaque tag, so the database's keys and its index say nothing.
- **Without a passphrase** both are made by `crypto.subtle.generateKey` with
  `extractable: false` and put into IndexedDB as `CryptoKey` objects (structured clone keeps
  them non-extractable). Their bytes never exist in script: not at creation, not at use.
- **With a passphrase** there is no key object in the database. The two keys are 64 random
  bytes that exist in script for the moment it takes to import them (non-extractable) and to
  wrap them, and again for a moment at each unlock; the buffer is overwritten afterwards. A
  non-extractable key cannot be wrapped, which is why setting a passphrase makes new keys
  rather than wrapping the ones the browser made.
- **Every change of lock state rotates both keys** (set, change, remove): every row is opened
  with the old keys, sealed with the new ones and written, together with the new keys row, in
  one transaction. The engine keeps running; the storage layer queues its reads and writes
  behind the change. Cost: the whole database is read and written once.
- **Nonces** are 12 random bytes per write. AES-GCM with random nonces is safe for about 2^32
  writes under one key; the most frequently written row (the sessions) is written once per
  message sent or received.

### The passphrase's key

| | |
|---|---|
| Function | Argon2id, version 0x13 (RFC 9106), no secret, no associated data |
| Memory | 64 MiB (`memoryKiB: 65536`) |
| Passes | 3 |
| Lanes | 1 (the wasm core runs on one thread) |
| Salt | 16 random bytes, new each time a passphrase is set or changed |
| Output | 32 bytes, imported as a non-extractable AES-256-GCM key |
| Input | the passphrase in Unicode NFKC, UTF-8. No trimming, no case folding |
| Minimum | 8 characters (after NFKC). The app recommends several unrelated words |

This is RFC 9106's second recommended setting (64 MiB, 3 passes) with one lane instead of
four. The parameters are stored with the wrapped keys and are part of their associated data,
so they can be raised later without breaking existing locks, and changing them on disk makes
the unlock fail rather than weaker. The implementation is RustCrypto's `argon2` in
`parolnet-crypto` (`kdf::argon2id`), exported from the wasm core; it is checked against
OpenSSL's Argon2id. PBKDF2 is not used anywhere. Measured in the flows (unlock, including the
start of the engine, on an Apple M-series machine): about 0.2 s in Chromium, 0.3 s in Firefox;
a phone will take a few times longer. The derivation runs on the main thread; the screen says
"Working" first. After the first use the wasm instance keeps the 64 MiB it grew by until the
page is closed.

Parameters read from the database or from a backup file are refused above 1 GiB of memory or
16 passes (in TypeScript and again in the Rust function), so a hostile file cannot make a
device exhaust itself.

### Wrong passphrases

A wrong passphrase fails the AES-GCM tag of the wrapped keys. The number of wrong tries in a
row is kept in the `vault` store (in the clear, with the time of the last one) and written
before each derivation starts, so closing the tab does not skip the count. From the third wrong
try on, the next try has to wait: 5 s, 10 s, 20 s, … doubling to 5 minutes. A clock set back
does not shorten the wait. The right passphrase resets the count.

This slows someone guessing at the device through the app. It does nothing against someone
with a copy of the database, who guesses offline at the cost of Argon2id per guess; that is
what the memory cost is for, and why the passphrase should be long.

**A forgotten passphrase cannot be recovered**, by anyone. The unlock screen offers the one
thing left: delete everything on this device (typed confirmation), after which a backup can be
restored if there is one. The app says this when the passphrase is set.

"Lock now" reloads the page: the keys exist only in the page's memory, so the next thing on
screen is the passphrase prompt. There is no automatic lock on a timer yet.

## Database layout

Database `parolnet-web`, **version 2**. Version 2 adds one object store, `vault`; the other
stores, their key paths and the `peerId` index are those of version 1
([engine.md](engine.md), "Storage schema").

### The `vault` store (key `id`), never sealed

| `id` | Row |
|---|---|
| `"keys"`, no passphrase | `{ id, format: 1, mode: "device", enc: CryptoKey, mac: CryptoKey }` |
| `"keys"`, passphrase | `{ id, format: 1, mode: "passphrase", kdf: { alg: "argon2id", version: 19, memoryKiB, passes, lanes }, salt: 16 bytes, nonce: 12 bytes, wrapped: 80 bytes }` |
| `"attempts"` | `{ id, failed, lastMs }`: wrong passphrases in a row; absent when there are none |

`wrapped` is AES-256-GCM over the 64 key bytes with the passphrase's key, the row's `nonce`,
and as associated data the UTF-8 of
`["parolnet-web-lock", 1, "argon2id", 19, memoryKiB, passes, lanes, "<salt hex>"]` (JSON, no
spaces).

A `format` this code does not know is refused: a database written by a newer app is never
rewritten by an older one.

### A sealed row (every other store)

```
{ <key column>: storedKey,      // the store's key path: id, peerId or key
  peerId: tag,                  // only in `messages` and `outbox`: the indexed column
  v: 1,
  n: 12 bytes,                  // nonce
  c: bytes }                    // AES-256-GCM ciphertext and tag
```

- **`storedKey`**: a numeric key (a message's or queue entry's id) is kept as it is, so order
  and "largest id" still work. A text key is replaced by its tag:
  the first 16 bytes, in hex, of `HMAC-SHA-256(mac, store ‖ 0x00 ‖ key)`. The store's name is
  part of the input, so the same contact has unrelated tags in `contacts`, `contactState`,
  `messages` and `outbox`.
- **Plaintext**: the whole row (key included) as JSON, UTF-8, padded with spaces to a multiple
  of 128 bytes. A `Uint8Array` inside a row is written as `{"$bytes": "<base64>"}`; anything
  else JSON cannot hold (a Map, a Blob, an ArrayBuffer) is refused at write time rather than
  stored mangled. Nothing is compressed.
- **Associated data**: the UTF-8 of `["parolnet-web-row", 1, "<store>", storedKey]`. A row
  moved to another key or another store, or put back from another database, does not decrypt.
- A row that does not decrypt is an error (`VaultError("Corrupt")`), never a missing row: the
  app refuses to start on a database that was tampered with rather than quietly lose part of it.

Rows come back to the engine sorted by their real keys, whatever order the tags sort in.

**Adding a store or an index** (file transfer will): add it to `KEY_PATHS` in `storage.ts`;
sealing covers it without further code. Rows must be JSON values plus `Uint8Array`. An index on
a column other than `peerId` needs that column tagged in `Sealer.seal` the way `peerId` is.

## What stays readable at rest

Everything a row holds is inside the ciphertext: names, peer ids, identity keys, message text,
timestamps, delivery state, the TURN password, the pairing blob, the sessions, the identity
secret. What a copy of the database still shows:

- the store names and **how many rows** each has: the number of contacts, of messages, of
  queued messages, whether a pairing code is pending (one row more in `identity`), how many
  settings are set;
- **message and queue ids** (small integers in the order things happened) and therefore the
  order of messages, but no times;
- **which messages belong to the same contact** (equal tags in the `messages` index), so the
  number of messages per contact, though not which contact, and not linkable to that contact's
  row in `contacts`;
- **the size of each row to the nearest 128 bytes**, so roughly how long a message is, and how
  large the sessions blob is (which grows with the number of contacts);
- whether a passphrase is set, its Argon2id parameters and salt, and the count and time of
  recent wrong tries;
- whatever the browser itself records about the database (file times, sizes).

Outside the database, in `localStorage` (preferences, never secrets): theme, language, chosen
camera, microphone and speaker ids, whether notifications were asked for, a custom address of
the app's server if one was set, and that the backup suggestion was dismissed.

## Migration from version 1 (plaintext)

The first start of this release on a device that ran the previous one finds the stores full of
plaintext rows and no `vault`. `Vault.open`:

1. Opening the database at version 2 creates the `vault` store. No row is touched in the
   upgrade (an upgrade transaction cannot wait for WebCrypto).
2. Reads every row of every store in one transaction.
3. Makes the two keys, seals every row in memory, and **opens each sealed row again and
   compares it with what went in** before accepting it.
4. Writes everything in **one transaction**: the plaintext rows under text keys are deleted,
   the sealed rows are put (numeric keys are overwritten in place), and the keys row is put.
   The transaction first checks that there is still no keys row and aborts otherwise, so two
   tabs starting at once cannot both migrate: the second finds the first one's keys and uses
   them.
5. Reads the stores back and checks that each has as many rows as before and that every one is
   sealed.

If the write fails, nothing changed: the database is still plaintext and the next start tries
again. If sealed rows are found without a keys row (which no code path produces), the app
refuses to start rather than write over them. A new database goes through the same code with
no rows: its keys are made at the first start, before "Start" is pressed; no identity is.

Nothing is asked of the person and nothing is shown: the app starts as before, a moment later
on a large history.

`Storage` (the engine's interface) is unchanged. `SealedStorage` implements it over
`RawStorage` (`IdbStorage` in the browser, `MemoryStorage` in tests); the engine's own tests
still run on `MemoryStorage` directly. "Delete all data on this device" deletes the database,
and the keys with it.
