# Web port: the engine

`web/src/engine` is the UI-free core of the web client: the TypeScript counterpart of
`crates/parolnet-app`. Commands go in, events and immutable snapshots come out. It imports no
DOM global and no framework; every platform dependency is injected. It follows the
[porting inventory](inventory.md), and where the old PWA disagreed with the specs or the native
core it follows the specs and the native core (the list is in "Deviations from the old PWA").

Tests live in `web/tests/engine` ("Running the tests" below). How the app's screens sit on
this engine is in [app.md](app.md).

## Modules

| File | What it holds |
|---|---|
| `mod.ts` | The public surface. `test-hooks.ts` is deliberately not re-exported |
| `types.ts` | The vocabulary shared with the desktop: `PathState`, `DeliveryState`, `RelayState`, `CallState`, `CallEnd`, `Contact`, `ContactView`, `ChatMessage`, `Snapshot`, `AppEvent`, `TurnSettings`, `EngineError` |
| `platform.ts` | The injected interfaces: `WasmApi`, `Storage`, `SocketFactory`, `PeerConnectionFactory`, `Clock`, `Random`, `Fetch`, `Sha256`, `Logger`, `MediaDevices`, `InstanceLock` |
| `engine.ts` | `Engine`: identity, pairing, connections, channel binding, chat and queue, contacts, settings |
| `calls.ts` | 1:1 calls on their own `RTCPeerConnection` |
| `relay.ts` | The relay WebSocket client (in the page) and the signaling budget |
| `ice.ts` | STUN from the app's own relay, the user's TURN settings, the connection configuration |
| `reconnect.ts` | The soft-offline probe schedule (a port of `reconnect.rs`) |
| `wire.ts` | Relay frames, data-channel frames, call signals, the initiator rule |
| `bytes.ts` | Hex, UTF-8, and the CBOR reader for a pairing code's public fields and an envelope's `source_hint` |
| `storage.ts` | The schema, and the two places rows are kept as given (`RawStorage`): `IdbStorage`, `MemoryStorage` |
| `vault.ts` | Encryption at rest: the storage keys, the sealed form of a row, the passphrase lock ([at-rest.md](at-rest.md)) |
| `sealed-storage.ts` | `SealedStorage`: the engine's `Storage` over a `RawStorage`, sealing every row |
| `backup.ts` | The backup file and what a restored device starts with ([backup.md](backup.md)) |
| `browser.ts` | The browser implementations of the platform interfaces. The only module that touches browser globals, each at call time |
| `test-hooks.ts` | The optional `__parolnetTest` contract ([interop.md](interop.md) §11.4) |

## Starting it

```ts
import { attachLifecycle, browserPlatform, Engine, sameOriginRelayUrl, wasmApi } from "./engine/mod.ts";

const wasm = wasmApi(glue); // the wasm-bindgen module, after `await glue.default(...)`
const platform = await browserPlatform({ wasm });
const engine = await Engine.start(platform, { relayUrl: sameOriginRelayUrl() });
const stop = engine.subscribe((event) => { /* update the store */ });
attachLifecycle(engine); // reconnect on `online` and when the page is shown again
```

`Engine.start` throws `EngineError("Busy")` when another tab already runs an engine on the same
database (Web Locks): two engines would fork the ratchets. One wasm instance holds one identity,
so one engine needs a wasm instance of its own.

In a test build only: `import { installTestHooks } from "./engine/test-hooks.ts"`.

## API

All ids are 64 lower-case hex characters. Every rejection is an `EngineError` with a `code`;
messages contain no key material, session state, plaintext or TURN credential.

```ts
class Engine {
  static start(platform: Platform, config: EngineConfig): Promise<Engine>;
  readonly peerId: string;
  readonly publicKey: string;

  subscribe(listener: (event: AppEvent) => void): () => void;
  snapshot(): Snapshot; // synchronous, immutable

  // Pairing (PNP-003)
  createPairingCode(): Promise<PairingCode>; // { code, expiresAtMs }
  cancelPairing(): Promise<void>;
  pairWithCode(code: string, how: { via: "scan" | "paste" }): Promise<Contact>;

  // Chat
  sendText(peerId: string, text: string): Promise<ChatMessage>; // state "Sent" or "Queued"
  takeBack(messageId: number): Promise<void>; // a queued message only
  editQueued(messageId: number, text: string): Promise<ChatMessage>;
  messages(peerId: string): Promise<ChatMessage[]>; // oldest first
  markRead(peerId: string): Promise<void>;

  // Contacts
  renameContact(peerId: string, name: string): Promise<Contact>; // local only
  removeContact(peerId: string): Promise<void>; // with its history, queue and session
  setVerification(peerId: string, verified: "compared" | "no"): Promise<Contact>;
  safetyNumber(peerId: string): string | null; // PNP-002 §10, 60 digits
  connect(peerId: string): void; // the user opened the chat or pressed retry

  // Calls
  startCall(peerId: string, video: boolean): Promise<CallInfo>;
  acceptCall(callId: string): Promise<CallInfo>;
  rejectCall(callId: string): Promise<void>;
  hangup(callId: string): Promise<void>;
  callMedia(callId: string): { local: MediaStream | null; remote: MediaStream | null } | null;
  setMuted(callId: string, muted: boolean): void;
  setCameraOff(callId: string, off: boolean): void;
  replaceCamera(callId: string, stream: MediaStream): Promise<void>; // another camera

  // Settings
  turnSettings(): Promise<TurnSettings | null>;
  setTurnSettings(settings: TurnSettings | null): Promise<void>;
  iceServers(): IceServer[]; // what connections use, without the credential
  networkChanged(): void;

  // Lifecycle
  shutdown(): Promise<void>;
  wipe(): Promise<void>; // "delete all data on this device"
}

interface EngineConfig {
  relayUrl: string; // ws:// or wss://
  stunServers?: string[]; // omitted: the relay's own /turn-credentials; []: host only
  reconnect?: ReconnectConfig;
  defaultContactName?: string;
}
```

`EngineError.code`: `Storage`, `InvalidCode`, `CodeExpired`, `OwnCode`, `NoSession`,
`UnknownContact`, `Crypto`, `Config`, `NotConnected`, `Busy`, `UnknownCall`, `UnknownMessage`,
`NotQueued`, `TooLong`, `Media`, `Stopped`.

### Events

The native kinds, with the same meaning: `Relay`, `ContactAdded`, `ContactUpdated`, `Path`,
`Message`, `MessageState`, `Notice`, `Call`. Web-only additions: `MessageEdited`,
`MessageRemoved`, `Pairing` (the window opened or closed), `ContactActivity` (unread count, last
activity), `CallMedia` (a call's local or remote stream changed).

`sendText` emits one `Message` with the final state (`Sent` or `Queued`); a queued message later
gets `MessageState` (`Sent` or `Dropped`).

`ContactRemoved` (web-only) follows `removeContact`. A `Notice` carries a `code` beside its
English `text`, so a UI can use its own words: `Storage` (a write to this device failed),
`BindingFailed` (with `peerId`: a connection failed its end-to-end check and was closed),
`TurnUnusable` (relay-only is on and the user's TURN server gave no path).

A call that fails because the microphone or camera could not be used ends with
`{ kind: "Failed", reason: CALL_FAILED_MEDIA }` (exported by `calls.ts`), so a UI can say that
instead of "could not connect".

### What a UI store must match

- `PathState`, `DeliveryState`, `RelayState { kind, profile | reason }`, `CallState { kind, end }`
  exactly as in `types.ts`. `Direct` means open **and** verified.
- `CallEnd` is `{ kind: "HungUp" | "RemoteHungUp" | "Declined" | "Rejected" | "NoAnswer" } |
  { kind: "Failed", reason }` (the native names; "the contact declined" is `Rejected`).
- On `Call` with `Ended`, and on `CallMedia` for a stream `callMedia()` no longer returns, the
  store detaches every media element playing the call's streams before the listener returns:
  the engine releases the media right after ("The end of a call").
- `Contact` has `verified: "in-person" | "compared" | "no"`, `identityKey`, `addedMs`. Path, queued
  count, unread count and last activity are on `ContactView`, not on the contact.
- `ChatMessage.text` is a string (text only in this phase); `id` is a number, increasing.
- `takeBack(messageId)` and `editQueued(messageId, text)` take the message id alone, are
  asynchronous, and reject with `NotQueued` once the message has left the device.
- Adding a contact is `pairWithCode(code, { via })` and returns the contact; the name comes later
  through `renameContact`. The presenter side gets its contact through `ContactAdded`.
- "You are offline" is `snapshot().relay.kind !== "Registered"`.
- A pairing code has an expiry (`PairingCode.expiresAtMs`). Where the core exports the
  pending bootstrap (`export_pending_bootstrap`), the code and that blob are stored, so after a
  reload within its lifetime the same code is shown and still works; otherwise there is none
  after a reload (`snapshot().pairing === null`) and the UI asks for a new one. Expiry,
  `cancelPairing` and use clear it from wasm memory (`clear_pending_bootstrap`) and storage.

## Storage schema

Database `parolnet-web`, version 2. Nothing is migrated from the old PWA's `parolnet` database.

This is the schema the engine sees through `Storage`. In the browser every row is sealed
before it is stored (`SealedStorage`), text keys are replaced by tags, and a `vault` store
(new in version 2) holds the keys: [at-rest.md](at-rest.md) has the stored form and the
migration from version 1.

| Store | Key | Index | Row |
|---|---|---|---|
| `identity` | `id` = `"self"` | | `{ id, secretHex }` |
| `identity` | `id` = `"pairing"` | | `{ id, code, expiresAtMs, pendingHex }`: the code on screen and its pending bootstrap (secret, kept like `secretHex`; deleted on use, expiry, cancel and wipe) |
| `sessions` | `id` = `"blob"` | | `{ id, json }`: the wasm `export_sessions()` output, one row |
| `contacts` | `peerId` | | `{ peerId, name, identityKey, addedMs, verified, verifiedMs, restoredMs? }` (`restoredMs`: it came out of a backup and no connection has proven its session since) |
| `messages` | `id` (number, allocated by the engine) | `peerId` | `{ id, peerId, direction, text, timestampMs, state, editedMs? }` |
| `outbox` | `id` (number, increasing) | `peerId` | `{ id, peerId, kind: "text", messageId, text, createdMs }` or `{ id, peerId, kind: "bootstrap", envelopeHex, createdMs }` |
| `contactState` | `peerId` | | `{ peerId, lastActivityMs, unread }` |
| `settings` | `key` | | `{ key, value }`; `turn` holds the user's TURN settings |

Differences from the schema recommended in [storage.md](storage.md) §8.7: keys of `messages` and
`outbox` are allocated by the engine instead of auto-incremented (so one write can refer to a
row it creates); the index is `peerId` alone (rows come back in key order, which is send order);
`outbox` holds plaintext, not envelopes (next section); contacts carry `verified`.

Every state change is one transaction (`Storage.write`): a received message and the ratchet
state that decrypted it are saved together, before anything is shown.

`wipe()` deletes the database, the storage keys with it, and clears the wasm state.

## Design decisions

**The mailbox.** One serial queue runs every command, relay frame, WebRTC callback and timer, so
the logic reads like the native actor. SDP work and media capture run outside it and re-enter it.

**Queued messages are kept as text and encrypted for the contact when they are flushed.** The old PWA and
the native core queue ready-made envelopes; the ratchet has then already advanced, so a queued
message can be neither edited nor removed without leaving a gap or re-encrypting out of order.
Here a queued text is an `outbox` row holding the text. `editQueued` and `takeBack` only touch
storage. This adds no exposure: the same text is in `messages` anyway, and both rows are
sealed at rest like every other ([at-rest.md](at-rest.md)). A side effect: queued
texts survive a re-pairing (the native core drops them, because its queued envelopes belong to
the old session).

**Save the ratchet before sending.** A flush encrypts a chunk, writes the advanced sessions, and
only then puts the envelopes on the channel; afterwards it marks them sent. A crash can skip a
message number or deliver a message twice; it can never reuse a message key. The old PWA wrote
the sessions fire-and-forget after sending.

**A failed decrypt is rolled back.** The core's `DoubleRatchetSession::decrypt` advances the
ratchet before it authenticates ("Defects found"). The engine keeps the sessions as last saved
and re-imports them after any decrypt that fails, and after the trial decrypt of a bootstrap
envelope (which tries every other session first).

**Only the channel's own peer.** An envelope is decrypted with the session of the peer the
channel was signalled for (`envelope_decode`), never by trial over all sessions. Before the
binding verifies, only the bootstrap envelope (0x03) and the binding (0x14) are acted on;
anything else is dropped. `gossip` frames are ignored.

**The presenter checks the scanner's key.** A bootstrap envelope is tried only when the SHA-256 of
its cleartext `source_hint` (the scanner's identity key) is the PeerId the channel was signalled
with, as the desktop does. The engine reads the hint with its own small CBOR reader, because
`trial_decrypt` reports only the resulting PeerId.

**Pairing window = the code's lifetime.** The window closes at `ts + 1800 s` of the code itself
(the timestamp the scanner will check), when someone pairs with it, or on `cancelPairing`.

**Relay keepalive.** Ping every 20 s; no frame for 40 s closes the socket with code 4000 and
reconnects (1 s doubling to 30 s, up to 25 % jitter, reset only by `registered`). After the page
was suspended (timers throttled) a catch-up ping goes out first and the relay gets 5 s to answer.
Exactly two `register` frames per socket.

**Signaling budget.** Outgoing `rtc_*` frames are counted against 54 a minute, 216 an hour and 58
per recipient per 10 minutes (the relay allows 60 / 240 / 64). New offers are staggered at 3 per
10 s. `rate_limited` pauses new offers for 60 s × 2^hits (exponent capped at 4, at most 10 min;
the count resets on `registered`).

**ICE.** STUN comes from `GET <the relay's origin>/turn-credentials`, `stun:` URIs only, and from
nowhere else. TURN is only ever the user's own server; `relayOnly` sets
`iceTransportPolicy: "relay"`, and a relay-only description without a candidate is never sent
(`NoDirectPath` plus a notice). Offers and answers are non-trickle (gathering is capped at 3 s;
at most 4 late candidates follow as `rtc_ice`).

**Removing a contact.** One transaction deletes the contact, its state, its messages, its queue
and its session from the saved sessions; a call with it is hung up first and its connection
closed. The session leaves wasm memory through `remove_session`, and a code being shown stays.
On an older core without it the engine reloads the identity and imports the remaining
sessions, which drops the pending bootstrap, so a code being shown is closed (`Pairing` with
`null`); the engine tests cover both. The contact is not told.

**Switching cameras.** `replaceCamera` swaps the video sender's track (`replaceTrack`, no
renegotiation) and keeps the microphone. `CallMedia` announces the new capture first; the old
video track is stopped in a later task (as at the end of a call, below). The engine owns the
new stream from then on and stops it when the call ends; a refused switch stops the offered
stream.

**The end of a call.** In this order: the call is forgotten, its timers cancelled and the
connection's handlers removed; `Call` with `Ended` is emitted; then, in tasks of their own on
the platform's clock (`setTimeout(…, 0)`, one after the other, also after `shutdown`), the
capture's tracks are stopped and the connection is closed. Each step is guarded and nothing
awaits it, so a step that throws, or a browser call that never returns, keeps neither the
ended state nor the next call waiting; a call started in between is not touched. A line is
logged before each browser call (`[Call] <id> releasing the capture`, `closing the media
connection`, `released`), so a page that freezes there names the call in its last line.
The order is not a matter of taste: in WebKit on Linux (GStreamer) a track that ends while a
media element still plays its stream can block the main thread for good inside
`RTCPeerConnection.close()` or `MediaStreamTrack.stop()` ("Defects found" below,
`web/tests/e2e/repro`). **A listener of `Ended` must stop playing the call's streams before
it returns** (`srcObject = null` on every element); the same holds for a stream that
`CallMedia` no longer lists.

**Calls.** Per-call `RTCPeerConnection`; `offer` / `answer` carry the SDP with its candidates;
incoming `ice` is accepted, also before the user accepts; every signal is matched by `callId` and
by peer; a second call gets `reject`; `reject` and `hangup` tear down both sides; ring 60 s,
connect 30 s. A call is Active when `connectionState` is "connected" or, where senders
expose their `RTCDtlsTransport`, when every transport still in use is connected (the spec's
rule, applied by the engine): Linux WebKit (GStreamer) leaves the offerer's `connectionState`
at "connecting" after the answer bundles the media lines and the extra transport closes.
`bundlePolicy: "max-bundle"` would avoid the extra transport, but Firefox then offers
bundle-only lines, which the desktop engine rejects. Capture goes through the injected `MediaDevices` when the call starts or is
accepted; the engine stops the tracks it obtained when the call ends ("The end of a call").

**Timers and limits.** As the native core: answer 20 s, connect 45 s, offer fallback 10 s + up to
2 s, disconnect grace 5 s, binding 20 s, retry 5 s doubling to 5 min (8 attempts), probes 15 s
doubling to 5 min (waited-for) or 15 min (idle) under a 12 + 1/min budget; queue 30 days, 500
per contact, 2000 in total.

**A contact restored from a backup.** Its row carries `restoredMs` ([backup.md](backup.md),
"Sessions in a backup go stale"). The engine removes the mark when a verified connection to
the contact is still open `RESTORED_PROVEN_MS` (10 s) after its binding verified, and when
the contact is paired with again. Verifying their binding alone is not proof: a stale
session usually still reads what they send, while they cannot read what we send and close
the connection at once.

## Deviations from the old PWA

| Old PWA | Engine | Reference |
|---|---|---|
| Relay socket in the service worker | In the page | inventory §9 |
| Extra unauthenticated `register` at boot | Exactly two per socket | PNP-001-MUST-075 |
| Fallback `https://parol.social/turn-credentials` | Removed: only the app's own relay is ever asked | PNP-001-MUST-082, `ice.rs` |
| STUN and TURN taken from a `relay` profile answer | `stun:` only, whatever the profile | `ice.rs:43-58` |
| `turns:`, arbitrary `RTCIceServer` JSON as "own servers" | One `turn:` server (UDP or TCP), username, password, `relayOnly` | `lib.rs` `TurnSettings` |
| `trial_decrypt` for every envelope, on any channel | The channel peer's session only | `engine.rs:1850-1860`, inventory §12.1 #3 |
| Content accepted before the binding | Dropped until verified | PNP-001-MUST-081, SHOULD-018 |
| Gossip broadcast and `gossip` frames | Not sent, ignored | inventory §12.1 #2, `wire.rs:230-237` |
| Contact row rewritten on every incoming chat | Upsert that never overwrites a name, key or verification | inventory §12.1 #1 |
| Presenter stores `source_hint` (actually the PeerId) as the identity key | Stores the real key, read from the envelope header | PNP-001-MUST-063 |
| No check of the bootstrap key against the signalling peer | SHA-256(source_hint) must be the channel's peer | `engine.rs:1862-1866` |
| Pairing window 30 min or 24 h, any render replaces the code | The code's own lifetime; a new code only on request; closed once used | inventory §12.1 #8 |
| Any data channel label accepted | Only `parolnet`, only one | `engine.rs:1516` |
| Queue of envelopes; no delivery state | Plaintext outbox; `Queued` / `Sent` / `Dropped`; edit and take-back | this document |
| Queue limit 50 MiB of payload | The native limits (30 d, 500, 2000) | `store.rs:34-36` |
| Sessions saved fire-and-forget after sending | Saved before sending, in one transaction with what they decrypted | inventory §2.1 |
| `rate_limited` count never resets | Resets on `registered`, exponent capped at 4 | `engine.rs:1118-1125` |
| No re-probing after `peer_offline` | The native schedule | PNP-001-SHOULD-019, `reconnect.rs` |
| Calls trickle; `ice` before accept dropped; `reject` only a toast; `callId` ignored | Non-trickle; `ice` buffered; teardown on both sides; `callId` and peer checked; busy → `reject` | inventory §12.1 #4-6, `engine.rs:2302-2370` |
| `navigator.storage.persist()` at boot | Never called by the engine (`requestPersistentStorage()` for the UI): Firefox answers with a prompt | found in the Firefox run |
| Decoy, duress, cover traffic, tokens, onion, telemetry, relay `message`, groups, identity rotation | Not ported | inventory DROP / DEFER |
| Files as PNP-007 §7 envelopes of 4096-byte chunks (never interoperable) | PNP-010: see "File transfer" below | `specs/PNP-010-file-transfer.md` |

One deviation from the **native core**: the web client keeps the spec's keepalive (20 s / 40 s);
the desktop pings every 25 s and has no silence timeout (inventory §12.1 #10).

## wasm API gaps

The engine works with today's `crates/parolnet-wasm`, but these would make it simpler or safer:

1. ~~Export and import of the pending bootstrap.~~ Now `export_pending_bootstrap` /
   `import_pending_bootstrap`; the engine stores the blob with the code (feature-detected).
2. ~~`clear_pending_bootstrap()`.~~ Now in the core; the engine calls it on expiry, cancel and
   use.
3. **`bootstrap_decrypt(envelope, expected_peer_id)`**: the §5.3.1 fallback alone, bound to one
   peer, returning the scanner's identity key. Today the only entry is `trial_decrypt`, which
   first tries every existing session (and damages them, see below) and returns the PeerId where
   `source_hint` should be the key. The engine works around all three.
4. **A transactional decrypt** in the core (see "Defects found"). The engine's rollback through
   `import_sessions` would then be unnecessary.
5. ~~`remove_session(peer_id)`.~~ Now in the core; the engine uses it (feature-detected).
6. **Per-session export** (`export_session(peer_id)`): the engine re-exports every session after
   every envelope.
7. `envelope_decode` is marked "unused" in the inventory; the engine depends on it.
8. ~~A memory-hard function for passphrases.~~ Now `argon2id` in the core
   (`parolnet_crypto::kdf::argon2id`); the passphrase lock and the backup file use it.

Editing queued messages needed no wasm change (plaintext outbox).

## Defects found

**The Double Ratchet advances before it authenticates** (`crates/parolnet-crypto/src/double_ratchet.rs:428-476`).
`decrypt` removes skipped keys, runs `dh_ratchet` on the header's ratchet key and steps the chain
before the AEAD check, and nothing is undone when that check fails. One envelope that does not
decrypt, carrying a ratchet key the session has not seen, leaves the session unable to decrypt
or encrypt for its peer again. Consequences:

- `parolnet-wasm` `trial_decrypt` (`lib.rs:506-578`) runs `decrypt_for_peer` over **every**
  session, so each incoming envelope from contact B damages the session with contact A when A's
  session is tried first. The old PWA decrypts everything this way.
- The native core calls the same `decrypt_for_peer` for whatever arrives on a contact's data
  channel, also before the binding verifies (`engine.rs:1855-1859`). By reading the code, a
  party that can open a data channel under a contact's PeerId (a relay can stage the
  signalling) could end that session with one envelope, and the next `persist_sessions` saves
  the damage. This was not run against the native binary.

Evidence (wasm, which wraps the same core): with a session between A and B working both ways,
`envelope_decode(B, <an envelope from a third device>)` on A throws, and afterwards neither A
nor B can decrypt the other's next message. `web/tests/engine/engine_chat_test.ts`, "sessions:
pairing a new contact, or an undecryptable envelope, leaves other sessions intact", fails
without the engine's rollback. The fix belongs in `parolnet-crypto`: decrypt on a copy of the
session and commit on success.

**WebKit on Linux: a track that ends while an element plays it can freeze the page.** In
the GStreamer ports (WPE, WebKitGTK; seen in the WPE build of Playwright 1.65.1),
`RTCPeerConnection.close()` and `MediaStreamTrack.stop()` sometimes never return when a
`<video>` is still playing the stream whose track they end: the main thread posts a message
on the element's playback pipeline, the playback bin deactivates a pad synchronously, and
that waits for the stream lock of a streaming thread that is itself waiting in a sink. The
page is dead from then on. `web/tests/e2e/repro` reproduces it with no app code (11 of 30
pages, three calls each, on a busy machine) and shows that it does not happen when the
elements are detached first (0 of 30). It was the cause of the WebKit call flow failing in CI
at hang-up: with the engine closing the connection before the screen had let go of the
streams, the flow froze in 6 of 36 runs under load; the page's last line was the one before
`pc.close()`. The engine now publishes the end first and releases afterwards ("The end of a
call"): in the 156 runs of the same flow on the final code no page froze at hang-up (153
passed; the other 3 are the next paragraph). Not reported upstream yet.

**WebKit on Linux: detaching a stream right after its camera track was switched off can
freeze the page too.** No track ends here. The main thread is inside a state change of the
element's pipeline, waiting on a condition inside WebKit, while a streaming thread of the
capture is in an object's destruction, also waiting inside WebKit (`web/tests/e2e/repro`,
`camera-off`). The engine has no part in it: it is what the call screen does at "Turn camera
off". In those 156 runs it froze the page of the person who pressed the button 3 times. The
app now detaches the self view before the track is switched off instead of after, which does
not freeze (app.md, "Browsers"; the numbers are in `web/tests/e2e/repro/README.md`).

## Running the tests

The engine's tests are part of the web app's tooling (`web/deno.json`). From `web/`:

```sh
denext task build-wasm     # crates/parolnet-wasm into public/wasm and .wasm-pkg (once)
denext task test:engine    # unit tests: real wasm, fake socket / peer connection / clock
denext task check && denext task lint && denext task fmt:check   # the app and the engine

# The engine alone in real browsers, against the real relay and the native bot:
cargo build -p parolnet-relay-server --bin parolnet-relay -p parolnet-app --example bot
denext task engine:e2e:build
(cd tests/engine/e2e && npm ci && npx playwright install chromium firefox)
E2E_BROWSER=chromium node tests/engine/e2e/run.mjs   # or firefox; webkit in the Playwright Linux image
```

The unit tests run each engine over its own wasm instance, so the crypto, the pairing code and
the channel binding in them are real. `e2e/run.mjs` documents its scenarios and environment
variables; it fails if any request leaves `127.0.0.1`. CI runs the unit tests (job `web`); the
scenarios of `e2e/run.mjs` are covered there through the app instead: `web/tests/e2e/real.flows.ts`
(web ↔ web) and `apps/desktop/interop/pwa-interop.mjs` with `INTEROP_APP=web` (web ↔ desktop),
both in job `pwa-interop`.

## File transfer (PNP-010)

`transfers.ts` and `files.ts`, with `crates/parolnet-app/src/engine/transfers.rs` and
`transfer.rs` as the reference; everything that decides what is valid or touches a key is in the
wasm core (`crates/parolnet-wasm/src/transfer.rs` over `crates/parolnet-transfer`).

- **API**: `offerFile(peerId, file)` (a browser `File`; it is read once for its SHA-256 before
  the offer exists, outside the mailbox), `acceptTransfer`, `declineTransfer`, `cancelTransfer`,
  `transfers(peerId?)`, `transferFile(id)` (a received, complete file as a `Blob` over what is
  stored), `removeTransfer(id)`, `receivedFilesPersist()`. Events: `Transfer` (every change, and
  progress at most five times a second) and `TransferRemoved`; notice code `Transfer` when
  something that arrived did not verify.
- **Control messages** are `FILE_TRANSFER` (0x15) envelopes on the verified channel. One that
  cannot go yet stays in the transfer's row as `pending` and is sealed and sent when the
  channel verifies (`TransferInfo.pending` is what a UI shows as "waiting on this device").
- **The record stream**: the receiver opens `pn-file/<id>` on the contact's connection after
  its accept has left, at most four at once. The engine now handles `ondatachannel` on both
  sides of a connection: the `parolnet` channel as before, a `pn-file/` channel the wasm core
  admits (an accepted transfer this device sends, a verified connection), anything else is
  closed. A channel's handlers are attached in the task that announces it (`adopt`), because
  the receiver's RESUME can arrive before the mailbox has looked at the channel.
- **Sending**: the picked `File` is read 1 MiB at a time, each record is sealed in wasm and
  sent; the loop pauses above 4 MiB of `bufferedAmount` and continues at 1 MiB
  (`bufferedamountlow`, with a look at the amount every 50 ms in case the event is missed).
- **Receiving**: each record's plaintext is sealed (`SealedFiles`, [at-rest.md](at-rest.md),
  "Received files") and written to a `FileStore` as segments of 256 records (16 MiB), each
  written once; a segment's records count as stored when it is closed, and the count is saved
  then. `transferFile` decrypts the segments into a `Blob`. `OpfsFileStore` (the origin
  private file system, when the browser lets a page use `createWritable`) keeps segments
  across a reload: the engine opens them, reads them back into the hash and asks for the next
  record; a segment that does not open (changed or cut short at rest) is dropped and the
  file starts over. `MemoryFileStore` (Blobs, of ciphertext) is the fallback: a reload starts
  that file over. `Platform.subtle` is the WebCrypto the sealing uses.
- **A reload of the sending page** loses the `File`, so its unfinished outgoing transfers are
  cancelled with reason `Unavailable` at the next start (PNP-010-MAY-001) and the contact is
  told when it is next reachable.
- **Storage**: one row per transfer in the `settings` store under `transfer:<id>` (no schema
  change): the offer with the file key until the transfer is over, the phase, the segment
  list, the pending control message, and for a file being received the key its stored
  segments are sealed with (`storeKey`). The row is sealed like every other. Received files
  stay in OPFS, sealed, until the transfer is removed or cancelled, its contact is removed,
  "delete all data", or a restore from a backup.
- **Not solved**: a page cannot slow a sender down. `RTCDataChannel` has no receive-side
  backpressure, so when the sender is faster than this device's storage (which now includes
  sealing each record) the unprocessed records wait in the page's memory. The protocol has
  no credit scheme for that yet.

## Not done in this phase

- No history trimming (the native core keeps 5000 messages per contact).
- Notifications are the app's (a tab in the background; no push).
- No automatic lock after a time of inactivity (the passphrase is asked for at start and
  after "Lock now").
- Groups, group files, identity rotation: deferred, as in the inventory.
