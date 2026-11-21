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
| `storage.ts` | The schema, `IdbStorage`, `MemoryStorage` |
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
- `Contact` has `verified: "in-person" | "compared" | "no"`, `identityKey`, `addedMs`. Path, queued
  count, unread count and last activity are on `ContactView`, not on the contact.
- `ChatMessage.text` is a string (text only in this phase); `id` is a number, increasing.
- `takeBack(messageId)` and `editQueued(messageId, text)` take the message id alone, are
  asynchronous, and reject with `NotQueued` once the message has left the device.
- Adding a contact is `pairWithCode(code, { via })` and returns the contact; the name comes later
  through `renameContact`. The presenter side gets its contact through `ContactAdded`.
- "You are offline" is `snapshot().relay.kind !== "Registered"`.
- A pairing code has an expiry (`PairingCode.expiresAtMs`); after a reload there is none
  (`snapshot().pairing === null`) and the UI asks for a new one.

## Storage schema

Database `parolnet-web`, version 1. Nothing is migrated from the old PWA's `parolnet` database.

| Store | Key | Index | Row |
|---|---|---|---|
| `identity` | `id` = `"self"` | | `{ id, secretHex }` |
| `sessions` | `id` = `"blob"` | | `{ id, json }`: the wasm `export_sessions()` output, one row |
| `contacts` | `peerId` | | `{ peerId, name, identityKey, addedMs, verified, verifiedMs }` |
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

Nothing is encrypted at rest in this phase (the inventory's open question on the passphrase
store). The identity secret, the sessions and the TURN password are plain rows; `wipe()` deletes
the database and clears the wasm state.

## Design decisions

**The mailbox.** One serial queue runs every command, relay frame, WebRTC callback and timer, so
the logic reads like the native actor. SDP work and media capture run outside it and re-enter it.

**Queued messages are plaintext at rest and encrypted when they are flushed.** The old PWA and
the native core queue ready-made envelopes; the ratchet has then already advanced, so a queued
message can be neither edited nor removed without leaving a gap or re-encrypting out of order.
Here a queued text is an `outbox` row holding the text. `editQueued` and `takeBack` only touch
storage. This adds no exposure: the same text is in `messages` anyway. A side effect: queued
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
closed. The core has no call to drop one session from wasm memory ("wasm API gaps" #5), so
without `remove_session` the engine reloads the identity and imports the remaining sessions.
That drops the pending bootstrap, so a code being shown is closed (`Pairing` with `null`). The
contact is not told.

**Switching cameras.** `replaceCamera` swaps the video sender's track (`replaceTrack`, no
renegotiation), stops the old video track, and keeps the microphone. The engine owns the new
stream from then on and stops it when the call ends; a refused switch stops the offered
stream.

**Calls.** Per-call `RTCPeerConnection`; `offer` / `answer` carry the SDP with its candidates;
incoming `ice` is accepted, also before the user accepts; every signal is matched by `callId` and
by peer; a second call gets `reject`; `reject` and `hangup` tear down both sides; ring 60 s,
connect 30 s. Capture goes through the injected `MediaDevices` when the call starts or is
accepted; the engine stops the tracks it obtained when the call ends.

**Timers and limits.** As the native core: answer 20 s, connect 45 s, offer fallback 10 s + up to
2 s, disconnect grace 5 s, binding 20 s, retry 5 s doubling to 5 min (8 attempts), probes 15 s
doubling to 5 min (waited-for) or 15 min (idle) under a 12 + 1/min budget; queue 30 days, 500
per contact, 2000 in total.

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
| Decoy, duress, cover traffic, tokens, onion, telemetry, relay `message`, groups, files, identity rotation | Not ported | inventory DROP / DEFER |

One deviation from the **native core**: the web client keeps the spec's keepalive (20 s / 40 s);
the desktop pings every 25 s and has no silence timeout (inventory §12.1 #10).

## wasm API gaps

The engine works with today's `crates/parolnet-wasm`, but these would make it simpler or safer:

1. **Export and import of the pending bootstrap** (seed and ratchet secret), or a
   `pending_bootstrap_export()` / `pending_bootstrap_import()` pair. Without it a reload
   invalidates a shown code; the engine can only say so (`snapshot().pairing === null`).
2. **`clear_pending_bootstrap()`.** An expired or cancelled code stays armed in wasm memory until
   replaced; the engine merely stops calling `trial_decrypt`.
3. **`bootstrap_decrypt(envelope, expected_peer_id)`**: the §5.3.1 fallback alone, bound to one
   peer, returning the scanner's identity key. Today the only entry is `trial_decrypt`, which
   first tries every existing session (and damages them, see below) and returns the PeerId where
   `source_hint` should be the key. The engine works around all three.
4. **A transactional decrypt** in the core (see "Defects found"). The engine's rollback through
   `import_sessions` would then be unnecessary.
5. **`remove_session(peer_id)`**, for deleting a contact (not implemented in this phase).
6. **Per-session export** (`export_session(peer_id)`): the engine re-exports every session after
   every envelope.
7. `envelope_decode` is marked "unused" in the inventory; the engine depends on it.

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

## Not done in this phase

- No history trimming (the native core keeps 5000 messages per contact).
- No encryption at rest, no export / import (the inventory's open questions). Notifications
  are the app's (a tab in the background; no push).
- Groups, files, identity rotation: deferred, as in the inventory.
