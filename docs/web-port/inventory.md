# Web client porting inventory

What the current vanilla-JS PWA (`pwa/`) does, so that the TypeScript rewrite works with the
native client (`crates/parolnet-app`, the reference for current behaviour) and passes
`apps/desktop/interop/pwa-interop.mjs`. This is documentation only. Every claim cites
`file:line`. Unless marked otherwise:

- paths are relative to the repository root;
- PWA paths are as on `origin/master` `bd493e2`. `pwa/` and `crates/parolnet-wasm` are identical on
  `m1/slice3` (only `pwa/tests/e2e/README.md` differs);
- **[s3]** means a file as it is on `m1/slice3` (the interop driver and `docs/m1-desktop.md`);
- desktop-core references are to `crates/parolnet-app/src/` on master. `wire.rs`, `signaling.rs` and
  `call.rs` are byte-identical on `m1/slice3`; `engine.rs` and `ice.rs` differ only in TURN policy and
  offline re-probing.

Where the PWA and the desktop core disagree, this document says which one the spec supports and flags
it with **DEVIATION**.

| File | Sections |
|---|---|
| `inventory.md` (this file) | 1 Module map · 2 wasm API · 12 Risks, open questions, porting order |
| [`wire.md`](wire.md) | 3 Relay WebSocket · 4 Peer connection and data channel · 5 Message types · 6 Calls · 7 Pairing |
| [`storage.md`](storage.md) | 8 Storage · 9 Service worker · 10 Settings and i18n |
| [`interop.md`](interop.md) | 11 Interop contract and the proposed test-hook contract |

Dispositions:

- **PORT**: needed.
- **DROP**: removed by the product plan. That covers cover traffic, the VOPRF token pool, onion
  mode/circuits, telemetry, the decoy calculator and duress/panic code, relay store-and-forward
  `message` frames, relay-provided TURN, and gossip.
- **DEFER**: groups, group calls, files. For these the document records what exists.

---

## 1. Module map

Line counts come from `wc -l`. The interop driver needs the bundle output `pwa/app.js`, `pwa/sw.js` and
`pwa/pkg/parolnet_wasm_bg.wasm` (`pwa-interop.mjs:210-214` [s3]). The PWA is built with
`npm run build:wasm && npm run build` (root `package.json`). Note that `pwa/package.json` has no build
scripts; the bundling is done by esbuild, `src/boot.js` → `app.js` (`pwa/build.mjs:78-80`).

### 1.1 Page modules (`pwa/src/`, bundled into `app.js`)

| File | Lines | Owns | Exports used elsewhere | Disposition |
|---|---:|---|---|---|
| `boot.js` | 795 | WASM load and init order; identity restore/create; session restore; service-worker registration and SW message bus; SW inbox drain; relay watchdog; auto-lock; `window.*` exports for inline handlers | `attemptUnlock`, `drainSwInbox` | **PORT** the init order, identity and session restore (`boot.js:44-130`). **DROP** the SW relay bus, inbox drain, token fetch, onion, cover traffic, decoy and duress (`boot.js:151-307,318-379,415-642`) |
| `connection.js` | 638 | `connMgr` (postMessage proxy to the SW's relay socket); outbound cross-relay sockets; the sender queue (`pending_sends`); presence `watch`; discovery tick | `connMgr`, `queueMessage`, `flushMessageQueue`, `flushBootstrapQueue`, `hydratePendingSends`, `queuedCountFor`, `sendPresenceWatch`, `onRelayRegistered`, `requestDirectPath`, `sendToRelay`, `discoverPeers` | **PORT** the queue (`:312-525`), watch (`:539-581`) and signaling-only tick (`:610-631`); the relay socket moves into the page. **DROP** outbound relays (`:115-296`), `sendToRelay`/`sendRelay` and `/bootstrap` discovery (`:583-608`) |
| `webrtc.js` | 884 | Data-channel peer connections; initiator, glare and retry logic; pairing window; CHANNEL_BINDING; ICE-server config; user TURN settings | `rtcConnections`, `connectToPeer`, `hasDirectConnection`, `sendViaWebRTC`, `handleRTCOffer/Answer/Ice`, `setPeerOnline`, `noteSignalingRateLimited`, `refreshIceServersFromRelay`, `maybeSendChannelBinding`, `handleChannelBinding`, `openPairingWindow`, `waitForTurnReady`, `getRtcConfig`, `isRelayOnlyActive`, `waitForSendBuffer`, `seenGossipMessages`, `markGossipSeen` | **PORT** all of it except gossip (`:837-884`, and the gossip branch at `:590-601`, **DROP**) and the parol.social fallback (`:225,248`, **DROP**) |
| `messaging.js` | 1672 | Relay-frame dispatch; send routing; envelope encode; incoming trial-decrypt and msg-type dispatch; call-signal handling; groups; files; identity rotation | `handleRelayMessage`, `sendRawEnvelope`, `sendCallSignal`, `onIncomingMessage`, `persistSessions`, `dispatchByMsgType`, group/file UI functions | **PORT** `sendRawEnvelope`'s direct/queue routes (`:130-166`), `sendCallSignal` (`:271-289`), `handleRelayMessage` minus `message`/`queued` (`:299-392`), `onIncomingMessage` (`:1591-1672`), the chat/system/call/binding handlers (`:1318-1438`). **DROP** the token, onion and cross-relay routes (`:167-264`). **DEFER** groups (`:394-750,996-1119,1440-1482`) and files (`:752-936,1121-1261`). Identity rotation (`:1489-1558`): see §12 |
| `ui-chat.js` | 1180 | Contact list, chat view, send, call UI (getUserMedia, initiate/answer/hangup), QR render/scan, paste code, path banner | `loadContacts`, `openChat`, `sendMessage`, `appendMessage`, `initiateCall`, `answerIncomingCall`, `hangupCall`, `stopLocalMedia`, `stopCallTimer`, `clearNoAnswerTimer`, `renderBootstrapQR`, `connectViaPassphrase`, `showAddTab`, … | **PORT** the logic (send `:278-348`; calls `:442-702`; pairing `:872-974,976-1069,1094-1161`); the UI is rewritten. **DROP** the gossip broadcast in `sendMessage` (`:350-367`) and the relay-token branch (`:323-334`) |
| `call.js` | 371 | Per-call `RTCPeerConnection`: offer, answer, ICE, teardown, media watchdog | `startCallConnection`, `acceptCallConnection`, `completeCallConnection`, `addRemoteIce`, `teardownCallConnection`, `setCallStatus`, `startMediaWatchdog`, `hasCallConnection` | **PORT** |
| `relay-profile.js` | 245 | Pure policy: server profile, send-route choice, initiator rule, backoff, offer stagger, queue limits, watch list, TURN parsing | everything | **PORT** (pure, unit-tested); remove the `relay` branches |
| `safety-number.js` | 141 | PNP-002 §10 safety number and modal | `computeSafetyNumber`, `showSafetyNumberModal` | **PORT** the derivation, or call wasm `safety_number` (§2) |
| `db.js` | 237 | IndexedDB `parolnet` v7; encrypted-store wrappers | `dbGet/Put/GetAll/Delete/Clear/GetByIndex`, `*Raw`, `updateContactState`, `loadAllContactStates`, `ENCRYPTED_STORES` | **PORT** with a fresh schema (storage.md §8.7) |
| `state.js` | 45 | Shared mutable globals (`wasm`, current view/peer/call, streams) | setters | **PORT** as typed stores |
| `protocol-constants.js` | 78 | PNP-001 §3.4 msg-type codes | constants | **PORT** |
| `i18n.js` | 143 | Locale loading, `t()`, `data-i18n*` DOM application, locale detection | `t`, `initI18n`, `changeLanguage`, `applyToDOM`, `getCurrentLang`, `detectLocale` | **PORT** the catalogs and `detectLocale`; the mechanism depends on the framework |
| `settings.js` | 756 | Settings view, encryption setup, export/import, identity rotation, network section, cover traffic, onion, decoy, duress, panic | many | **PORT** encryption at rest, export/import and the language and TURN settings. **DROP** cover traffic (`:15-75`), onion (`:133-232`), relay directory (`:460-550`), duress (`:610-639`), decoy (`:641-655`), panic (`:751-756`) |
| `views.js` | 163 | `showView`; pairing window on add-contact; calculator | `showView`, `calcPress`, `loadPanicCode` | **PORT** `showView`'s side effects (`:11-36`). **DROP** the calculator and panic code (`:38-163`) |
| `utils.js` | 476 | Toasts, escaping, `formatTime/Size`, notifications, `safeEval`, `detectPlatform` | `showToast`, `showErrorToast`, `showLocalNotification`, `requestNotificationPermission`, `generateMsgId`, … | **PORT** notifications (`:458-476`). **DROP** `safeEval` (calculator) and `generateMsgId` (gossip) |
| `live-relay-handler.js` | 31 | Re-buffers undeliverable live SW frames | `handleLiveRelayMsg` | **DROP** (SW relay socket) |
| `cover-traffic.js` | 165 | PNP-006 decoys | `markRealSend`, start/stop | **DROP** |
| `token-pool.js` | 599 | VOPRF Privacy Pass tokens (`/tokens/issue`) | `acquireToken`, `spendOneToken`, `maybeRefill`, `requestBatch`, `dropTokenPoolFor` | **DROP** |
| `onion.js` | 287 | PNP-004 3-hop circuits over a page WebSocket | `enableOnion`, `disableOnion`, `isOnionActive`, `sendViaOnion` | **DROP** |
| `peer-relay-cache.js` | 492 | `/peers/lookup` home-relay cache (`peer_relay_cache` store) | `lookupHomeRelay` | **DROP** (federation) |
| `telemetry.js` | 66 | `POST /telemetry` (relay profile only) | `telemetry.track` | **DROP** |

### 1.2 Other files

| File | Lines | Owns | Disposition |
|---|---:|---|---|
| `pwa/relay-client.js` | 929 | Federation directory (`GET /directory`, CBOR, authority endorsements via wasm); `localStorage` directory cache; bridge relays in IDB `parolnet_settings` | **DROP**. The directory result is never used for the relay URL: `_currentRelayIndex` is never advanced (`connection.js:38,74`) |
| `pwa/crypto-store.js` | 217 | Optional passphrase encryption at rest (PBKDF2 + AES-GCM), duress slot | **PORT** the normal slot if at-rest encryption stays (§8.3). **DROP** duress (`:52-126,145-189`) |
| `pwa/data-export.js` | 93 | Encrypted export/import blob | **PORT** if backup stays (§8.5) |
| `pwa/sw.source.js` | 712 | Cache-first SW with SRI check; offline page; **the relay WebSocket**; inbox; push/notification click | **PORT** caching only (§9) |
| `pwa/index.html` | 531 | All views as hidden `<div class="view">`, inline `onclick` handlers | Rewritten. The ids the interop driver touches are listed in §11 |
| `pwa/kill-sw.html` | 61 | Unregisters SWs, clears caches, `localStorage` and every IDB database (panic/reset) | **DROP** as panic. A "reset app" path is optional |
| `pwa/network-config.js` | 13 | Generated federation constants (`BOOTSTRAP_RELAYS`, authority keys) | **DROP** |
| `pwa/qrcode.js` | 2297 | Kazuhiko Arase QR generator (MIT) | **PORT** (replace with an npm QR library) |
| `pwa/qrdecoder.js` | 10101 | jsQR (fallback when `BarcodeDetector` is absent, `ui-chat.js:811`) | **PORT** (an npm library) |
| `pwa/styles.css`, `calculator.css` | 1519, 284 | Styling | Rewritten / **DROP** |
| `pwa/build.mjs`, `build.sh` | 109, 203 | esbuild bundle, SW hash substitution, network config | Replaced by the new toolchain |
| `pwa/manifest.json`, `manifest-calculator.json` | 33, 18 | PWA manifests (calculator = decoy) | **PORT** the first; **DROP** the second |
| `pwa/lang/*.json` | 16 × 312 keys | Locale catalogs | **PORT** (§10.2) |

### 1.3 Port sizing

- **PORT**, protocol glue: about 3.0k lines. That is the PORT parts of `connection`, `webrtc`, `messaging`,
  `call`, `relay-profile`, `safety-number`, `db`, the relevant parts of `boot`, and the `ui-chat` logic.
- **DROP**: about 4.4k lines (`cover-traffic`, `token-pool`, `onion`, `peer-relay-cache`, `telemetry`,
  `live-relay-handler`, `relay-client`, the dropped halves of `boot`/`settings`/`views`/`messaging`, and
  the SW relay section).
- **DEFER**, groups and files in `messaging.js`: about 0.9k lines.

---

## 2. wasm API actually used

### 2.1 Init order and state

1. Load the module: `import('./pkg/parolnet_wasm.js')` then
   `wasm.default({module_or_path: './pkg/parolnet_wasm_bg.wasm?v=' + Date.now()})`
   (`boot.js:48-52`). `#[wasm_bindgen(start)] init()` installs the panic hook
   (`crates/parolnet-wasm/src/lib.rs:80-83`).
2. If at-rest encryption is set up but locked, stop at the unlock view (`boot.js:66-74`). After
   unlock, `onWasmReady()` runs again (`boot.js:366-371`).
3. Identity: read `settings/identity_secret` (3 s timeout) and call `initialize_from_key(hex)`
   (`boot.js:78-84`). If that fails, call `initialize()` and persist `export_secret_key()` under
   `settings/identity_secret` (`boot.js:90-108`). Set `window._peerId` (`boot.js:110`; the interop
   driver polls this, §11).
4. Sessions: `import_sessions(settings/sessions_blob)` (`boot.js:113-118`).
5. `get_peer_id()`, then `connMgr.registerPeer` (`boot.js:124-130`). `renderBootstrapQR()` calls
   `generate_qr_payload`, which creates a pending bootstrap (`boot.js:145`, `ui-chat.js:987`).
6. Relay: `relayClient.discover()` (DROP), then `connMgr.start()` (`boot.js:215-217`).

All state lives in one global `STATE` mutex (`lib.rs:54-77`):

| State | Persisted? |
|---|---|
| `client`: identity plus the Double Ratchet sessions | Identity and sessions are persisted by JS: the secret hex in `settings.identity_secret`; sessions as the `export_sessions()` JSON in `settings.sessions_blob` |
| `call_manager` | in memory only |
| `file_senders`, `file_receivers` | in memory only |
| `unlock_code_hash` (decoy) | **never persisted**: decoy mode does not survive a reload (`lib.rs:1597-1626`; `set_unlock_code` is only called from `settings.js:646`) |
| `pending_bootstrap` (seed + ratchet secret) | **never persisted**. A reload invalidates every shown QR code, and each `generate_qr_payload` replaces the previous one (`lib.rs:1662-1665`) |

Sessions are re-exported after every encrypt and decrypt:

- `persistSessions()` at `messaging.js:37-43`, called from `messaging.js:1641`, `ui-chat.js:312,888,950`
  and `webrtc.js:726`;
- the persist is fire-and-forget `dbPut`, so a crash between a ratchet step and the write can
  desynchronise the ratchet.

### 2.2 Exports the PWA calls

| Export | Arguments → return | Called at | Purpose | Disp. |
|---|---|---|---|---|
| `default` (init) | `{module_or_path}` | `boot.js:52` | load | PORT |
| `initialize` | `() → peerIdHex` | `boot.js:92` | new identity | PORT |
| `initialize_from_key` | `(secretHex32) → peerIdHex` | `boot.js:83`, `settings.js:403` | restore identity | PORT |
| `export_secret_key` | `() → secretHex32` | `boot.js:97`, `settings.js:330,686` | persist identity | PORT |
| `get_peer_id` | `() → hex \| ""` | `boot.js:125` | own PeerId | PORT |
| `get_public_key` | `() → Ed25519 pk hex` | `messaging.js:307`, `connection.js:173`, `ui-chat.js:935,984`, `token-pool.js:430` | relay auth; QR; bootstrap `source_hint` | PORT |
| `sign_bytes` | `(dataHex) → sigHex64` (signs the hex-decoded bytes) | `messaging.js:306`, `connection.js:172`, `token-pool.js:429` | relay challenge | PORT |
| `relay_name`, `sign_relay_register` | `(host, port) → "host:port"`; `(nonceHex, relayName) → sigHex64` over the register message of PNP-001 §10.7 | `messaging.js`, `connection.js`; `web/src/engine/engine.ts` | relay challenge since PNP-001 v0.17 (replaces `sign_bytes` there; `token-pool.js` still uses `sign_bytes`) | PORT |
| `envelope_encode` | `(destPeerHex, msgType u8, plaintext Uint8Array, nowSecs BigInt, sourceHintHex?) → envelopeHex` (bucket-padded, `lib.rs:403-450`) | `messaging.js:86,279,911`, `ui-chat.js:310,938`, `webrtc.js:723`, `cover-traffic.js:81` | every outgoing envelope | PORT |
| `trial_decrypt` | `(envelopeHex) → {source_peer_id, source_hint, msg_type, plaintext_hex, timestamp, bootstrapped}`; throws if nothing decrypts (`lib.rs:506-608`) | `messaging.js:1614` | every incoming envelope; presenter-side bootstrap (§7) | PORT |
| `has_session` | `(peerHex) → bool` | `messaging.js:54,70,80,272,894`, `ui-chat.js:302,493`, `webrtc.js:716` | gate sends and binding | PORT |
| `session_count` | `() → u32` | `messaging.js:1624` | classify decrypt failure as transient | PORT (or drop with the inbox) |
| `export_sessions` | `() → JSON string {peerHex: sessionHex} \| ""` | `messaging.js:40`, `ui-chat.js:31`, `settings.js:339` | persist | PORT |
| `import_sessions` | `(json) → count` | `boot.js:116`, `settings.js:413` | restore | PORT |
| `channel_binding_body` | `(localSdp, remoteSdp) → Uint8Array` (CBOR); throws on no fingerprint | `webrtc.js:721` | PNP-001 §10.5.1 | PORT |
| `channel_binding_verify` | `(body Uint8Array, localSdp, remoteSdp) → bool` | `webrtc.js:741` | PNP-001 §10.5.1 | PORT |
| `generate_qr_payload` | `(ikHex, relayHint\|null) → payloadHex`; sets `pending_bootstrap` | `ui-chat.js:987` | presenter code | PORT |
| `process_scanned_qr` | `(payloadHex) → {peer_id, their_identity_key, bootstrap_secret}`; creates the initiator session (`lib.rs:1684-1737`) | `ui-chat.js:882` | scanner | PORT |
| `start_call` | `(peerHex) → callIdHex` (16 bytes → 32 hex) | `ui-chat.js:481` | call id | PORT, or generate 16 random bytes in TS as the desktop does (`call.rs:234-239`) |
| `answer_call`, `hangup_call` | `(callIdHex)` | `ui-chat.js:579`; `574,593,632` | wasm call bookkeeping only; no wire effect | DROP (nothing reads that state) |
| `version` | `() → crate version` | `boot.js:134` | settings | PORT |
| `generate_identity` | `() → peerIdHex` (a throwaway keypair) | `ui-chat.js:1004` | QR fallback text; never meaningful | DROP |
| `parse_qr_payload` | `(hex) → payload` | `boot.js:693` | `?bootstrap=` URL param. Dead code: it runs on `DOMContentLoaded`, before `wasm` is set (`boot.js:674,689-698`) | DROP |
| `get_next_chunk` | `(fileIdHex) → {chunk_index, data_hex, is_last} \| null` | `messaging.js:902` | 1:1 file send. The JS treats the result as bytes (`chunk.length`, `Array.from(chunk)`), so each chunk is sent empty | DEFER (broken) |
| `create_file_transfer` | `(bytes, name, mime?) → fileIdHex` | `ui-chat.js:747` | 1:1 file send. No offer is ever sent: it reports "Sent" locally (`ui-chat.js:745-749`) | DEFER (broken) |
| `handle_identity_rotation` | `(oldPubHex, payloadJson) → {ok, new_peer_id_hex, new_ed25519_pub_hex, rotated_at, grace_expires_at}` | `messaging.js:1510` | incoming 0x13 | see §12 |
| `rotate_identity` | `(nowSecs) → {old_peer_id_hex, new_peer_id_hex, …, per_contact_envelopes:[[peer, env]], retired_identity_secret_hex}` | `settings.js:674` | user rotation | see §12 |
| `create_sender_key`, `receive_sender_key` | — | `messaging.js:477,680,744` | **These do not exist in the wasm crate** (calls are guarded with `if (wasm.create_sender_key)`), so group sender keys silently never happen | DEFER |
| `is_decoy_enabled`, `set_unlock_code`, `verify_unlock_code`, `panic_wipe` | — | `boot.js:68,137,146,362,706`, `views.js:87-88`, `settings.js:646,754` | decoy / panic | DROP |
| `token_prepare_blind`, `token_unblind` | — | `token-pool.js:424,470` | VOPRF | DROP |
| `verify_authority_signature` | — | `relay-client.js:19,64` | directory | DROP |

`onion.js` calls the circuit API through an injected handle (`onion.js:132,175,225,252`; `build_circuit`,
`circuit_send`, … in `circuit.rs:525-799`). DROP.

### 2.3 Exports that exist but are unused

- `generate_keypair`, `create_session`, `send_message`, `envelope_decode`, `list_session_peer_ids`
  (`lib.rs:97,341,370,457,670`).
- `safety_number` (`lib.rs:632`): the PWA uses its own JS (`safety-number.js:60-82`). Same algorithm;
  the new app can use either.
- `reject_call`, `get_call_state`, `start/stop_screen_share`, `is_screen_sharing`,
  `is_peer_screen_sharing`.
- `get_file_offer`, `receive_file_offer`, `receive_chunk`, `assemble_file`.
- All group APIs: `create_group` … `assemble_group_file` (`lib.rs:1003-1578`).
- `enter_decoy_mode`, `compute_sas` (6-digit SAS, `lib.rs:1740`), `verify_directory`,
  `verify_endorsed_descriptor`, `get_network_id`, `get_authority_pubkeys`, `get_authority_threshold`,
  `verify_ed25519_signature`, `get_webrtc_privacy_config`, `parse_bridge_address`,
  `create_bridge_address`.
- The `ws_*` helpers (`websocket.rs:231-299`).

**For the port:** the new client needs only the 17 PORT rows above. A slimmer wasm surface (identity,
sign, envelope encode / trial-decrypt, sessions export/import, QR generate/scan, channel binding,
safety number) would be a separate Rust change; it is out of scope here.

---

## 12. Risks, open questions, porting order

### 12.1 Spec deviations and bugs (do not replicate)

1. **Contact rows are clobbered on every incoming chat.** `dbPut('contacts', {peerId, name: '<8hex>...'})`
   overwrites the row (`messaging.js:1334-1337`). This erases a user rename and the stored
   `identityPubKey`, the PNP-002 §8 trust anchor that identity-rotation verification needs
   (`messaging.js:1502`). The new client must upsert without destroying fields.
2. **Gossip leaks content to other peers.** `sendMessage` sends the envelope for contact A, as
   `{type:'gossip', from: <our id>, to: A, ttl: 3}`, on every open data channel, including channels to
   other contacts and channels whose binding has not verified (`ui-chat.js:350-367`). This breaks
   PNP-001-SHOULD-018 (hold content until the binding verifies) and leaks who-talks-to-whom to third
   parties. The desktop ignores `gossip` (`wire.rs:230-237`). DROP.
3. **Incoming envelopes are accepted on any channel and before verification.** The data-channel
   `onmessage` calls `onIncomingMessage` for every `chat` frame, whatever the channel's peer and binding
   state (`webrtc.js:588-589`). The decrypted sender is not compared with the channel's peer. The spec
   only constrains sending (PNP-001-MUST-081, SHOULD-018), so this is not a violation. **Recommended:**
   before verification, accept only 0x03 (bootstrap) and 0x14 from the channel's own peer, and drop
   frames whose `source_peer_id` ≠ the channel's peer.
4. **Calls trickle ICE and send SDP before gathering finishes.**
   - `startCallConnection` returns the offer as soon as `setLocalDescription` resolves
     (`call.js:249-253`), and every candidate goes out as a separate `ice` CALL_SIGNAL
     (`call.js:150-180`).
   - A PWA callee drops every `ice` that arrives before the user accepts (`call.js:322-327`), so
     PWA→PWA calls with a slow accept lose all of the caller's candidates.
   - The desktop embeds its candidates in the SDP and sends no `ice` (desktop report §7,
     `engine.rs:2125-2141`).
   - **Recommended:** wait for ICE gathering (bounded) before sending the call `offer`/`answer`, as the
     data channel already does (`webrtc.js:433-448`). Keep accepting `ice` for compatibility.
5. **`reject` does not tear down the caller.** On `reject` the caller only shows a toast
   (`messaging.js:1432-1434`). The PC, local media and the 60 s no-answer timer stay until that timer
   fires (`ui-chat.js:540-544`).
6. **Call signals ignore `callId`.** `answer`/`ice`/`hangup` apply to whatever call PC exists for that
   peer (`messaging.js:1397-1431`, `call.js:34`). A second incoming `offer` overwrites
   `incomingCallInfo` with no busy reply. The desktop replies `reject` when busy and ignores a
   duplicate `callId` (`engine.rs:2086-2093`). Match the desktop.
7. **Encrypted-at-rest rows are not indexed.** When the passphrase store is on, a row is stored as
   `{<keyField>, _enc}` (`db.js:165-174`). The `peerId` and `groupId` indexes on `messages` and
   `group_messages` then match nothing, so `loadMessages` (`ui-chat.js:256`) shows no history, and
   `dbGetByIndex` never decrypts (`db.js:203-213`). The interop driver's raw IDB reads
   (`m.peerId`, `m.content`, `pwa-interop.mjs:551-559` [s3]) only work with encryption off.
8. **Pairing.**
   - The pending bootstrap is in memory only and single (§2.1). Each render of the QR replaces it
     (`showView('add-contact')` renders, and so does `showAddTab('qr-show')`: `views.js:24-25`,
     `ui-chat.js:1088-1090`).
   - "Copy Code" opens a 24 h pairing window (`ui-chat.js:1058`), but the code expires after
     1800 s (`crates/parolnet-core/src/bootstrap.rs:95,128-135`) and the window is lost on reload
     (`webrtc.js:615-623`, in memory).
   - The open pairing window accepts an offer from *any* PeerId (`webrtc.js:625-632`), and the
     desktop does the same (`engine.rs:1025-1029`).
   - **Recommended:** open the window only for the code's lifetime, regenerate the code on demand
     rather than on every render, and close the window once the bootstrap materialises.
9. **The data-channel identity frame is never checked.** `{type:'identity', peerId}` remaps a
   `pending_` record (`webrtc.js:578-587`). Neither side rejects a mismatch with the signalling `from`
   (desktop: `engine.rs:1601-1609`). It is informational; never trust it.
10. **Keepalive.** The PWA's SW follows PNP-001 §10.3 (ping 20 s, dead after 40 s; `sw.source.js:404-458`).
    **DEVIATION (desktop):** the desktop pings every 25 s and has no silence timeout
    (`signaling.rs:28,190-193`). The spec is right; the new web client should keep 20 s / 40 s.
11. **Dead UI handlers.**
    - `setCustomRelay()` is not exported to `window`, so the "custom relay" button throws
      (`index.html:430`, `settings.js:431`).
    - `clearCustomRelay` calls a non-existent `connMgr._connectRelay` (`settings.js:556-559`).
    - `showAddMemberDialog` does not exist (`index.html:211`).
    - Notification click posts `{type:'openChat'}`, which no page listener handles, and `?chat=` is
      never read (`sw.source.js:368-375`).
12. **Groups and files are non-functional today** (see §2.2 and wire.md §5): sender keys are missing,
    the 1:1 file offer is never sent, and chunks are sent empty. DEFER means re-design against PNP-010
    and MLS, not port.
13. **`?bootstrap=` handling** is dead code (§2.2).

### 12.2 Open questions for the orchestrator

- **Identity rotation (0x13).** The PWA can send and receive it (`settings.js:663-724`,
  `messaging.js:1489-1558`); the desktop logs and drops 0x13 (desktop report §6,
  `engine.rs:1695-1697`). It is in neither the DROP nor the DEFER list. Recommended: DEFER (no interop
  partner, no tests).
- **Passphrase encryption at rest.** It is in neither list. The desktop keeps its key in the OS keychain
  (`docs/m1-desktop.md` "Storage" [s3]). For the web, decide between keeping PBKDF2 + AES-GCM (§8.3),
  fixing the index problem (12.1 #7), or dropping it.
- **Export/import** uses its own blob format (§8.5) with no desktop equivalent. Keep or drop?
- **Notifications.** Without the SW relay socket, nothing arrives while the page is closed. Is that
  acceptable? It matches the signaling-only model (§9).

### 12.3 Suggested porting order (smallest end-to-end slice first)

1. **wasm boot and identity.** Init, `initialize`/`initialize_from_key`, persist the secret and
   sessions, expose `window._peerId` (test hook, §11).
2. **Relay socket in the page.** Connect to `location.host/ws`; `register` → `challenge` → signed
   `register` → `registered` (log `Registered with relay`); ping 20 s and dead at 40 s; backoff
   1→30 s; `watch` after every `registered`.
3. **Pair, presenter side.** `generate_qr_payload`, show the code (`qr-share-code` hook), pairing
   window, accept the offer, answer non-trickle, `trial_decrypt` bootstrap → contact. This is interop
   case 1.
4. **Pair, scanner side.** `process_scanned_qr`, queue the bootstrap envelope, force-offer. This is
   interop case 2.
5. **Channel binding.** Send after the bootstrap, verify, 20 s timeout, block content until verified;
   log `direct channel verified with <id8>`. This is case 4.
6. **Text chat.** Raw UTF-8 0x01 envelopes in `{type:'chat'}` frames; store and render. Cases 1, 2, 7.
7. **Sender queue** in IDB, flushed on verify. Case 3.
8. **Presence, initiator, glare, retry and rate-limit handling.**
9. **Calls**: per-call PC, CALL_SIGNAL JSON, accept / hangup hooks. Cases 5 and 6.
10. Settings (language, own TURN), safety number, i18n.
