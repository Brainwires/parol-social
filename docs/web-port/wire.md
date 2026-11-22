# Web port: on the wire

Part of the [porting inventory](inventory.md). The conventions (paths, **[s3]**, **DEVIATION**) are
explained there. Desktop-core references are to `crates/parolnet-app/src/` on master.

## 3. Relay WebSocket protocol as the client speaks it

### 3.1 Who owns the socket

**The home-relay WebSocket lives in the service worker, not the page.**

- The page talks to it only through `postMessage` (`connection.js:23-53`, `sw.source.js:381-712`).
- The page's `connMgr._swRelayConnected` mirrors the SW's `relay_status` broadcasts (`boot.js:585-601`).
- The new app has a plain caching worker (§9), so **the socket must move into the page**. Everything
  below describes the frames, wherever they are sent from.

**URL.**

- The default is `(https ? 'wss:' : 'ws:') + '//' + location.host + '/ws'`, or `settings.custom_relay_url`
  if set (`connection.js:56-64`).
- The interop harness relies on the same-origin default: its HTTP server proxies `/ws` and every
  non-file path to the relay (`pwa-interop.mjs:14-15,228-254` [s3]).

### 3.2 Connection, registration, keepalive

| Step | Frame (exact) | Where |
|---|---|---|
| open | client → `{"type":"register","peer_id":"<64hex>"}` | `sw.source.js:483-485` |
| relay | ← `{"type":"challenge","nonce":"<hex>"}` | handled `messaging.js:302-325` |
| client | → `{"type":"register","peer_id":"<64hex>","pubkey":"<Ed25519 pk hex>","signature":"<hex, Ed25519 over the register message: label, nonce, pin, relay name; PNP-001 §10.7>","nonce":"<same hex>","relay":"<host:port the socket was opened to>"}` (since PNP-001 v0.17; before, the signature was over the bare nonce and there was no `relay`) | page signs (`messaging.js:306-315`), SW sends (`sw.source.js:671-680`) |
| relay | ← `{"type":"registered", "profile":"signaling-only"\|"relay", "online_peers":…}`; a missing `profile` is treated as `"relay"` | `messaging.js:327-333`, `relay-profile.js:28-30` |
| on `registered` | client → `watch` (§3.3), the discovery tick, refetch of `/turn-credentials` | `connection.js:576-581`, `webrtc.js:238-241` |
| keepalive | → `{"type":"ping","ts":<ms>}` every 20 s; `pong` ignored; any inbound frame resets liveness; closed with code 4000 after 40 s of silence (checked every 5 s) | `sw.source.js:404-458,495-513` |
| reconnect | backoff 1 s, doubling, max 30 s; reset only on `registered` (not on TCP open) | `sw.source.js:390,505-510,530-538` |
| identity change | a socket may register one PeerId: a new id closes with code 4001 and re-registers on a fresh socket | `sw.source.js:656-670` |

The desktop matches this flow (`signaling.rs:120-173`). **DEVIATION (desktop):** it pings every 25 s and
has no silence timeout (`signaling.rs:28`). PNP-001-MUST-065 and MUST-066 require 20 s / 40 s; keep
20 s / 40 s in the web client.

Other behaviour of the current client:

- Page-side watchdogs: every 10 s it polls SW liveness and re-sends `relay_connect` if the SW is silent
  for more than 8 s; it also nudges on `visibilitychange` and `focus` (`boot.js:254-281`). Not needed
  once the socket lives in the page; a page-side reconnect on `online` and `visibilitychange` is enough.
- `connMgr.registerPeer` posts an extra unauthenticated `register` on boot (`boot.js:130`,
  `sw.source.js:666-669`). The relay allows at most 4 `register` frames per socket (PNP-001-MUST-075);
  the new client should send exactly two (plain, then signed).
- Frames posted while the SW socket is not OPEN are silently dropped (`sw.source.js:672,684,694,702`).
  `sendSignaling` reports success from the possibly stale `_swRelayConnected` flag (`connection.js:84-88`).

### 3.3 Presence

| Frame | Shape | Where |
|---|---|---|
| → watch | `{"type":"watch","peer_ids":[<64hex lowercase>, …]}`, at most 256, most recently active contact first; replaces the previous set | `sw.source.js:698-705`, `relay-profile.js:187-204`, `connection.js:539-558` |
| ← presence | `{"type":"presence","peer_id":"<64hex>","online":bool}`. `peer_id` must match `^[0-9a-fA-F]{64}$`; it is lower-cased | `messaging.js:335-339` |

`watch` is sent:

- with `force` after every `registered` (`connection.js:576-578`);
- on a `relay_status` connected transition (`boot.js:593`);
- when contacts change, debounced 1 s (`connection.js:562-573`, event from `db.js:158-162`);
- by the 5 min tick (`connection.js:610-612`).

`presence online:true` resets the retry counter and calls `connectToPeer(reason:'presence')`.
`online:false` cancels timers and drops a still-connecting PC (`webrtc.js:330-345`).

### 3.4 Signaling frames

Outgoing (`sw.source.js:693-696`), with the payload built at `webrtc.js:450-456,480-483`:

```json
{"type":"rtc_offer","to":"<64hex>","payload":"{\"type\":\"offer\",\"sdp\":\"v=0\\r\\n...\"}"}
{"type":"rtc_answer","to":"<64hex>","payload":"{\"type\":\"answer\",\"sdp\":\"...\"}"}
{"type":"rtc_ice","to":"<64hex>","payload":"{\"candidate\":\"candidate:...\",\"sdpMid\":\"0\",\"sdpMLineIndex\":0,\"usernameFragment\":\"...\"}"}
```

Incoming: the same with `from` in place of `to` (`messaging.js:354-362`).

- `payload` is a **JSON string**: double-encoded `RTCSessionDescriptionInit` / `RTCIceCandidateInit`.
  The desktop expects exactly that (`wire.rs:174-180`).
- Size caps the client checks: SDP payload ≤ 16384 (warning only, `webrtc.js:452-454`), ICE payload ≤ 2048
  (dropped, `webrtc.js:481`), at most 4 late `rtc_ice` per attempt (`relay-profile.js:214-216`,
  `webrtc.js:479`). These match PNP-001-MUST-072.

### 3.5 Errors handled

The frame is `{"type":"error","code":…,"message":…,"peer_id"?}` (`messaging.js:364-387`).

| code | Client action |
|---|---|
| `peer_offline` | `setPeerOnline(peer_id, false)`: the "waiting" path state, timers cleared (`messaging.js:367-371`) |
| `rate_limited` | pause new offers for 60 s × 2^hits, capped at 10 min (`relay-profile.js:114-117`, `webrtc.js:348-352`). Note `rateLimitHits` never resets (`webrtc.js:285,349`). The desktop resets on register and caps the exponent at 4 (`engine.rs:969-976`) |
| `signaling_only` | set the profile to signaling-only (`messaging.js:375-379`) |
| `payload_too_large`, `not_registered` | ignored |
| (no code) `message:"peer not connected"` | toast (`messaging.js:384-386`); relay profile only |

Rate limits the client must respect (PNP-001 §10.5, `webrtc.js:15-19`):

- per sender: 60 signaling frames/min and 240/h; per (sender, recipient): 64 per 10 min;
- client-side stagger: at most 3 new offers per 10 s window (`relay-profile.js:121-135`, `webrtc.js:383-399`).

DROP (relay profile only):

- `message` and `queued` frames (`messaging.js:341-352`);
- the outbound `{"type":"message","to","token","payload"}` (`sw.source.js:682-691`, `connection.js:245-250`).

### 3.6 HTTP endpoints

| Endpoint | Caller | Signaling-only | Disposition |
|---|---|---|---|
| `GET {relay http base}/turn-credentials` → `{uris:[…], username, credential, profile}` | `webrtc.js:243-272`. The base is the relay URL with `ws`→`http` and `/ws` stripped (`webrtc.js:227-231`). Only `stun:`/`stuns:` URIs are kept on a signaling-only answer (`relay-profile.js:221-235`). Also sets the profile (`webrtc.js:259`). Logs `[WebRTC] ICE servers from <url> …`, which interop checks must **not** appear (§11) | Returns STUN URIs only (PNP-001-MUST-071) | **PORT**, STUN only, like the desktop (`ice.rs:43-94`) |
| `GET https://parol.social/turn-credentials` | fallback when our relay announces nothing (`webrtc.js:224-225,248`) | — | **DROP**. A third-party request that leaks the client IP. The interop harness has to block it (`pwa-interop.mjs:24-27,356-358,375,468-469` [s3]) |
| `GET /bootstrap?exclude=<peerId>` | `connection.js:583-608`, relay profile only | Answers `[]` (PNP-001-SHOULD-017) | **DROP** |
| `GET /peers/lookup?id=` | `peer-relay-cache.js:322-324` | — | **DROP** |
| `GET {relay}/directory` | `relay-client.js:351-353`, at boot for every known relay (`boot.js:215`) | readable | **DROP** (the result is never used for routing) |
| `POST /tokens/issue`, `POST /telemetry` | `token-pool.js:442`, `telemetry.js:35` | not served | **DROP** |

---

## 4. Peer connection and data channel

### 4.1 Who offers

- **Initiator rule.** The lexicographically smaller lower-case hex PeerId offers
  (`relay-profile.js:90-96`); the desktop does the same (`wire.rs:244-247`).
- **The non-initiator waits** 10 s plus 0–2 s jitter for an offer, then offers itself
  (`webrtc.js:372-380`); the desktop matches (`engine.rs:1131-1140`).
- **`force` offers immediately.** It is used for QR scan/paste (`ui-chat.js:971`), retries
  (`webrtc.js:419`) and the signaling-only tick for queued peers (`connection.js:617-626`, at most 5 peers
  per 5 min tick).
- **Triggers.** `openChat` → `connectToPeer(reason:'user')` (`ui-chat.js:193`); presence online; queued
  send → `requestDirectPath` (`connection.js:635-638`); `/bootstrap` discovery (relay profile only).
- **Glare** (`webrtc.js:639-650`). If we hold a connecting initiator PC in `have-local-offer`, the
  designated initiator ignores the incoming offer and the other side yields. Same rule as the desktop
  (`engine.rs:1049-1057`).
- **Offer acceptance gate** (`webrtc.js:625-637`). We accept from a peer we offered to, a stored contact,
  or anyone while the pairing window is open (§7). Anything else is logged and dropped.

### 4.2 SDP and ICE

- **Non-trickle.** After `setLocalDescription` the client waits for `iceGatheringState === 'complete'`
  or 3 s, then sends the description with the candidates in it (`webrtc.js:433-448,508-512,662-666`).
  Late candidates go out as `rtc_ice` (at most 4). Incoming `rtc_ice` is applied, or buffered (up to 32)
  until a remote description exists (`webrtc.js:686-697`). The desktop never sends `rtc_ice` (desktop
  report §2).
- **ICE servers** (`webrtc.js:73-82`): the user's own servers plus the relay's STUN. The default list is
  empty: no public STUN (`webrtc.js:37-40`). `waitForTurnReady(3000)` runs before each data PC
  (`webrtc.js:461`).
- **Relay-only mode** (user's own TURN): `iceTransportPolicy:'relay'`, with `typ host` / `typ srflx`
  candidates filtered from `rtc_ice` (`webrtc.js:74-75,478`). Effective only when the user has a TURN URL
  (`webrtc.js:65-68`). Changing it closes every connection (`webrtc.js:187`).
- **Timers.**

  | Timer | Value | Where |
  |---|---|---|
  | answer timeout | 20 s | `webrtc.js:287,521-527` |
  | gather cap | 3 s | `webrtc.js:288` |
  | disconnected grace | 5 s | `webrtc.js:289,491-498` |
  | binding timeout | 20 s | `webrtc.js:291` |
  | user-intent window (for the "no path" banner) | 10 min | `webrtc.js:292` |

- **Retry** (`webrtc.js:401-421`, `relay-profile.js:100-110`).
  - Only the side that would offer retries.
  - Delay is 5 s × 2^n, capped at 5 min, plus up to 25 % jitter.
  - It gives up after 8 attempts unless presence says online.
  - Retries stop while the peer is known offline.
- **No-path detection.** On failure, `emitPath('failed', {intent})` fires. The chat banner shows "No
  direct path to …" if the user acted in the last 10 min or messages are queued, with at most one toast
  per peer per 10 min (`ui-chat.js:202-252`). Path events (`parolnet:peer-path`):

  | State | Emitted at |
  |---|---|
  | `offline` | `webrtc.js:343` |
  | `failed` | `webrtc.js:427` |
  | `closed` | `webrtc.js:572` |
  | `binding-failed` | `webrtc.js:747` |
  | `open`, only after the binding verifies | `webrtc.js:757` |

### 4.3 The `parolnet` data channel

- The offerer creates it: `pc.createDataChannel('parolnet', {ordered: true})` (`webrtc.js:505`). It is
  reliable, not negotiated, and its id is assigned by SCTP. The desktop uses the same label with default
  options (`wire.rs:17`, `rtc/lib.rs:748-749`).
- The answerer takes it from `ondatachannel` (`webrtc.js:529-531`). The PWA does not check the label.
  The desktop accepts only `parolnet` (`engine.rs:1360-1364`).
- **All frames are text JSON** (`webrtc.js:545,702,765`):

  | Frame | Exact shape | Direction | Disposition |
  |---|---|---|---|
  | identity | `{"type":"identity","peerId":"<own 64hex>"}`, sent once on open | both | PORT (send it; the desktop sends it too, `engine.rs:1365-1368`). Informational: it only remaps a `pending_` key (`webrtc.js:578-587`) |
  | chat | `{"type":"chat","payload":"<hex of the padded CBOR envelope>"}`. This carries **every** envelope: text, bootstrap, binding, call signals | both | PORT |
  | gossip | `{"type":"gossip","msgId","from","to","payload","ttl"}` | PWA only | DROP; the desktop ignores it (`wire.rs:230-237`) |
  | fallback | non-JSON text is fed to `onIncomingMessage` as hex (`webrtc.js:602-604`); the desktop also accepts bare hex | — | optional |

### 4.4 Open sequence and CHANNEL_BINDING (0x14)

On `dc.onopen` (`webrtc.js:541-565`):

1. Send `identity`.
2. Mark `status='open'` and presence online, and clear the retry, wait and answer timers.
3. `flushBootstrapQueue(peer)`: send queued entries flagged `bootstrap` on the **unverified** channel, in
   order (`connection.js:422-439`). Only the scanner has one.
4. `maybeSendChannelBinding(peer)` (`webrtc.js:713-731`). It needs an open channel and
   `wasm.has_session(peer)`. The body is `wasm.channel_binding_body(pc.localDescription.sdp,
   pc.remoteDescription.sdp)`, sent as `envelope_encode(peer, 0x14, body)` in a `chat` frame. It is sent
   once per connection (`bindingSent`). A presenter has no session yet, so its binding goes out later:
   after any decrypted non-binding envelope (`messaging.js:1667-1669`), or after it verifies the peer's
   binding (`webrtc.js:754`).
5. Start the 20 s binding timer. If no verified binding arrives, `connectionFailed` closes the
   connection and retries (`webrtc.js:558-564`). This is PNP-001-MUST-081.

On receiving 0x14 (`handleChannelBinding`, `webrtc.js:735-759`):

- It looks up the connection by the decrypted sender, then calls
  `channel_binding_verify(body, localSdp, remoteSdp)`.
- **Mismatch:** an error toast `toast.channelBindingFailed`, `cleanupRTC`, `binding-failed`, retry. This
  is PNP-001-MUST-080.
- **Match:** set `verified`; log `[WebRTC] direct channel verified with <id8>` (the interop driver
  parses it, §11); send our binding if we have not; reset the attempt counter; emit `open`;
  `flushMessageQueue({peerId})`.

The binding body is a CBOR map `{"v":1,"local":[fp…],"remote":[fp…]}`. Each `fp` is
`"<alg lowercase> <HEX:UPPER>"`, sorted and deduplicated, 1–8 entries
(`crates/parolnet-protocol/src/channel_binding.rs:40-80`; PNP-001 §10.5.1). The SDPs used are exactly
`pc.localDescription.sdp` and `pc.remoteDescription.sdp`. The interop tamper case overrides the
`localDescription` getter once the PC is connected (`pwa-interop.mjs:408-423` [s3]), so the TS port must
read `pc.localDescription` at binding time, not a cached string.

**Blocked until verified** (`hasDirectConnection` requires `verified`, `webrtc.js:832-835`):

- every content send and call signal (`sendViaWebRTC`, `webrtc.js:761-773`);
- the queue flush;
- the "direct" indicator.

Only the bootstrap envelope and our own binding go out earlier (`sendOnChannel`, `webrtc.js:699-708`).
This matches the desktop (desktop report §4) and PNP-001-MUST-081/SHOULD-018, except for gossip
(inventory §12.1 #2).

### 4.5 Sender-side queue

**Data.**

- In memory (`connection.js:312`), mirrored row by row to IDB `pending_sends`.
- Row shape: `{id (auto), toPeerId, payload: <envelope hex>, timestamp, nextTryAt, bootstrap?: true}`
  (`connection.js:341-354`).
- Rows are hydrated after unlock, and rows older than 30 days are dropped (`connection.js:387-417`).

**Limits** (`relay-profile.js:139-183`):

- 30 days, 2000 entries, 500 per peer, 50 MiB of payload;
- the oldest entries go first (per peer first, then overall).

The desktop has 30 days / 500 / 2000 (`store.rs:21-23`).

**What is queued.** Text and other content envelopes, when there is no verified channel
(`messaging.js:160-166`, `ui-chat.js:341-348`). **Not queued:** call signals and file chunks
(`noQueue`: `messaging.js:113-115,280-281,921`).

Note: the payload is the *already-encrypted* envelope. The ratchet advanced at queue time, so queued
envelopes must be sent in order and never re-encrypted.

**Flush** (`connection.js:447-525`).

- Triggered by verification for one peer (`webrtc.js:758`), and by relay connect (`boot.js:594`).
- Entries without a verified channel are skipped untouched.
- A failed send backs off 5 s (`RETRY_BACKOFF_MS`, `:319`).
- `queue-changed` events drive the "Waiting for <name> to come online" banner (`ui-chat.js:214-235`).

**Delivery state.** There is none. A sent message is stored once as `direction:'sent'`, with no
queued / sent / failed state on the row (`ui-chat.js:284-296`). The desktop has Queued → Sent → Dropped
states (desktop report §6). Recommended: store a `state` field on messages in the new app.

---

## 5. Message types and envelopes

**Envelope.** `wasm.envelope_encode` produces the PNP-001 §3 CBOR 4-array
`[cleartext_header, ratchet_header, ciphertext, padding]`, padded to exactly 256 / 1024 / 4096 / 16384
bytes (`lib.rs:403-450`; `crates/parolnet-core/src/envelope.rs:113-163`):

- the timestamp argument is `BigInt(floor(Date.now()/1000))`;
- `source_hint` is omitted except on the bootstrap envelope.

Incoming:

- `wasm.trial_decrypt` tries every session (`lib.rs:506-578`);
- dedup uses the first 128 hex characters of the envelope, in a 1000-entry FIFO set shared with gossip
  (`messaging.js:1596-1600`, `webrtc.js:838-850`);
- a decrypt failure with zero sessions is "deferred" (for the SW inbox); with sessions it is dropped
  (`messaging.js:1615-1633`).

| Code | Name | Sent by PWA | Handled | Payload | Disposition |
|---|---|---|---|---|---|
| 0x01 | TEXT | `ui-chat.js:310` | `messaging.js:1318-1359` | **raw UTF-8 text**, no JSON (same as the desktop, `engine.rs:692-699`) | PORT |
| 0x03 | CONTROL | bootstrap only, `ui-chat.js:938-944` | logged (`messaging.js:1361-1369`) | empty, `source_hint` = scanner Ed25519 pk | PORT |
| 0x04 | DECOY | `cover-traffic.js:81` | dropped silently (`messaging.js:1272-1276`) | random | DROP (keep the silent drop) |
| 0x09 | FILE_CHUNK | `messaging.js:904-911` | `messaging.js:846-860` | JSON `{fileId, chunkIndex, totalChunks:-1, data:[bytes…]}`; broken (§2.2) | DEFER |
| 0x0A | FILE_CONTROL | accept only, `messaging.js:823` | `messaging.js:1377-1387` | JSON `{action:'offer'\|'accept', fileId, fileName, fileSize, totalChunks}`; the offer is never sent | DEFER |
| 0x0B | CALL_SIGNAL | `messaging.js:271-289` | `messaging.js:1389-1438` | JSON, §6 | PORT |
| 0x0C | GROUP_TEXT | `messaging.js:565-579`, pairwise fan-out | `messaging.js:586-611` | JSON `{groupId, sender, content, timestamp}`, pairwise Double Ratchet (not sender keys) | DEFER |
| 0x0D | GROUP_CALL_SIGNAL | `messaging.js:1015-1027` | `messaging.js:1446-1454` | JSON `{action:'invite', groupId, callId, groupName}` | DEFER |
| 0x0E / 0x0F | GROUP_FILE_OFFER / CHUNK | `messaging.js:1169-1193` | `messaging.js:1209-1261` | JSON; 16384-byte chunks as number arrays | DEFER |
| 0x11 | SENDER_KEY_DISTRIBUTION | `messaging.js:682-685`, never runs | `messaging.js:739-750` | JSON `{groupId, keyData:[…]}` | DEFER |
| 0x12 | GROUP_ADMIN | `messaging.js:668-673` | `messaging.js:718-737,1474-1482` | JSON `{action:'invite', groupId, groupName, members}` | DEFER |
| 0x13 | IDENTITY_ROTATE | `settings.js:709-718` (wasm-built envelopes) | `messaging.js:1489-1558` | wasm JSON payload | see inventory §12.2 |
| 0x14 | CHANNEL_BINDING | `webrtc.js:721-724` | `webrtc.js:735-759` | CBOR map (§4.4) | PORT |
| other | — | — | warned and discarded (`messaging.js:1303-1306`), per PNP-001-MUST-008 | — | PORT |

The desktop handles only 0x01, 0x03, 0x0B and 0x14 (desktop report §6).

Group and file JSON uses JS number arrays for bytes, which roughly triples the size. Any DEFERred
redesign should follow PNP-010 / MLS instead.

**Text chat end to end** (`ui-chat.js:278-386`):

1. Store `{peerId, direction:'sent', content, timestamp}`.
2. `envelope_encode(peer, 0x01, utf8)`.
3. If the channel is verified, send it; otherwise queue it and `requestDirectPath`.
4. Update `contact_state`.

Receive (`messaging.js:1318-1359`): store `{peerId, direction:'received', content, timestamp}`, upsert the
contact (inventory §12.1 #1), update `contact_state` (unread=1), then notify or render.

---

## 6. Calls

**Precondition.** A verified data channel. Otherwise the client calls `connectToPeer(user)` and shows a
waiting / no-path toast (`ui-chat.js:450-457`). The desktop does the same (`engine.rs:1795-1804`).

**Caller** (`initiateCall`, `ui-chat.js:442-547`):

1. `waitForTurnReady(5000)`.
2. `getUserMedia({audio: true, video: withVideo ? {width:320, height:240} : undefined})`
   (`ui-chat.js:463-465`).
3. Call id: `wasm.start_call(peer)`, 32 hex characters (`ui-chat.js:479-487`).
4. `startCallConnection`: a **new** `RTCPeerConnection(getRtcConfig())` with all local tracks added,
   `createOffer`, `setLocalDescription`, and the SDP returned **without waiting for gathering**
   (`call.js:139-260`).
5. Send CALL_SIGNAL `offer`.
6. Show the call view, `Calling...`, and start a 60 s no-answer timer that ends in `hangupCall`
   (`ui-chat.js:526-546`).

**Callee.**

1. `offer` → `incomingCallInfo` and the `#incoming-call-notification` banner (`messaging.js:940-963`).
2. `acceptIncomingCall` (`messaging.js:965-983`) → `answerIncomingCall` (`ui-chat.js:549-613`):
   getUserMedia with the same constraints → `acceptCallConnection` (new PC,
   `setRemoteDescription(offer)`, flush pending ICE, `createAnswer`) → CALL_SIGNAL `answer` → media
   watchdog of 15 s (`call.js:41,51-65`).
3. Decline → `reject` (`messaging.js:985-994`).

**Signals**: CALL_SIGNAL (0x0B) envelopes on the verified data channel, never queued
(`messaging.js:271-289`). The JSON is built as `{action, ...payload}`:

```json
{"action":"offer","callId":"<32hex>","withVideo":true,"sdp":"v=0\r\n..."}
{"action":"answer","callId":"<32hex>","withVideo":true,"sdp":"v=0\r\n..."}
{"action":"ice","callId":"<32hex>","candidate":{"candidate":"candidate:...","sdpMid":"0","sdpMLineIndex":0,"usernameFragment":"..."}}
{"action":"hangup","callId":"<32hex>"}
{"action":"reject","callId":"<32hex>"}
```

These come from `ui-chat.js:511-515,596-600,622`, `call.js:165` and `messaging.js:989-992`. `sdp` is the
raw SDP string. The shapes are identical to the desktop's (`call.rs:181-230`).

**ICE.** Each local candidate is trickled as an `ice` signal (`call.js:150-180`). In relay-only mode,
host and srflx candidates are filtered (`call.js:67-74`). Incoming `ice` is queued until the remote
description is set (`call.js:319-343`), but **dropped if no call PC exists yet**, i.e. before the user
accepts (`call.js:322-327`). See inventory §12.1 #4.

**Media and codecs.** No codec preferences are set; the browser defaults apply. The desktop offers
Opus/111 and VP8/96 only and answers with those (desktop report §7). Interop requires VP8 and Opus to
flow both ways (`pwa-interop.mjs:727-737` [s3]). Remote tracks are attached to `#remote-audio` and
`#remote-video` from `event.streams[0]` (`call.js:87-110`). A track without a stream is not played.

**Mute / camera.** These toggle `track.enabled` on the local tracks (`ui-chat.js:674-702`), with no
signalling and no renegotiation. Camera-off keeps the track. The desktop sends black frames.

**Teardown.**

- `hangupCall` sends `hangup` first, then `teardownCallConnection` (close the PC, clear the media
  elements), stops local tracks and the timer, and goes back to chat (`ui-chat.js:615-638`,
  `call.js:345-367`).
- On a remote `hangup`, the same, without signalling (`messaging.js:1420-1431`).
- PC `failed`, or the 15 s media watchdog, dispatches `parolnet:call-failed` → `hangupCall`
  (`call.js:206-225`, `ui-chat.js:433-440`).
- On a remote `reject`: a toast only (inventory §12.1 #5).

**Timeouts compared.** PWA: 60 s ring (caller), 15 s answer → connected. Desktop: 60 s ring, 30 s accept
→ media (`engine.rs:65,67`). The callee side has no ring timeout in the PWA.

---

## 7. Pairing (PNP-003)

**Code format.** Lower-case hex of the CBOR map
`{v:1, ik:bstr32 (Ed25519 pk), seed:bstr32, rk:bstr32 (X25519 ratchet pk), relay:null, ts: floor(now/300)*300, net:2}`.

- The map is built by `generate_qr_payload(get_public_key(), null)` (`ui-chat.js:984-988`,
  `crates/parolnet-core/src/bootstrap.rs:45-81`).
- The QR image encodes the same hex text: version auto, ECC `M` (`ui-chat.js:1015-1036`).
- The interop driver checks `/^[0-9a-f]{100,}$/i` (`pwa-interop.mjs:639` [s3]). The desktop's code has
  the identical format (`engine.rs:594-603`).
- Fallbacks `parolnet:<pk or peerId>` (`ui-chat.js:989-1007`) are legacy and cannot pair securely. DROP.

**Expiry.** The scanner rejects `ts` older than 1800 s (`bootstrap.rs:95,128-135`). The presenter's
pending bootstrap lasts until replaced or the page reloads (inventory §2.1).

**Presenter** (shows the code).

1. Entering `add-contact` renders the code and opens a 30 min pairing window (`views.js:24-29`). Copy
   Code opens a 24 h window (`ui-chat.js:1058`).
2. The scanner's offer is accepted under the window (`webrtc.js:625-632`); the data channel opens.
3. The scanner's 0x03 envelope arrives. `trial_decrypt` falls back to the pending bootstrap
   (PNP-001 §5.3.1) and returns `bootstrapped:true` with `source_peer_id` = SHA-256(source_hint)
   (`lib.rs:556-578`).
4. The page stores the contact `{peerId, name:'<8hex>...', identityPubKey: source_hint}` and
   `contact_state` (`messaging.js:1645-1664`), then sends its binding (`messaging.js:1669`).

The desktop additionally requires SHA-256(source_hint) == the signalling peer (desktop report §5). The
PWA does not check this, because trial-decrypt has no channel peer. Recommended: port the desktop check.

**Scanner** (camera scan or paste; both use `handleScannedQR`, `ui-chat.js:872-974`). Paste strips
whitespace and quotes; hex longer than 64 characters is treated as a full code (`ui-chat.js:1102-1112`).

1. `process_scanned_qr(hex)` creates the initiator session; persist the sessions.
2. Reject our own id.
3. Store the contact `{peerId, name, identityPubKey: their_identity_key}` and `contact_state`.
4. `envelope_encode(peer, 0x03, empty, now, ourIk)`, then `sendRawEnvelope(…, {bootstrap:true})`. With
   no channel yet, this queues it with `bootstrap:true` (`ui-chat.js:935-964`).
5. `connectToPeer(force)`, then `openChat`.

**Legacy add.** A bare 64-hex or `parolnet:` code adds a contact with no session
(`ui-chat.js:1114-1160`). Sending to it then fails with "no secure session" (`ui-chat.js:302-305`).
DROP.

**After pairing, stored:** the `contacts` row, the `contact_state` row and `settings.sessions_blob`.
Nothing else. A pairing that is half done is not persisted on the presenter.

**Safety number** (PNP-002 §10, `safety-number.js:60-82`):

1. `SHA-256(min(pidA,pidB) ‖ max(pidA,pidB))` over the raw 32-byte PeerIds in byte order.
2. Take the first 30 bytes as six 5-byte big-endian integers, each mod 10^10, zero-padded to 10 digits.
3. Join with spaces (60 digits).

Vector: `specs/vectors/PNP-002/safety_number.json`. PeerIds `11…11` and `22…22` →
`0203903273 2487506436 7022175877 9751782849 2461095953 2148788959` (recomputed independently for this
document). The same algorithm is in wasm `safety_number` (`lib.rs:632-636`) and the desktop
(`crates/parolnet-protocol/src/channel_binding.rs:163-180`). The modal is opened from the chat header
(`index.html:151`).
