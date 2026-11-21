# Web port: interop contract

Part of the [porting inventory](inventory.md). The source is
`git show m1/slice3:apps/desktop/interop/pwa-interop.mjs` (899 lines). All `pwa-interop.mjs:N`
references are to that version.

## 11. What `pwa-interop.mjs` requires from the page

### 11.1 Environment

**Build artefacts.** It refuses to start unless `pwa/app.js`, `pwa/sw.js` and
`pwa/pkg/parolnet_wasm_bg.wasm` exist (`:210-214`). It serves `pwa/` statically (`no-store`), proxies
every other path, including the `/ws` upgrade byte for byte, to a local `parolnet-relay`
(signaling-only by default, `:209-260`), and opens `http://127.0.0.1:<port>/index.html` (`:471`). The
new app therefore needs:

- a built output directory the driver can point at (today hard-coded as `pwa/`, `:87`);
- an `index.html` entry;
- the relay at same-origin `/ws`, with no settings required.

**Relay.** Started with `RELAY_CONN_PER_MINUTE=1000`, `RELAY_MAX_PEERS_PER_IP=16` and
`RELAY_MAX_CONNS_PER_IP=32` (`:162-192`). The page must not open extra sockets beyond that.

**Desktop peer.** The headless bot `examples/bot.rs` runs with
`--relay ws://127.0.0.1:<p>/ws --data-dir … --host-only --bind <ip>` and speaks JSON lines (`:264-310`).

**Browsers** (`:351-403`). Each case uses a persistent context with a fresh profile; case 3 reuses its
profile.

| Browser | Base flags / prefs | With `media` (cases 5–7) | ICE mode `loopback` | ICE mode `mdns` |
|---|---|---|---|---|
| Chromium (`channel:"chromium"`, headless) | `--no-first-run --no-default-browser-check --host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost" --autoplay-policy=no-user-gesture-required` | `--use-fake-device-for-media-stream --use-fake-ui-for-media-stream` | `--allow-loopback-in-peer-connection --disable-features=WebRtcHideLocalIpsWithMdns` | defaults (mDNS host candidates) |
| Firefox | `media.autoplay.default=0`, `media.autoplay.blocking_policy=0`; a dead HTTP proxy for every host except 127.0.0.1 | `media.navigator.streams.fake=true`, `media.navigator.permission.disabled=true` | `media.peerconnection.ice.loopback=true`, `obfuscate_host_addresses=false` | `obfuscate_host_addresses=true` |
| WebKit (Linux WPE) | dead proxy | `permissions:["camera","microphone"]` | — | — (mode `host` only) |

Mode selection: `INTEROP_ICE`, defaulting to `mdns` on Linux, `loopback` elsewhere and `host` for WebKit
(`:98-104`). The harness also records every `RTCPeerConnection` in `window.__pcs`, with
`__pairChanges`, through `addInitScript` (`:425-458`). The new app must therefore construct connections
through the global `window.RTCPeerConnection` at call time, not from a reference captured at module
load. A captured reference would bypass the wrapper and break `callStats`, `openCallPcs`, `diag` and
the case 7 role check.

### 11.2 Page contract (current PWA)

**Globals and functions called through `page.evaluate`:**

| Hook | Expected behaviour | Used at |
|---|---|---|
| `window._peerId` | a 64-character hex string once the identity is ready (polled ≤ 30 s) | `:472-474` |
| `window.showView("add-contact")` | shows the add-contact view; renders the code and opens the pairing window | `:518,526` |
| `window.showAddTab("qr-show" \| "passphrase")` | switches tabs (`qr-show` re-renders the code) | `:519,527` |
| `window.connectViaPassphrase()` | reads `#add-tab-passphrase input` and pairs | `:529` |
| `window.openChat(peerId)` | opens the chat; sets the current peer | `:564,774` |
| `window.sendMessage()` (awaited) | sends `#message-input`'s value to the current peer | `:567` |
| `window.acceptIncomingCall()` | accepts the ringing call | `:761` |
| `window.initiateCall(peerId, true)` (awaited) | starts a video call | `:775` |
| `window.hangupCall()` | hangs up the current call | `:785` |
| `RTCPeerConnection.prototype.localDescription` getter | overridden in case 4 to fake the fingerprint once `connectionState === "connected"` | `:408-423` |
| `navigator.mediaDevices.getUserMedia` | the driver calls it itself in case 7, to hold permission | `:812-815` |

**DOM read or written:**

| Selector | Use | Used at | Current element |
|---|---|---|---|
| `#qr-share-code` `.textContent.trim()` | the presenter's pairing code (`/^[0-9a-f]{100,}$/i`) | `:520,639` | `index.html:129` |
| `#add-tab-passphrase input` `.value` | paste field | `:528` | `index.html:140` |
| `#message-input` `.value` | outgoing text | `:566` | `index.html:160` |
| `#incoming-call-notification` (ringing ⇔ no `hidden` class) | incoming-call detection | `:758-760` | `index.html:241` |

**IndexedDB read directly** (`:533-559`):

- `indexedDB.open("parolnet")`, stores `contacts` (`c.peerId`) and `messages`
  (`m.peerId`, `m.direction === "received"`, `m.content`).
- "Contact exists" is how the driver learns pairing finished (`:643,667`).
- "A received message with this text exists" is how it learns delivery worked (`:555-559`, `:619,686`).

**Console lines parsed:**

| Line | Meaning | Used at | Emitted by |
|---|---|---|---|
| starts with `Registered with relay` | relay registration done (*not* `SW registered`) | `:475-479` | `messaging.js:330` |
| contains `direct channel verified with` and the peer's first 8 hex characters | binding verified | `:602-604` | `webrtc.js:753` |
| contains `[WebRTC] ICE servers from` | **failure** if present: the page learned STUN/TURN, so a request left the machine | `:860-865` | `webrtc.js:264` |
| page error containing `/turn-credentials due to access control checks` | tolerated (WebKit, the refused fallback) | `:468-469` | `webrtc.js:252` |

**`getStats` and connection inspection** (through `window.__pcs`):

- **Call media:** an open PC with an audio or video receiver track, `connected`, inbound-rtp video
  `framesDecoded ≥ 20`, audio `packetsReceived ≥ 50` and `totalSamplesReceived > 0`, within 30 s
  (`:573-594,732-737`).
- **Call teardown:** no non-closed PC with transceivers, within 15 s (`:596-600,768`).
- **Case 7:** a `connected` PC with `pc.sctp` whose `localDescription.type === "offer"`, so the PWA was
  the data-channel offerer (`:825-828`).

### 11.3 The seven cases, step by step

Shared helpers:

- **`Pwa.open`:** goto, wait for `_peerId`, wait for the `Registered with relay` console line
  (`:405-482`).
- **`bothVerified`:** both the PWA console line and the bot's stderr `direct channel verified`, each
  within 20 s (`:607-612`).
- **`chatBothWays`:** the bot sends `send <pwa> hello from the desktop (<tag>)`; wait for the PWA
  `messages` row; then the PWA `openChat`, waits 100 ms, fills `#message-input` and awaits `sendMessage`;
  wait for the bot's `message` event (`:616-625`).

| Case | Steps | PWA role / timings |
|---|---|---|
| **1** PWA code → desktop (`:627-650`) | bot ready + registered → `Pwa.open` → `showCode()` (showView add-contact, showAddTab qr-show, read `#qr-share-code`) → bot `pair <code>` → bot `paired`, then bot path `Direct` (≤ 45 s) → PWA `contacts` has the bot (≤ 30 s) → `bothVerified` → `chatBothWays` | presenter, answerer (the bot scans and force-offers). The pairing window must accept the bot's offer; the bootstrap must materialise via `trial_decrypt` |
| **2** desktop code → PWA paste (`:652-672`) | bot `code` → `pasteCode(code)` → PWA `contacts` has the bot (≤ **10 s**) → bot `contact` (≤ 45 s) → `Direct` → `bothVerified` → `chatBothWays` | scanner, force-offerer. The contact must be stored within 10 s of the paste |
| **3** sender queue (`:674-687`, continues case 2) | `browser.close()` → bot path `Offline` (≤ 45 s) → bot `send … sent while you were away` must report `Queued` → relaunch the same profile → `Pwa.open` again → the PWA receives the message (≤ **60 s**) | identity, contacts and **sessions must survive the restart**. After registering the PWA must reconnect to the bot (presence, initiator rule or the bot's probe) |
| **4** tampered binding (`:693-725`) | `Pwa.open(tamperBinding)` → presenter code → bot `pair` → bot `paired` → bot notice containing `failed its end-to-end check` (≤ 45 s) → path `BindingFailed` (≤ 10 s); never `Direct`; a further bot send stays `Queued` | the PWA must send a binding built from `pc.localDescription.sdp` read **after** the connection is up |
| **5** desktop video-calls PWA (`:739-769`) | pair as in case 1 with `media` → `Direct` + verified → bot `call <pwa> video` → `Outgoing` → `#incoming-call-notification` visible (≤ 20 s) → `acceptIncomingCall()` → bot `Active` (≤ 30 s) → bot receives ≥ 50 audio and video RTP → the PWA decodes (above) → bot `hangup` → the PWA closes its call PCs (≤ 15 s) | callee |
| **6** PWA video-calls desktop (`:770-787`) | `openChat(bot)` + `initiateCall(bot, true)` → bot `Incoming` with `video: true` (≤ 30 s) → bot `accept` → `Active` → media both ways → `hangupCall()` → bot `Ended(RemoteHungUp)` (≤ 15 s) | caller, ICE controlling. Skipped with `INTEROP_PWA_CALLS=0` |
| **7** PWA offers with media held (`:801-841`) | `Pwa.open` with `media`; `getUserMedia({audio, video})` held → bot `code` → paste → bot `contact`, `Direct` → `bothVerified` → the PWA's connected data PC is the offer side → `chatBothWays` → sleep 5 s → `chatBothWays` again | scanner, offerer, under Chromium renomination |

After all cases: no page logged `[WebRTC] ICE servers from` (`:860-865`). In `mdns` mode the bot must
have seen mDNS answers (`:867-871`).

### 11.4 Proposed stable test-hook contract for the new app

> **Status.** Implemented: `web/src/engine/test-hooks.ts`, installed only by the test build of
> the web app (`denext task build:test`; the production export fails its build if the bundle
> names the hooks). The driver takes `INTEROP_APP=web` to run the same seven cases against the
> web app; `class Web` in `apps/desktop/interop/pwa-interop.mjs` lists, case by case, what it
> checks in place of each old-PWA internal. It acts through the interface (first run, the
> add-a-contact screen, the composer, the call buttons) and reads the app's database
> (`parolnet-web`) and the hooks; the `data-testid`s below that the app uses are
> `pairing-code`, `pairing-code-input`, `pairing-code-submit`, `composer-input`,
> `composer-send`, `incoming-call`, `call-accept`, `call-decline`, `call-hangup`,
> `contact-item` (with `data-peer-id`) and `message-item` (with `data-direction`).

The aims:

- keep the seven cases runnable with a small driver diff;
- stop depending on internal IDB layout and incidental log wording.

The hooks can be compiled in always: they expose nothing beyond what the UI already shows. Or they can
be gated on a build flag; the driver can tell which through `window.__parolnetTest.version`.

**1. `window.__parolnetTest`.** All methods are async; ids are lower-case 64-character hex.

| Member | Replaces | Contract |
|---|---|---|
| `version: 1` | — | contract version |
| `ready(): Promise<{peerId}>` | polling `window._peerId` | resolves once the identity is loaded |
| `relayRegistered(): boolean` and the event `parolnet:test` `{kind:'relay', state:'registered'}` | console `Registered with relay` | true after `registered`, false on disconnect |
| `showPairingCode(): Promise<string>` | `showView` + `showAddTab` + `#qr-share-code` | navigates to the presenter screen, opens the pairing window, returns the hex code |
| `pairWithCode(code): Promise<void>` | `showView` / `showAddTab` / input / `connectViaPassphrase` | the same path as the paste UI |
| `contacts(): Promise<string[]>` | IDB `contacts` | peer ids |
| `messages(peerId): Promise<{direction:'sent'\|'received', text, state}[]>` | IDB `messages` | the history as the UI shows it |
| `sendText(peerId, text): Promise<{state}>` | `openChat` + `#message-input` + `sendMessage` | sends through the same code path as the composer |
| `pathState(peerId): 'offline'\|'connecting'\|'direct'\|'failed'\|'binding-failed'` | console `direct channel verified with` | `direct` only after the binding verifies |
| `incomingCall(): {peerId, callId, video} \| null` | `#incoming-call-notification` | — |
| `acceptCall()`, `rejectCall()`, `startCall(peerId, video)`, `hangup()` | the window functions | the same behaviour as the UI buttons |
| `callState(): 'idle'\|'outgoing'\|'incoming'\|'connecting'\|'active'` | — | — |
| `iceServers(): RTCIceServer[]` | console `[WebRTC] ICE servers from` | the servers in use. Must be `[]` in the harness |

**2. `data-testid` attributes**, for UI-level tests and as a fallback for the driver:

| `data-testid` | Element |
|---|---|
| `pairing-code` | text of the presenter's hex code |
| `pairing-code-input` | paste field |
| `pairing-code-submit` | paste submit button |
| `composer-input` | message input |
| `composer-send` | send button |
| `incoming-call` | the ringing banner (present or visible only while ringing) |
| `call-accept` | accept button |
| `call-decline` | decline button |
| `call-hangup` | hang-up button |
| `contact-item`, with `data-peer-id` | contact list rows |
| `message-item`, with `data-direction` | message rows |

**3. Console lines.** Keep these exact strings as a stable, documented contract, since the driver's
failure reports also print the console:

- `Registered with relay. Profile: <p>`;
- `[WebRTC] direct channel verified with <id8>`;
- `[WebRTC] ICE servers from <url>`, logged only when servers are actually learned.

**4. Platform invariants the driver relies on:**

- `RTCPeerConnection` is looked up on `window` at construction (§11.1);
- the binding reads `pc.localDescription` live;
- the relay is at same-origin `/ws`;
- STUN comes only from same-origin `/turn-credentials`, with no third-party fallback;
- the identity, sessions and contacts persist in the browser profile across a relaunch (case 3).

**5. The driver change.** Replace the `Pwa` methods (`:516-604`) with calls into `__parolnetTest`, and
point `pwaDir` and the artefact check (`:87,210-214`) at the new app's build output.
