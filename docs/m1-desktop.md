# M1: headless core, desktop chat and calls, PWA interop

Status of M1 after its third slice (plan: `plans/parolnet-gpui.md` M1, revised for the
signaling-only relay). What runs, how it is tested, what it does not do yet.

## What runs end to end

- **Two `parolnet-app` instances against the relay binary in its default signaling-only profile**
  (`crates/parolnet-app/tests/two_peers.rs`): register by challenge; pair with the PWA's QR
  payload (presenter shows the code, scanner enters it); the scanner offers, the presenter accepts
  because its pairing window is open; the `parolnet` data channel opens; the bootstrap envelope
  materializes the presenter's session; both sides bind the channel (below); chat flows both ways
  as PNP-001 TEXT envelopes; one side shuts down, the other's message waits in its sender queue;
  the first side restarts from its data directory, the relay's presence push tells the other side,
  the queue flushes. An offer from a stranger is ignored. A video call: ring, accept, VP8 and Opus
  RTP both ways, hang up; a declined call.
- **Desktop ↔ PWA in Chromium, Firefox and WebKit** (`apps/desktop/interop/pwa-interop.mjs`,
  CI job `pwa-interop` on ubuntu-latest): the bot (`parolnet-app`'s headless peer, the same core
  the GPUI app runs) against the real PWA in a headless browser (Playwright;
  `INTEROP_BROWSER=chromium|firefox|webkit`) through the relay binary. The same seven cases in
  every browser, none skipped; the PWA and the desktop core needed no per-browser change.
  1. PWA code → desktop: bootstrap over the data channel, messages both ways.
  2. Desktop code → the PWA's "Paste Code" tab (which now pairs like a camera scan), messages
     both ways.
  3. Sender queue across a PWA restart.
  4. A PWA that binds a fingerprint it did not see is refused by the desktop ("failed its
     end-to-end check"), and nothing queued goes out on that channel.
  5. The desktop video-calls the PWA (the browser's fake camera and microphone): the desktop
     receives the browser's VP8 and Opus, the browser decodes the desktop's VP8 test pattern and
     Opus tone (decoded frames and received audio samples from `getStats`); the desktop hangs up
     and the PWA closes its call connection.
  6. The PWA video-calls the desktop: the same checks; the PWA hangs up.
  7. A data channel the PWA offers while it holds a live camera and microphone stream: bindings
     verified, messages both ways, and again after the connection has settled.

  | Browser (headless, Playwright) | Candidates | Cases 1-7 |
  |---|---|---|
  | Chromium (full browser, `chromium` channel) | mDNS names; loopback | pass; pass |
  | Firefox | mDNS names; loopback | pass; pass |
  | WebKit (Playwright's Linux build, WPE + libwebrtc) | plain host address | pass |

  Chromium and Firefox run twice in CI: as shipped (host candidates are mDNS `<uuid>.local`
  names; the desktop resolves them, and the test requires mDNS answers to have arrived) and with
  loopback candidates (Chromium `--allow-loopback-in-peer-connection`, Firefox
  `media.peerconnection.ice.loopback`; the default on a developer's Mac, where no multicast and
  no LAN address is used). WebKit runs once: Playwright's Linux build gathers the default-route
  address as a plain host candidate. Fake media: Chromium's fake device flags, Firefox's
  `media.navigator.streams.fake`, WebKit's mock capture devices. No request leaves the machine
  (Chromium: resolver rule; Firefox and WebKit: a proxy that refuses every host but 127.0.0.1),
  and a run fails if a page learned a STUN or TURN server.
- **The desktop app's call media** (`parolnet-desktop --call-check`, `apps/desktop/interop/
  desktop-call.mjs`, in the `desktop-spike` workflow): the window's call session without a window
  video-calls the bot with synthetic media (the test pattern as a 720p YUYV camera through
  conversion, scaling and libvpx; a tone through the audio path with AEC3 and Opus; playback into
  nothing); it decoded every VP8 frame of the bot's test pattern (309 in 10 s, no decode errors)
  and 8 s of Opus, sent 247 video frames and 410 Opus packets, and the bot received the desktop's
  VP8. `parolnet-desktop --media-check` (same workflow) runs the echo measurement below and the
  synthetic camera through libvpx with no network.
- **Desktop UI** (default mode): contact list with path badges, pairing screen, chat view with
  delivery state, rename, retry, Verify (the safety number), Call / Video call when the path is
  direct, the incoming-call banner (Accept / Decline) and the call panel (status, the remote video
  tile through the M0 decode and render path, Mute, Hang up). The window itself was not opened on
  the dev Mac (no GUI windows there); its pure helpers are unit-tested and `--call-check` runs the
  same media code.

## Data-channel binding (PNP-001 v0.12 §10.5.1)

The data channel's SDP crosses the signaling relay in plaintext. Once the channel is open each side
sends a CHANNEL_BINDING envelope (message type 0x14, CBOR `{v, local, remote}`) inside the ratchet
session naming the DTLS fingerprints of its local description and of the remote description it
applied. The receiver compares them with its own view; a mismatch, or no binding within 20 s,
closes the connection. Before verification only the scanner's bootstrap envelope and the binding
cross the channel: queued messages, new messages and call signals wait, and the path is not shown
as direct. The desktop and the PWA (through `parolnet-wasm`'s `channel_binding_body` /
`channel_binding_verify`) run the same `parolnet-protocol::channel_binding` code; conformance
tests in `crates/parolnet-conformance/tests/pnp_001_channel_binding.rs`. Calls need no separate
binding: their SDP travels inside the session.

Safety numbers (PNP-002 v0.4 §10): 60 digits from both PeerIds, the PWA's existing derivation,
with a vector in `specs/vectors/PNP-002/safety_number.json` checked by Rust, the PWA's JS and the
wasm build.

## Calls

A call runs on its own WebRTC connection (as the PWA's `call.js`), set up by `CALL_SIGNAL`
envelopes in the PWA's JSON (`offer` / `answer` / `ice` / `hangup` / `reject`) on the verified data
channel. The core does no capture or decoding: the client feeds encoded frames to a `FrameSink`
and receives RTP. The desktop's side of that line is `parolnet-media` (`crates/parolnet-media`)
driven by `apps/desktop/src/call.rs`:

- **Video out.** The camera through `nokhwa` when the machine has one, in the mode closest to
  the send size (640x360 at 30 fps; `PAROLNET_VIDEO=720p` sends 1280x720), converted to I420
  (NV12, YUYV, MJPEG, RGB), cropped and scaled, encoded by libvpx (the C shim
  `crates/parolnet-media/src/vp8/vp8enc.c`, compiled against the system's headers). Capture runs
  on its own thread into a latest-frame slot: an encoder that falls behind skips pictures. With
  no camera, or with synthetic media (`--call-check`, `PAROLNET_SYNTHETIC_MEDIA=1`), the test
  pattern stands in, delivered as a 720p YUYV camera would so the same conversion runs.
  **Camera off** releases the device and sends one black frame a second; a camera that fails or
  is refused does the same and says why in the call panel.
- **Audio.** One thread runs both directions in 10 ms frames at 48 kHz
  (`parolnet_media::duplex`): microphone → resample → `process_capture` → 20 ms Opus frames, and
  the contact's Opus → playout buffer (40 ms prebuffer after an underrun, trimmed to 80 ms past
  300 ms) → `process_render` → resample → speakers. The render side is pulled by the output
  queue, so each frame passes the processor's reverse stream just before it is played, and the
  stream delay told to the processor is the output queue plus the device latencies plus the
  capture backlog. The processor is WebRTC's AEC3, noise suppression and AGC2 in the pure-Rust
  port `sonora`. The sound card's callbacks only move samples through wait-free rings. **Mute**
  sends silence and keeps the microphone running through the processor.
- **Devices.** Camera, microphone and speaker menus in the call panel, switchable mid-call; the
  choice holds for later calls in the same run. A device that goes away is closed and reported;
  audio then tries the system default once.

### Echo cancellation, measured

`parolnet_media::selftest` plays speech-shaped noise as the far end, feeds the microphone its
echo through three reflections (42, 55 and 71 ms; the strongest 6 dB down), and after 9 s adds
a near-end 1 kHz tone. No device and no clock are involved, so the result is the same on every
run.

| | far end alone (ERLE) | double talk (ERLE) | near-end tone |
| --- | --- | --- | --- |
| AEC3, `sonora` 0.3.0, direct 10 ms frames | 67.5 dB | 8.6 dB | -1.9 dB |
| the same through the duplex path, devices at 44.1 kHz | 67.4 dB | 6.8 dB | -2.2 dB |
| the same, devices at 48 kHz | 67.7 dB | 7.6 dB | -2.1 dB |
| reference: WebRTC's C++ module (`webrtc-audio-processing` 2.1.0, macOS arm64), direct | 53.2 dB | 7.7 dB | -1.7 dB |
| passthrough | 0 dB | 0 dB | 0 dB |

The tests require 30 dB, 5 dB and ±4 dB. During double talk AEC3 holds its suppressor back to
keep the near-end voice, so only the linear filter's share is left; the C++ module behaves the
same. `cargo test -p parolnet-media` and `parolnet-desktop --media-check` run it.

### Manual checklist (nothing below runs in CI or on the dev machine)

CI has no camera, microphone, speakers or (outside the spike workflow) screen, and the dev Mac
opens none of them. Before a release, on each OS:

1. Video call with a built-in and a USB camera: the picture is upright, in colour, not
   stretched; the self-view matches. macOS asks for camera access once and shows the usage
   string. (macOS is the riskiest: `nokhwa`'s AVFoundation backend is used through its packed
   4:2:2 path only, see `crates/parolnet-media/src/camera.rs`.)
2. Camera off and on; switch cameras mid-call; unplug the camera mid-call (black, a reason in
   the panel, no crash).
3. Voice call on laptop speakers, both sides talking: no echo of the contact's voice comes
   back; switch microphone and speaker mid-call; unplug a headset mid-call.
4. A 44.1 kHz output device and a 16 kHz Bluetooth headset microphone.
5. The device menus, the Camera button and the self-view tile look right (they were built
   without opening a window).

## Storage (`parolnet-store`, third slice)

Everything the client keeps is in one database in the data directory, `store.db`, encrypted page
by page with SQLCipher (AES-256-CBC and HMAC-SHA512 per page, the WAL included): the identity
secret, contacts, ratchet sessions, history, the sender queue, settings. Beside it sits
`store.json`, plaintext, which names the key provider and the key's random id and nothing else.

- **The key** is 256 random bits made on first run. The desktop app keeps it in the OS keychain
  (`KeyStorage::Keychain`: macOS Keychain, Windows Credential Manager, Secret Service on Linux;
  entry `social.parol.ParolNet` / `store-key-<id>`). The bot, `--call-check` and tests use
  `KeyStorage::File`: `store.key`, owner-only, in the data directory. That is **weaker**: whoever
  copies the directory has the key too; it exists for machines without a keychain service. A
  store keeps the kind it was created with: opening a keychain store with `--key-storage file`
  (or the reverse) is refused, and a store whose key is missing is reported, never recreated.
  A Linux desktop without a Secret Service (no GNOME Keyring / KWallet running) fails to start
  with the keychain; `--key-storage file` on a new data directory is the explicit way around.
- **Decision: SQLCipher, not application-level record encryption.** The alternative (plain
  SQLite, each record sealed with ChaCha20-Poly1305) would leave table sizes, row counts per
  contact and write patterns readable on disk; SQLCipher leaves the file size. Its cost is a C
  cipher: on Apple systems SQLCipher uses CommonCrypto from the system (nothing extra to build);
  elsewhere it links OpenSSL's libcrypto, built from source by `openssl-src` and linked
  statically, so the binary needs no system OpenSSL. Checked: macOS arm64 (build and tests),
  Linux arm64 in a `rust:1.91-bookworm` container (build, 3.5 minutes cold). Not yet run: the
  Windows x64 / arm64 builds. If the vendored OpenSSL proves a problem there, the fallback is the
  record-encryption design behind the same `parolnet-store` API.
- **Scope of CLAUDE.md invariant 6** ("no C dependencies for crypto"): it governs the E2EE
  layer (`parolnet-crypto`, `parolnet-protocol`), which stays pure Rust. Storage encryption on
  the device is a separate layer and uses SQLCipher's C cipher.
- **Build requirements this adds**: a C compiler everywhere (already needed). Off Apple systems,
  `perl` and `make` for OpenSSL (present on the Ubuntu runners and in the `rust` images). On
  Windows, a native perl (Strawberry Perl; Git Bash's own perl cannot run OpenSSL's Configure,
  so the workflow sets `OPENSSL_SRC_PERL`) and `nmake` from the Visual Studio tools.
- **Writes**: the engine still calls `save_state` after each change; the store works out the
  changed rows and a dedicated writer thread commits them in one transaction (WAL, every commit
  synced). A thread rather than `spawn_blocking`: writes must land in order and one thread on one
  channel gives that without a runtime. Shutdown waits for the last commit.
- **Migration**: a data directory from slices 1-2 (`identity.key`, `state.json`) is imported on
  first open, read back inside the transaction, then the plaintext files are overwritten with
  zeros and removed, the identity last. On SSDs and copy-on-write filesystems overwriting is
  best effort.

## The user's own TURN server; contacts the relay called offline

- **TURN is never the relay's.** The public relay is signaling-only and announces STUN URIs only;
  the app would ignore TURN URIs and credentials from any relay, and has no TURN server built in.
  Settings → "Relay through my own TURN server" takes the address (`turn:host:port`, UDP), a
  username and a password of a server the user runs or rents, and a switch:
  - off: the relay candidate is one more candidate, used by pairs with no direct path;
  - "use only this server": relay candidates only. Contacts see the server's address instead of
    the device's; nothing is sent to, or accepted from, any other address, and no host or
    server-reflexive candidate (or related address) is signalled. If the server gives no relay
    candidate the contact shows "no path" with a notice; there is no fallback to direct.

  The settings are saved with the app state and apply at once: existing data connections are
  rebuilt. `parolnet-rtc` drives the engine's sans-I/O `rtc-turn` client on the connection's own
  socket (allocate, permissions, channel binds, refresh, release on close). Tests: an in-process
  TURN server (`parolnet_rtc::test_turn`) under `crates/parolnet-rtc/tests/turn.rs` and
  `crates/parolnet-app/tests/two_peers.rs` (pairing, chat and a video call relay-only on both
  sides; restart; clearing; an unreachable server); CI job `turn-coturn` repeats the relay-only
  exchange against coturn.
- **Offline is provisional without a presence push.** The relay reports presence only between
  mutual watchers. When the only evidence is a `peer_offline` answer, the contact is offered to
  again with backoff (15 s doubling to 5 min for contacts the user waits for, 15 min for the
  rest) under a shared budget of at most 72 probes an hour, until it answers or a presence push
  arrives (`parolnet_app::reconnect`). `two_peers.rs` reproduces the old bug behind a proxy that
  drops the client's `watch` frames: nothing queued, no push, the contact comes back, and the
  connection is rebuilt by a probe.

## Connections that follow the network (PNP-011 sections 5.5 and 8)

- **Candidates.** A connection binds one UDP socket per usable local address, IPv4 and IPv6,
  and announces each as a host candidate (`parolnet_rtc::net::select_addresses`): no loopback
  or link-local address unless the machine has nothing else; per interface and /64 one IPv6
  address, the temporary one the system itself uses and never the hardware-derived one beside
  it; the default route's addresses first, IPv6 before IPv4, at most six. Every socket asks
  the STUN servers of its own family; the user's TURN allocation lives on the first socket
  whose family the server has. `AppConfig::bind_ip` (the bot's `--bind`, the tests) pins one
  address as before. Remote mDNS names are resolved as before.
- **Noticing a change.** The core polls the interface list every 2 s and counts a new address
  set once two polls agree (`parolnet_rtc::NetworkMonitor`). Polling, not the systems' push
  notifications: the route socket (macOS, BSD), netlink (Linux) and `NotifyIpInterfaceChange`
  (Windows) are three implementations to keep correct, the one crate that wraps two of them
  (`if-addrs`, MIT OR BSD-3-Clause, used here for the interface list) has none for Apple
  systems, and listing the interfaces is one system call. So a change is acted on 2 to 4 s
  after it happened. `AppHandle::network_changed()` does the same on request.
- **ICE restart before teardown.** On a change (and when a connection reports that it lost its
  path) the relay client is asked at once whether its socket lives, and ICE is restarted in
  place: on the data connection through a second `rtc_offer` / `rtc_answer`, on a call through
  `reoffer` / `reanswer` inside the session. The driver binds the addresses the machine has
  now, gathers again and offers new credentials; DTLS, SRTP and SCTP continue, on the old pair
  until the restart selects a new one. The receiver applies a restart offer to the connection
  it has only when the connection is verified and the offer carries the DTLS fingerprints its
  channel binding covers; anything else is a new connection, as before. Crossing restarts are
  settled by the designated initiator (data) and the caller (call).
- **Fallback.** A restart that is not answered and connected within 15 s ends as before
  restarts existed: the data connection is rebuilt (with backoff), a call ends when its ICE
  fails. A restart offer made while the relay is away is sent when the relay is back.
- **Only between peers that say so.** The data channel's identity frame lists `ice-restart`,
  a call's `offer` / `answer` lists `renegotiate`. The web app and the PWA list neither (and
  ignore both): with them nothing is restarted or renegotiated and everything works as it did
  (`two_peers.rs`, with one side started with `AppConfig::renegotiation = false`; the browser
  interop). The web engine's `networkChanged()` reconnects its relay socket and no more; for
  it to restart ICE it has to list the feature and implement sections 7 and 8 of PNP-011.
- **The path state stays honest.** A connection without a working pair shows "connecting"
  from the moment ICE says so, and "direct" again when a pair is selected; a restart on a
  path that still works changes nothing on screen.
- **Not covered.** A relay-only connection whose TURN allocation was on the address that
  went away is not restarted (the allocation cannot be moved): it is rebuilt. TURN over TCP /
  TLS is still M4.

## Renegotiation, adaptation, quality (PNP-011 sections 7, 9 and 10)

- **Camera off and on, audio to video.** `AppHandle::set_call_video`: with a contact whose
  app renegotiates, an audio call gains a video section (the contact's side receives until it
  turns its own camera on the same way), and a camera that is turned off stops its stream.
  With any other contact a video call keeps its stream and black is sent, as before, and an
  audio call cannot gain video. The desktop's Camera button does this; an audio call shows it
  when the contact's app can add video. A `reoffer` not answered in 10 s is taken back.
- **Bitrate.** A call connection runs the engine's TWCC-driven congestion control (trendline
  filter, AIMD; 300 kbit/s to start, 100 kbit/s to 2.5 Mbit/s). Its estimate reaches the call
  session as `MediaEvent::TargetBitrate`; libvpx's rate is set to nine tenths of what the
  estimate leaves after 80 kbit/s of audio (`parolnet_app::video_bitrate_for`), never above
  the picture size's own rate. Video is repaired over RTX. Received audio is de-jittered in
  the driver (`parolnet_rtc::jitter`): in order, at the sender's pace, held as long as packets
  have recently been late (5 ms on a steady path, up to 400 ms).
- **Quality.** `AppEvent::CallQuality` once a second (RTT, loss each way, bitrates, the
  estimate, the selected pair's candidate types). The call panel shows one line, such as
  "Weak connection: packets are being lost, low bandwidth (relayed)", while loss exceeds 5%,
  the round trip 400 ms, or the estimate is under 200 kbit/s; nothing otherwise.

## The simulated network (`parolnet-simnet`)

A test-only crate: an in-memory internet whose hosts' uplinks lose, delay, jitter, reorder and
cap what they send, from a seeded generator, with deliveries ordered by time and sequence. A
host is a `parolnet_rtc::Network`, and the driver takes every instant from tokio's clock, so
the same driver that runs on UDP sockets runs there on a paused runtime in virtual time:
thirty seconds of call take about five seconds of CPU in a debug build and do not depend on
the machine's load. What the engine randomizes (ICE credentials, certificates, SSRCs) still
differs between runs, so a run is reproducible in its shape, not byte for byte. NAT is not
modelled.

`crates/parolnet-simnet/tests/m1.rs` puts two drivers in a call with `parolnet-media`'s
synthetic sources (the tone through Opus into the desktop's playout buffer, popped on the
clock as a sound card would; a rate-following video source through the engine's VP8
packetizer, or with `--features vpx` the test pattern through libvpx and back) and checks:

| Check | What is asserted |
| --- | --- |
| Call setup | connected in under 1 s over a 10 ms link with 50 ms signaling; first frame within 0.5 s; 30 frames a second; audio is the tone |
| Renegotiation (2% loss) | an audio call gains video in under 2 s, the other side adds its own, one side turns its off: the other is told and receives none; audio unaffected |
| ICE restart | one machine's address is replaced; the monitor reports it within 4 s; the restart connects on the new address within 2 s of being asked; video is back within 2 s; the connection never fails. The same move without a restart ends the call. A restart whose offer never arrives leaves the old path in use |
| Estimate | open link: never down, 1 Mbit/s after about 16 s, the maximum after 28 s. 300 kbit/s cap: the median between 150 and 330 kbit/s, never over 450; under 6% of the datagrams dropped. A cap that appears is followed in under 4 s, one that goes is climbed out of |
| 2% loss, 300 kbit/s cap, 100 ms jitter (three seeds each) | **video does not freeze**: never more than 2 s without a usable frame, at least 500 usable frames in 30 s, the video bitrate within the estimate's share. **Audio stays intelligible**: at least 92% of the played 20 ms windows are the tone that was sent at its level (most of their power at 440 Hz, level within 6 dB), no dropout over 0.4 s |

Measured (seed 1, debug build): 2% loss: 899 of 901 frames usable, longest gap 0.23 s, audio
98.4%; 300 kbit/s cap: 1196 of 1200 frames, gap 0.77 s, audio 95.6%, the estimate between
about 115 and 395 kbit/s; 100 ms jitter: 894 of 900 frames, gap 0.13 s, audio 100%, the estimate
at its floor (a delay-based estimator reads random jitter with reordering as congestion, so
video runs at its minimum there: adapted, not frozen).

## Known gaps

- **Fixed: the PWA calling the desktop.** When Chromium offers it is the ICE controlling side,
  and once it holds media permission it gathers on every interface and moves its nomination to
  another pair a moment after connecting; the engine's controlled agent kept its first selected
  pair, so media stopped after about a second. `webrtc-rs-rtc` `v0.22.0+brainwires.5` follows the
  later nomination; interop case 6 (the PWA video-calls the desktop) and case 7 (a data channel
  the PWA offers while it holds camera and microphone permission) run by default.
- Browser interop is headless with fake devices on Linux (CI) only: no real Safari (macOS / iOS)
  and no WebKit run on macOS; WebKit's mDNS host candidates are not exercised (Playwright's Linux
  WebKit exposes plain addresses), so mDNS resolution is covered by Chromium and Firefox; no
  browser run goes through STUN or TURN (host candidates only).
- Camera, microphone and speaker paths are unverified on real devices (the checklist above);
  the call panel's new controls are unverified on screen.
- Renegotiation and ICE restart exist between native clients only: the web app and the PWA
  do not list the features, so with them a camera that is off sends black, an audio call
  stays audio, and a network change is survived only by rebuilding. The desktop's Camera
  button in an audio call, the upgrade's tiles and the weak-connection line are unverified on
  screen (built without opening a window; their helpers are unit-tested).
- Engine findings (reported to the fork; ParolNet carries no patch): with transport-wide
  sequence numbers a NACK retransmission without RTX is refused by SRTP's index-reuse check
  and still counted as sent, so the peer's feedback reports it lost (worked around by
  negotiating RTX); the engine's other congestion controller and its pacer were tried and set
  aside (its delay detector rarely fired on a capped link, and the pacer queued audio behind
  video). Under 100 ms of random jitter the estimate sits at its floor.
- The pacer is not used: a keyframe leaves as a burst. The audio's share of the estimate is
  a constant (80 kbit/s), not measured.
- The playout buffer is a fixed prebuffer, not an adaptive jitter buffer (no time stretching,
  no packet-loss concealment beyond Opus's own); Opus in-band FEC and DTX are not switched on.
  In front of it the driver now de-jitters and reorders received audio (above).
- A device chosen in the call panel is not remembered across restarts (the settings screen).
- No macOS app bundle yet: the usage strings are embedded in the executable.
- TURN: the user's own TURN server over UDP works (below). TURN over TCP and TLS on 443 (for
  networks that block UDP) is M4; `turn:...?transport=tcp` and `turns:` are refused by name. A
  connection made before the TURN settings changed is still rebuilt, not migrated (a restart
  keeps its allocation); a contact in a call keeps its connections until the next reconnect. The engine's TURN client
  keeps its own copy of the password in memory without wiping it. Every re-probe of an offline
  contact gathers candidates first (non-trickle), so with a TURN server set it allocates and
  releases on that server once per probe.
- Storage (`parolnet-store`, see "Storage" below): no settings UI for "Delete all data on this
  device" (`parolnet_app::delete_all_data` exists) or for a store whose key is gone from the
  keychain (the start error says so); no key rotation; the keychain path has run on no real
  keychain yet (opt-in test `crates/parolnet-store/tests/keychain.rs`), and the vendored OpenSSL
  build has not run on the Windows runners.
- Files (PNP-010), multi-device.

## Next slice

1. The manual media checklist on the three OSes; device choices in the settings screen; an
   adaptive jitter buffer and Opus FEC / DTX; renegotiation and ICE restart in the web
   engine (PNP-011 sections 7 and 8).
2. Settings: "Delete all data on this device" over `parolnet-store`.
