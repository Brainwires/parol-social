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
- **Desktop ↔ PWA** (`apps/desktop/interop/pwa-interop.mjs`, CI job `pwa-interop` on
  ubuntu-latest): the bot (`parolnet-app`'s headless peer, the same core the GPUI app runs)
  against the real PWA in headless Chromium through the relay binary.
  1. PWA code → desktop: bootstrap over the data channel, messages both ways.
  2. Desktop code → the PWA's "Paste Code" tab (which now pairs like a camera scan), messages
     both ways.
  3. Sender queue across a PWA restart.
  4. A PWA that binds a fingerprint it did not see is refused by the desktop ("failed its
     end-to-end check"), and nothing queued goes out on that channel.
  5. The desktop video-calls the PWA (Chromium's fake camera and microphone): the desktop receives
     Chromium's VP8 and Opus, Chromium decodes the desktop's VP8 test pattern and Opus tone; the
     desktop hangs up and the PWA closes its call connection.

  It runs twice in CI: as Chromium ships (host candidates are mDNS `<uuid>.local` names; the
  desktop resolves them, and the test requires mDNS answers to have arrived) and with loopback
  candidates (`--allow-loopback-in-peer-connection`, the default on a developer's Mac, where no
  multicast and no LAN address is used).
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

## Known gaps

- **Fixed: the PWA calling the desktop.** When Chromium offers it is the ICE controlling side,
  and once it holds media permission it gathers on every interface and moves its nomination to
  another pair a moment after connecting; the engine's controlled agent kept its first selected
  pair, so media stopped after about a second. `webrtc-rs-rtc` `v0.22.0+brainwires.5` follows the
  later nomination; interop case 6 (the PWA video-calls the desktop) and case 7 (a data channel
  the PWA offers while it holds camera and microphone permission) run by default.
- Camera, microphone and speaker paths are unverified on real devices (the checklist above);
  the call panel's new controls are unverified on screen.
- Adding or removing a track mid-call (an audio call that becomes a video call): camera off /
  on keeps the video track and sends black. The engine at `v0.22.0+brainwires.5` has
  `RTCRtpTransceiver::set_direction` with negotiation-needed and re-binds a sender after a
  renegotiation; what is missing is on our side: `parolnet-rtc` exposes no renegotiation, the
  call signals carry one offer and one answer, and the PWA does not renegotiate either.
- The playout buffer is a fixed prebuffer, not an adaptive jitter buffer (no time stretching,
  no packet-loss concealment beyond Opus's own); Opus in-band FEC and DTX are not switched on.
  Call stats in the UI.
- A device chosen in the call panel is not remembered across restarts (the settings screen).
- No macOS app bundle yet: the usage strings are embedded in the executable.
- TURN: the user's own TURN server over UDP works (below). TURN over TCP and TLS on 443 (for
  networks that block UDP) is M4; `turn:...?transport=tcp` and `turns:` are refused by name. No
  ICE restart, so a connection made before the TURN settings changed is rebuilt, not migrated; a
  contact in a call keeps its connections until the next reconnect. The engine's TURN client
  keeps its own copy of the password in memory without wiping it. Every re-probe of an offline
  contact gathers candidates first (non-trickle), so with a TURN server set it allocates and
  releases on that server once per probe.
- IPv6 host candidates and several sockets; ICE restart on network change (E9).
- Storage (`parolnet-store`, see "Storage" below): no settings UI for "Delete all data on this
  device" (`parolnet_app::delete_all_data` exists) or for a store whose key is gone from the
  keychain (the start error says so); no key rotation; the keychain path has run on no real
  keychain yet (opt-in test `crates/parolnet-store/tests/keychain.rs`), and the vendored OpenSSL
  build has not run on the Windows runners.
- Files (PNP-010), multi-device.

## Next slice

1. The manual media checklist on the three OSes; device choices in the settings screen; an
   adaptive jitter buffer and Opus FEC / DTX; audio-to-video upgrade by renegotiation.
2. Settings: "Delete all data on this device" over `parolnet-store`.
3. Interop in Firefox and WebKit.
