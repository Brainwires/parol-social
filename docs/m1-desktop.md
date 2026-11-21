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
- TURN candidates for a user-supplied TURN server (`rtc-turn`); IPv6 host candidates and several
  sockets; ICE restart on network change (E9).
- `parolnet-store` (SQLCipher, key in the OS keychain); today's JSON state file is owner-only but
  not encrypted. Files (PNP-010), multi-device.

## Next slice

1. The manual media checklist on the three OSes; device choices in the settings screen; an
   adaptive jitter buffer and Opus FEC / DTX; audio-to-video upgrade by renegotiation.
2. `parolnet-store` behind the same `Store` interface; settings screen with the user's TURN server
   once `parolnet-rtc` gathers TURN candidates.
3. Interop in Firefox and WebKit.
