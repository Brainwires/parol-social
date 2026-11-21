# M1: headless core, desktop chat and calls, PWA interop

Status of M1 after its second slice (plan: `plans/parolnet-gpui.md` M1, revised for the
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
  video-calls the bot; it decoded every VP8 frame of the bot's test pattern (310 in 10 s, no
  decode errors) and 8 s of Opus, and the bot received the desktop's libvpx-encoded test pattern.
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
and receives RTP. The desktop sends a synthetic test pattern (640x360, 30 fps) through a libvpx
VP8 encoder (a C shim compiled against the system's headers, `apps/desktop/src/vp8enc.c`) and the
default microphone through opus-rs (48 kHz mono, 20 ms); it plays the contact's Opus through cpal
and shows its video in the call panel.

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
- Camera capture (nokhwa / platform capture), echo cancellation (AEC3), device menus, camera on /
  off mid-call (renegotiation, E1), call stats in the UI.
- TURN candidates for a user-supplied TURN server (`rtc-turn`); IPv6 host candidates and several
  sockets; ICE restart on network change (E9).
- `parolnet-store` (SQLCipher, key in the OS keychain); today's JSON state file is owner-only but
  not encrypted. Files (PNP-010), multi-device.

## Next slice

1. Camera capture and AEC3 in a `parolnet-media` crate (the libvpx encoder / decoder and the test
   pattern move there), camera toggle mid-call.
2. `parolnet-store` behind the same `Store` interface; settings screen with the user's TURN server
   once `parolnet-rtc` gathers TURN candidates.
