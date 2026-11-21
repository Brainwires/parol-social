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
- Camera capture (nokhwa / platform capture), echo cancellation (AEC3), device menus, camera on /
  off mid-call (renegotiation, E1), call stats in the UI.
- TURN: the user's own TURN server over UDP works (below). TURN over TCP and TLS on 443 (for
  networks that block UDP) is M4; `turn:...?transport=tcp` and `turns:` are refused by name. No
  ICE restart, so a connection made before the TURN settings changed is rebuilt, not migrated; a
  contact in a call keeps its connections until the next reconnect. The engine's TURN client
  keeps its own copy of the password in memory without wiping it. Every re-probe of an offline
  contact gathers candidates first (non-trickle), so with a TURN server set it allocates and
  releases on that server once per probe.
- IPv6 host candidates and several sockets; ICE restart on network change (E9).
- `parolnet-store` (SQLCipher, key in the OS keychain); today's JSON state file is owner-only but
  not encrypted. Files (PNP-010), multi-device.

## Next slice

1. Camera capture and AEC3 in a `parolnet-media` crate (the libvpx encoder / decoder and the test
   pattern move there), camera toggle mid-call.
2. `parolnet-store` behind the same `Store` interface (the TURN credential is in the JSON state
   file until then).
3. Interop in Firefox and WebKit.
