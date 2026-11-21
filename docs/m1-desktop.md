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

## Known gaps

- **Fixed: the PWA calling the desktop.** When Chromium offers it is the ICE controlling side,
  and once it holds media permission it gathers on every interface and moves its nomination to
  another pair a moment after connecting; the engine's controlled agent kept its first selected
  pair, so media stopped after about a second. `webrtc-rs-rtc` `v0.22.0+brainwires.5` follows the
  later nomination; interop case 6 (the PWA video-calls the desktop) and case 7 (a data channel
  the PWA offers while it holds camera and microphone permission) run by default.
- Camera capture (nokhwa / platform capture), echo cancellation (AEC3), device menus, camera on /
  off mid-call (renegotiation, E1), call stats in the UI.
- TURN candidates for a user-supplied TURN server (`rtc-turn`); IPv6 host candidates and several
  sockets; ICE restart on network change (E9).
- Storage (`parolnet-store`, see "Storage" below): no settings UI for "Delete all data on this
  device" (`parolnet_app::delete_all_data` exists) or for a store whose key is gone from the
  keychain (the start error says so); no key rotation; the keychain path has run on no real
  keychain yet (opt-in test `crates/parolnet-store/tests/keychain.rs`), and the vendored OpenSSL
  build has not run on the Windows runners.
- Files (PNP-010), multi-device.

## Next slice

1. Camera capture and AEC3 in a `parolnet-media` crate (the libvpx encoder / decoder and the test
   pattern move there), camera toggle mid-call.
2. Settings screen: the user's TURN server once `parolnet-rtc` gathers TURN candidates, and
   "Delete all data on this device" over `parolnet-store`.
3. Interop in Firefox and WebKit.
