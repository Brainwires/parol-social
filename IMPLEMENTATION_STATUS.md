# ParolNet Implementation Status

### Document Status: CURRENT CODE SNAPSHOT
### Date: 2026-11-20 (milestone M0)

This document records what the repository implements today versus what the protocol
specifications and the plan describe. The `specs/` directory is the design target; not every
specification is wired into the PWA, the relay server or the desktop client yet.

## Summary

ParolNet is being repositioned (M0) from a censorship-circumvention messenger into a general-purpose,
decentralized, end-to-end encrypted communication system: calls, messages, files and data channels,
with Rust crates, a federated relay, GPUI desktop clients and the PWA. See [README.md](README.md) and
[THREAT_MODEL.md](THREAT_MODEL.md) (version 1.0).

It is pre-release and unaudited. The PWA sends end-to-end encrypted messages over the relay
WebSocket and WebRTC data channels; native clients do not exist yet beyond the M0 video spike.

## Workspace

The root Cargo workspace has 15 members; the desktop app is a separate workspace.

| Crate | Current role |
|------|--------------|
| `parolnet-crypto` | AEAD, HKDF, identity keys, X3DH, Double Ratchet, sender keys |
| `parolnet-protocol` | Wire types, CBOR codec, padding, gossip/message/address types |
| `parolnet-transport` | Native TLS and WebSocket transport building blocks |
| `parolnet-mesh` | Gossip, peer manager, store-forward, UDP broadcast discovery |
| `parolnet-relay` | Relay cells, circuit primitives, onion encryption helpers, relay directory, federation |
| `parolnet-core` | Client/session/bootstrap APIs, media/file/group helpers, panic wipe helpers |
| `parolnet-wasm` | Browser bindings for crypto/session/bootstrap/core functions |
| `parolnet-relay-server` | Axum WebSocket relay. Default signaling-only profile (registration, SDP/ICE between online peers, presence push, directory read, STUN URIs; resource bounds per PNP-001 §10.6); opt-in relay profile adds store-forward, tokens, onion cells, gossip, TURN credentials, federation |
| `parolnet-authority-cli` | Authority key and relay endorsement CLI |
| `parolnet-cli` | Headless test client (QR bootstrap, messaging over the relay) |
| `parolnet-clause`, `parolnet-conformance` | Spec-clause attribute and the conformance suite |
| `parolnet-rtc` | **New (M0, extended in M1).** Async driver for the sans-I/O `webrtc-rs-rtc` engine |
| `parolnet-store` | **New (M1).** Encrypted native persistence: SQLite with SQLCipher, key in the OS keychain or a key file; identity, contacts, sessions, messages, queue, settings |
| `parolnet-app` | **New (M1).** Headless client core: identity, pairing, signaling, direct data channels, 1:1 chat |
| `parolnet-media` | **New (M1).** Call media for native clients: frames, capture traits and synthetic sources, resampler, Opus, AEC3 / noise suppression / gain (sonora, pure Rust), the audio duplex path; opt-in features for libvpx VP8, cpal, nokhwa |
| `xtask` | Clause and test-vector tooling |
| `apps/desktop` (own workspace) | **New (M0/M1).** GPUI client: contacts, pairing, chat (UI v0); the M0 video spike behind `--spike` |

## Web app (`web/`): the client that replaces the PWA

Not deployed yet; `pwa/` is still the live client. [docs/web-port/app.md](docs/web-port/app.md)
lists what is owed before the switch (encryption at rest and a backup, migration or a notice
for people who have the old PWA, translations).

- **Engine** (`web/src/engine`, [docs/web-port/engine.md](docs/web-port/engine.md)): identity,
  relay client, PNP-003 pairing, one bound data channel per contact, 1:1 text with a sender-side
  queue (edit and take-back of what still waits), verification state, removal of a contact, the
  user's own TURN server, 1:1 calls, IndexedDB storage (plaintext at rest), one tab at a time.
- **App**: first run, add a contact (QR code made and scanned on the device, or a pasted code),
  conversations on real state, safety numbers, calls, settings, "open in another tab" with
  take-over; nine locales, English complete.
- **Desktop ↔ web app** (`INTEROP_APP=web node apps/desktop/interop/pwa-interop.mjs`, steps of
  the CI job `pwa-interop`; the same seven cases as the PWA matrix below, the web app driven
  through its interface):

  | | Chromium | Firefox | WebKit (Playwright, Linux) |
  |---|---|---|---|
  | Pairing both ways, chat, sender queue, refused tampered binding (cases 1-4) | pass | pass | pass |
  | Video calls both ways, VP8 + Opus decoded on both sides (cases 5-6) | pass | pass | pass |
  | Web-offered data channel while holding media (case 7) | pass | pass | pass |
  | Host candidates covered | mDNS names, loopback | mDNS names, loopback | plain address only |

- **Web ↔ web** (`web/tests/e2e/real.flows.ts`, the production export behind the production
  CSP with a real relay at the same origin, in the same three browsers): first run, pairing by
  paste and by camera, chat, the queue, unread counts, a video call, a second tab, settings,
  delete all data. No CSP violation, no console error, no request leaving the test server.
- Not covered: real Safari (macOS / iOS), a phone's camera, STUN / TURN paths in a browser,
  notifications (the permission cannot be granted in these runs).

## M1 (in progress): third slice, media

- **`parolnet-media`** (new, root workspace; default features pure Rust, so the workspace's CI
  jobs need no system library): see the crate's `lib.rs` for the module table. The libvpx VP8
  encoder / decoder and the test pattern moved here from `apps/desktop`.
- **Echo cancellation**: WebRTC's AEC3, noise suppression and AGC2 through `sonora`, the
  pure-Rust port, behind `AudioProcessor`; a deterministic ERLE test (67 dB far end alone, 7 to
  9 dB in double talk, near-end tone within 2 dB) runs in `cargo test --workspace`.
- **Desktop**: camera capture with a test-pattern fallback, one audio thread with the render
  stream as AEC3's reverse stream, device menus, camera off / on, self-view, `--media-check`.
  **Not verified on real devices or on screen**: the dev machine opens no window, camera or
  microphone; the camera and device paths compile on macOS arm64 and run with synthetic sources.
  See the manual checklist in [docs/m1-desktop.md](docs/m1-desktop.md).

## M1 (in progress): first slice

See [docs/m1-desktop.md](docs/m1-desktop.md) for what runs end to end, the tests and the next slice.

- **`parolnet-app`** (new): identity load / create, the PWA's QR / code pairing (PNP-003 +
  PNP-001 §5.3.1), the relay's signaling-only profile (register by challenge, `watch` /
  `presence`, non-trickle `rtc_offer` / `rtc_answer`, `rtc_ice`), one direct WebRTC connection per
  contact with the PWA's `parolnet` data channel and JSON frames, 1:1 chat as PNP-001 TEXT
  envelopes, a sender-side queue (PWA limits) flushed when the channel opens, and the
  "no direct path" state. State lives in `parolnet-store` (below); the first slices' plaintext
  JSON file and identity file are imported and removed on first start.
- **`parolnet-store`** (new, third slice): one SQLCipher-encrypted SQLite database per data
  directory for the identity secret, contacts, ratchet sessions, history, the sender queue and
  settings. Random 256-bit key held by a key provider: the OS keychain (`keyring`; what the
  desktop app uses), an owner-only key file (headless peers; weaker, it sits next to the
  database) or memory (tests); the provider kind is fixed when the store is created. Version
  table and forward migrations, incremental transactional writes on a writer thread (WAL,
  synced commits), import of the plaintext layout, `wipe`. SQLCipher's cipher is C
  (CommonCrypto on Apple systems, vendored OpenSSL libcrypto elsewhere): storage encryption,
  not part of the pure-Rust E2EE layer. Not exercised yet: the keychain path on a real
  keychain (an opt-in test exists, `tests/keychain.rs`), Windows builds of the vendored
  OpenSSL, key rotation, and a UI for "delete all data" / a lost key.
- **`parolnet-rtc`**: server-reflexive candidates from STUN (binding request on the connection's
  socket before its loop starts), text data-channel messages, the channel label on open,
  `default_local_ip`. Engine pin `v0.22.0+brainwires.5` (was `.3`; `.5` follows ICE renomination).
- **TURN, user-supplied only** (PNP-001-MUST-082): `parolnet-rtc` gathers a relay candidate from
  the TURN server the user configured (UDP, long-term credentials, `rtc-turn` driven on the
  connection's socket) and has a relay-only ICE policy; `parolnet-app` stores `TurnSettings` and
  applies it to data and call connections; the desktop has the Settings pane. Nothing but STUN
  URIs is taken from a relay. TURN over TCP / TLS is M4.
- **Re-probing after `peer_offline`** (PNP-001-SHOULD-019): a contact the relay called offline
  with no presence push behind it is offered to again with backoff under a probe budget.
- **Desktop**: chat UI v0 (contact list with path badges, pairing screen with QR code and code
  entry, chat view with delivery state, rename, retry, the no-path message).
- **Desktop ↔ PWA browser matrix** (`apps/desktop/interop/pwa-interop.mjs`, CI job `pwa-interop`,
  headless on ubuntu-latest with fake media devices; the seven cases are listed in
  [docs/m1-desktop.md](docs/m1-desktop.md)):

  | | Chromium | Firefox | WebKit (Playwright, Linux) |
  |---|---|---|---|
  | Pairing both ways, chat, sender queue, refused tampered binding (cases 1-4) | pass | pass | pass |
  | Video calls both ways, VP8 + Opus decoded on both sides (cases 5-6) | pass | pass | pass |
  | PWA-offered data channel while holding media (case 7) | pass | pass | pass |
  | Host candidates covered | mDNS names, loopback | mDNS names, loopback | plain address only |

  Not covered: real Safari (macOS / iOS), WebKit's mDNS candidates, STUN / TURN paths in a browser.

## M0

- **`parolnet-rtc` skeleton.** One tokio task per peer connection owns its UDP socket and the
  engine's timers; commands in (offer, answer, remote candidates, data, keyframe requests, stats),
  events out (local description, states, tracks, RTP, data-channel messages). Host candidates on
  the bound socket only; srflx / TURN gathering, multiple sockets and the virtual-time mode are M1.
  A loopback test connects two drivers and exchanges data-channel messages.
- **Engine pin.** `rtc` from `Brainwires/webrtc-rs-rtc` tag `v0.22.0+brainwires.1` (git dependency).
- **Desktop spike** (`apps/desktop`). A GPUI window shows a VP8 stream that headless Chromium sends
  through `webrtc-rs-rtc`; libvpx decodes it; macOS draws an IOSurface-backed NV12 `CVPixelBuffer`
  with `gpui::surface()`, other platforms a BGRA `RenderImage`. Verified on macOS arm64 (headless
  decode and the pixel-buffer path); the window and the other four targets run in the dispatched
  `desktop-spike.yml` workflow. Findings and go / no-go notes: [docs/m0-spike.md](docs/m0-spike.md).
- **Licence gate.** `cargo-deny` (`deny.toml`, `apps/desktop/deny.toml`) runs in CI: permissive
  licences only, MPL-2.0 only for three named crates GPUI brings, no GPL / LGPL / AGPL.
- **Codec2 is opt-in.** The `codec2` crate is LGPL-2.1, so `parolnet-core` builds it only with the
  `codec2` feature (off by default); PNP-011 removes Codec2 in M1.
- **`mesh` feature.** `parolnet-core`'s dependency on `parolnet-mesh` sits behind a `mesh` feature
  (on by default, so nothing changes for existing users; the desktop client will build without it).
  A `hardened` feature for the onion circuit / bridge / traffic-shaping modules is **not** in yet:
  the relay node's handshake and pool are built on the onion module, so separating them needs a
  design pass (M1).

## Current User-Facing Path

The current PWA path is:

1. Browser loads `pwa/index.html`, JavaScript, WASM, and service worker assets.
2. Identity keys are generated or restored through WASM.
3. QR bootstrap can establish a Double Ratchet session between contacts.
4. Messages are encrypted in WASM when a session exists.
5. Encrypted payloads are sent through the relay server's `/ws` endpoint or a WebRTC data channel.
6. The relay server forwards or buffers JSON messages keyed by PeerId.

This path provides end-to-end content encryption when a Double Ratchet session exists. It does not provide the full anonymity, traffic-shaping, or relay-path metadata protections described by PNP-004 and PNP-006.

## Implemented Or Mostly Implemented

- Ed25519 identity keys and `PeerId = SHA-256(public_key)`.
- X3DH-style shared secret derivation and Double Ratchet sessions.
- ChaCha20-Poly1305 and AES-256-GCM wrappers.
- Bucket padding utilities in `parolnet-protocol`.
- CBOR header/envelope codec with size guards.
- Sender-key primitives for group messaging.
- QR bootstrap helpers exposed to WASM.
- Relay cell type, 512-byte cell serialization, onion encryption helpers, and partial circuit construction APIs.
- Relay directory descriptors, signature verification, authority endorsement types, and `/endorse` endpoint.
- Gossip envelope types, PoW checks, dedup/rate limiting, and store-forward primitives.
- PWA encrypted IndexedDB mode using AES-GCM and PBKDF2.
- PWA decoy calculator mode and panic wipe flow for browser storage/cache cleanup.
- Browser-side WebSocket transport: `WasmWebSocket` wrapper over `web_sys::WebSocket` with binary send/recv, async `wait_open`, and JS exports (`ws_connect`, `ws_send`, `ws_recv`, `ws_close`, `ws_is_open`, `ws_wait_open`).
- Relay health/reputation scoring: `RelayHealth` tracks latency EMA, success/failure counts, and computes weighted scores. `select_random()` and `select_guards()` use health-weighted selection.
- Relay federation: gossip-based directory propagation via `POST /directory/push`, bidirectional pull+push sync, dynamic peer discovery from directory entries (capped at 50), push rate limiting, `merge_descriptors()` API.
- 3-hop onion circuit support: WASM circuit builder constructs 3-hop circuits over WebSocket with X25519 handshake, layered ChaCha20-Poly1305 encryption, and HMAC key confirmation. Relay server processes binary relay cells (CREATE/EXTEND/DATA/DESTROY) with single-relay MVP mode. JS exports (`build_circuit`, `circuit_send`, `circuit_recv`, `circuit_destroy`) allow PWA to send messages through onion circuits.
- WebRTC: direct (host + srflx) with STUN by default, since the default relay profile is signaling-only and carries no user traffic; contacts on a direct connection see each other's IP address (the app shows a notice). Relay-only ICE is an opt-in setting that uses only a TURN server the user configures. `GET /turn-credentials` returns STUN URIs only on a signaling-only relay and time-limited HMAC-SHA1 TURN credentials on a relay-profile relay with `TURN_SECRET`. WASM `get_webrtc_privacy_config()` export.
- Domain fronting & bridge relays: `BridgeAddress` type with QR encoding, relay server bridge mode (unlisted, X-Forwarded-For proxy support), PWA bridge relay discovery and priority connection, WASM bridge address parsing exports. CDN-side domain fronting is an operational deployment concern (configure CDN to proxy to bridge relay).
- PWA group management UI: create/join/leave groups, group chat with per-group IndexedDB message history, member management modal, Chats/Groups tab switcher.
- PWA file receive flow: incoming file offer accept/decline, chunked receive with progress, download link on completion.
- PWA incoming call notifications: slide-down banner with accept/decline for 1:1 and group calls.
- PWA group calls: participant grid (up to 8), mute toggle, group call invitations via structured messages.
- PWA group file transfer: chunked send to all group members with progress tracking.
- Sender key distribution for group encryption via structured `_pn_type: 'sender_key'` messages.
- Reproducible builds: `Dockerfile.release` with pinned Rust 1.92.0, wasm-pack 0.13.1, and binaryen for deterministic WASM optimization. `scripts/reproducible-build.sh` builds artifacts and supports `--verify` mode (build twice, compare SHA-256 checksums). CI job generates and uploads release artifacts.

## Partial Or Prototype

- 3-hop relay circuits: library primitives exist and are now wired into the WASM/relay-server path via single-relay MVP mode; multi-relay path selection with real network hops is not yet used for normal PWA chat.
- Relay-to-relay directory sync uses bidirectional pull+push with dynamic peer discovery; the broader PNP-008 federation plan (consensus, voting) is not fully implemented.
- TLS camouflage is an approximation using rustls settings: cipher suite order, key exchange group order, ALPN and SNI follow a fingerprint profile, and profiles are loadable CBOR files (PNP-006 §5.4). Full browser ClientHello mimicry (extension order, GREASE, signature algorithms) is not possible with rustls and is not implemented. The library TLS transport frames its traffic as HTTP/2 DATA; the shipped clients' relay socket is a WebSocket over HTTP/1.1.
- Traffic shaping: the native client paces what it sends on direct data channels (one frame per padding interval, with jitter); constant-rate padding and dummy traffic exist for library circuits (`parolnet_relay::shaped`) and are not applied to the PWA relay path or by the web app.
- Mesh discovery is implemented as obfuscated UDP broadcast, not mDNS/BLE as written in older spec text.
- File, call, group call, and group file APIs: core/WASM primitives exist and PWA UI is wired for basic flows; messages are not yet routed through the full onion circuit protocol stack.
- WebRTC data channels connect directly over STUN by default; pairs behind NATs that block a direct path need a user-supplied TURN server (no TURN on the signaling-only public relay). Offline delivery is the sender-side queue; there is no relay mailbox in the default profile.

## Not Yet Implemented

- Production multi-relay 3-hop onion routing (current MVP simulates 3 hops on a single relay).
- Constant-rate cover traffic for browser relay connections.
- HTTP/2 framing for ParolNet cells on the current relay server.
- BLE bootstrap.
- mDNS `_parolnet._tcp` discovery. Current code uses UDP broadcast with an HMAC-derived tag and masked PeerId.
- Full domain fronting with HTTP/2 DATA frame wrapping (current bridge mode uses standard WebSocket over CDN proxy).
- Certificate pinning.

## Known Dependency Advisories

`cargo deny check advisories` reports advisories on the existing tree (for example
`hickory-proto` 0.24, `crypto-bigint` 0.5, `anyhow` 1.0.102) and unmaintained crates in GPUI's
graph. CI gates licences, sources and bans today; advisories become a gate once these are updated
(M1 dependency train).

## Documentation Rule

When docs say "ParolNet provides" a property, that statement must refer to code exercised by the current application path. When docs describe a protocol target, they should say "the protocol is designed to" or "PNP-00X specifies" unless the feature is wired into the current app.
