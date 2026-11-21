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

The root Cargo workspace has 14 members; the desktop app is a separate workspace.

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
| `parolnet-app` | **New (M1).** Headless client core: identity, pairing, signaling, direct data channels, 1:1 chat |
| `xtask` | Clause and test-vector tooling |
| `apps/desktop` (own workspace) | **New (M0/M1).** GPUI client: contacts, pairing, chat (UI v0); the M0 video spike behind `--spike` |

## M1 (in progress): first slice

See [docs/m1-desktop.md](docs/m1-desktop.md) for what runs end to end, the tests and the next slice.

- **`parolnet-app`** (new): identity load / create, the PWA's QR / code pairing (PNP-003 +
  PNP-001 §5.3.1), the relay's signaling-only profile (register by challenge, `watch` /
  `presence`, non-trickle `rtc_offer` / `rtc_answer`, `rtc_ice`), one direct WebRTC connection per
  contact with the PWA's `parolnet` data channel and JSON frames, 1:1 chat as PNP-001 TEXT
  envelopes, a sender-side queue (PWA limits) flushed when the channel opens, and the
  "no direct path" state. State is a JSON file in the data directory, **not yet encrypted at
  rest** (`parolnet-store` replaces it).
- **`parolnet-rtc`**: server-reflexive candidates from STUN (binding request on the connection's
  socket before its loop starts), text data-channel messages, the channel label on open,
  `default_local_ip`. Engine pin `v0.22.0+brainwires.5` (was `.3`; `.5` follows ICE renomination).
- **Desktop**: chat UI v0 (contact list with path badges, pairing screen with QR code and code
  entry, chat view with delivery state, rename, retry, the no-path message).

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
- TLS camouflage is an approximation using rustls settings. Full browser ClientHello mimicry, HTTP/2 DATA framing, GREASE behavior, and updatable fingerprint profiles are not implemented.
- Traffic shaping exists as constants/helpers and some jitter, but constant-rate padding and dummy traffic are not applied end-to-end to the current PWA relay path.
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
