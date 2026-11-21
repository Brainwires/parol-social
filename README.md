# ParolNet

**Calls, messages, files and data between people and apps, end-to-end encrypted, on servers anyone
can run, with no account.**

ParolNet is a decentralized, end-to-end encrypted communication system: 1:1 and group voice and
video, screen sharing, messages, file transfer, and application-defined data channels. It ships as

- **Rust crates** others can build on (identity, sessions, the realtime engine driver, transfer),
- **a federated relay** anyone can run (signaling, store-and-forward, directory, TURN credentials),
- **desktop clients** built with [GPUI](https://www.gpui.rs/) for macOS, Windows and Linux,
- **the PWA**, which stays a first-class client on the same protocol.

It stays strong where it counts: everything is end-to-end encrypted, there is no phone number, email
or username, keys live only on devices, relays and media servers are treated as untrusted, and one
account spans several devices.

> *Parol*: *parole* (word) in French, *пароль* (password) in Russian, *parola* in Italian and
> Turkish.

**Status: pre-release, milestone M0.** The crypto, protocol, relay and PWA code is substantial; the
native clients, media engine integration and multi-device support are being built now. Nothing is
audited yet (a third-party audit is planned before 1.0). Read
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) and [THREAT_MODEL.md](THREAT_MODEL.md) before
relying on it.

---

## What it protects, and what it does not

- **Content.** Messages, files, calls and data channels are end-to-end encrypted between devices.
  Relays, TURN servers and (from M2) media servers see ciphertext only.
- **Identity.** An identity is an Ed25519 key; its `PeerId` is the SHA-256 of the public key. You
  add contacts by QR code or a pairing code and verify them with safety numbers. There is nothing
  to register.
- **Servers anyone can run.** Relays federate; you choose your home relay or run your own.
- **Signaling-only public relay.** By default a relay only helps contacts set up direct connections
  (registration, WebRTC offer / answer / ICE between two online contacts, presence, STUN URIs); no
  message, file, group, call or decoy traffic transits or is stored on it
  ([PNP-001 §10.5](specs/PNP-001-wire-protocol.md)). Content travels peer to peer, so a contact you
  connect to sees your IP address unless you add your own TURN server; messages to an offline
  contact wait on your device. Operators who want store-and-forward, tokens, TURN credentials or
  federation run the relay profile (`SIGNALING_ONLY=0`).
- **Metadata, honestly stated.** Your home relay learns your `PeerId`, your IP address, when you are
  online and the `PeerId`s you exchange signaling with (and, on a relay-profile relay, envelopes). A media server (M2) learns who is in a room
  and packet sizes and timing. The default mode does **not** hide that you use ParolNet, resist
  traffic analysis, circumvent censorship or offer deniability. The experimental `hardened` mode
  (onion circuits, bridges, traffic shaping, messages only) is described with its limits in
  [THREAT_MODEL.md](THREAT_MODEL.md), appendix A.

## Architecture

```
apps/desktop (GPUI)      pwa/ (JS + wasm)        later: iOS / Android shells (UniFFI)
        \                    |                         /
         parolnet-app   (headless app core: accounts, conversations, calls as observable state)
            |        |          |            |            |
   parolnet-core  parolnet-call  parolnet-transfer  parolnet-mls  parolnet-store
                  |        \
              parolnet-media  parolnet-rtc ── webrtc-rs-rtc (sans-I/O) ── rtc-turn / rtc-stun / rtc-ice
                                   |
   relay-server (+ feature sfu → parolnet-sfu)      coturn (until a Rust TURN server)
```

| Crate | Role | State |
| --- | --- | --- |
| `parolnet-crypto` | Ed25519 identity, X3DH, Double Ratchet, AEAD, KDF (pure Rust, wasm) | exists |
| `parolnet-protocol` | Envelopes, CBOR, message padding (wasm) | exists |
| `parolnet-transport`, `-relay`, `-mesh` | Relay connections, federation, directory, tokens; onion circuits and mesh (optional) | exists |
| `parolnet-core` | Client library: bootstrap, sessions, groups, files | exists |
| `parolnet-wasm` | Browser bindings for the PWA | exists |
| `parolnet-relay-server` | Axum relay: signaling-only by default (register, SDP / ICE, presence, STUN URIs); opt-in relay profile with store-and-forward, federation, TURN credentials | exists |
| `parolnet-rtc` | Async driver for the sans-I/O [`webrtc-rs-rtc`](https://github.com/Brainwires/webrtc-rs-rtc) engine (native): host + STUN candidates, data channels, RTP | M1 in progress |
| `parolnet-store` | Encrypted native persistence: SQLite with SQLCipher (bundled), database key in the OS keychain (`keyring`) or an owner-only key file on machines without one; identity, contacts, sessions, messages, sender queue, settings; schema migrations, incremental transactional writes, import of the earlier plaintext data directory, wipe | M1 |
| `parolnet-app` | Headless client core: identity, PWA-compatible pairing, signaling-only relay client, a direct data channel per contact bound to the E2EE session (DTLS fingerprints, PNP-001 §10.5.1), 1:1 encrypted chat, sender-side queue, 1:1 voice / video calls | M1 |
| `apps/desktop` | GPUI desktop client: contacts, pairing, chat (UI v0); the M0 video spike behind `--spike` | M1 first slice |
| `parolnet-media`, `-call`, `-transfer`, `-simnet` | Media, calls, PNP-010 transfer, network simulator | M1 |
| `parolnet-mls`, `-sframe`, `-sfu` | MLS groups and devices, SFrame, the SFU | M2 |

Media: Opus audio with echo cancellation (AEC3), VP8 video (VP9 / AV1 later), DTLS-SRTP end to end
for 1:1 and mesh calls, SFrame keyed from MLS for SFU calls.

## Protocol specifications

The specs in [`specs/`](specs/) are the source of truth for wire formats and behaviour.

| Spec | Name | Notes |
|------|------|-------|
| [PNP-001](specs/PNP-001-wire-protocol.md) | Wire Protocol | Envelopes, padding of messages |
| [PNP-002](specs/PNP-002-handshake-protocol.md) | Handshake Protocol | X3DH + Double Ratchet (1:1 until MLS replaces it in M4) |
| [PNP-003](specs/PNP-003-bootstrap-protocol.md) | Bootstrap Protocol | QR / passphrase pairing |
| [PNP-004](specs/PNP-004-relay-circuit.md) | Relay Circuit Protocol | Onion circuits: experimental, `hardened` only |
| [PNP-005](specs/PNP-005-gossip-mesh.md) | Gossip/Mesh Protocol | Store-and-forward, LAN discovery: optional (`mesh`) |
| [PNP-006](specs/PNP-006-traffic-shaping.md) | Traffic Shaping Protocol | Experimental, `hardened` only |
| [PNP-007](specs/PNP-007-media-file-transfer.md) | Media and File Transfer | To be superseded by PNP-010 (files) and PNP-011 (calls) in M1 |
| [PNP-008](specs/PNP-008-relay-federation.md) | Relay Federation | Directory, federation, bridges |
| [PNP-009](specs/PNP-009-group-communication.md) | Group Communication | Sender keys: replaced by MLS (PNP-012) in M2 |

## Building

```bash
cargo check --workspace                 # the library, relay and CLI crates
cargo test --workspace
wasm-pack build crates/parolnet-wasm    # the PWA's wasm
cargo deny check licenses sources bans  # the licence gate (no GPL / AGPL)
```

The desktop app is its own Cargo workspace (it needs a newer toolchain and system libraries):

```bash
brew install libvpx                     # macOS; apt install libvpx-dev (+ X11/Wayland headers) on Linux;
                                        # vcpkg install libvpx:x64-windows-static-md on Windows
cd apps/desktop && cargo run --release  # see apps/desktop/README.md
```

### Relay server and PWA

```bash
npm run build:all        # the wasm and the PWA bundle
npm run docker:rebuild   # + the relay image, then restarts the container
```

For PWA work without rebuilding the image, a `docker-compose.override.yml` (gitignored) that
bind-mounts `./pwa` into the running container lets you edit and reload; `npm run build:wasm`
rebuilds only the wasm. See [GETTING-STARTED.md](GETTING-STARTED.md) and
[STARTUP-GUIDE.md](STARTUP-GUIDE.md).

## Roadmap

| Milestone | Scope |
| --- | --- |
| **M0** | GPUI + `webrtc-rs-rtc` spike, licence gate, repositioning (this) |
| **M1** | Desktop 1:1: pairing, messages, PNP-010 file transfer, voice and video calls with the PWA |
| **M2** | MLS groups and multi-device, SFrame, the SFU, group calls |
| **M3** | Screen sharing |
| **M4** | 1:1 on MLS, fuzzing, external audit, 1.0 |

The milestone notes live in [`docs/`](docs/); the M0 findings are in
[docs/m0-spike.md](docs/m0-spike.md). The project's earlier strategy and roadmap documents are kept
in [`docs/archive/`](docs/archive/).

## Licence

MIT OR Apache-2.0, at your option. Dependencies must carry a permissive licence; `cargo-deny`
enforces it in CI.
