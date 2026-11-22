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
  add contacts by QR code or a pairing code, compare a short verification code with them while you
  do, and can compare safety numbers later. There is nothing to register.
- **Servers anyone can run.** Relays federate; you choose your home relay or run your own.
- **Signaling-only public relay.** By default a relay only helps contacts set up direct connections
  (registration, WebRTC offer / answer / ICE between two online contacts, presence, STUN URIs); no
  message, file, group, call or decoy traffic transits or is stored on it
  ([PNP-001 §10.5](specs/PNP-001-wire-protocol.md)). Content travels peer to peer, so a contact you
  connect to sees your IP address unless you relay through your own TURN server (Settings; the
  relay never offers one and the apps have none built in); messages to an offline
  contact wait on your device. Operators who want store-and-forward, tokens, TURN credentials or
  federation run the relay profile (`SIGNALING_ONLY=0`). A registration is signed for the relay
  it is made at (its `host:port`, which an operator sets in `RELAY_PUBLIC_NAMES`), so one relay
  cannot register you at another, and a signaling-only relay answers no HTTP request about who
  is online ([PNP-001 §10.7](specs/PNP-001-wire-protocol.md)).
- **Metadata, honestly stated.** Your home relay learns your `PeerId`, your IP address, when you are
  online and the `PeerId`s you exchange signaling with (and, on a relay-profile relay, envelopes). A media server (M2) learns who is in a room
  and packet sizes and timing. The default mode does **not** hide that you use ParolNet, resist
  traffic analysis, circumvent censorship or offer deniability. The experimental `hardened` mode
  (onion circuits, bridges, traffic shaping, messages only) is described with its limits in
  [THREAT_MODEL.md](THREAT_MODEL.md), appendix A.

## Architecture

```
apps/desktop (GPUI)      web/ (TS + wasm)        later: iOS / Android shells (UniFFI)
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
| `parolnet-protocol` | Envelopes, CBOR, message padding, the PNP-006 send scheduler (bandwidth modes, send slots, jitter) (wasm) | exists |
| `parolnet-transport`, `-relay`, `-mesh` | Relay connections, federation, directory, tokens; onion circuits (PNP-004: relay node and service, circuit builder and pool, descriptor publishing) with PNP-006 cover traffic, an HTTP/2-framed TLS transport and the gossip mesh (PNP-005: validation and forwarding, store-and-forward, sync, scoring, mDNS and UDP discovery). Library code and the opt-in relay profile; the default clients do not use them | exists |
| `parolnet-core` | Client library: bootstrap, sessions, groups, files | exists |
| `parolnet-wasm` | Browser bindings for the PWA | exists |
| `parolnet-relay-server` | Axum relay: signaling-only by default (register, SDP / ICE, presence, STUN URIs); opt-in relay profile with store-and-forward, federation, TURN credentials | exists |
| `parolnet-rtc` | Async driver for the sans-I/O [`webrtc-rs-rtc`](https://github.com/Brainwires/webrtc-rs-rtc) engine (native): sockets on every interface (IPv4 and IPv6), STUN and the user's TURN server, data channels, RTP with RTX, ICE restart, track renegotiation, the congestion controller's estimate, a statistics digest; runs on real sockets or, in virtual time, on `parolnet-simnet` | M1 |
| `parolnet-store` | Encrypted native persistence: SQLite with SQLCipher (bundled), database key in the OS keychain (`keyring`) or an owner-only key file on machines without one; identity, contacts, sessions, messages, sender queue, settings; schema migrations, incremental transactional writes, import of the earlier plaintext data directory, wipe | M1 |
| `parolnet-app` | Headless client core: identity, PNP-003 pairing (code or QR, verification code, the same exchange as the web app), signaling-only relay client, a direct data channel per contact bound to the E2EE session (DTLS fingerprints, PNP-001 §10.5.1), 1:1 encrypted chat paced by the PNP-006 bandwidth mode, sender-side queue, 1:1 voice / video calls, file transfer that survives a lost connection and a restart (PNP-010) | M1 |
| `apps/desktop` | GPUI desktop client: contacts, pairing, chat (UI v0), 1:1 calls with camera, echo cancellation and device menus; the M0 video spike behind `--spike` | M1 |
| `parolnet-media` | Call media for native clients (no dependency on the rest of the workspace): frames, the capture traits and synthetic sources, resampling, Opus, echo cancellation / noise suppression / gain (AEC3, pure Rust), the audio duplex path; behind opt-in features, VP8 through libvpx, microphone and speakers (cpal), camera capture (nokhwa) | M1 |
| `parolnet-transfer` | File transfer (PNP-010) without I/O, for native and wasm: the offer and its answers, sealed 64 KiB records (ChaCha20-Poly1305, STREAM nonces, a key per attempt), resume at the record the receiver names, the final SHA-256 check, limits. `parolnet-app` streams files from and to disk with it; the web app drives it through `parolnet-wasm` | M1 |
| `parolnet-simnet` | Test-only: a deterministic in-memory network (loss, jitter, reordering, a rate cap) that runs `parolnet-rtc` in virtual time, and the M1 call checks on it (setup, renegotiation, ICE restart, the estimate; 2% loss, 300 kbit/s cap, 100 ms jitter) | M1 |
| `parolnet-call` | Calls | M1 |
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
wasm-pack build crates/parolnet-wasm    # the wasm core (web/ builds it with `denext task build-wasm`)
cargo deny check licenses sources bans  # the licence gate (no GPL / AGPL)
```

The desktop app is its own Cargo workspace (it needs a newer toolchain and system libraries):

```bash
brew install libvpx                     # macOS; apt install libvpx-dev (+ X11/Wayland headers) on Linux;
                                        # vcpkg install libvpx:x64-windows-static-md on Windows
cd apps/desktop && cargo run --release  # see apps/desktop/README.md
```

### Relay server and web app (deployment)

The relay image builds everything from source: the relay binary, the wasm core and the web
app's static export (`web/out`), which nginx serves at `/pwa/` with its Content-Security-Policy
and cache rules, the relay behind it at the same origin. Nothing has to be built on the host
first. To deploy or update:

```bash
git pull && docker compose up -d --build
```

Build arguments: `AUTHORITY_PUBKEYS` (comma-separated hex Ed25519 keys) and
`AUTHORITY_THRESHOLD` are baked into the wasm core (the dev placeholder keys when empty);
`BUILD_COMMIT`, `BUILD_VERSION`, `BUILD_DATE` are printed by the container at startup. The
first build takes a while (Rust twice: the relay and the wasm core); later builds reuse the
Rust and Denext layers when only the app changes. `scripts/image-smoke.sh http://127.0.0.1:1411`
checks a running container (CI's `image` job runs it). See [server/README.md](server/README.md).

### Web app rewrite (`web/`)

The PWA is rewritten as a [Denext](https://denext.dev) app with a new design
([docs/ux/web-app.md](docs/ux/web-app.md)). `web/` is the whole client now: a UI-free engine
(identity, relay, pairing, the bound data channel, chat with its queue, verification, 1:1 calls,
IndexedDB storage; [docs/web-port/engine.md](docs/web-port/engine.md)) and the screens on it
(first run, adding a contact by QR code or pasted code, conversations, safety numbers, calls,
settings; [docs/web-port/app.md](docs/web-port/app.md)), exported as static files that run under
`/pwa/` behind a strict CSP. What it keeps on a device is encrypted at rest and can be locked
with a passphrase ([docs/web-port/at-rest.md](docs/web-port/at-rest.md), which also says what
that does not protect against); a device can be backed up to one encrypted file and restored
from it ([docs/web-port/backup.md](docs/web-port/backup.md)). Nine languages, eight of them
machine-translated and awaiting review. It passes the seven desktop ↔ browser interop cases in Chromium,
Firefox and WebKit. It is the client the relay image serves at `/pwa/`; the legacy vanilla-JS client it replaced
has been removed from the repository (what [app.md](docs/web-port/app.md#still-owed) lists as
owed still applies). See [web/README.md](web/README.md).

```bash
cd web
denext task build-wasm   # crates/parolnet-wasm -> web/public/wasm
denext task build:test   # the test build (state lab, test hooks) in web/out-test
denext task build        # the production export in web/out
denext task test         # unit tests; `denext task e2e` and `e2e:flows` run the three browsers
```

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
