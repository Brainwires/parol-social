# ParolNet - Claude Code Instructions

## Project Overview

ParolNet is a general-purpose, decentralized, end-to-end encrypted communication system: 1:1 and group voice / video, screen share, messages, files and application-defined data channels. It ships as Rust crates, a federated relay anyone can run, GPUI desktop clients (`apps/desktop`) and the PWA. Everything is end-to-end encrypted, there is no account (no phone / email / username), keys live only on devices, relays and SFUs are untrusted, and an account spans several devices. See `THREAT_MODEL.md` (1.0) for what the default mode does and does not protect.

## Build & Test Commands

```bash
cargo check --workspace          # Verify compilation
cargo test --workspace           # Run all tests
cargo doc --workspace --no-deps  # Generate docs
wasm-pack build crates/parolnet-wasm  # Build WASM bindings
cargo deny check licenses sources bans  # Licence gate (no GPL / LGPL / AGPL)
```

The desktop app (`apps/desktop`) is its own Cargo workspace with its own toolchain pin
(`apps/desktop/rust-toolchain.toml`) and needs libvpx; build it from that directory. Its licence
gate is `cargo deny --manifest-path apps/desktop/Cargo.toml --config apps/desktop/deny.toml check
licenses sources bans`.

## Coding Conventions

- **Rust edition 2024**, MSRV 1.91
- **Error handling**: Use `thiserror` for error enums, propagate with `?`
- **Async**: Use `tokio` directly (no runtime abstraction)
- **Serialization**: CBOR via `ciborium` + `serde`
- **Traits**: Use `async-trait` for async trait methods
- **Logging**: Use `tracing` crate

## Security Invariants (ALWAYS ENFORCE)

These are non-negotiable and must be maintained in every change:

1. **No identifying registration** - `PeerId = SHA-256(Ed25519_pubkey)`. No phone numbers, emails, usernames, or any external identifiers anywhere in the codebase.
2. **Zeroize all key material** - Every struct holding secret key material MUST derive `Zeroize` and `ZeroizeOnDrop`.
3. **Messages are padded** - No unpadded message may reach the transport layer. Use `PaddingStrategy` trait. Media and bulk transfers (calls, PNP-010 file records) are not padded.
4. **No compression before encryption** - Prevents CRIME/BREACH-style attacks.
5. **Constant-time crypto** - Use `subtle` crate for comparisons. ChaCha20-Poly1305 is the default AEAD (constant-time without AES-NI).
6. **No C dependencies for E2EE crypto** - The end-to-end layer (`parolnet-crypto`, MLS, SFrame keying) is pure Rust (no openssl, no system libraries). The realtime engine's DTLS / SRTP provider is ring (C and assembly); a pure-Rust provider is optional engine work (E12).

## Dependency Policy

- Use latest stable versions of all dependencies
- No C dependencies for end-to-end cryptography (see invariant 6 for the engine's transport crypto)
- Licences: permissive only (MIT, Apache-2.0, BSD, ISC, Zlib, ...). No GPL / LGPL / AGPL, ever; MPL-2.0 only for the crates `deny.toml` names. `cargo-deny` enforces it in CI
- The realtime engine is `rtc` from `Brainwires/webrtc-rs-rtc`, pinned by git **tag** in the root `Cargo.toml`, never a branch. ParolNet never carries engine patches: fixes land in the fork with a release tag first
- GPUI is pinned exactly (`gpui-pre`, `gpui-component`) in `apps/desktop/Cargo.toml` with `Cargo.lock` committed; upgrades are their own change
- `parolnet-crypto`, `parolnet-protocol` and `parolnet-transfer` must remain WASM-compatible (no tokio dependency)
- Prefer audited, well-maintained crates from established projects (dalek-cryptography, RustCrypto)

## Documentation Requirements

- Keep `README.md` updated when adding new crates, changing architecture, or adding features
- Keep `CHANGELOG.md` updated with every meaningful change (new features, breaking changes, security fixes)
- Protocol specs in `specs/` are the source of truth for wire formats and behavior

## Crate Dependency Order

```
parolnet-crypto (no workspace deps, WASM-compatible)
  |
  v
parolnet-protocol (depends on crypto, WASM-compatible)
  |
  v
parolnet-transport (depends on crypto + protocol, native only)
  |
  +---> parolnet-mesh (+ transport)
  +---> parolnet-relay (+ transport)
  |
  v
parolnet-core (depends on all above)

parolnet-wasm (depends on crypto + protocol + transfer, WASM target only)

parolnet-transfer (PNP-010 file transfer, sans-I/O; no workspace deps, WASM-compatible: no tokio)

parolnet-rtc (native only; drives the sans-I/O `rtc` engine; no workspace deps)
  |
  +---> parolnet-simnet (test-only; an in-memory network that runs parolnet-rtc in virtual
          time, and the M1 call checks; + parolnet-media default features; `vpx` opt-in)
parolnet-store (native only; encrypted persistence: SQLite + SQLCipher, key in the OS keychain; no workspace deps)
  |
  v
parolnet-app (native; headless client core: crypto + protocol + core (no default features) + rtc + store
  + transfer)

parolnet-media (native only; call media; no workspace deps. Default features are pure Rust
  (Opus, AEC3, conversion); `vpx` (system libvpx), `audio-io` (cpal) and `camera` (nokhwa) are
  opt-in and must stay out of the default set: the workspace's CI installs no system libraries)

apps/desktop (own workspace; GPUI; depends on parolnet-app, parolnet-rtc and parolnet-media
  with `vpx`, `audio-io`, `camera`)
```

`parolnet-store` encrypts local storage with SQLCipher, whose cipher is C (CommonCrypto on Apple
systems, a vendored OpenSSL libcrypto elsewhere). Security invariant 6 covers the E2EE layer
(`parolnet-crypto`, `parolnet-protocol`); at-rest storage encryption is outside it.

`parolnet-core` features: `native` (default), `mesh` (default; store-forward and LAN discovery),
`codec2` (opt-in, LGPL-2.1, being removed), `wasm`.

## Protocol Specifications

The `specs/` directory contains formal RFC-style specifications (PNP-001 through PNP-011; PNP-010 is file transfer and supersedes PNP-007 §7; PNP-011 is 1:1 calls and supersedes PNP-007's call and media sections). These define the wire formats, state machines, and behavioral rules. Code implementations must match the specs. If the spec needs to change, update the spec document first, then update the code.
