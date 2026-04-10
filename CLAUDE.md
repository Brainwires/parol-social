# ParolNet - Claude Code Instructions

## Project Overview

ParolNet is a decentralized, censorship-resistant communication platform. The top priority is **untrackable, obfuscated activity** so citizens in authoritarian regimes feel comfortable using it.

## Build & Test Commands

```bash
cargo check --workspace          # Verify compilation
cargo test --workspace           # Run all tests
cargo doc --workspace --no-deps  # Generate docs
wasm-pack build crates/parolnet-wasm  # Build WASM bindings
```

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
3. **All messages padded** - No unpadded message may reach the transport layer. Use `PaddingStrategy` trait.
4. **No compression before encryption** - Prevents CRIME/BREACH-style attacks.
5. **Constant-time crypto** - Use `subtle` crate for comparisons. ChaCha20-Poly1305 is the default AEAD (constant-time without AES-NI).
6. **No C dependencies for crypto** - Pure Rust only (no openssl, no system libraries).

## Dependency Policy

- Use latest stable versions of all dependencies
- No C dependencies for cryptographic operations
- `parolnet-crypto` and `parolnet-protocol` must remain WASM-compatible (no tokio dependency)
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

parolnet-wasm (depends on crypto + protocol, WASM target only)
```

## Protocol Specifications

The `specs/` directory contains formal RFC-style specifications (PNP-001 through PNP-006). These define the wire formats, state machines, and behavioral rules. Code implementations must match the specs. If the spec needs to change, update the spec document first, then update the code.
