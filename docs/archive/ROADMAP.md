# ParolNet Roadmap

> **ParolNet** — "Word/Password Network"
> A secure and resilient communication platform promoting free expression and open access to information.
>
> The name "Parol" carries meaning across language barriers: *parole* (speech/word) in French, *пароль* (password) in Russian, *parola* (password) in Turkish, *parola* (word) in Italian, and shares roots with Spanish *palabra* and Portuguese *palavra*. It embodies the dual mission: **free speech protected by strong security**.

---

## Phase 1: Research & Problem Definition (Weeks 1-4)

### Key Issues to Investigate
- **Censorship**: DNS blocking, IP blocking, deep packet inspection (DPI), app store removals
- **Surveillance**: Metadata collection, traffic analysis, endpoint compromise
- **Privacy**: Data minimization, identity protection, forward secrecy
- **Resilience**: Single points of failure, centralized infrastructure dependencies

### Existing Landscape to Study
- Signal Protocol (end-to-end encryption gold standard)
- Tor / I2P (traffic anonymization)
- Matrix/Element (federated messaging)
- Briar (peer-to-peer, mesh-capable)
- Cwtch (metadata-resistant)
- IPFS / libp2p (decentralized content distribution)

### Key Question
Where are the gaps? Common ones include usability, censorship resistance at the transport layer, and offline/mesh capability.

---

## Phase 2: Goal Setting & Architecture (Weeks 5-8)

### High-Impact Focus Areas

| Goal | Difficulty | Impact |
|------|-----------|--------|
| Pluggable transport library (obfuscates traffic to bypass DPI) | Medium | High |
| Mesh messaging protocol (works without internet) | High | High |
| Censorship-resistant relay network | High | Very High |
| E2EE group communication with metadata protection | High | High |
| Educational toolkit / developer SDK for adding E2EE to apps | Medium | Medium |

### Architecture Principles
- **Zero-trust**: Assume the network and servers are compromised
- **Decentralized**: No single point of failure or control
- **Metadata-minimal**: Protect who talks to whom, not just content
- **Offline-first**: Work in degraded network conditions
- **Open source**: Auditable, forkable, community-owned

---

## Phase 3: Development Plan (Weeks 9-24+)

### Example: Pluggable Transport + Mesh Messaging Library

#### Milestone 1 — Core Crypto & Protocol (Weeks 9-14)
- Implement or integrate Double Ratchet (Signal Protocol)
- Define message format (protobuf/CBOR)
- Build peer discovery (mDNS for local, DHT for internet)
- Transport abstraction layer

#### Milestone 2 — Censorship Resistance (Weeks 15-18)
- Pluggable transports: obfs4-style, domain fronting, WebSocket disguise
- Traffic shaping to defeat DPI fingerprinting
- Bootstrap mechanisms that don't rely on a single DNS lookup

#### Milestone 3 — Mesh & Offline (Weeks 19-22)
- Bluetooth LE / Wi-Fi Direct peer-to-peer
- Store-and-forward for delay-tolerant networking
- Gossip protocol for multi-hop message delivery

#### Milestone 4 — Usability & Integration (Weeks 23-24+)
- SDK with clear APIs (Rust core + FFI bindings for mobile)
- Reference mobile app (Flutter or native)
- Documentation and threat model writeup

---

## Phase 4: Implement & Iterate

- **Security audits**: Budget for at least one third-party audit before public release
- **Threat modeling**: Use STRIDE or similar frameworks, update continuously
- **Dogfooding**: Use it yourself in realistic conditions
- **Bug bounty**: Even informal ones help

---

## Phase 5: Promote & Sustain

- Publish the threat model and design docs openly
- Engage with organizations like EFF, Access Now, OTF (Open Technology Fund)
- Apply for grants (OTF, NLnet, Mozilla Foundation)
- Present at conferences (DEF CON, CCC, RightsCon)
- Build a contributor community with good onboarding docs

---

## Suggested Tech Stack

- **Core**: Rust (memory safety, no runtime, good for FFI)
- **Networking**: libp2p or custom over QUIC
- **Crypto**: rust-crypto / ring / libsodium bindings
- **Mobile**: Kotlin/Swift with Rust FFI, or Flutter
- **Build**: Reproducible builds (for trust)
