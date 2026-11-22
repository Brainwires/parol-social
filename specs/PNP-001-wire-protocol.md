# PNP-001: ParolNet Wire Protocol

### Status: CANDIDATE
### Version: 0.17
### Date: 2026-11-21

---

## Changelog

**v0.17 (2026-11-21) — Registration is bound to the relay; no presence over HTTP on a signaling-only relay (wire-incompatible)**

- Added §10.7 "Registration". It specifies the register challenge, which earlier revisions left to the reference implementation, and changes what the client signs: no longer the relay's bare nonce but a register message made of a domain-separation label, the nonce, an optional pinned relay identity key and the **canonical name of the relay the client dialed** (`host:port`). A relay accepts an answer only for a name it is configured to serve. Before, a relay E that a client connected to could open a socket to another relay R in the client's name, pass R's nonce on as its own challenge and present the client's answer at R: E was then registered at R as that client and received its signaling. New clauses: **PNP-001-MUST-083** … **PNP-001-MUST-087**, **PNP-001-MAY-006**.
- §10.5: a signaling-only relay no longer serves `GET /peers/presence` and `GET /peers/lookup` (PNP-008 §10.5, §10.6). Both answered anyone, so anyone could ask whether a given PeerId was online. Presence on a signaling-only relay is now learned only over a registered socket. **PNP-001-MUST-071** is restated accordingly (same clause ID); relay-profile relays keep the endpoints behind request signatures (PNP-008 v0.8 §10.8).
- §10.5 (SHOULD-017): the reference relay's `GET /bootstrap` now returns an empty list in the relay profile too. It listed up to 20 online PeerIds to any caller: the same disclosure, unauthenticated.
- **Wire-incompatible** with v0.16 and earlier: the `register` answer carries a new `relay` field and a signature over a different message, so a v0.14 client cannot register at a v0.15 relay or the reverse. No deployed implementation of an earlier revision has to be kept working. MUST count: 87.

**v0.16 (2026-11-21) — Nonce catalog matches the session and sender-key layers**

- §3.3 (**PNP-001-MUST-006**, same clause ID) and the `N-SESSION` row of §9 now state the nonce the session layer has used throughout and PNP-002 §5.7 already describes: the first 8 bytes of the message's ratchet public key followed by `msg_number` (4 bytes, big-endian). The former text (`chain_index (4B) || seq_number (8B)`) described no implementation and named counters that do not exist in the Double Ratchet state. The `N-SENDERKEY` row of §9 now agrees with PNP-009 §5.4: the first 8 bytes of `SHA-256(signing_public_key)` followed by `chain_index` (4 bytes, big-endian). No wire change.
- §9 points to the limits of the counters that feed these nonces: PNP-002 §5.9, PNP-009 §5.9 and PNP-004 §5.1. No counter wraps.

**v0.15 (2026-11-21) — Message type 0x15 FILE_TRANSFER**

- §3.4: code `0x15 FILE_TRANSFER` is allocated to PNP-010 (File Transfer): the offer and the accept / decline / cancel / complete messages of a transfer whose records flow on a data channel of their own. The reserved range is now `0x16–0xFF`. Codes 0x02, 0x09 and 0x0A stay allocated; the file transfer they belonged to (PNP-007 §7) is superseded by PNP-010. No clause changes.

**v0.14 (2026-11-21) — The whole ratchet header is associated data (wire-incompatible)**

- §3.3: the session AEAD's associated data now starts with the complete Double Ratchet header, encoded as `ratchet_public_key (32) || prev_chain_len (u32 big-endian) || msg_number (u32 big-endian)`, in place of the 32-byte ratchet public key alone; the cleartext header bytes follow as before. **PNP-001-MUST-007** is restated accordingly (same clause ID); the rule itself is **PNP-002-MUST-042** (PNP-002 v0.6 §5.7). §3.1, §3.5, §3.6 and §3.9.2 (MUST-057) follow.
- Before, `prev_chain_len` was authenticated by nothing: whoever relayed the first message of a new sending chain could raise it (the receiver derived and stored keys for messages that do not exist) or lower it (late messages of the previous chain became undecryptable), and the message still verified. `msg_number` was bound only through the nonce.
- **Wire-incompatible** with v0.13 and earlier: a message protected under one version fails AEAD verification under the other. The `version` field of the cleartext header (§3.2) stays 0x01: no deployed implementation of an earlier revision exists, both reference clients are built from the same crates, and this specification defines no negotiation of envelope versions. MUST count unchanged: 82.

**v0.13 (2026-11-21) — Client ICE policy: TURN is the user's own; re-probing after `peer_offline`**

- §10.5 gains "TURN is user-supplied": a client never takes a TURN server from a signaling-only relay and ships none; the only TURN server it uses is one the user configured, either as one more candidate or, in relay-only mode, as the only path, with no fallback to a direct connection when that server gives no relay candidate. **PNP-001-MUST-082**
- §10.5 gains "Presence without a push": a `peer_offline` answer that no `presence` push backs is provisional, so the client offers again with exponential backoff and jitter under a budget well below the relay's signaling caps, whether or not messages are queued. Before, a contact that did not (yet) watch back, or lay beyond the 256 watched ids, stayed "offline" until the user intervened. **PNP-001-SHOULD-019**
- MUST count: 82.

**v0.12 (2026-11-20) — Direct data-channel binding**

- Added §10.5.1 "Direct Data-Channel Binding". On a signaling-only relay the data channel's SDP crosses the relay in plaintext, so a hostile relay could replace both DTLS fingerprints and terminate DTLS on each side. Each peer now sends a CHANNEL_BINDING message (new code 0x14) inside the end-to-end encrypted session, on the channel itself, naming its own DTLS fingerprints and the ones it received; the receiver compares them with its own view and drops the connection on a mismatch or when no binding arrives.
- New clauses: **PNP-001-MUST-079** … **PNP-001-MUST-081**, **PNP-001-SHOULD-018**. MUST count: 81.

**v0.11 (2026-11-20) — Signaling-only relay profile; resource bounds for every relay**

- Added §10.5 "Signaling-Only Relay Profile". A relay in this profile only helps peers establish direct connections: registration, WebRTC SDP / ICE exchange between two online peers, presence, directory reads and STUN URIs. It accepts no `message` / `gossip` frames and no onion cells, holds no store-and-forward buffer, mints no Privacy Pass tokens, issues no TURN credentials and does not federate, so no user content transits or rests on it. It is the default profile of the reference relay; the full feature set (now called the *relay profile*) is an explicit operator opt-in.
- Added §10.6 "Resource Bounds" with frame-size, rate, connection, registration and storage caps that apply to every relay, closing unbounded-memory and unmetered-forwarding paths reachable by anonymous clients.
- New clauses: **PNP-001-MUST-070** … **PNP-001-MUST-078**, **PNP-001-SHOULD-016**, **PNP-001-SHOULD-017**. §10.2 issuance accounting now points at MUST-078 for per-address issuance limits. MUST count: 78.

**v0.10 (2026-04-19) — Client-relay WS liveness, queued-response semantics, token epoch hygiene**

- Added §10.3 "Client-Relay WebSocket Liveness" formalizing the application-layer ping/pong heartbeat between a client and its home relay. Prior drafts assumed TCP keepalive (PNP-006) would suffice, but observed stuck-state bugs in the reference PWA showed that a silently-dead WebSocket can leave `relayConnected` reading true for hours — clients kept writing to a dead socket, the relay kept the peer in its `local` presence map, and inbound messages vanished. The new ping/pong + 40 s dead-threshold + 60 s presence reap closes that window.
- Added **PNP-001-MUST-065** (client MUST ping every 20 s), **PNP-001-MUST-066** (client MUST treat WS dead after 40 s silence from server), **PNP-001-MUST-067** (relay MUST reap `local` presence on client close within 60 s), **PNP-001-SHOULD-014** (relay SHOULD close idle client sockets at 60 s).
- Extended §10.1 with **PNP-001-MUST-068** defining the `{type:"queued"}` response frame as a *provisional-delivery signal* (peer offline + relay accepted into store-and-forward), and **PNP-001-SHOULD-015** telling clients how to render it without alarming users.
- Added **PNP-001-MUST-069** to §10.2 requiring clients to purge retired-epoch Privacy Pass tokens on rotation. MUST-050 already forbade the relay from accepting stale tokens; the reciprocal client obligation was missing.
- MUST count: 69. New SHOULDs: 014, 015.

**v0.9 (2026-04-18) — QR bootstrap: scanner IK travels in `source_hint`**

- SHOULD-003 (§5.1) gets an explicit bootstrap carve-out. During QR pairing the scanner's FIRST envelope to the presenter MUST set `source_hint` to the scanner's 32-byte Ed25519 identity public key. Without this, the presenter cannot derive the bootstrap shared secret (PNP-003 §5.1 step 7) and cannot materialize the responder Double Ratchet session — pairing stalls in `SECRET_SHARED` forever. This was the root cause of the "contact added on one side, never appears on the other" bug observed in the reference PWA.
- Added §5.3.1 "Bootstrap Session Materialization" specifying the receive-side rule: the presenter derives BS from `source_hint`, constructs the candidate responder session, attempts AEAD decryption, and only on success commits the session to the session manager and consumes `pending_bootstrap`. AEAD failure drops the frame without touching session state, so a forged `source_hint` cannot poison the session table.
- Post-bootstrap envelopes return to the default SHOULD-003 (null `source_hint`). Only the exactly-one bootstrap-completing envelope carries the IK.
- Allocated `PNP-001-MUST-063`, `PNP-001-MUST-064`, `PNP-001-SHOULD-013`. MUST count: 64.
- Privacy note: the scanner's IK is visible to the relay on this one frame. This is strictly no worse than `/peers/presence` (PNP-008) which exposes PeerIds post-pairing anyway, and is a necessary consequence of QR being a one-way (presenter → scanner) out-of-band channel.

**v0.8 (2026-04-18) — Issuance rate limit demoted to optional**

- §10.2 issuance accounting reworked from `PNP-001-MUST-063` (cumulative cap REQUIRED) to `PNP-001-MAY-005` (cumulative cap OPTIONAL). Identity creation is free in PNP-002, so a per-identity budget cannot stop an adversary — they just rotate keys. Legitimate users (browser reloads, multi-tab workflows) were the ones getting rate-limited. MUST-050 (per-epoch spent-set) and MUST-052 (Ed25519 sig gate) are the real defenses and stand on their own; network-layer abuse is the job of fail2ban on the deployment host, not the application layer.
- The MAY form still describes the exact accounting any opt-in deployment MUST use (running total, 429 without advance, epoch-reset) so a relay that chooses to enable it stays interoperable. Default relay builds no longer enforce the cap.
- PNP-001 MUST count drops back to 62 (MUST-063 promoted to MAY-005).

**v0.7 (2026-04-18) — Token issuance accounting clarified — superseded by v0.8**

- Added `PNP-001-MUST-063` to §10.2 making the `budget_per_epoch` cap explicitly cumulative per (identity, epoch). Relaxed in v0.8 after the cap was shown to gate legitimate reloads without deterring identity-rotating attackers.

**v0.6 (2026-04-17) — Envelope fragmentation & reassembly**

- Added §3.9 "Fragmentation" defining the normative reassembly algorithm for application bodies that overflow the 16384-byte bucket ceiling. Formalizes use of the `is_fragment` and `is_final_fragment` flag bits (already reserved in §3.3 v0.3) and introduces two optional plaintext fields `fragment_id` (16 random bytes shared across all fragments of one message) and `fragment_seq` (u32, 0-based).
- Allocated clauses `PNP-001-MUST-053` through `PNP-001-MUST-062` covering fragment identity, in-order & out-of-order reassembly, per-sender buffer caps, 30-second reassembly timeout, AAD binding of fragment metadata, and duplicate-fragment handling. Closes the last wire-format ambiguity that was blocking multi-envelope message transport through 3-hop onion circuits.
- Added `specs/vectors/PNP-001/fragment_*.json` test vectors.
- §3.3 plaintext map description extended to list the two new optional keys; lex ordering (MUST-023) preserved.

**v0.5 (2026-04-17) — Outer Relay Frame + H9 Privacy Pass token auth**

- Added §4 "Outer Relay Frame" specifying the JSON envelope the relay sees on the WebSocket (wraps the CBOR envelope defined in §3). The frame is `{type, to, token, payload}`; the prior `from` field is removed — relays no longer learn per-frame sender identity.
- Added §4.2 "Token Auth (Privacy Pass)" defining the VOPRF-backed rotating-token scheme (RFC 9578 Privacy Pass + RFC 9497 VOPRF, ciphersuite `Ristretto255-SHA512`). Epoch length 3600 s, grace window 300 s, per-client budget 8192 tokens/epoch.
- Allocated clauses `PNP-001-MUST-048` through `PNP-001-MUST-052` for the new outer-frame / token-auth rules.

**v0.4 (2026-04-17) — Identity rotation message type**

- Extended §3.4 Message Types table to include code `0x13 IDENTITY_ROTATE` from PNP-002 §7 (H5 identity rotation). Reserved-code range shifted to `0x14–0xFF`.

**v0.3 (2026-04-17) — Wire-level envelope padding + AAD binding**

- §3.1 Envelope Structure rewritten: envelope is now a 4-element CBOR array `[cleartext_header, ratchet_header, encrypted_payload, padding]`. The Double Ratchet header is carried explicitly so the receiver can advance state before AEAD decryption. Padding is applied to the serialized envelope (wire level), not inside the plaintext payload, so the final CBOR byte sequence lands exactly on a bucket boundary.
- §3.3 Encrypted Payload: removed the `pad` field from the plaintext CBOR map. Padding is now a sibling field of the ciphertext at the envelope level, not a field inside the ciphertext. The plaintext map is now `{body, chain, flags, seq}` in lexicographic order.
- §3.5 MAC: the 16-byte AEAD tag is now the trailing 16 bytes of the `encrypted_payload` byte-string (in-place, as produced by ChaCha20-Poly1305 / AES-256-GCM). There is no separate `mac` field on the wire.
- §3.6 Padding Scheme rewritten: padding is applied to the serialized envelope. The sender iteratively sizes `padding` so that `len(CBOR(envelope))` equals exactly the chosen bucket size. A single fixpoint iteration suffices to absorb the CBOR `bstr` length-prefix tier delta.
- PNP-001-MUST-007 (AAD binding) now reads as: AEAD AAD is `ratchet_public_key || CBOR(cleartext_header)`. The session AEAD tag therefore binds both the Double Ratchet identity of the message and every relay-visible field.

**v0.2 (2026-04-17) — Harmonization pass**

- Status bumped from DRAFT to CANDIDATE (spec is now the authoritative oracle for conformance tests).
- Extended §3.4 Message Types table to include codes 0x07–0x11 from PNP-007 and PNP-009. PNP-001 is now the canonical message-type registry.
- Added §5.4 "Replay / Seen-Message Windows" — single table consolidating all cache retention and timestamp windows that appear across this spec.
- Added §6.6 "AEAD Layering" — clarifies that PNP-001 governs the *session-layer* AEAD and that PNP-004 onion layers have independent cipher rules (ChaCha20-Poly1305 only; no negotiation).
- Added §9 "Nonce Construction Catalog" — names the four nonce schemes used across the stack (`N-SESSION`, `N-HANDSHAKE`, `N-ONION`, `N-SENDERKEY`) to prevent cross-context nonce misuse.
- Added numbered normative clause IDs (`PNP-001-MUST-NNN`, `-SHOULD-NNN`, `-MAY-NNN`) to every RFC 2119 statement. IDs are stable across versions — new clauses receive new numbers, retired clauses retain their numbers as `RESERVED`.
- Completed §8 cross-reference table.

**v0.1 (2026-04-10)** — Initial draft.

---

## Implementation Note

This document is a protocol design target. Current code implements envelope and padding helpers, but the user-facing PWA path does not yet make all traffic indistinguishable from normal HTTPS traffic end to end.

## 1. Overview

The ParolNet Wire Protocol (PWP) defines the envelope format for all messages transmitted between peers in the ParolNet network. Every message -- whether it carries user content, control signaling, handshake material, or decoy traffic -- is encapsulated in a single, uniform envelope. The protocol is designed so that an observer with access to the wire sees only fixed-size, encrypted, authenticated blobs that are indistinguishable from one another in structure and from normal HTTPS traffic in transit.

PWP sits above the transport layer (TLS 1.3 over TCP or WebSocket) and below session-layer protocols such as the Handshake Protocol (PNP-002) and application-layer message handling.

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

- **Peer**: Any node in the ParolNet network, identified by a PeerId.
- **PeerId**: A 32-byte value computed as `SHA-256(Ed25519_identity_public_key)`.
- **Envelope**: The complete wire-level unit of transmission.
- **Bucket Size**: One of the four fixed sizes to which all envelopes are padded: 256, 1024, 4096, or 16384 bytes.
- **Coarsened Timestamp**: A Unix timestamp truncated to the nearest 5-minute (300-second) boundary: `floor(unix_epoch_seconds / 300) * 300`.
- **Decoy Message**: A message carrying no semantic content, generated to provide cover traffic.
- **Hop**: One relay forwarding step between the origin and the destination.
- **AEAD**: Authenticated Encryption with Associated Data. The session-layer AEAD cipher is either ChaCha20-Poly1305 (primary / MTI) or AES-256-GCM (optional). Relay-layer (onion) AEAD cipher rules are defined in PNP-004; they are scoped independently and are NOT negotiable.
- **Clause ID**: A stable identifier of the form `PNP-XXX-(MUST|SHOULD|MAY)-NNN` placed at the end of a normative sentence. Used by the `parolnet-conformance` test suite and the `cargo xtask clauses` coverage gate.

## 3. Message Format

### 3.1 Envelope Structure

Every envelope on the wire is a single definite-length CBOR array with four elements. The final serialized byte sequence is the envelope as it appears on the wire.

```
Envelope = CBOR Array(4 items):
  [0] cleartext_header    : CBOR array (see §3.2)
  [1] ratchet_header      : CBOR array [ratchet_pub(32B), prev_chain_len, msg_number]
  [2] encrypted_payload   : bstr   -- ciphertext including 16-byte AEAD tag (§3.5)
  [3] padding             : bstr   -- wire-level random padding (§3.6)
```

```
+-----------+-----------+---------------------+------------+
| cleartext | ratchet   | encrypted_payload   |  padding   |
| header    | header    | (ciphertext||tag)   | (bstr)     |
+-----------+-----------+---------------------+------------+
|<---------- total CBOR length == bucket size ------------>|
```

The total envelope (the serialized CBOR array, including its own outer length prefixes) MUST equal exactly one of the bucket sizes: 256, 1024, 4096, or 16384 bytes. **PNP-001-MUST-001**

Using an array (rather than a map) at the outer level keeps the envelope compact enough that small messages still fit in the 256-byte bucket after accounting for the cleartext header, the ratchet header, and AEAD overhead. The ratchet header is carried on the wire so the receiver can advance the Double Ratchet state before AEAD decryption; it is not encrypted, but every field of it is authenticated: the encoded ratchet header is the first component of the AEAD AAD (see §3.3 / MUST-007).

### 3.2 Cleartext Header

The cleartext header is the only portion of the envelope visible to intermediary relays. It is CBOR-encoded (RFC 8949) as a definite-length CBOR array. **PNP-001-MUST-002**

```
Cleartext Header = CBOR Array(6 or 7 items):
  [0] version        : uint8       -- Protocol version. MUST be 0x01 for this spec.
  [1] msg_type        : uint8       -- Message type code (see Section 3.4).
  [2] dest_peer_id    : bstr(32)   -- Destination PeerId. 32 bytes.
  [3] message_id      : bstr(16)   -- Random 128-bit message identifier.
  [4] timestamp       : uint64     -- Coarsened Unix timestamp (5-min bucket).
  [5] ttl_and_hops    : uint16     -- Upper 8 bits: TTL (max remaining hops).
                                      Lower 8 bits: hop count (hops so far).
  [6] source_hint     : bstr(32)   -- OPTIONAL. Source PeerId hint.
                        / null         If omitted for anonymity, encode as CBOR null.
```

The `version` field MUST be set to 0x01 for this specification. **PNP-001-MUST-003**

Field details:

| Field | CBOR Major Type | Size | Notes |
|-------|----------------|------|-------|
| version | 0 (unsigned int) | 1 byte value | MUST be 1 |
| msg_type | 0 (unsigned int) | 1 byte value | See Section 3.4 |
| dest_peer_id | 2 (byte string) | 32 bytes | SHA-256 of destination Ed25519 public key |
| message_id | 2 (byte string) | 16 bytes | Cryptographically random, unique per message |
| timestamp | 0 (unsigned int) | 8 bytes value | `floor(now / 300) * 300` |
| ttl_and_hops | 0 (unsigned int) | 2 byte value | TTL in bits [15:8], hops in bits [7:0] |
| source_hint | 2 (byte string) / 7 (simple: null) | 32 bytes or 1 byte | OPTIONAL sender identity hint |

### 3.3 Encrypted Payload

The encrypted payload carries the actual message content. It is encrypted using the session AEAD (ChaCha20-Poly1305 or AES-256-GCM) derived from the Double Ratchet session state. **PNP-001-MUST-004**

```
Plaintext (before encryption) = CBOR Map (keys in lexicographic order):
  {
    "body"         : bstr,            -- The application-layer content
                                      -- (one fragment's slice if is_fragment=1).
    "chain"        : uint32,          -- Ratchet chain index.
    "flags"        : uint8,           -- Bitfield (see below).
    "fragment_id"  : bstr (16 bytes), -- OPTIONAL; present iff is_fragment=1.
                                      -- See §3.9.
    "fragment_seq" : uint32,          -- OPTIONAL; present iff is_fragment=1.
                                      -- See §3.9.
    "seq"          : uint64           -- Sequence number within the Double
                                      -- Ratchet chain (independent of fragment_seq).
  }
```

The plaintext CBOR map MUST NOT contain a `pad` field. Wire-level padding is carried as a sibling of `encrypted_payload` at the envelope level (see §3.1 and §3.6); it is NOT inside the AEAD ciphertext.

Flags bitfield:

| Bit | Meaning |
|-----|---------|
| 0 | `is_decoy`: 1 if this is a decoy message |
| 1 | `requires_ack`: 1 if sender expects acknowledgment |
| 2 | `is_fragment`: 1 if this is a fragment of a larger message |
| 3 | `is_final_fragment`: 1 if this is the last fragment |
| 4-7 | Reserved, MUST be 0 **PNP-001-MUST-005** |

The AEAD nonce for the session layer MUST be constructed per scheme `N-SESSION` defined in §9:

```
nonce (12 bytes) = ratchet_public_key[0..8] (8 bytes) || msg_number (4 bytes, big-endian)
```

**PNP-001-MUST-006**

`ratchet_public_key` and `msg_number` are the fields of the message's ratchet header (§3.1). `msg_number` never reaches 2^24 and never wraps (PNP-002 §5.9), and every message is encrypted under a message key of its own, so no (key, nonce) pair repeats.

The AEAD additional authenticated data (AAD) MUST be the concatenation of the encoded Double Ratchet header of the message (all three fields of the wire ratchet header, in the fixed 40-byte encoding of PNP-002 §5.7) followed by the serialized CBOR bytes of the cleartext header:

```
ratchet_header_bytes (40 bytes) = ratchet_public_key (32 bytes)
                               || prev_chain_len (4 bytes, big-endian)
                               || msg_number     (4 bytes, big-endian)

AAD = ratchet_header_bytes || CBOR(cleartext_header)
```

**PNP-001-MUST-007**

This construction makes the AEAD tag tamper-evident with respect to (a) every relay-visible field in the cleartext header, and (b) the Double Ratchet identity of the sending state. A relay cannot rewrite `dest_peer_id`, `msg_type`, `message_id`, `timestamp`, `ttl_and_hops`, or `source_hint` without causing AEAD tag verification to fail on the receiver. An attacker cannot attach a stolen ciphertext to a different ratchet public key without the same tag failure. The `ratchet_header` fields `prev_chain_len` and `msg_number` are part of the AAD as well (**PNP-002-MUST-042**): the receiver acts on both before it can verify the tag, and `prev_chain_len` in particular selects no key of the message it travels in, so only the AAD binds it. A relay that rewrites any ratchet header field causes AEAD tag verification to fail, and the receiver's session is left unchanged (**PNP-002-MUST-041**).

### 3.4 Message Types

Codes 0x01–0x06 and 0x14 are allocated by this specification. Codes 0x07–0x0B are allocated by PNP-007 (Media & File Transfer). Codes 0x0C–0x12 are allocated by PNP-009 (Group Communication). Code 0x13 is allocated by PNP-002 (Handshake Protocol) for identity rotation. Code 0x15 is allocated by PNP-010 (File Transfer). PNP-001 is the canonical registry — new message types MUST be assigned here in future revisions.

| Code | Name | Allocated By | Description |
|------|------|-------------|-------------|
| 0x01 | TEXT | PNP-001 | User text message |
| 0x02 | FILE | PNP-001 | File transfer payload or fragment |
| 0x03 | CONTROL | PNP-001 | Session control (ack, typing indicator, read receipt) |
| 0x04 | DECOY | PNP-001 | Cover traffic; indistinguishable from real messages |
| 0x05 | HANDSHAKE | PNP-001 | Session establishment (PNP-002 messages) |
| 0x06 | RELAY_CONTROL | PNP-001 | Relay-layer signaling (routing, keepalive, congestion) |
| 0x07 | AUDIO | PNP-007 | Audio stream frame (Opus/Codec2) |
| 0x08 | VIDEO | PNP-007 | Video stream frame |
| 0x09 | FILE_CHUNK | PNP-007 | File transfer chunk (see PNP-007 §5) |
| 0x0A | FILE_CONTROL | PNP-007 | File transfer control signaling |
| 0x0B | CALL_SIGNAL | PNP-007 | Call state-machine signaling |
| 0x0C | GROUP_TEXT | PNP-009 | Group text message (sender-key encrypted) |
| 0x0D | GROUP_CALL_SIGNAL | PNP-009 | Group call state-machine signaling |
| 0x0E | GROUP_FILE_OFFER | PNP-009 | Group file offer |
| 0x0F | GROUP_FILE_CHUNK | PNP-009 | Group file transfer chunk |
| 0x10 | GROUP_FILE_CONTROL | PNP-009 | Group file transfer control |
| 0x11 | SENDER_KEY_DISTRIBUTION | PNP-009 | Sender key distribution |
| 0x12 | GROUP_ADMIN | PNP-009 | Group admin operation (invite, member add/remove; see PNP-009 §6.2) |
| 0x13 | IDENTITY_ROTATE | PNP-002 | Signed identity rotation notification (see PNP-002 §7) |
| 0x14 | CHANNEL_BINDING | PNP-001 | DTLS fingerprints of a direct data channel (§10.5.1) |
| 0x15 | FILE_TRANSFER | PNP-010 | File transfer offer and control (accept, decline, cancel, complete); the records flow on the transfer's own data channel |

Codes 0x16–0xFF are reserved for future assignment.

Implementations MUST treat unrecognized message type codes as DECOY and silently discard them after decryption. **PNP-001-MUST-008**

### 3.5 MAC

The AEAD tag is the trailing 16 bytes of `encrypted_payload` (produced in-place by ChaCha20-Poly1305 or AES-256-GCM). There is NO separate `mac` field on the wire. The tag authenticates the ciphertext and the AAD defined in §3.3 (`ratchet_header_bytes || CBOR(cleartext_header)`). **PNP-001-MUST-009**

### 3.6 Padding Scheme

All envelopes MUST be padded to the smallest bucket size that can accommodate the complete envelope after CBOR serialization. **PNP-001-MUST-010** The bucket sizes are:

```
BUCKET_SIZES = [256, 1024, 4096, 16384]
```

Padding is applied to the serialized envelope (wire level), NOT to the plaintext inside the AEAD. The `padding` field of the envelope absorbs whatever bytes are needed so that the final CBOR byte sequence is exactly one bucket size long. The padding bytes are cryptographically random — a relay MUST NOT be able to distinguish padding from any other `bstr` content on the wire.

The padding procedure is:

1. Serialize the cleartext header to CBOR bytes: `H`.
2. Encrypt the plaintext map (per §3.3) under the session AEAD using `AAD = ratchet_header_bytes || H` (§3.3). Let the ciphertext (including the 16-byte tag) be `C`.
3. Serialize the envelope `[cleartext_header, ratchet_header, C, bstr(0)]` (empty padding) to CBOR bytes and measure its length `L0`.
4. Select the smallest bucket size `B` such that `B >= L0`. If `L0` exceeds the largest bucket, the message MUST be fragmented. **PNP-001-MUST-011**
5. Compute an initial `pad_length = B - L0 - cbor_bstr_header_size(B - L0)` and fill `pad_length` cryptographically random bytes into the `padding` field. **PNP-001-MUST-012**
6. Re-serialize the envelope and measure its length `L1`. If `L1 != B` (this happens when growing `padding` crossed a CBOR `bstr` length-prefix tier boundary at 24 / 256 / 65536 bytes), adjust `pad_length` by `B - L1` and re-serialize once. One fixpoint iteration is sufficient because the CBOR length-prefix overhead is monotonic in `pad_length`.
7. The final envelope bytes MUST be exactly `B` bytes long. **PNP-001-MUST-013**

Implementations MUST NOT leak the original message size through timing, error responses, or any other side channel. **PNP-001-MUST-014**

### 3.7 Decoy Messages

Decoy messages MUST be constructed identically to real messages:

1. The `msg_type` in the cleartext header MUST be set to 0x04 (DECOY) by default. **PNP-001-MUST-015** However, when decoys are used for traffic analysis resistance, an implementation MAY set `msg_type` to any valid type code (such as 0x01) so that even the type field does not distinguish real from decoy traffic at the cleartext header level. **PNP-001-MAY-001**
2. The `dest_peer_id` SHOULD be a valid PeerId known to the sender (e.g., a recent contact or a well-known relay). **PNP-001-SHOULD-001**
3. The `body` field MUST contain cryptographically random bytes of a plausible length. **PNP-001-MUST-016**
4. The `is_decoy` flag (bit 0 of `flags`) MUST be set to 1 inside the encrypted payload so the recipient can discard it after decryption. **PNP-001-MUST-017**
5. All other fields (message_id, timestamp, ttl_and_hops) MUST be populated normally. **PNP-001-MUST-018**

An intermediary relay MUST NOT be able to distinguish a decoy from a real message. **PNP-001-MUST-019**

### 3.8 CBOR Encoding Rules

1. All CBOR encoding MUST use definite-length encoding. Indefinite-length encoding MUST NOT be used. **PNP-001-MUST-020**
2. Integer values MUST use the shortest CBOR encoding that can represent the value. **PNP-001-MUST-021**
3. Byte strings MUST use definite-length encoding. **PNP-001-MUST-022**
4. Map keys in the encrypted payload MUST be text strings and MUST appear in lexicographic order. **PNP-001-MUST-023**
5. Implementations MUST reject envelopes containing duplicate map keys. **PNP-001-MUST-024**
6. Implementations MUST ignore unknown map keys in the encrypted payload (forward compatibility). **PNP-001-MUST-025**

### 3.9 Fragmentation

Application bodies that would produce an envelope larger than the 16384-byte ceiling (§3.6) MUST be fragmented. Each fragment is a fully-formed envelope (own ratchet header, own AEAD tag, bucket-padded per §3.6) carrying one slice of the body plus reassembly metadata.

#### 3.9.1 Fragment identity & ordering

**PNP-001-MUST-053**: When a sender decides to fragment a message it MUST generate a cryptographically random 16-byte `fragment_id` and include it in the plaintext map (§3.3) of every fragment produced from that message. A `fragment_id` MUST NOT be reused across different source messages.

**PNP-001-MUST-054**: Each fragment MUST carry a `fragment_seq` value in the plaintext map — a 0-based monotonically increasing `uint32` indexing its position in the original body. The first fragment has `fragment_seq = 0`.

**PNP-001-MUST-055**: Exactly one fragment in a message MUST have its `is_final_fragment` bit set (§3.3 bit 3); that fragment MUST also have the highest `fragment_seq` value of the message.

**PNP-001-MUST-056**: The `is_fragment` bit (§3.3 bit 2) MUST be set on every fragment of a fragmented message. If `is_fragment = 0` the `fragment_id` and `fragment_seq` fields MUST be absent from the plaintext map; if `is_fragment = 1` both fields MUST be present (MUST-024 still forbids duplicate keys regardless).

#### 3.9.2 AAD binding

**PNP-001-MUST-057**: When `is_fragment = 1`, the AEAD AAD defined in §3.3 is extended to `ratchet_header_bytes || CBOR(cleartext_header) || fragment_id || fragment_seq_be`, where `fragment_seq_be` is the 4-byte big-endian encoding of `fragment_seq`. This prevents a relay from reshuffling fragments across messages or splicing a fragment from one message into another while keeping the AEAD tag valid.

#### 3.9.3 Reassembly

**PNP-001-MUST-058**: Receivers MUST buffer fragments keyed by `(sender_peer_id, fragment_id)` until every `fragment_seq` from `0` through the seq of the `is_final_fragment = 1` fragment has been observed, then concatenate the `body` fields in `fragment_seq` order to produce the reassembled message. Fragments arriving out of order MUST be held without dropping until reassembly completes or the timeout expires.

**PNP-001-MUST-059**: Receivers MUST enforce a 30-second reassembly timeout measured from the arrival of the first fragment of a given `(sender, fragment_id)` tuple. On timeout the buffer MUST be dropped without reassembly and MUST NOT be retained.

**PNP-001-MUST-060**: Receivers MUST enforce an 8-messages-per-sender in-flight cap and a 256-fragments-per-message limit. Excess fragments on either limit MUST be dropped; the receiver MAY decrement the sender's peer score per PNP-004 §5.7 if the limits are repeatedly exceeded.

**PNP-001-MUST-061**: Duplicate fragments (same `(sender_peer_id, fragment_id, fragment_seq)` tuple, AEAD-verified) MUST be silently discarded; the first successful instance is retained. A duplicate whose AEAD verification fails MUST cause the original buffer to be dropped under the assumption an attacker is attempting content substitution.

**PNP-001-MUST-062**: Reassembled messages inherit the `msg_type` and all other cleartext-header fields from the fragment with `fragment_seq = 0`; receivers MUST reject the reassembled message if fragments within the same `fragment_id` carry inconsistent values for `msg_type`, `dest_peer_id`, or `source_hint`.

## 4. State Machine

The Wire Protocol itself is stateless at the envelope level. Each envelope is independently parseable. Session state is managed by higher-layer protocols (PNP-002 for handshakes, Double Ratchet for ongoing sessions).

Envelope processing follows this flow:

```
                    +------------------+
                    |  Receive Bytes   |
                    +--------+---------+
                             |
                    +--------v---------+
                    | Validate Length   |
                    | (must be bucket)  |
                    +--------+---------+
                             |
                   +---------v----------+
                   | Decode Cleartext   |
                   | Header (CBOR)      |
                   +---------+----------+
                             |
              +--------------+--------------+
              |                             |
     +--------v--------+          +--------v--------+
     | Dest is self?    |          | Dest is other?  |
     | Decrypt payload  |          | Relay / drop    |
     +--------+---------+          | (check TTL)     |
              |                    +-----------------+
     +--------v---------+
     | Validate MAC     |
     +--------+---------+
              |
     +--------v---------+
     | Decode payload   |
     | (CBOR map)       |
     +--------+---------+
              |
     +--------v---------+
     | Check is_decoy   |-----> Discard silently
     +--------+---------+
              |
     +--------v---------+
     | Dispatch to       |
     | handler by type   |
     +-------------------+
```

## 5. Processing Rules

### 5.1 Sending

1. A sender MUST populate all cleartext header fields. **PNP-001-MUST-026**
2. A sender MUST set `timestamp` to the current coarsened timestamp. Implementations MUST NOT use the actual wall-clock time directly. **PNP-001-MUST-027**
3. A sender MUST generate a cryptographically random `message_id` for each envelope. **PNP-001-MUST-028**
4. A sender MUST set `ttl_and_hops` with TTL in the upper 8 bits and hop count 0x00 in the lower 8 bits. **PNP-001-MUST-029**
5. A sender SHOULD set a default TTL of 7. **PNP-001-SHOULD-002** A sender MAY use a lower TTL for latency-sensitive messages. **PNP-001-MAY-002**
6. A sender SHOULD omit `source_hint` (encoding it as CBOR null) unless the recipient needs it for initial contact resolution. **PNP-001-SHOULD-003** The QR-bootstrap carve-out of §5.3.1 is the single normative exception: on the scanner's first envelope after `process_scanned_qr`, `source_hint` MUST carry the scanner's 32-byte Ed25519 identity public key (**PNP-001-MUST-063**). On every envelope sent over a session already committed to the session manager, `source_hint` SHOULD return to CBOR null. **PNP-001-SHOULD-013**
7. A sender MUST pad the envelope to the appropriate bucket size per Section 3.6. **PNP-001-MUST-030**
8. A sender SHOULD generate decoy messages at random intervals to maintain a minimum baseline traffic rate. **PNP-001-SHOULD-004**

### 5.2 Relaying

1. A relay MUST increment the hop count (lower 8 bits of `ttl_and_hops`) by 1. **PNP-001-MUST-031**
2. A relay MUST drop the envelope if the hop count equals or exceeds the TTL (upper 8 bits). **PNP-001-MUST-032**
3. A relay MUST NOT modify any other cleartext header fields. **PNP-001-MUST-033**
4. A relay MUST NOT attempt to decrypt the payload. **PNP-001-MUST-034**
5. A relay SHOULD forward the envelope within 50ms plus a random jitter of 0-200ms to frustrate timing correlation. **PNP-001-SHOULD-005**
6. A relay MAY batch-forward multiple envelopes simultaneously. **PNP-001-MAY-003**
7. A relay MUST maintain a seen-message cache keyed by `message_id` and MUST drop duplicate envelopes. **PNP-001-MUST-035** The cache SHOULD retain entries for at least 30 minutes. **PNP-001-SHOULD-006**

### 5.3 Receiving

1. A receiver MUST verify that the envelope length matches a valid bucket size. If not, the envelope MUST be silently discarded. **PNP-001-MUST-036**
2. A receiver MUST verify the AEAD authentication tag. If verification fails, the envelope MUST be silently discarded. **PNP-001-MUST-037**
3. A receiver MUST check the `message_id` against a replay cache. Duplicate message IDs MUST be silently discarded. **PNP-001-MUST-038** The cache SHOULD retain entries for at least 60 minutes. **PNP-001-SHOULD-007**
4. A receiver MUST verify the timestamp is within an acceptable window. The timestamp MUST NOT be more than 30 minutes (6 buckets) in the past or more than 1 bucket (5 minutes) in the future. Messages outside this window MUST be discarded. **PNP-001-MUST-039**
5. A receiver SHOULD process decoy messages (is_decoy flag set) identically to real messages up to the point of application delivery, then discard them. **PNP-001-SHOULD-008**

### 5.3.1 Bootstrap Session Materialization

A receiver in the QR-presenter role (holding a pending bootstrap: `seed` + `ratchet_secret` from `generate_qr_payload`, and no committed session for the sender) processes an incoming envelope as follows:

1. Run normal trial-decrypt against every committed session. If any session AEAD-decrypts the envelope, deliver the plaintext and stop.
2. If no committed session decrypts, AND the receiver has a pending bootstrap, AND the envelope's `source_hint` is a 32-byte value (not CBOR null), treat `source_hint` as the scanner's Ed25519 identity public key candidate.
3. Derive `BS = HKDF-SHA-256(salt="ParolNet_bootstrap_v1", ikm=seed, info=sorted_concat(our_IK, candidate_IK))` (PNP-003 §5.1 step 7).
4. Construct a **candidate** responder Double Ratchet session from `BS` + `ratchet_secret`. This session MUST NOT yet be committed to the session manager.
5. Attempt AEAD decryption of the envelope under the candidate session.
6. **On AEAD success**: commit the candidate session to the session manager keyed by `SHA-256(candidate_IK)` (the scanner's PeerId), erase the pending bootstrap, and deliver the plaintext. **PNP-001-MUST-064**
7. **On AEAD failure**: discard the candidate session without committing and drop the envelope silently. The pending bootstrap MUST remain intact so a subsequent legitimate first-envelope can still be processed.

The atomicity of step 6 (commit-on-AEAD-success) is the security property of MUST-064: an attacker cannot poison the session manager by shipping a frame with a `source_hint` they control, because the AEAD tag verifies only under the `BS` that requires knowledge of `seed` (which was transferred out-of-band via QR). A forged `source_hint` produces a candidate session that fails AEAD immediately.

### 5.4 Replay / Seen-Message Windows

Several caches and windows are defined across this spec. They serve different purposes and have different scopes. This table is normative.

| Window | Purpose | Minimum Duration | Where |
|--------|---------|------------------|-------|
| Timestamp freshness (past) | Reject stale messages | 30 minutes (6 coarsened buckets) | §5.3 item 4 |
| Timestamp freshness (future) | Reject future-dated messages | 5 minutes (1 coarsened bucket) | §5.3 item 4 |
| Relay seen-message cache | Drop duplicate relays | 30 minutes | §5.2 item 7 |
| Receiver replay cache | Reject replayed deliveries | 60 minutes | §5.3 item 3 |

QR-code freshness (30 minutes) is defined in PNP-003 §5.1.6 and is unrelated to the envelope-level windows above.

## 6. Security Considerations

1. **Indistinguishability**: The bucket padding scheme ensures that message lengths do not leak content type or size. Implementations MUST NOT compress payloads before encryption, as compression ratios can leak information about plaintext content (CRIME/BREACH-style attacks). **PNP-001-MUST-040**

2. **Nonce Reuse**: The nonce construction from chain_index and sequence_number guarantees uniqueness within a Double Ratchet session. Implementations MUST NOT reuse a (key, nonce) pair. **PNP-001-MUST-041** If the sequence number overflows 2^64, the session MUST be rekeyed. **PNP-001-MUST-042**

3. **Replay Protection**: The combination of message_id uniqueness checking and timestamp windowing prevents replay attacks. The seen-message cache MUST be persisted across brief restarts (up to 60 minutes of downtime). **PNP-001-MUST-043**

4. **Relay Integrity**: Relays can observe cleartext headers. The `dest_peer_id` reveals the intended recipient to every relay on the path. For stronger anonymity, implementations SHOULD use onion-style layered encryption (PNP-004) where each relay only sees the next hop, not the final destination. **PNP-001-SHOULD-009**

5. **Timing Attacks**: Random relay jitter (§5.2.5) provides partial protection. Implementations SHOULD also implement constant-rate traffic shaping (PNP-006) to prevent traffic analysis. **PNP-001-SHOULD-010**

6. **AEAD Layering**: PNP-001 defines the **session-layer AEAD** applied to the encrypted payload of every envelope. ChaCha20-Poly1305 MUST be the default session-layer AEAD. **PNP-001-MUST-044** AES-256-GCM MAY be used as the session-layer AEAD when hardware AES acceleration is available and both peers explicitly agree during the PNP-002 handshake. **PNP-001-MAY-004** An implementation MUST NOT downgrade from ChaCha20-Poly1305 to AES-256-GCM without explicit peer negotiation. **PNP-001-MUST-045**

   PNP-004 onion layers use a separate, independently scoped AEAD: ChaCha20-Poly1305 ONLY, with no negotiation (see PNP-004 §5.1). The session-layer cipher chosen here does NOT affect the onion-layer cipher.

## 7. Privacy Considerations

1. **Source Anonymity**: The `source_hint` field is OPTIONAL and SHOULD be omitted (CBOR null) in most cases. When it is present, it reveals the sender's identity to any relay that can observe the cleartext header.

2. **Destination Privacy**: The `dest_peer_id` is always visible in the cleartext header. This is a necessary trade-off for relay routing. To mitigate this, peers SHOULD use ephemeral forwarding PeerIds that rotate periodically and are known only to their contacts. **PNP-001-SHOULD-011**

3. **Timestamp Coarsening**: Timestamps are coarsened to 5-minute buckets to prevent precise timing correlation. Implementations MUST NOT include sub-bucket timing information anywhere in the envelope. **PNP-001-MUST-046**

4. **Traffic Analysis**: Fixed bucket sizes and decoy traffic reduce the effectiveness of traffic analysis. However, long-term observation of traffic patterns (volume, timing, source/destination pairs) can still reveal communication patterns. Implementations SHOULD use constant-rate traffic scheduling (PNP-006) where feasible. **PNP-001-SHOULD-012**

5. **Message ID Linkability**: The `message_id` is random and does not link to sender identity. However, if the same message is observed at multiple points in the relay path, the `message_id` can be used to correlate them. Implementations MAY re-encrypt and assign a new `message_id` at each relay hop at the cost of losing deduplication capability. **PNP-001-MAY-005**

## 8. Cross-Protocol References

| Spec | Relationship |
|------|-------------|
| PNP-002 (Handshake) | HANDSHAKE message type (0x05) carries PNP-002 payloads. Session AEAD cipher is negotiated in PNP-002 handshake. |
| PNP-003 (Bootstrap) | Initial session keys derived from PNP-003 bootstrap before any PNP-001 envelope is exchanged. |
| PNP-004 (Relay Circuit) | Envelopes may be carried inside relay circuit DATA cells. Onion-layer AEAD is scoped separately (see §6.6). |
| PNP-005 (Gossip Mesh) | Gossip messages are transmitted as PNP-001 envelopes. |
| PNP-006 (Traffic Shaping) | Governs timing and padding behavior for envelope transmission. |
| PNP-007 (Media & File) | Allocates message-type codes 0x07–0x0B (§3.4). |
| PNP-008 (Relay Federation) | Directory-sync messages are PNP-001 envelopes with RELAY_CONTROL (0x06). |
| PNP-009 (Group Communication) | Allocates message-type codes 0x0C–0x12 (§3.4). |
| PNP-002 (Handshake Protocol) | Allocates message-type code 0x13 IDENTITY_ROTATE (§3.4) for H5 identity rotation. |
| PNP-010 (File Transfer) | Allocates message-type code 0x15 FILE_TRANSFER (§3.4); reserves data-channel labels under `pn-` on the direct connection of §10.5. |

## 9. Nonce Construction Catalog

Multiple independently scoped AEAD contexts exist in the ParolNet stack. Each uses its own nonce construction. This catalog names each scheme so that implementations and specifications can reference them unambiguously. **Cross-context nonce reuse is a critical security failure**; each scheme is scoped to one context and MUST NOT be reused elsewhere.

| Scheme | Context | Construction | Size | Defined |
|--------|---------|--------------|------|---------|
| `N-SESSION` | Session-layer envelope AEAD (§3.3) | `ratchet_public_key[0..8] \|\| msg_number (4B BE)` | 12 bytes | PNP-001 §3.3, PNP-002 §5.7 |
| `N-HANDSHAKE` | PNP-002 X3DH-derived handshake AEAD | HKDF-SHA-256 of shared secret with context label | 12 bytes | PNP-002 §5.2 |
| `N-ONION` | PNP-004 onion-layer AEAD (per hop) | `nonce_seed (12B) XOR counter (12B BE)` | 12 bytes | PNP-004 §5.1.5 |
| `N-SENDERKEY` | PNP-009 group sender-key AEAD | `SHA-256(signing_public_key)[0..8] \|\| chain_index (4B BE)` | 12 bytes | PNP-009 §5.4 |

The counters in these constructions have limits, and none may wrap: `msg_number` in PNP-002 §5.9 (**PNP-002-MUST-045** to **MUST-048**), `chain_index` in PNP-009 §5.9 (**PNP-009-MUST-078** to **MUST-081**), the onion `counter` in PNP-004 §5.1 (**PNP-004-MUST-019**, **MUST-056**, **MUST-059**).

Implementations MUST NOT construct an AEAD nonce by any scheme other than those listed here in the context specified. **PNP-001-MUST-047** Future nonce schemes MUST be added to this catalog in a future revision of PNP-001.

## 10. Outer Relay Frame

The CBOR envelope defined in §3 is the *inner* wire unit — it is what end-to-end recipients decrypt. When a client pushes that envelope through the WebSocket to a relay, the envelope rides as the `payload` field of a JSON-encoded **outer relay frame**. This section normatively defines that outer frame. Logically it is a layer **above** §3 — the relay sees only the outer frame, never the plaintext of the envelope it carries.

### 10.1 Outer Frame Schema

The outer frame is a JSON object with four required fields:

```
OuterMessageFrame = {
  "type"    : "message",     -- string literal
  "to"      : hex(bstr32),   -- destination PeerId (hex-encoded)
  "token"   : hex(bstr),     -- CBOR-serialized Privacy Pass Token (hex-encoded)
  "payload" : hex(bstr)      -- the §3 envelope, hex-encoded
}
```

The frame MUST carry a non-empty `token` field. There is no `from` field. **PNP-001-MUST-048** The relay therefore does not see a sender identity on any per-frame send; sender authentication is discharged at *issuance* time (§10.2), not at *spend* time.

Any frame that reaches the relay without a valid, non-empty `token` field MUST be dropped silently — no error response is returned, so an adversary cannot probe which identity a frame belonged to.

#### 10.1.1 The `queued` Response

When the sender's outer `message` frame passes token auth but the recipient is not in the relay's local `peers` map, the relay accepts the frame into store-and-forward and emits the following JSON response back to the sender:

```
QueuedResponse = {
  "type"    : "queued",
  "message" : "peer offline, message stored"
}
```

The relay MUST emit `{type:"queued"}` on the sender's WebSocket IFF: (a) the outer frame passed token auth, AND (b) the recipient was not in the local `peers` map, AND (c) the relay successfully enqueued the frame into store-and-forward for later delivery. **PNP-001-MUST-068** `queued` is a **provisional-delivery signal**, not a failure. If any of (a)(b)(c) fails, the relay MUST NOT emit `queued`.

Clients SHOULD render the `queued` state on a per-message basis as a visible provisional indicator (e.g. a clock icon or single tick) distinct from both "sending" (local-in-flight, not yet at the relay) and "delivered" (peer has end-to-end acknowledged). Clients MUST NOT render `queued` as an error, MUST NOT display a modal toast for it, and MUST NOT re-queue the message locally — the relay already owns the retry. **PNP-001-SHOULD-015**

### 10.2 Token Auth (Privacy Pass)

ParolNet relays authenticate per-frame sends with [RFC 9578] Privacy Pass tokens backed by a [RFC 9497] VOPRF. The ciphersuite is **`Ristretto255-SHA512`** (RFC 9497 §4.1).

**Issuance.** A client presents its long-term Ed25519 identity to the relay over `POST /tokens/issue`:

```
TokenIssueRequest = CBOR map {
  "ed25519_pubkey_hex"    : tstr,                -- 32-byte key, hex
  "ed25519_sig_hex"       : tstr,                -- 64-byte signature, hex
  "challenge_nonce_hex"   : tstr,                -- 32-byte nonce, hex
  "blinded_bytes_list"    : [ bstr, bstr, ... ]  -- up to `budget_per_epoch`
                                                  --   serialized BlindedElements
}
```

The relay MUST reject any issuance request whose Ed25519 signature does not verify under the supplied public key over the supplied challenge nonce. **PNP-001-MUST-052** On success the relay runs `blind_evaluate` (RFC 9497 §3.3.2) on each `BlindedElement` under the **active epoch's** VOPRF secret and returns a `TokenIssueResponse`:

```
TokenIssueResponse = CBOR map {
  "epoch_id"     : bstr(4),         -- opaque 4-byte epoch identifier
  "activated_at" : uint,            -- Unix seconds the epoch started
  "expires_at"   : uint,            -- Unix seconds it fully expires (past grace)
  "ciphersuite"  : tstr("ristretto255-SHA512"),
  "budget"       : uint,            -- per-epoch budget
  "evaluated"    : [ bstr, ... ]    -- serialized EvaluationElements
}
```

The client unblinds each `EvaluationElement` via `OprfClient::finalize` to recover the per-token output, packages each as a `Token`, and stores the batch.

**Spend.** Each outer frame's `token` is the hex-encoded CBOR serialization of:

```
Token = CBOR map {
  "epoch_id"    : bstr(4),
  "nonce"       : bstr(32),   -- the 32-byte VOPRF input chosen at blind time
  "evaluation"  : bstr        -- the client-unblinded VOPRF output
}
```

On receiving an outer frame the relay MUST:

1. Parse the `token` field and identify its epoch by `epoch_id`. If the epoch id matches neither the active nor the prior-within-grace epoch, reject.
2. Recompute `OprfServer::evaluate(sk, nonce)` under the located epoch's VOPRF secret and compare against `token.evaluation` in constant time. If the comparison fails, reject. **PNP-001-MUST-049**
3. Check the per-epoch spent-set for `nonce`. If the nonce is already present, reject. Otherwise insert it and route the frame. **PNP-001-MUST-050**

All three rejection paths drop the frame silently (no error to the sender).

**Issuance accounting.** Independently of any per-identity budget, a relay MUST bound issuance per client network address and per request (§10.6, **PNP-001-MUST-078**); a signaling-only relay (§10.5) does not offer issuance at all. Relays MAY enforce a per-identity cumulative budget on BlindedElements evaluated per (identity, epoch). Such a budget is a belt-and-suspenders abuse control on top of the two real defenses — the Ed25519 signature gate (MUST-052) and the per-epoch spent-set (MUST-050) — and is NOT REQUIRED. **PNP-001-MAY-005** Identity creation is free (PNP-002 requires no registration), so a per-identity budget does not deter attackers; network-layer rate limiting (e.g., fail2ban on `POST /tokens/issue`) is the deployment-preferred abuse control. If a relay does enforce a cumulative budget, it MUST track the running total per (identity, epoch), reject overflow with HTTP 429 without advancing the counter, and reset on epoch rotation so that partial-batch rejections leave the cap intact.

> **Implementation note (non-normative).** The reference relay in this repo — `crates/parolnet-relay-server` — ships with the cumulative-budget rate limit **disabled** as of PNP-001 v0.8. The earlier v0.7 draft required the cap (then `MUST-063`), but operational experience showed it rejected legitimate clients — a browser tab across a handful of reloads would exhaust the 8192 budget while an attacker rotating identities never hit it. The `budget_per_epoch` parameter in the table below and the `budget` field in `TokenIssueResponse` above are still honoured by the protocol: they describe what a relay would enforce *if* it opted back in via MAY-005. Operators considering re-enabling the cap should treat it as a tunable response to observed abuse, not a default.

**Epoch rotation.** Each epoch lasts **3600 seconds**. At every epoch boundary the relay generates a fresh VOPRF secret for the new epoch and retains the previous epoch's secret for a **300-second grace window** so tokens that were issued just before the boundary still verify. Once the grace window elapses, the prior secret and its spent-set MUST be dropped. **PNP-001-MUST-051**

| Parameter | Value |
|-----------|-------|
| `epoch_secs` | 3600 |
| `grace_secs` | 300 |
| `budget_per_epoch` | 8192 |
| Ciphersuite | `Ristretto255-SHA512` (RFC 9497 §4.1) |

**Zeroization.** The relay's implementation MUST hold the VOPRF server secret behind a `Zeroize + ZeroizeOnDrop` wrapper so epoch rotation leaves no secret residue in freed heap memory (see `CLAUDE.md` §"Security Invariants").

**Rate-limit.** Each identity is entitled to at most one `TokenIssueResponse` per active epoch; repeat requests from the same `ed25519_pubkey_hex` within a single epoch return `429 Too Many Requests`.

**Client-side epoch hygiene.** A client MUST NOT spend a Privacy Pass token whose `epoch_id` matches neither the relay's currently-active epoch NOR the prior-within-grace epoch. **PNP-001-MUST-069** On observing an epoch rotation (via the next `TokenIssueResponse`'s `epoch_id` changing, or via the `expires_at` timestamp of a previously-issued batch elapsing), the client MUST purge all tokens whose `epoch_id` matches a retired epoch from its local pool BEFORE the next spend. Spending a retired-epoch token is indistinguishable from a double-spend at the relay (MUST-050 drops the frame silently), so this is the only way to prevent silent message loss across epoch boundaries.

### 10.3 Client-Relay WebSocket Liveness

A client maintains a persistent WebSocket (`/ws`) to its home relay for the lifetime of the app session. TCP keepalive (PNP-006) guards the transport layer, but does not detect application-layer silence — a NAT rebind, a backgrounded mobile tab, or a service-worker eviction can leave the socket in a `readyState === OPEN` state while no frames flow either direction. This section defines the application-layer heartbeat and silence timeouts.

**Ping / Pong frames.** The client sends a JSON frame:

```
PingFrame = {
  "type" : "ping",
  "ts"   : uint   -- client-local Unix milliseconds
}
```

The relay replies with:

```
PongFrame = {
  "type" : "pong",
  "ts"   : uint   -- verbatim echo of the client's ts
}
```

The `ts` echo lets the client measure round-trip time and unambiguously match pongs to pings.

**Cadence.**

1. Whenever its WebSocket is in `OPEN`, the client MUST send a `ping` every 20 seconds. **PNP-001-MUST-065** Missing a ping (for example because the SW was sleeping at the 20 s mark) is acceptable but SHOULD trigger an immediate catch-up ping when the client next executes.

2. The client MUST treat its WebSocket as *dead* and tear it down (`close()` + schedule a fresh reconnect) if it has not received ANY frame — pong, message, queued, registered, etc. — from the relay in the last 40 seconds. **PNP-001-MUST-066** The 40 s ceiling is 2× ping interval + 1× slack; any inbound frame resets the silence timer, not just pongs, because the relay's response to other traffic is equally strong evidence of liveness.

3. The relay SHOULD close client WebSockets that have sent no frame in the last 60 seconds. **PNP-001-SHOULD-014** This bounds the zombie-peer window in `local` presence.

**Presence reap.** On any path that terminates the WebSocket — client-initiated close, idle-timeout close (SHOULD-014), or abrupt TCP RST — the relay MUST call `remove_local(peer_id)` on its presence authority within 60 seconds of the last observed frame. **PNP-001-MUST-067** Without this, federation presence lookups (`/peers/lookup`, PNP-008) report dead peers as online and senders send into a black hole.

| Parameter | Value |
|-----------|-------|
| `ping_interval_secs` | 20 |
| `dead_threshold_secs` (client-side) | 40 |
| `idle_close_secs` (relay-side SHOULD) | 60 |
| `presence_reap_secs` (relay-side MUST) | 60 |

**Interaction with SHOULD-013 sealed-sender default.** The `ping` frame carries no `source_hint` equivalent — it is an outer-relay-frame concern, not an envelope concern, and the relay already knows the client's PeerId from the registered WebSocket session. No sealed-sender accommodation is needed.

### 10.4 Cross-References

| Construct | Where |
|-----------|-------|
| `Token` type, `TokenAuthority`, epoch rotation | `crates/parolnet-relay/src/tokens.rs` |
| `POST /tokens/issue` + frame router | `crates/parolnet-relay-server/src/main.rs` |
| Profile, admission checks, signaling / connection limits, presence watch | `crates/parolnet-relay-server/src/policy.rs` |
| Store-and-forward bounds (relay profile) | `crates/parolnet-relay-server/src/storage.rs` |
| Register challenge, relay names, register-answer verification (§10.7) | `crates/parolnet-relay-server/src/challenge.rs` |
| Register message, canonical relay name (§10.7) | `crates/parolnet-protocol/src/relay_auth.rs` |
| VOPRF crate | `voprf = "0.5"` (audited, RustCrypto-adjacent) |

### 10.5 Signaling-Only Relay Profile

A relay operates in exactly one of two profiles:

- **signaling-only** — the relay helps peers set up direct connections and carries nothing else. It is the default profile of the reference relay.
- **relay** — the full feature set of §10.1 – §10.2 (store-and-forward, Privacy Pass tokens, onion cells per PNP-004, gossip per PNP-005, TURN credentials, federation per PNP-008). An operator selects it explicitly (`SIGNALING_ONLY=0` in the reference relay).

**Profile announcement.** The relay MUST include `profile` in every `registered` frame, with the value `"signaling-only"` or `"relay"`, and MUST include the same `profile` field in its `GET /turn-credentials` response. **PNP-001-MUST-070** A client that receives no `profile` field MUST treat the relay as `"relay"` (pre-v0.11 relays). The reference relay MUST default to `"signaling-only"` when no profile is configured.

**What a signaling-only relay accepts.** On the client WebSocket a signaling-only relay MUST accept only the text frame types `register`, `ping`, `rtc_offer`, `rtc_answer`, `rtc_ice` and `watch`, MUST answer any other type with `{type:"error", code:"signaling_only"}` without acting on it, and MUST close the socket (close code 1003) on a binary frame. **PNP-001-MUST-071** It MUST NOT keep a store-and-forward buffer, MUST NOT serve `POST /tokens/issue`, `POST /telemetry`, `POST /endorse`, `POST /directory/push`, the federation link, `GET /peers/presence` or `GET /peers/lookup` (each is answered 404, whatever the request carries), and MUST NOT issue TURN credentials: `GET /turn-credentials` returns only STUN URIs with empty `username` / `credential`. `GET /directory` stays readable.

**Who learns that a peer is online.** A signaling-only relay tells nobody over HTTP which PeerIds are connected to it: it does not serve the presence and lookup endpoints of PNP-008 §10.5 – §10.6 (MUST-071 above), `GET /bootstrap` returns an empty list, and `GET /peers` is the operator's (an admin token). Whether a peer is online is learned only over a socket that has registered per §10.7: by the `presence` push between mutual watchers (MUST-076) and by the `peer_offline` answer to a signaling frame (MUST-073), both within the caps of MUST-074. Registration is free, so this does not hide presence from a determined party that knows a PeerId; it makes asking cost a registered, rate-limited socket where it used to cost one anonymous HTTP request.

**Signaling frames.** `rtc_offer` / `rtc_answer` / `rtc_ice` MUST be forwarded only from a registered socket to a peer that is registered and online at that moment, with `from` set to the sender's registered PeerId; they MUST NOT be queued for a peer that is offline. When the recipient is not online the relay MUST answer `{type:"error", code:"peer_offline", peer_id:<to>}`. **PNP-001-MUST-073** The `payload` of an `rtc_offer` or `rtc_answer` MUST NOT exceed 16384 bytes and that of an `rtc_ice` MUST NOT exceed 2048 bytes; a larger payload is refused with `code:"payload_too_large"`. **PNP-001-MUST-072** Per registered sender the relay MUST forward at most 60 signaling frames per minute and 240 per hour, and at most 64 frames per 10 minutes for one (sender, recipient) pair, refusing the excess with `code:"rate_limited"`. **PNP-001-MUST-074** With these caps a modified client can tunnel at most a few kilobytes per second to one cooperating online peer, which is the floor for any signaling service.

**Presence push.** A registered client MAY send `{type:"watch", peer_ids:[<hex PeerId>, …]}`. Each `watch` replaces the sender's previous set; the relay keeps at most 256 ids per sender and drops malformed ids and the sender's own id. The relay MUST report presence only between **mutual** watchers: it sends `{type:"presence", peer_id:X, online:true}` to W only if W watches X and X watches W — immediately after either `watch` makes the pair mutual while both are online, and when X registers later — and `{type:"presence", peer_id:X, online:false}` when X's socket closes. **PNP-001-MUST-076** A stranger who watches a PeerId therefore learns nothing from the push. The watch set is dropped when the socket closes. `watch` and `presence` are available in both profiles.

**Client behaviour (non-normative rationale, normative SHOULD).** Because a signaling-only relay forwards at most a few dozen signaling frames per minute per sender, clients SHOULD send connection SDP non-trickle (wait for ICE gathering to complete, bounded at a few seconds, and send the candidates inside the offer / answer), SHOULD stagger new connection attempts, and SHOULD back off on `rate_limited` instead of retrying at once. **PNP-001-SHOULD-016** With no relay message path, all content (chat, group fan-out, files, call signalling) rides the direct peer-to-peer data channel; messages for a contact who is offline queue on the sender until both are online. Direct connections reveal each side's network address to the contact (never to strangers, since connections are only attempted to contacts); clients SHOULD say so plainly and SHOULD let the user configure their own TURN server, which then relays only for that user.

**TURN is user-supplied (client).** A TURN server sits on the path of every packet it relays and learns both endpoints' addresses, so which one is used is the user's decision alone. A client MUST NOT gather relay candidates from, or send any traffic through, a TURN server announced by a relay whose profile is `signaling-only` (it takes only the `stun:` URIs of that relay's `/turn-credentials` answer and ignores every other URI and any `username` / `credential`), and MUST NOT have a TURN server built in. The only TURN server such a client uses is one the user configured with its own credential. That server is used in one of two ways, which the user chooses: as one more candidate next to the direct ones (for pairs with no direct path), or **relay-only**, where the client MUST gather and signal relay candidates from that server only (no host or server-reflexive candidate, and no related address that names one), MUST NOT send connectivity checks to, or answer them from, any address but through that server, and, when the server yields no relay candidate (unreachable, credential refused), MUST NOT fall back to a direct connection: the contact is reported as having no path, and the user is told why. **PNP-001-MUST-082** The reference native client applies the first sentence to relays of either profile. Relay-only hides the user's address from contacts; the TURN server's operator still sees it, which is why it must be the user's own.

**Presence without a push (client).** A `peer_offline` answer says only that the recipient was not registered at that moment. Unless the pair are mutual watchers within the 256-id limit, the relay never reports that this changed. A client whose only evidence that a contact is offline is a `peer_offline` answer (no `presence` push for that contact since) SHOULD treat it as provisional and offer again with exponential backoff and jitter, whether or not messages are queued for the contact (the reference client: after 15 seconds, doubling up to 5 minutes for a contact that has queued messages or that the user asked to connect to, and up to 15 minutes for any other), and SHOULD stop when a connection comes up or a `presence` push for the contact arrives; a push is authoritative in both directions, so a contact pushed offline is not probed. A user's explicit request to connect SHOULD offer at once and start the backoff over. All such probes together SHOULD stay well below the per-sender caps of MUST-074 (the reference client: a bucket of 12 probes refilled one per minute, at most 72 an hour, contacts the user waits for first) and SHOULD pause while the client backs off after `rate_limited`. **PNP-001-SHOULD-019**

**Logging.** A relay SHOULD NOT write PeerIds at its default log level, SHOULD NOT write access logs that pair client addresses with PeerIds, and SHOULD NOT accept PeerIds in request URLs; the reference relay, in both profiles, answers `GET /bootstrap` with an empty list and ignores its `exclude` parameter (through v0.14 a relay-profile relay listed up to 20 online PeerIds there to any caller). **PNP-001-SHOULD-017**

#### 10.5.1 Direct Data-Channel Binding

The data channel's SDP (offer and answer, with each side's DTLS certificate fingerprint) crosses the relay in plaintext. A relay that replaced both fingerprints with its own could terminate DTLS towards each peer and relay between them: it could not read end-to-end encrypted envelopes, but it would sit on the "direct" path, learn its timing and sizes, and drop envelopes the sender believes delivered. The binding below detects that.

**The binding message.** A CHANNEL_BINDING envelope (`msg_type = 0x14`) carries a CBOR map `{ "v": 1, "local": [fp, …], "remote": [fp, …] }`. Each `fp` is a text string `"<hash function> <fingerprint>"` taken from an `a=fingerprint:` line (RFC 8122), the hash function in lower case and the fingerprint in upper-case hex with colons; each list is sorted, has no duplicates and holds 1 to 8 entries. `local` lists the fingerprints of the sender's own local description for the connection the channel runs on; `remote` lists those of the remote description the sender applied. The envelope is an ordinary Double Ratchet envelope (§3), padded like any other.

**Sending.** Once the data channel of a direct connection is open and the sender holds a session with the peer, it MUST send exactly one CHANNEL_BINDING envelope on that channel. The QR scanner (PNP-003) sends its bootstrap-completing envelope (§5.3.1) first and its binding right after it; the presenter sends its binding once that envelope has materialized its session. **PNP-001-MUST-079**

**Verifying.** The receiver MUST compare the binding with its own view of the same connection: the peer's `local` list MUST equal the fingerprints of the remote description the receiver applied, and the peer's `remote` list MUST equal the fingerprints of the receiver's own local description. On any difference, or a binding that does not decode, the receiver MUST close the connection without sending further envelopes on it and MUST tell the user that the direct connection failed its end-to-end check. **PNP-001-MUST-080**

**Before verification.** Until the peer's binding has verified, a client MUST NOT send call signals (PNP-007 `CALL_SIGNAL`) on the channel and MUST NOT present the path to the user as a direct connection. A client that has not received a valid binding within 20 seconds of the channel opening MUST close the connection (it MAY retry with a new connection). **PNP-001-MUST-081** A client SHOULD hold every content envelope other than the bootstrap-completing envelope and its own binding until the peer's binding has verified, so that envelopes reported as sent did not go to an interposed relay. **PNP-001-SHOULD-018**

Call connections need no separate binding: their offer and answer travel as `CALL_SIGNAL` envelopes inside the session, so their fingerprints are end-to-end authenticated already. A user who also compares safety numbers (PNP-002 §10) knows the session itself is with the right person.

### 10.6 Resource Bounds

These bounds apply to every relay, whatever its profile. They close paths by which an anonymous client could make a relay hold unbounded memory or forward unmetered traffic.

**Connections and registration.** The relay MUST: cap the size of one WebSocket message (32768 bytes in the signaling-only profile, 131072 bytes in the relay profile; larger messages close the socket); limit new WebSockets per client network address (20 per minute) and concurrent WebSockets per address (8) and in total (5000 by default); close a socket that has not completed registration within 10 seconds; accept from an unregistered socket only `register` and `ping` (anything else is refused with `code:"not_registered"`, including onion cells and `message` / `gossip` frames in the relay profile); allow at most 4 `register` frames per socket and at most 3 PeerIds registered at once from one address; and apply a per-socket frame budget to every frame, registered or not. **PNP-001-MUST-075** Behind a reverse proxy the client address is the one the proxy reports, accepted only from configured trusted proxies.

**Store-and-forward (relay profile).** The per-recipient bounds of PNP-005 §5.4 (256 messages, 4 MB) are not sufficient on their own because the recipient PeerId is never checked to exist. The relay MUST refuse to buffer a frame larger than the per-recipient size cap, MUST cap the number of recipients with buffered messages (4096 in the reference relay) and MUST cap the total bytes buffered across all recipients (64 MB in the reference relay); a refused frame is answered with an `error` frame, not `queued`. **PNP-001-MUST-077**

**Issuance and onion state (relay profile).** The relay MUST cap the BlindedElements accepted in one `POST /tokens/issue` request (1024) and MUST rate-limit issuance requests per client network address (10 per minute), answering the excess with HTTP 429; it MUST cap the onion circuits one socket may hold (64). **PNP-001-MUST-078**

| Parameter | Value |
|-----------|-------|
| `max_ws_message_bytes` (signaling-only / relay) | 32768 / 131072 |
| `max_sdp_payload_bytes` / `max_ice_payload_bytes` | 16384 / 2048 |
| signaling per sender | 60 / min, 240 / h |
| signaling per (sender, recipient) | 64 / 10 min |
| new sockets per address | 20 / min |
| concurrent sockets per address / total | 8 / 5000 |
| register deadline | 10 s |
| register frames per socket | 4 |
| registered PeerIds per address | 3 |
| watch ids per socket | 256 |
| buffered recipients / total bytes (relay profile) | 4096 / 64 MB |
| BlindedElements per issuance request / requests per address (relay profile) | 1024 / 10 per min |
| onion circuits per socket (relay profile) | 64 |
| register challenge lifetime | 60 s |

### 10.7 Registration

A client registers a PeerId on a relay socket by proving that it holds the Ed25519 key the PeerId is the hash of. Everything a relay does for a PeerId (forwarding signaling to it, reporting its presence, delivering its mailbox in the relay profile) goes to the socket that registered it, so a registration obtained in someone else's name is an impersonation towards everyone who signals to that PeerId.

**The exchange.**

```
client → relay   {"type":"register","peer_id":<64 hex>}
relay  → client  {"type":"challenge","nonce":<64 hex>,"peer_id":<64 hex>}
client → relay   {"type":"register","peer_id":<64 hex>,"pubkey":<64 hex>,
                  "signature":<128 hex>,"nonce":<64 hex>,"relay":<relay name>
                  [,"relay_key":<64 hex>]}
relay  → client  {"type":"registered","peer_id":…,"profile":…}
            or   {"type":"error","code":"register_failed","message":…}
```

**The challenge.** The nonce MUST be 32 bytes from a cryptographically secure random source, issued by the relay on that socket in answer to a `register` without credentials. The relay MUST accept a `register` with credentials only if its `nonce` equals (compared in constant time) the nonce outstanding on **that socket**, issued no more than 60 seconds earlier and not yet answered; the relay MUST verify the signature over its own copy of the nonce, never the client's; and every `register` with credentials MUST spend the outstanding nonce, whether it is accepted or refused, so that one nonce is checked against at most one signature. **PNP-001-MUST-083** A relay MAY return the same nonce to a second credential-less `register` that arrives while one is outstanding; its lifetime is not extended. A refusal carries no new nonce: the client asks again, within the register-frame limit of §10.6.

**The register message.** The client MUST compute `signature` as its Ed25519 signature, with the identity key, over exactly these bytes:

```
register_message =
    label      (25 bytes)  ASCII "PNP-001-relay-register-v1"
 || nonce      (32 bytes)  the relay's challenge
 || pin        ( 1 byte )  0x01 if the client pins the relay's identity key, else 0x00
 || relay_key  (32 bytes)  that Ed25519 public key; 32 zero bytes when pin = 0x00
 || name_len   ( 2 bytes)  length of name in bytes, big-endian
 || name       (name_len)  the canonical relay name (below), ASCII
```

Every field but the last has a fixed length and the last is length-prefixed, so two different inputs never give the same bytes. A client MUST NOT answer a challenge whose nonce is not 32 bytes, and MUST NOT sign the nonce in any other form (least of all the nonce alone, as revisions before v0.15 did). **PNP-001-MUST-084** The label keeps the signature from being taken for any other statement made with the identity key (and any of those for a register answer).

**The relay name.** The name is `host ":" port`, at most 259 bytes:

- `host` is the host of the URL the client opened the socket to: a DNS name or IPv4 literal in lowercase ASCII (letters, digits, `.`, `-`, `_`; an internationalised name in its A-label form; a single trailing dot removed), or an IPv6 literal in square brackets, in lowercase hexadecimal without leading zeros, the first longest run of two or more zero groups written `::`, and no dotted-decimal part.
- `port` is always present, in decimal without leading zeros. When the URL names no port it is the default of the URL's scheme: 443 for `wss` (and `https`), 80 for `ws` (and `http`).

`wss://Parol.Social/ws` gives `parol.social:443`; `ws://127.0.0.1:9000/ws` gives `127.0.0.1:9000`; `wss://[2001:DB8::1]:8443/ws` gives `[2001:db8::1]:8443`. The client MUST derive the name from the URL it opens the socket to, so that it names the host and port the socket actually goes to, and from nothing the relay sends; it MUST send the name in the `relay` field, and it MUST NOT open the socket when the URL has no such name (user information in the URL, a host outside the alphabet above, a scheme other than the four named). **PNP-001-MUST-085** The reference web client takes host and port from the browser's URL parser, the one the WebSocket constructor itself uses; the native client refuses any URL that is not a plain `scheme://host[:port]` followed by a path in that alphabet, so that no URL can be read as one host by it and as another by the library that connects.

**What the relay checks.** A relay is configured with the names its clients dial it under (`RELAY_PUBLIC_NAMES` in the reference relay). On a `register` with credentials whose nonce passed MUST-083 the relay MUST verify, and MUST answer `{type:"error", code:"register_failed"}` without registering the socket when any of it fails, that: `peer_id` is the SHA-256 of `pubkey`; `relay` is a relay name in canonical form, byte for byte, and one of the relay's configured names; and `signature` verifies under `pubkey` over the register message built from the relay's own copy of the nonce and that configured name. **PNP-001-MUST-086** An answer the client made for another relay therefore fails at this one, whether it is presented as made (the name is not this relay's) or with the `relay` field rewritten (the signature covers the other name). A relay with no configured name MUST accept only loopback names (`localhost`, an address in `127.0.0.0/8`, `[::1]`; any port) and no other: a client that signed a loopback name was talking to its own machine, so the default serves development on one host and gives nothing to a relay elsewhere.

**Pinning the relay's identity key.** A client that already knows the Ed25519 identity key of the relay it means to reach (from a descriptor that passed PNP-008 §6.3, or out of band) MAY bind it: it sets `pin` to 0x01, puts the key in `relay_key` of the register message and sends the key as the `relay_key` field. **PNP-001-MAY-006** The client MUST NOT take that key from the socket it is registering on. A relay that receives a `relay_key` field MUST refuse the answer unless the field equals its own identity key, and MUST verify the signature over the register message with `pin` = 0x01 and its own key; when the field is absent it MUST verify with `pin` = 0x00 and 32 zero bytes. **PNP-001-MUST-087** Neither side can therefore add or remove the pin after the fact. Neither reference client pins today: on a signaling-only relay a client knows only the relay's URL.

**What this does and does not establish.** The binding is to the name the client dialed. A client that dials relay E gives E an answer that only E can use. It does not protect a client that reaches an impostor under the genuine relay's own name: over `wss` that takes a certificate for that name, and over plain `ws` only control of the network path, which is why a client outside development uses `wss`. Two processes configured with one name are one relay as far as registration goes; an operator who runs several behind one name intends exactly that.

[RFC 9497]: https://www.rfc-editor.org/rfc/rfc9497.html
[RFC 9578]: https://www.rfc-editor.org/rfc/rfc9578.html
