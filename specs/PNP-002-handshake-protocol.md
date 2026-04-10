# PNP-002: ParolNet Handshake Protocol

### Status: DRAFT
### Version: 0.1
### Date: 2026-04-10

---

## 1. Overview

The ParolNet Handshake Protocol (PHP) defines how two peers establish an encrypted session. It adapts the Extended Triple Diffie-Hellman (X3DH) key agreement protocol for a fully decentralized environment where no central key server exists. Pre-key bundles are distributed through the relay network, direct exchange, or out-of-band mechanisms (PNP-003).

Upon completion of the handshake, both peers derive a shared secret that initializes a Double Ratchet session for ongoing message encryption. The protocol provides forward secrecy, future secrecy (via rekeying), and cryptographic deniability.

## 2. Terminology

All RFC 2119 keywords apply as defined in PNP-001 Section 2. Additional terms:

- **IK**: Identity Key. A long-term Ed25519 keypair. The public key hashes to the PeerId.
- **SPK**: Signed Pre-Key. A medium-term X25519 keypair, signed by the IK. Rotated periodically (RECOMMENDED: every 7-30 days).
- **OPK**: One-Time Pre-Key. An ephemeral X25519 keypair, used once and discarded. Peers SHOULD maintain a pool of 20-100 OPKs.
- **EK**: Ephemeral Key. A single-use X25519 keypair generated at handshake initiation time.
- **Pre-Key Bundle**: The set {IK_pub, SPK_pub, SPK_sig, [OPK_pub]} published by a peer.
- **KDF**: Key Derivation Function. HKDF-SHA-256 (RFC 5869).

## 3. Message Format

### 3.1 Pre-Key Bundle

The pre-key bundle is CBOR-encoded and distributed via the relay network, direct transfer, or out-of-band (PNP-003). It is wrapped in a PNP-001 envelope with `msg_type = 0x05` (HANDSHAKE).

```
PreKeyBundle = CBOR Map:
  {
    "ik"      : bstr(32),       -- Ed25519 identity public key.
    "spk"     : bstr(32),       -- X25519 signed pre-key public key.
    "spk_id"  : uint32,         -- Signed pre-key identifier.
    "spk_sig" : bstr(64),       -- Ed25519 signature over (spk || spk_id).
    "opks"    : [                -- Array of one-time pre-keys. MAY be empty.
                  {
                    "id"  : uint32,    -- One-time pre-key identifier.
                    "key" : bstr(32)   -- X25519 one-time pre-key public key.
                  }
                ]
  }
```

A peer SHOULD publish a new pre-key bundle whenever its OPK pool is depleted or its SPK is rotated.

### 3.2 Handshake Initiation Message (Alice -> Bob)

```
HandshakeInit = CBOR Map:
  {
    "type"       : uint8,          -- 0x01 (INIT).
    "ik_a"       : bstr(32),       -- Alice's Ed25519 identity public key.
    "ek_a"       : bstr(32),       -- Alice's ephemeral X25519 public key.
    "spk_id_b"   : uint32,         -- ID of Bob's signed pre-key Alice used.
    "opk_id_b"   : uint32 / null,  -- ID of Bob's one-time pre-key Alice used,
                                      or null if none was available.
    "nonce"      : bstr(16),       -- 128-bit cryptographically random nonce.
    "ciphertext" : bstr,           -- Initial message encrypted with derived key.
    "aead_algo"  : uint8           -- 0x01 = ChaCha20-Poly1305, 0x02 = AES-256-GCM.
  }
```

### 3.3 Handshake Response Message (Bob -> Alice)

```
HandshakeResponse = CBOR Map:
  {
    "type"       : uint8,         -- 0x02 (RESPONSE).
    "ik_b"       : bstr(32),      -- Bob's Ed25519 identity public key.
    "ek_b"       : bstr(32),      -- Bob's ephemeral X25519 public key.
    "nonce"      : bstr(16),      -- 128-bit cryptographically random nonce.
    "ciphertext" : bstr,          -- Response encrypted with session key.
    "ratchet_key": bstr(32)       -- Bob's initial Double Ratchet public key.
  }
```

### 3.4 Rekeying Message

```
RekeyMessage = CBOR Map:
  {
    "type"         : uint8,       -- 0x03 (REKEY).
    "new_spk"      : bstr(32),    -- New X25519 signed pre-key public key.
    "new_spk_id"   : uint32,      -- New signed pre-key identifier.
    "new_spk_sig"  : bstr(64),    -- Ed25519 signature over (new_spk || new_spk_id).
    "nonce"        : bstr(16),    -- 128-bit cryptographically random nonce.
    "ciphertext"   : bstr         -- Confirmation, encrypted with current session.
  }
```

### 3.5 Close Message

```
CloseMessage = CBOR Map:
  {
    "type"       : uint8,         -- 0x04 (CLOSE).
    "nonce"      : bstr(16),      -- 128-bit cryptographically random nonce.
    "ciphertext" : bstr           -- Reason/confirmation, encrypted.
  }
```

## 4. State Machine

```
                         publish PreKeyBundle
                                |
                                v
                        +-------+-------+
          (Alice)       |     INIT      |       (Bob)
       generate EK ---->               <---- waiting for contact
                        +-------+-------+
                                |
                  Alice sends HandshakeInit
                                |
                                v
                        +-------+-------+
                        |    OFFERED    |
                        | (Alice waits) |
                        +-------+-------+
                                |
                  Bob validates, sends HandshakeResponse
                                |
                                v
                        +-------+-------+
                        |   ACCEPTED   |
                        | (Bob waits   |
                        |  for first   |
                        |  DR message) |
                        +-------+-------+
                                |
                  Alice validates, sends first DR message
                                |
                                v
                        +-------+-------+
                        |  ESTABLISHED |
                        | (both peers  |
                        |  in Double   |
                        |  Ratchet)    |
                        +-------+-------+
                           |         |
              rekey trigger|         | close trigger
                           v         v
                   +-------+--+  +---+--------+
                   | REKEYING |  |   CLOSED   |
                   +-------+--+  +------------+
                           |
                   rekey complete
                           |
                           v
                   +-------+-------+
                   |  ESTABLISHED  |
                   +---------------+
```

State transition table:

| Current State | Event | Next State | Action |
|--------------|-------|------------|--------|
| INIT | Alice sends HandshakeInit | OFFERED | Start timeout (60s) |
| INIT | Bob receives HandshakeInit | ACCEPTED | Validate, derive keys, send HandshakeResponse |
| OFFERED | Alice receives HandshakeResponse | ESTABLISHED | Validate, derive keys, init Double Ratchet |
| OFFERED | Timeout (60s) | INIT | MAY retry with new EK |
| ACCEPTED | Bob receives first DR message | ESTABLISHED | Confirm session |
| ACCEPTED | Timeout (120s) | INIT | Discard session state |
| ESTABLISHED | Either peer sends RekeyMessage | REKEYING | Begin key rotation |
| REKEYING | Peer confirms rekey | ESTABLISHED | Update session keys |
| REKEYING | Timeout (60s) | ESTABLISHED | Abort rekey, keep old keys |
| ESTABLISHED | Either peer sends CloseMessage | CLOSED | Destroy session state |
| Any | Unrecoverable error | CLOSED | Destroy session state |

## 5. Processing Rules

### 5.1 X3DH Key Agreement (Adapted for Decentralized Use)

The X3DH computation proceeds as follows. Alice has obtained Bob's pre-key bundle through one of:
- The relay network (Bob published it as a HANDSHAKE message).
- Direct exchange (Bluetooth, local network, USB).
- Out-of-band bootstrap (PNP-003).

Alice MUST verify `spk_sig` against `ik` before proceeding. If verification fails, the handshake MUST be aborted.

Alice converts her Ed25519 IK to an X25519 key for DH computation (using the birational map defined in RFC 8032, Section 5.1.5). Bob's IK is similarly converted.

Alice computes:

```
DH1 = X25519(IK_a_x25519_private, SPK_b)
DH2 = X25519(EK_a_private, IK_b_x25519)
DH3 = X25519(EK_a_private, SPK_b)
DH4 = X25519(EK_a_private, OPK_b)      -- only if OPK_b is available
```

The shared secret is:

```
If OPK used:
  SK = HKDF-SHA-256(
    salt = 32 zero bytes,
    ikm  = 0xFF repeated 32 bytes || DH1 || DH2 || DH3 || DH4,
    info = "ParolNet_X3DH_v1",
    len  = 32
  )

If no OPK:
  SK = HKDF-SHA-256(
    salt = 32 zero bytes,
    ikm  = 0xFF repeated 32 bytes || DH1 || DH2 || DH3,
    info = "ParolNet_X3DH_v1",
    len  = 32
  )
```

The leading 32 bytes of 0xFF serve as a domain separator (consistent with the Signal X3DH specification).

### 5.2 Handshake Initiation (Alice)

1. Alice MUST generate a fresh ephemeral X25519 keypair (EK_a).
2. Alice MUST perform the X3DH computation as described in Section 5.1.
3. Alice MUST derive an encryption key and IV from SK for the initial ciphertext:
   ```
   init_key = HKDF-SHA-256(salt=SK, ikm="ParolNet_init_key", len=32)
   init_iv  = HKDF-SHA-256(salt=SK, ikm="ParolNet_init_iv", len=12)
   ```
4. Alice MUST encrypt her initial payload (which MAY include an initial text message, or MAY be empty) using the negotiated AEAD with `init_key` and `init_iv`.
5. Alice MUST send the HandshakeInit in a PNP-001 envelope with `msg_type = 0x05`.
6. Alice MUST transition to the OFFERED state and start a 60-second timeout.
7. Alice MUST delete EK_a private key material only after the session is ESTABLISHED. If the handshake fails, Alice MUST delete it immediately.

### 5.3 Handshake Response (Bob)

1. Bob MUST verify that `spk_id_b` matches a current or recent SPK. Bob SHOULD accept SPKs from the previous rotation period (to handle race conditions).
2. If `opk_id_b` is present, Bob MUST verify it matches an unused OPK and MUST delete that OPK after use (one-time property).
3. Bob MUST perform the X3DH computation (DH operations are symmetric).
4. Bob MUST derive the same `init_key` and `init_iv` and verify Alice's ciphertext.
5. Bob MUST generate a fresh ephemeral key (EK_b) and a Double Ratchet initial keypair.
6. Bob MUST send the HandshakeResponse.
7. Bob MUST transition to the ACCEPTED state.

### 5.4 Session Establishment

1. Upon receiving the HandshakeResponse, Alice MUST verify Bob's identity key and derive the session keys.
2. Both peers MUST initialize the Double Ratchet with:
   - `SK` as the root key.
   - Bob's `ratchet_key` as the initial ratchet public key.
3. Alice MUST send the first Double Ratchet message (which performs the first ratchet step) to confirm the session.
4. Both peers MUST transition to ESTABLISHED upon successful completion.

### 5.5 Rekeying

1. Either peer MAY initiate rekeying. Implementations SHOULD rekey after 7 days or 10,000 messages, whichever comes first.
2. The initiating peer MUST generate a new SPK and sign it with their IK.
3. The RekeyMessage MUST be encrypted with the current Double Ratchet session.
4. The receiving peer MUST verify the new SPK signature and acknowledge the rekey.
5. Both peers MUST derive a new root key:
   ```
   new_root = HKDF-SHA-256(
     salt = current_root_key,
     ikm  = DH(old_ratchet_private, new_spk),
     info = "ParolNet_rekey_v1",
     len  = 32
   )
   ```
6. Both peers MUST continue accepting messages encrypted with the old keys for a grace period of 120 seconds after rekey completion, to handle in-flight messages.

### 5.6 Session Closure

1. Either peer MAY send a CloseMessage at any time.
2. Upon sending or receiving a CloseMessage, the peer MUST securely erase all session state: root key, chain keys, message keys, ratchet keypairs.
3. A peer MUST NOT reuse any key material from a closed session.
4. After closure, a new handshake (starting from INIT) is REQUIRED to re-establish communication.

## 6. Security Considerations

1. **Forward Secrecy**: The use of ephemeral keys (EK_a, EK_b) and the Double Ratchet ensures that compromise of long-term identity keys does not reveal past session content. Each message uses a unique key derived through the ratchet.

2. **Key Compromise Impersonation (KCI)**: If Alice's IK is compromised, an attacker can impersonate Alice to Bob but cannot impersonate Bob to Alice (because the attacker does not know Bob's IK private key). This is a property inherited from X3DH.

3. **One-Time Pre-Key Exhaustion**: If Bob's OPK pool is exhausted, the handshake falls back to 3-DH (DH1, DH2, DH3). This provides weaker forward secrecy for the initial handshake (compromise of Bob's SPK and IK would reveal the initial messages). Implementations SHOULD replenish OPK pools proactively.

4. **SPK Rotation**: The SPK SHOULD be rotated every 7-30 days. The previous SPK SHOULD be retained for one additional rotation period to handle in-flight handshakes. SPKs older than two rotation periods MUST be deleted.

5. **Ed25519 to X25519 Conversion**: The birational map from Ed25519 to X25519 is well-defined and safe. Implementations MUST use a well-audited library for this conversion (e.g., the dalek-cryptography crate).

6. **Nonce Reuse Prevention**: Every handshake message includes a fresh 128-bit random nonce. Implementations MUST use a cryptographically secure random number generator.

7. **Timeout Handling**: The 60-second timeout in OFFERED state prevents resource exhaustion from unanswered handshakes. Implementations MUST limit the number of concurrent pending handshakes (RECOMMENDED: maximum 32).

8. **Deniability**: The handshake does not produce a non-repudiable transcript. The X3DH shared secret can be computed by either party, so neither can prove to a third party that the other participated. The SPK signature proves that Bob published a pre-key bundle, but does not prove that a specific session was established. Implementations MUST NOT add signatures or MACs over the handshake transcript that would break deniability.

## 7. Privacy Considerations

1. **Identity Key Exposure**: The HandshakeInit message contains Alice's identity public key (`ik_a`) in the cleartext header of the handshake payload. To mitigate this, `ik_a` SHOULD be placed inside the encrypted portion of the envelope payload when possible (i.e., when both peers have an existing session or a shared secret from PNP-003).

2. **Pre-Key Bundle Metadata**: Publishing pre-key bundles through the relay network reveals that a PeerId exists and is active. Implementations SHOULD publish pre-key bundles at regular intervals regardless of activity, and MAY publish decoy bundles for non-existent PeerIds.

3. **Handshake Correlation**: An observer who sees both a HandshakeInit and HandshakeResponse can correlate them by timing and the `spk_id_b` / `opk_id_b` values. These values are inside the encrypted payload and thus protected from relay observers, but the timing correlation remains. Implementations SHOULD add random delay before responding (100-2000ms).

4. **Session Duration**: Long-lived sessions can be correlated by traffic patterns. Periodic rekeying (Section 5.5) does not change the session's traffic pattern. For stronger privacy, peers MAY close and re-establish sessions periodically through different relay paths.
