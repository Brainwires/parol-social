# PNP-010: ParolNet File Transfer

### Status: CANDIDATE
### Version: 0.1
### Date: 2026-11-21

---

## Changelog

**v0.1 (2026-11-21)** — Initial specification. Replaces PNP-007 §7 (file transfer as Double Ratchet envelopes of 4096-byte chunks through relay circuits), which nothing deployed implements end to end. Allocates message-type code `0x15 FILE_TRANSFER` in the PNP-001 §3.4 registry and reserves data-channel labels under `pn-`.

---

## Implementation Note

Implemented by `crates/parolnet-transfer` (the messages, the record stream and both state machines, without I/O), driven by the native client core (`crates/parolnet-app`) and, through `crates/parolnet-wasm`, by the web client (`web/src/engine/transfers.ts`). Test vectors are in `specs/vectors/PNP-010/`; they were produced by an independent implementation.

---

## 1. Overview

PNP-010 moves one file from one peer to another. It has two parts:

- **Control messages** inside the end-to-end encrypted session (PNP-001, PNP-002): the *offer* (an identifier, the file's name, size and MIME type, the SHA-256 of its plaintext and a fresh 256-bit *file key*), and the receiver's and sender's later decisions (accept, decline, cancel, complete).
- **The record stream** on a reliable, ordered WebRTC data channel of its own, labelled `pn-file/<id>`, on the direct peer connection the two peers already share. The file is cut into records; each is sealed with ChaCha20-Poly1305 in the STREAM construction, so a record that was altered, reordered, repeated, taken from another attempt, or a stream that was cut short, fails at that record. When the last record has arrived the receiver compares the SHA-256 of what it stored with the offer's.

A transfer survives the loss of its channel, of the peer connection, of the Double Ratchet session and of either application process: the receiver states the next record it needs each time a channel opens.

Files travel only peer to peer. No record is ever carried by a relay as an envelope, stored on a relay, or sent through an onion circuit or the mesh. When the two peers have no direct path (or the user's own TURN server, which carries only DTLS it cannot read), the transfer waits.

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

- **Sender / receiver**: the peer that offers the file / the peer it is offered to.
- **Transfer**: one file offered by one sender to one receiver, named by its `id`. A transfer is scoped to the pair of peers: the same `id` from another contact is another transfer.
- **File key**: 256 random bits made by the sender for one transfer.
- **Record**: one piece of the file's plaintext, sealed. **Chunk**: the plaintext of a record.
- **Channel**: the data channel `pn-file/<id>`. **Attempt**: the life of one channel, from its opening to its closing.
- **Verified connection**: a direct peer connection whose channel binding has verified (PNP-001 §10.5.1).
- **Durably stored**: written to storage that survives the process and, as far as the platform allows it to be known, a power loss.

## 3. Transfer States

Each side keeps, per transfer, its *role* (sender or receiver) and a *phase*:

| Phase | Meaning | Final |
|-------|---------|-------|
| `offered` | The offer exists; the receiver has not answered. | no |
| `accepted` | The receiver accepted. Records flow whenever a verified connection exists. | no |
| `complete` | Every record arrived and the hash verified. | yes |
| `declined` | The receiver refused the offer. | yes |
| `cancelled` | Either side stopped the transfer. | yes |

```
            accept                 complete
 offered ───────────► accepted ───────────────► complete
    │                    │
    │ decline            │ cancel (either side)
    ▼                    ▼
 declined            cancelled ◄── cancel (either side, from offered too)
```

1. A control message moves a transfer only as follows; every other combination MUST be ignored without any change of state and without an answer: `accept` and `decline` move the **sender's** transfer from `offered`; `complete` moves the **sender's** transfer from `accepted`; `cancel` moves either side's transfer from `offered` or `accepted`; an `offer` creates a transfer on the receiver only when no transfer with that `id` and that peer exists. In particular a control message that names an unknown `id` (other than a new offer), or that arrives for a transfer in a final phase, MUST be ignored. **PNP-010-MUST-007**
2. An `offer` whose `id` names an existing transfer with that peer MUST NOT replace or change that transfer's name, size, hash or key, whatever its phase. **PNP-010-MUST-008**
3. When a transfer reaches a final phase, each side MUST erase its copy of the file key (from memory and from persistent storage). Implementations MUST hold file keys and the per-attempt record keys in memory that is zeroized on release and MUST NOT write them to logs or diagnostics. **PNP-010-MUST-009**

## 4. Control Messages

### 4.1 Encoding

A control message is the plaintext of an ordinary PNP-001 envelope with `msg_type = 0x15` (`FILE_TRANSFER`). The plaintext is a CBOR map (RFC 8949) with text-string keys:

```
Offer    = { "v": 1, "t": "offer",    "id": bstr(16),
             "name": tstr, "size": uint, "mime": tstr,
             "sha256": bstr(32), "key": bstr(32) }
Accept   = { "v": 1, "t": "accept",   "id": bstr(16) }
Decline  = { "v": 1, "t": "decline",  "id": bstr(16) }
Cancel   = { "v": 1, "t": "cancel",   "id": bstr(16), "reason": uint }
Complete = { "v": 1, "t": "complete", "id": bstr(16) }
```

1. A control message MUST be a single CBOR map of this shape with `v` equal to 1, and its encoding MUST NOT exceed 1024 bytes. A receiver MUST ignore a body that is not one well-formed CBOR item followed by nothing, is not a map, has a non-text or repeated key, lacks a field of its kind or has one of another type or length, or carries a `v` or `t` it does not know. It MUST ignore keys it does not know. Senders SHOULD write the keys in the order shown. **PNP-010-MUST-001**
2. `id` MUST be 16 bytes from a cryptographically secure random number generator, chosen anew for every offer. **PNP-010-MUST-002**
3. In an offer, `name` MUST be 1 to 255 bytes of UTF-8; `size` MUST be the exact length of the plaintext in bytes and MUST NOT exceed 2^40 (1 TiB); `mime` MUST be at most 127 bytes, each in the range 0x21–0x7E (it MAY be empty); `sha256` and `key` MUST be 32 bytes each. A sender MUST NOT send, and a receiver MUST ignore, an offer outside these limits. **PNP-010-MUST-003**
4. `key` MUST be 256 bits from a cryptographically secure random number generator, generated for this transfer alone. It MUST NOT be derived from, or reused as, any other key. **PNP-010-MUST-004**
5. `sha256` MUST be the SHA-256 digest of the file's entire plaintext, computed before the offer is sent. **PNP-010-MUST-005**
6. Control messages MUST be sent only as Double Ratchet envelopes of the session with that peer, padded like every other envelope (PNP-001 §3.6), and only on a verified connection. An implementation that cannot send one now (no verified connection) keeps it and sends it when it can. **PNP-010-MUST-006**

`mime` is the sender's claim and nothing more. A receiver SHOULD NOT open, execute or render a received file on its own initiative, and SHOULD treat `name` and `mime` as untrusted text when showing them. **PNP-010-SHOULD-007**

### 4.2 Accept and Decline

The receiver's user (or policy, §8) answers an offer with `accept` or `decline`. After `decline` the sender MUST NOT send any record of that transfer: a channel the peer opens for a transfer that is not in the `accepted` phase is closed (§5.1). **PNP-010-MUST-036**

### 4.3 Complete

1. The receiver MUST send `complete` once the final check (§7.2) has passed, and only then. The sender MUST NOT treat a transfer as delivered, nor show it as such, before it has received `complete`: having written the last record to the channel is not delivery. **PNP-010-MUST-023**

### 4.4 Cancel

Either side MAY cancel a transfer that is not in a final phase by sending `cancel`. `reason` is one of:

| Code | Name | Meaning |
|------|------|---------|
| 0 | user | The user cancelled. |
| 1 | unavailable | The sender can no longer read the file (removed, changed, permission lost). |
| 2 | integrity | A record or the final hash did not verify. |
| 3 | storage | The receiver could not store the file. |
| 4 | limit | A limit of the canceller (size, count, age). |

Codes above 4 are reserved; a receiver treats an unknown code as "cancelled".

1. On sending or receiving `cancel` both sides MUST stop sending records of that transfer and close its channel, and the receiver MUST delete whatever part of the file it stored. **PNP-010-MUST-035**
2. A sender that can no longer provide the file (for example a web page that was reloaded and lost its file handle) MAY cancel with reason 1 instead of keeping the transfer waiting. **PNP-010-MAY-001**

## 5. The Channel

### 5.1 Opening and Admission

1. The record stream of a transfer MUST flow on a WebRTC data channel that is reliable and ordered (the defaults: no `maxRetransmits`, no `maxPacketLifeTime`, `ordered` true), whose label is `pn-file/` followed by the 32 lower-case hexadecimal digits of the transfer's `id`. The channel is opened by the **receiver**, after it has sent `accept`, on the verified connection it has with the sender; it is created in-band (DCEP), with no renegotiation. **PNP-010-MUST-010**
2. Data-channel labels that begin with `pn-` are reserved for ParolNet specifications. An implementation MUST close a channel the peer opened whose label begins with `pn-` and is not a label it implements; under this specification that is every such label that is not `pn-file/` followed by exactly 32 lower-case hexadecimal digits. Labels that do not begin with `pn-` are outside this specification (the label `parolnet` is the session's own channel, PNP-001 §10.5). **PNP-010-MUST-011**
3. The sender MUST close a `pn-file/<id>` channel the peer opened unless all of the following hold: the connection is verified; `<id>` names a transfer with that peer in which this side is the sender; that transfer is in the `accepted` phase. **PNP-010-MUST-012**
4. A new channel for a transfer supersedes an older one for the same transfer: both sides close the older.

### 5.2 Frames

Every message on the channel is a binary message whose first byte is the frame type:

```
RESUME (0x01), receiver → sender, 21 bytes:
  0x01 || next (u32, big-endian) || receiver_nonce (16 bytes)

START (0x02), sender → receiver, 21 bytes:
  0x02 || next (u32, big-endian) || sender_salt (16 bytes)

RECORD (0x03), sender → receiver, 17 to 65536 bytes:
  0x03 || ciphertext || tag (16 bytes)
```

1. No message on the channel may exceed 65536 bytes, the size every WebRTC implementation accepts (RFC 8841 §6). A message that is longer, is empty, is a text message, has an unknown type, or has a length its type does not allow MUST end the attempt: the side that received it closes the channel and processes nothing of it. Ending an attempt MUST NOT by itself change the transfer's phase. **PNP-010-MUST-013**
2. The receiver MUST send exactly one RESUME, as its first message on the channel. `next` MUST be the number of records it has durably stored, that is, the index of the next record it needs; `receiver_nonce` MUST be 16 bytes from a cryptographically secure random number generator, new for every channel. **PNP-010-MUST-014**
3. The sender MUST NOT send anything before it has received RESUME. It MUST answer with exactly one START that repeats `next` and carries a `sender_salt` of 16 bytes from a cryptographically secure random number generator, new for every channel, followed by the records `next`, `next + 1`, … up to the last, in order. If `next` is not smaller than the transfer's record count, or the first message is not a RESUME, it MUST close the channel. **PNP-010-MUST-015**
4. A well-formed frame out of place MUST end the attempt in the same way: a RECORD before START, a second START, a START whose `next` differs from the RESUME's, a RECORD after the last record, a RESUME or any second message received by the sender, a RESUME received by the receiver. **PNP-010-MUST-020**

## 6. The Record Stream

### 6.1 Records

Let `CHUNK = 65519` (so that a RECORD frame is at most 65536 bytes: one type byte, the chunk, a 16-byte tag).

1. A file of `size` bytes is carried by `N = max(1, ceil(size / CHUNK))` records. Record `i` (counting from 0) carries bytes `i × CHUNK` up to, not including, `min(size, (i + 1) × CHUNK)` of the plaintext: every record but the last carries exactly `CHUNK` bytes, the last carries the rest (1 to `CHUNK` bytes, or nothing when the file is empty). **PNP-010-MUST-016**

### 6.2 Keys and Nonces

1. Each attempt has its own record key:

   ```
   record_key = HKDF-SHA-256(
       salt = sender_salt || receiver_nonce,              (32 bytes)
       ikm  = file key,
       info = "PNP-010 record key v1" || id || next,      (ASCII, 16 bytes, u32 big-endian)
       L    = 32)
   ```

   where `sender_salt`, `receiver_nonce` and `next` are those of the attempt's START and RESUME. **PNP-010-MUST-017**
2. Record `i` MUST be sealed with ChaCha20-Poly1305 (RFC 8439) under the attempt's record key, with empty associated data and the 12-byte nonce `0x00 × 7 || i (u32, big-endian) || flag`, where `flag` is `0x01` for the last record of the file (`i = N − 1`) and `0x00` for every other. The RECORD frame carries the ciphertext followed by the tag. **PNP-010-MUST-018**
3. Both sides MUST use a new `sender_salt` and a new `receiver_nonce` for every attempt and MUST discard an attempt's record key when its channel closes. A record sealed in one attempt therefore opens in no other, and no record index is ever sealed twice under one key, even when the sender's file changed between attempts. **PNP-010-MUST-026**
4. Records are neither padded nor compressed: the ciphertext of a record MUST be exactly as long as its chunk, and the plaintext MUST NOT be compressed before sealing (compression before encryption leaks through length). **PNP-010-MUST-028**

### 6.3 Sending

1. The sender SHOULD pause when the channel's buffered amount (W3C `bufferedAmount`) exceeds 4 MiB and continue when it has fallen to 1 MiB or below, reading the file as it goes; it SHOULD NOT hold more of the file in memory than those buffers need. **PNP-010-SHOULD-001**
2. Before each attempt the sender SHOULD check that the file still has the offered size and has not been modified since the offer, and cancel with reason 1 when it has. **PNP-010-SHOULD-004**

### 6.4 Receiving

1. The receiver MUST open each RECORD as record `next` (the count of records received so far in order), with the last-record flag set exactly when `next = N − 1`. A record that does not authenticate, or whose plaintext is not exactly as long as §6.1 says record `next` is, MUST be discarded whole: none of its plaintext is stored, shown or hashed, `next` does not move, and the attempt ends (§5.2). **PNP-010-MUST-019**
2. The receiver MUST NOT regard the transfer as received until it has opened the record sealed with the last-record flag. A channel that closes earlier, for whatever reason and however much has arrived, leaves the transfer in the `accepted` phase. **PNP-010-MUST-021**
3. A receiver that ends three attempts in a row on a record that did not verify, with no record accepted in between, SHOULD cancel the transfer with reason 2. **PNP-010-SHOULD-005**

## 7. Completion, Resume and Storage

### 7.1 Resume

1. While a transfer is in the `accepted` phase and no channel for it is open, the receiver MUST open a new channel (§5.1) whenever it has a verified connection with the sender and capacity (§8), and state in RESUME the next record it needs. The sender MUST serve any `next` from 0 to `N − 1`, whatever it sent before; it MUST NOT require the transfer to start over, and the receiver MUST NOT ask for records it has durably stored. **PNP-010-MUST-024**
2. Until a transfer reaches a final phase both sides MUST keep, in persistent storage, what the transfer needs to continue: the offer with its file key, the phase, and (receiver) the number of records durably stored together with those records' plaintext, (sender) the means to read the file again. This state MUST NOT depend on the Double Ratchet session, the peer connection or the process that existed when the offer was made. A receiver that continues after a restart MUST include the plaintext it stored before the restart in the final hash. **PNP-010-MUST-025**
3. The receiver SHOULD count a record as stored only after its plaintext has been flushed to durable storage, and SHOULD record its progress at least every 16 MiB or every second. **PNP-010-SHOULD-002**
4. Either side SHOULD drop a transfer that has made no progress for 30 days: a pending offer is declined or cancelled with reason 4. **PNP-010-SHOULD-003**

### 7.2 Final Check

1. When the last record has been opened and stored, the receiver MUST compute the SHA-256 digest of the entire plaintext it stored and compare it with the offer's `sha256` in constant time. If they are equal the transfer is `complete` (§4.3). If they differ the receiver MUST delete the stored data, MUST NOT present any of it to the user as the file, and MUST cancel the transfer with reason 2. **PNP-010-MUST-022**

### 7.3 File Names

1. The receiver MUST NOT use the offered `name` as a path. It MUST derive the local file name from it by keeping only the last path component (both `/` and `\` separate components), removing control characters, the characters `< > : " | ? *` and the Unicode direction and invisible formatting characters (U+200B–U+200F, U+202A–U+202E, U+2060–U+2069, U+FEFF), removing leading dots, surrounding white space and trailing dots, and substituting a fixed name when nothing is left; and it MUST NOT replace an existing file when it stores the result (it picks another name instead). **PNP-010-MUST-034**

## 8. Limits and Abuse Bounds

1. A receiver MUST have a maximum size for the files it accepts and MUST decline an offer above it without asking the user. The default is 4 GiB. **PNP-010-MUST-030** A receiver MAY let its user choose another limit, lower or higher, up to the protocol's 2^40 bytes. **PNP-010-MAY-002**
2. A receiver MUST keep at most 16 offers from one contact waiting for an answer and MUST decline further offers from that contact while 16 are waiting. **PNP-010-MUST-031**
3. A receiver MUST limit the rate of offers it lets in from one contact with a bucket of 10 offers that regains one every 6 seconds, and MUST decline the offers above it. **PNP-010-MUST-032**
4. At most 4 transfer channels may be open at once on one connection in each direction: a receiver MUST NOT open a fifth channel for transfers from one sender, and a sender MUST close a channel the peer opens while 4 of that peer's transfer channels are open on the connection. Accepted transfers beyond that wait their turn. **PNP-010-MUST-033**
5. File records MUST be sent only on the transfer's own data channel of a direct peer connection, as RECORD frames (§5.2). They MUST NOT be sent as envelopes, through a relay's message path or store-and-forward buffer, through onion circuits (PNP-004) or the mesh (PNP-005). A relay is involved only as far as it already is for the connection itself: signaling, or the user's own TURN server relaying DTLS it cannot read. When no direct path exists the transfer waits. **PNP-010-MUST-027**
6. A sender MUST NOT let the channel's buffered amount exceed 16 MiB (some implementations close a channel beyond that). **PNP-010-MUST-029**
7. A receiver that declines an offer under 1–3 SHOULD send `decline`, so that the sender's side settles. **PNP-010-SHOULD-006**

## 9. Security Considerations

**What an attacker on the path can do.** The connection is DTLS between the two peers, bound to their session by PNP-001 §10.5.1, so a relay or network attacker sees ciphertext, its timing and its volume. Records are sealed again under the file key, which travelled only inside the session: even an endpoint of the DTLS connection that is not the peer (a failure of the binding, a future relayed path) learns nothing of the file and cannot alter it. Tampering costs the attacker nothing and the peers an attempt; it cannot make the receiver store a byte the sender did not send (§6.4), and the receiver gives up after repeated failures (SHOULD-005).

**STREAM.** The nonce carries the record index and a last-record flag, and the key is unique to the attempt. A record moved to another position, repeated, or taken from another attempt fails authentication; a stream cut after any record cannot be passed off as complete, because only the record sealed with the flag ends it (MUST-021), and the record count follows from `size`, which is authenticated by the session. The final SHA-256 check additionally covers what was stored across attempts and restarts, including storage that was corrupted or altered at rest in between.

**Keys.** The file key is independent of the ratchet: compromise of a file key reveals one file. It is erased when the transfer ends (MUST-009). Because offers are ratchet messages, they have the session's forward secrecy; the stored offer of an unfinished transfer does not, and is as safe as the client's storage (the native store is encrypted with a key in the OS keychain; the web client's storage is described in its own documentation).

**Nonce reuse.** Resume means the same record index is sealed more than once. Deriving the record key from fresh contributions of both sides (MUST-017, MUST-026) keeps every (key, nonce) pair unique even when the sender's file changed between attempts, which with a fixed key would expose the XOR of two plaintexts and the Poly1305 key.

**The receiver's storage.** The partial and the finished file are plaintext on the receiver's device: files are for the user to open. A client states where it keeps them. A receiver never executes or opens a file by itself, and never trusts its name (§7.3) or MIME type.

**Abuse.** Offers come only from contacts with a session. §8 bounds what one contact can make a client keep (offers), store (size) and carry (channels), and at what rate it can demand the user's attention.

## 10. Privacy Considerations

- File records are **not padded**: the size of a file is visible, to the byte, to anyone who can observe the volume of the direct connection (the two peers' networks, and the user's TURN server when one relays). The control messages are padded like all envelopes and reveal only that some message was sent. The name, MIME type and hash are never visible outside the session.
- A transfer needs a direct connection, which shows each peer's network address to the other (as every direct ParolNet connection does), or the user's TURN server's address in relay-only mode.
- `complete`, `accept` and `decline` tell the sender when the receiver acted. A client that wants to hide that the user saw an offer simply does not answer it.

## 11. Cross-Protocol References

| Spec | Relation |
|------|----------|
| PNP-001 (Wire Protocol) | `FILE_TRANSFER` is message type `0x15` in the §3.4 registry; control messages are ordinary padded envelopes (§3.6). The channel runs on the direct connection of §10.5 and requires its binding (§10.5.1). |
| PNP-002 (Handshake) | The Double Ratchet session that carries the control messages. |
| PNP-007 (Media & File Transfer) | §7 of PNP-007 (FILE_OFFER / FILE_CHUNK / FILE_CONTROL as envelopes, codes 0x02, 0x09, 0x0A) is superseded by this specification. Its codes stay allocated and unused. |
| PNP-009 (Group Communication) | Group files (0x0E–0x10) are not changed by this version. A later revision fans a group file out as one PNP-010 transfer per member. |
