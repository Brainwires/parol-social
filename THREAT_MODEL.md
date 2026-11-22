# ParolNet Threat Model

### Version: 1.0 (outline, M0)
### Date: 2026-11-20
### Supersedes: version 0.2 ([docs/archive/THREAT_MODEL-0.2.md](docs/archive/THREAT_MODEL-0.2.md))

This is the threat model of the repositioned ParolNet: a general-purpose, decentralized,
end-to-end encrypted system for calls, messages, files and data channels. Version 0.2 modelled a
censorship-circumvention tool against national firewalls and global observers; those adversaries
now appear only in Appendix A, which says what the experimental `hardened` mode does and does not
do.

M0 fixes the structure, the adversaries, the stated non-goals and the metadata statement. Each
section gains its detailed analysis with the milestone that builds the mechanism (noted per
section). Where the code does not yet do what a section describes, the section says so; the
current state of the code is in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md). Nothing
here has been audited; a third-party audit of the E2EE layer, SFrame keying and the relay / SFU
trust boundary is planned before 1.0.

---

## 1. System and assets

**Components.** Clients (GPUI desktop, the PWA, later mobile shells), each holding device keys;
home relays (signaling over `/ws`, store-and-forward, federation, directory, TURN credentials);
TURN servers (coturn until a Rust one); SFUs hosted by relays (M2); the update channel.

**Assets, in order.**
1. Content: messages, files, call media, application data-channel payloads.
2. Keys: the account Ed25519 key, device keys, session / ratchet state, MLS group state (M2).
3. The social graph: who is a contact of whom, who is in which group or call.
4. Activity metadata: when a device is online, with whom it exchanges traffic, how much.
5. Integrity of the software a user runs (releases, updates, dependencies).

**Identity.** `PeerId = SHA-256(account Ed25519 public key)`. No phone number, email or username
exists anywhere. Contacts are added by QR code or pairing code (PNP-003) and verified by safety
number. From M2 the account key signs a versioned device list; contacts verify it against the
`PeerId` they already trust.

## 2. Security goals (default mode)

| Goal | Mechanism | From |
| --- | --- | --- |
| Confidentiality and integrity of messages | X3DH + Double Ratchet (PNP-002); MLS (RFC 9420) for groups and devices, then for 1:1 | M1 / M2 / M4 |
| Confidentiality of 1:1 and mesh call media | DTLS-SRTP with certificate fingerprints carried in E2EE call signals, so the session authenticates them | M1 (PNP-011) |
| Confidentiality of SFU call media | SFrame (RFC 9605) on whole encoded frames, keys from the MLS exporter per epoch and sender | M2 (PNP-013) |
| Confidentiality and integrity of files | Per-file key in the E2EE offer; 64 KiB ChaCha20-Poly1305 STREAM records; SHA-256 check | M1 (PNP-010) |
| Forward secrecy and post-compromise security | Ratchet (1:1), MLS epochs (groups, devices) | M1 / M2 |
| Membership integrity | MLS commits ordered by a sequencing relay; clients refuse forks; signed room admission tokens | M2 |
| Device loss handling | At-rest encryption keyed from the OS keychain; remote unlink removes the device at the next epoch | M1 / M2 |
| Software integrity | Signed releases and update manifests (Ed25519), reproducible builds, `cargo-deny` licence / source gate | M1 |

## 3. Adversaries in scope

### 3.1 Network observer of content (L-ADV)
Anyone on the path: Wi-Fi operator, ISP, a hostile network. Can read, drop, delay, replay and inject
packets. **Must not** learn content or forge messages, media or files. **Can** see IP addresses,
timing, volume, that ParolNet is in use, and which relay and TURN servers a device talks to.
*Detail: M1 (PNP-010, PNP-011).*

### 3.2 Compromised relay, TURN server or SFU (R-ADV)
A server the user did not choose to trust, or one that was compromised. A home relay sees the
`PeerId`s its clients exchange envelopes with, their IPs and timing. A TURN server sees both peers'
addresses and traffic volume. An SFU (M2) sees who is in a room, RTP headers, packet sizes and
timing, never media. **Must not** read content, impersonate a participant, add itself to a group or
room, or fork a group's history unnoticed. **Can** deny service, drop or delay traffic, and log
metadata. *Detail: M2 (SFU trust boundary, commit sequencing, PNP-012 / PNP-013).*

### 3.3 Malicious group member
A legitimate member who misbehaves. Can read what the group can read while a member, and share it.
**Must not** forge other members' messages or media, keep reading after removal (at the next
epoch), or split the group's view of membership. *Detail: M2.*

### 3.4 Compromised or stolen linked device (D-ADV)
Reduced in scope from version 0.2. ParolNet encrypts data at rest with a key held by the OS
keychain and lets the user unlink a device remotely; once unlinked it decrypts nothing new.
"Delete all data on this device" erases local state. A device that is unlocked and in the
attacker's hands while linked exposes what it holds. *Detail: M1 (storage), M2 (unlink).*

As built in M1 (`parolnet-store`): the identity secret, ratchet sessions, contacts, history and
the sender queue are in one SQLCipher database (every page encrypted and authenticated, the
write-ahead log included); its random 256-bit key is in the OS keychain. An attacker with the
disk but not the user's login (a powered-off or locked device, a backup, a copied profile
directory) learns the database's size and that ParolNet was used, not its content. An attacker
who runs code as the logged-in user can ask the keychain for the key: that case is the unlocked
device above. Headless installations without a keychain service keep the key in an owner-only
file next to the database (an explicit setting, never a silent fallback), which protects nothing
once the directory is copied. Deleting all data removes the key first, then the files; on flash
storage old blocks may persist until reused, but without the key they are noise. SQLCipher's
cipher is a C library (CommonCrypto, or OpenSSL's libcrypto), outside the pure-Rust E2EE layer.

The web app has no OS keychain to rely on (`docs/web-port/at-rest.md`). It seals every row of
its IndexedDB database with AES-256-GCM under a WebCrypto key that script cannot export; the
key is stored in the same browser profile. That stops what reads the database as data, and only
partly stops an attacker who copies the whole profile (how well depends on the browser). The
protection against a seized device in a browser is the optional passphrase: with it the profile
holds no key, only one wrapped under Argon2id (64 MiB, 3 passes) of the passphrase, and the app
asks for it at every start. Neither protects against script running in the app's origin (a
compromised server serving a changed app): section 3.5 and the Content-Security-Policy are the
defences there. A forgotten passphrase is not recoverable; an encrypted backup file
(`docs/web-port/backup.md`) is the person's own safeguard against losing the device.

### 3.5 Malicious update channel and supply chain
A compromised build host, release server, dependency or update feed. Releases and update manifests
are signed with a key held offline; clients verify before installing; builds are reproducible;
dependencies are pinned with lockfiles, licence- and source-checked by `cargo-deny`, and the
realtime engine is consumed by git tag from the project's fork, never a branch. Code signing:
macOS Developer ID and notarization; Windows builds ship unsigned until an Authenticode
certificate exists. *Detail: M1 (packaging and updater).*

## 4. Explicit non-goals of the default mode

The default mode does **not** provide:
- **Traffic-analysis resistance.** Timing and volume are visible to the network and to servers.
- **Hiding that ParolNet is in use.** Its relays, TURN servers and protocols are recognisable.
- **Censorship circumvention.** A network that blocks the relays blocks ParolNet.
- **Coercion resistance.** A user forced to unlock a device exposes what it holds; there is no
  decoy mode in the desktop client.
- **Deniability.** The Double Ratchet's deniability lasts only while 1:1 uses it; MLS (M4) signs
  messages, so it goes.
- **Protection from a compromised endpoint.** Malware on a device sees what the user sees.

## 5. Metadata statement

Stated exactly, for the default mode:
- **The home relay learns** each client's `PeerId`, IP address and online times, and the `PeerId`s
  it exchanges envelopes with (sender and recipient of each envelope it routes or stores), with
  envelope sizes (messages are padded to buckets; media and bulk transfers are not) and timing.
- **A federated relay** forwarding an envelope learns the same for that envelope.
- **A TURN server** learns both endpoints' addresses and the call's traffic volume and timing.
- **An SFU** learns room membership by connection, RTP headers (SSRCs, sequence numbers,
  timestamps, header extensions such as audio level), packet sizes and timing.
- **Peers in a direct call** learn each other's IP addresses unless "Always relay calls" is on.
- **Nothing outside the devices** learns content, contact names, or the account key.

## 6. Trust boundaries

| Boundary | Inside | Outside | Detail |
| --- | --- | --- | --- |
| Device | Keys, plaintext, local database | Everything else | M1 |
| E2EE session / MLS group | Members' devices | Relays, SFUs, TURN, network | M1 / M2 |
| Media path | Encoder and decoder at the endpoints | Packetizer clear ranges, SFU, TURN | M1 / M2 |
| Relay | Its own logs and metadata | Content (ciphertext only) | M2 |
| Update channel | Signing key (offline) | Release hosting, CDN | M1 |

## 7. Analysis to come (per milestone)

- **M1:** STRIDE per component for `parolnet-rtc`, PNP-010 and PNP-011; signaling authentication
  of DTLS fingerprints; ICE / TURN policies ("Always relay calls"); storage and keychain; updater.
- **M2:** MLS (device lists, commit sequencing, fork refusal, failover); SFrame key schedule and
  clear ranges; SFU admission tokens; a test relay that logs everything it can see, with the check
  that it yields no plaintext media or message bytes.
- **M3:** screen capture permission flows and what a shared screen exposes.
- **M4:** 1:1 on MLS; fuzzing of every parser added in M1..M3; the audit's findings and fixes.

---

## Appendix A: the `hardened` mode (experimental)

The onion circuits (`parolnet-relay::circuit`, `onion`; PNP-004), bridges and domain fronting
(PNP-008), traffic shaping and cover traffic (PNP-006) and TLS camouflage remain in the tree as an
experimental mode for **messages only, never media**. They are kept behind a `hardened` build
feature (being separated in M1; today they are built by default) and are documented as
experimental.

What it is designed to do: hide the sender's IP from the destination relay (3-hop circuits), make
relay discovery harder to block (bridges), and blur timing and size (padding, cover traffic).

What it does **not** do today: production multi-relay circuits (the relay runs a single-relay MVP
of 3 hops), constant-rate cover traffic on the PWA path, browser-grade TLS fingerprint mimicry, or
any protection for calls, which always use direct or TURN paths. It does not defend against a
national firewall operator or a global passive adversary (the adversaries of version 0.2): those
are out of scope for ParolNet. If the mode is still partial at M4 it is removed.

## Appendix B: Revision history

| Version | Date | Change |
| --- | --- | --- |
| 0.1 / 0.2 | 2026-04 | STRIDE model of the censorship-circumvention design (archived) |
| 1.0 (outline) | 2026-11-20 | Repositioning: new scope, adversaries, non-goals, metadata statement; `hardened` moved to Appendix A |
