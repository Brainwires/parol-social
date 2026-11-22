# Conformance audit, November 2026

`cargo xtask clauses` counts a spec clause as covered when a test in `crates/parolnet-conformance` names its id in a `#[clause(...)]` attribute. On master d8ceedb it reported 591 of 595 MUST and 102 of 109 SHOULD clauses covered. This audit asked a different question of every MUST and SHOULD clause: does a test call the implementation and fail if the implementation breaks the clause?

Mostly not. Large parts of the specs describe a design the product did not build or has moved away from (onion circuits, the gossip mesh, traffic shaping, the X3DH handshake messages, passphrase / SAS / mDNS / BLE bootstrap, SRTP keyed from the ratchet, federation), and the tests for those clauses pass because they assert constants or values they build themselves.

## Summary

"Real" as defined above. Everything else (partial, hollow, mis-pinned, unimplemented, no test) is in the other column. PNP-001 is counted after the tests branch `test/conformance-100` adds; the others as found, with the two clauses that branch covered noted.

| Spec | MUST real / total | SHOULD real / total | File |
|---|---|---|---|
| PNP-001 Wire protocol | 34 / 82 (14 more partial) | 7 / 19 | [PNP-001.md](PNP-001.md) |
| PNP-002 Handshake | 12 / 44 | 0 / 12 | [PNP-002.md](PNP-002.md) |
| PNP-003 Bootstrap | 1 / 52 | 0 / 8 | [PNP-003.md](PNP-003.md) |
| PNP-004 Relay circuit | 5 / 58 (since then: 58 / 58, see the note in the file) | 0 / 7 (since then: 7 / 7) | [PNP-004.md](PNP-004.md) |
| PNP-005 Gossip mesh | 10 / 49 (since then: 49 / 49, see the note in the file) | 1 / 17 (SHOULD-017, added on the branch; since then: 17 / 17) | [PNP-005.md](PNP-005.md) |
| PNP-006 Traffic shaping | 6 / 45 | 0 / 15 (SHOULD-015 partial, added on the branch) | [PNP-006.md](PNP-006.md) |
| PNP-007 Media and file transfer | 4 / 90 | 0 / 13 | [PNP-007.md](PNP-007.md) |
| PNP-008 Relay federation | 32 / 98 | 0 / 11 | [PNP-008.md](PNP-008.md) |
| PNP-009 Group communication | 28 / 77 | 0 / 7 | [PNP-009.md](PNP-009.md) |
| Total | 132 / 595 | 8 / 109 | |

Each file has one row per MUST and SHOULD clause: verdict, the test and its line, where the clause is implemented or that it is not, a suggested real test, and whether the shipped product (the native client `parolnet-app`, the web clients through `parolnet-wasm`, the default signaling-only relay) does what the clause says. Each ends with the places where code and spec disagree.

## Method

- PNP-002 to PNP-009: four reviewers (Claude Opus, read-only, two specs each) read each clause sentence, every test naming it and the code, and classified the clause. They ran nothing. Their instructions asked them to be strict but fair: a clause that defines a constant or a wire code is properly tested by a constant check.
- PNP-001: read by the agent that implemented the branch, alongside writing the new tests.
- The files for PNP-002 to PNP-007 were written by the reviewers themselves. The files for PNP-008 and PNP-009 were assembled by the implementing agent from that reviewer's report: for the clauses judged real the report held only the id, so their rows carry the test location from the `#[clause]` attributes and nothing about the implementation, and the "Shipped?" cells of the other rows are derived from the "Implemented where" cell. Both files say so.
- Commit: the reviewers read the worktree of `test/conformance-100` while it stood a few commits after d8ceedb. Some files name d8ceedb and some name the worktree head of the moment (`2bd86cd`, a commit since rewritten into two). In the code they audited the two differ only by nine lines of `crates/parolnet-relay-server/src/main.rs` (the idle-close fix). Line numbers in the old test files are those of d8ceedb, except `pnp_001_wire.rs`, which is two lines longer after line 92 on the branch.

## What was and was not verified

Verified by the implementing agent itself:

- The PNP-001 verdicts for the parts of the test files it read (each row in PNP-001.md says "(not read)" where the verdict rests on test names and imports only).
- Everything the branch's new tests prove, by running them: the session nonce, the channel binding rules, the receive rules, the sender queue, the relay's log and `/bootstrap`, and the relay idle close. The last one failed against the unfixed relay, which is how that defect was found.
- That the PNP-001 §3.3 plaintext map and §3.9 envelope-level fragmentation are not implemented, that `send_n` is an unchecked `u32`, that no timestamp window is enforced on receive, and that `MessageFlags::set_group` uses a bit PNP-001 reserves.
- A handful of the reviewers' verdicts, spot-checked while reading the same code. They held.

Not verified:

- The reviewers' verdicts in general. A strict reviewer can under-count: treat a "hollow" or "partial" verdict as a pointer to read that test, not as settled.
- Every "Shipped?" cell outside PNP-001.
- Every defect in the next section.
- Anything in the legacy PWA or the web app's TypeScript. Where a file names `pwa/src/...`, a reviewer read it; nobody ran it. The legacy PWA has since been removed from the repository, so those paths refer to the tree the audit read, and its "legacy PWA" rows no longer describe anything that ships.
- MAY clauses: not audited.

## Reported defects, not verified

These came out of the reviewers' reading. None was reproduced, and none was fixed on the branch. Each needs a test that shows it before it is acted on.

- **Forwarded gossip fails signature verification after one hop.** `signable_bytes` covers `ttl` (`crates/parolnet-protocol/src/gossip.rs:248`), the forwarder decrements `ttl` (`crates/parolnet-mesh/src/gossip.rs:488`) and the next hop verifies over the new value (`gossip.rs:468-471`). The spec is inconsistent on the point: PNP-005-MUST-003 excludes only `sig`, `seen` and `hops` from the signature while §5.2 has `ttl` change at each hop. See PNP-005.md.
- **File hashes are compared in variable time.** `crates/parolnet-core/src/file_transfer.rs:181` (`computed != self.offer.sha256`) and `crates/parolnet-core/src/group_file.rs:203` (`computed != self.expected_hash`), against PNP-007-MUST-062, PNP-009-MUST-069 and CLAUDE.md security invariant 5. The conformance tests for both clauses do their own `subtle` comparison, so they pass regardless.
- **Sender-key rotation keeps the signing key.** `SenderKeyState::rotate()` replaces the chain key and index only (`crates/parolnet-crypto/src/sender_key.rs:267-276`); PNP-009-MUST-029 / -033 require a new signing keypair.
- **Group operations are neither signed nor verified.** `GroupManager::add_member` / `remove_member` return `signature: Vec::new()` (`crates/parolnet-core/src/group.rs:250-338`) and nothing fills or checks it, the PWA's GROUP_ADMIN handler included (`pwa/src/messaging.js:1474`). PNP-009-MUST-020 to -024 and -071. The last admin can also be removed (`group.rs:297-319`, MUST-019).
- **Authority endorsements are not bound to the descriptor they endorse.** The endorsement signs `SHA-256(peer_id || endorsed_at || expires_at)` (`crates/parolnet-relay/src/authority.rs:72-78`), not the descriptor with its keys and address (PNP-008-MUST-002); `verify_threshold` also skips the descriptor's self-signature and age (`authority.rs:98-134`).
- **The QR timestamp check has gaps.** `crates/parolnet-core/src/bootstrap.rs:127`: `if payload.ts > 0 && now.saturating_sub(ts) > 1800`. A payload with `ts = 0` skips the check and a timestamp in the future is never refused (PNP-003-MUST-011).

Others of the same standing are listed in the per-spec files, among them: the relay accepts a CREATE on an existing circuit id and overwrites the circuit; gossip scoring and rate limiting key on the claimed `src` before the signature is checked; `X3dhKeyAgreement::respond` never reads the signed pre-key id; bundle descriptors are parsed before the bundle signature is verified; the desktop QR code uses error-correction level L where PNP-003-MUST-008 asks for at least M.
