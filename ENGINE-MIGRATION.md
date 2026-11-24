# Engine migration: `rtc` 0.22.0+brainwires.6 to `rtci` 0.1.0

Release-day checklist for the draft PR "Engine: next release (pre-release testing, not
mergeable)". This file is deleted when the PR merges.

The PR is prepared against the engine's development line, pinned to a git `rev`. Until the
engine releases `v0.1.0` (repository `Brainwires/rtci`, crates `rtci` / `rtci-*`; see the
engine's `docs/rename.md`) it must not merge.

## 1. Release-day steps

1. **Pin** (root `Cargo.toml`): replace

   ```toml
   rtc = { git = "https://github.com/Brainwires/webrtc-rs-rtc", rev = "<sha>" }
   ```

   with

   ```toml
   rtci = { git = "https://github.com/Brainwires/rtci", tag = "v0.1.0" }
   ```

   and drop the "NOT MERGEABLE" comment above it. A tag, never a branch or a rev
   (CLAUDE.md, dependency policy).
2. **Dependency names**: `crates/parolnet-rtc/Cargo.toml` has `rtc.workspace = true`; it becomes
   `rtci.workspace = true`. No other crate names the engine directly (`parolnet-simnet`,
   `parolnet-app`, `parolnet-conformance` and `apps/desktop` reach it through `parolnet-rtc`).
   ParolNet uses no `rtc-*` sub-crate directly.
3. **`use` paths**: every `rtc::` path in `crates/parolnet-rtc/src` (lib.rs, net.rs, turn.rs,
   test_turn.rs, jitter.rs) becomes `rtci::`. `parolnet-rtc` re-exports the engine as
   `pub use rtc;`; make it `pub use rtci;` and rename the callers' `parolnet_rtc::rtc::` paths
   (`parolnet-simnet`, `parolnet-app`, `parolnet-conformance`, `apps/desktop`). A grep for
   `parolnet_rtc::rtc::` and `\brtc::` finds them all. (A one-line alternative is
   `rtc = { package = "rtci", ... }`; not recommended, it keeps the old name alive.)
4. **Feature names**: ParolNet enables no engine feature (default features only); none to
   rename. Do not enable `chrome-defaults` / `performance-defaults` or
   `turn-tls-webpki-roots` (CDLA licence).
5. **Lock files**: `cargo update -p rtci` in the root and in `apps/desktop` (its own workspace).
   Check that no other package moved.
6. **CI workflow**: `.github/workflows/ci.yml` goes back to `cargo test --workspace` (drop
   `--no-fail-fast`) and the "m1 figures" step is removed.
7. **Licence gates**: `cargo deny check licenses sources bans` for both workspaces
   (`deny.toml` allows the git source; update it if it names `webrtc-rs-rtc`).
8. **Docs**: CHANGELOG.md (the "pre-release testing" entry becomes the engine bump entry, with
   the release's name), IMPLEMENTATION_STATUS.md (engine pin line), README.md if it names the
   engine crate; delete this file.
9. **CI green on the exact merge SHA**, including `parolnet-simnet` m1 and the PWA interop job.

## 2. Settings ParolNet sets on the engine, and why

All in `parolnet-rtc` `build_peer_connection`. Everything else is the engine's default
(`BehaviourProfile::Rfc`).

| Setting | Value | Why |
|---|---|---|
| `with_ice_software` | `None` | No STUN SOFTWARE attribute (implementation fingerprint) in ICE checks, responses or consent checks (THREAT_MODEL.md). Our own STUN requests and TURN client (`ClientConfig::software = ""`) send none either. Asserted by `m1::call_setup`, `m1::an_ice_restart_follows_a_machine_to_another_network` (simnet counts every STUN message) and `turn::relay_only_on_both_sides_goes_through_the_turn_server` (the test TURN server checks requests and relayed STUN). |
| `with_srtp_key_lifetime` | `RtcConfig::srtp_key_lifetime` (`None` = profile default) | Tests re-key a call every few seconds. |
| `with_srtp_automatic_rekeying` | default (on) | Re-keying is handled: the side whose outbound key nears its end re-offers with an ICE restart (PNP-011 v0.2 section 7.6). `m1::srtp_re_keying_by_one_side_keeps_the_call`, `m1::srtp_re_keying_keeps_the_call`. |
| `with_dtls_new_association_on_previous_addresses` | default (`false`: RFC 8842 section 5.1) | A new association runs on new ports: the driver binds them itself (`renew_sockets`) before it offers a re-keying or answers a peer's new `a=tls-id`; the previous sockets close 5 s after the new pair is selected. |
| `with_discard_local_candidates_during_ice_restart` | `true` | A restart announces the sockets bound then, not the network left behind. |
| `with_tcp_candidate_gathering` | `false` | No ICE-TCP; the driver gathers its own UDP candidates. |
| `with_turn_over_streams`, `with_turn_tcp_relay` | `false` | No engine-run TURN over TCP/TLS. |
| `with_server_reflexive_gathering` | `Application` | The driver does its own STUN. |
| `with_relay_gathering` | `Application` | The driver runs its own TURN client. |
| `with_sctp_message_size_limit_without_interleaving` | `false` | PNP-010 records (64 KiB) and chat frames (~32 KiB) must reach browsers. |
| `with_sctp_message_interleaving` | `false` | Two ParolNet peers keep sending DATA chunks. |
| `with_ice_nomination_acceptance` | `Latest` | Chromium renominates right after connecting (the `.5` fix). |
| `with_multicast_dns_mode` | `QueryOnly` / `Disabled` | Resolve remote `.local` candidates; none when relay-only. |
| Interceptors | spelled out (`configure_nack`, `configure_rtcp_reports`, `configure_twcc`, `GccInterceptorBuilder` at `Slot::CongestionControl`) | No pacer, no RED (`audio/red` is not registered, so not offered or accepted), no FEC. |

Engine defaults deliberately left as they are: `with_audio_redundancy` (RED is not registered:
PNP-011 lists Opus with in-band FEC only, so there is no redundancy between ParolNet peers);
NACK responder rate limit (engine default: `UpToTarget` on master, `WithinTarget` on
`conf/gcc-2-rfc-retransmission`); NACK generator without give-up limit; behaviour profile `Rfc`.

### Decisions

- **New DTLS association (RFC 8842 section 5.1, engine `conf/mt-10-gather-anew`, in
  `conf/train-13`)**: ParolNet gathers on new ports, it does not take the opt-out
  `with_dtls_new_association_on_previous_addresses(true)`. Its sockets are per connection and
  ephemeral (port 0 in every product configuration), an ICE restart already rebinds and runs a
  STUN round for sockets without a server-reflexive address, and the only trigger in ParolNet is
  re-keying, which it now initiates and answers itself. So: when ParolNet offers or answers a new
  association, it binds new sockets on the addresses it has, gathers on them (STUN included),
  keeps the old ones until the new pair is selected plus 5 s. Implemented against engine master
  df82663c (train 13 merged). The TURN allocation is renewed too: a new allocation from a new
  socket, the previous one released with the retired sockets
  (`turn_rekey::a_relay_only_call_re_keys_on_new_allocations`). The loop waits for the new
  allocation (one or two exchanges with the server, at most `RtcConfig::turn_timeout`).
  `RtcHandle::relayed_addr` keeps naming the first allocation.
- **Re-keying**: handled, not turned off (see the table). A peer that does not renegotiate gets
  no re-offer (PNP-011-MUST-020); such a call ends at the key's limit, as with a browser, which
  ignores a new `a=tls-id`. The default lifetimes are not reached by a call.
- **Pacer**: not adopted in this change. The encoder already follows the target with a tenth
  held back (PNP-011-MUST-034), and the point of this PR is to measure the engine with
  ParolNet's chain unchanged. What adopting it would change: frames leave paced instead of in a
  burst (less self-made queueing at a bottleneck, so GCC's delay signal is cleaner), and with
  `PacerQueueOverflow::Drop` media over the target or older than 2 s is dropped at the sender
  (counted as loss by the receiver) instead of queueing in the network. To be measured as its
  own change with the m1 suite.

## 3. What each ParolNet test measured, old engine vs new

From CI (the "m1 figures" step prints `figure <test> | <side> | <what> = <value>`). Runs on the
draft PRs (#52 for master, #53 for the gcc-2 branch). The tag column is from PR #52's earlier
runs on `v0.22.0+brainwires.6` (recovery relaxed there).

| Test (assertion) | tag brainwires.6 | master 81e2253e | master df82663c | gcc-2 77185407 | gcc-2 e3bfc7e0 |
|---|---|---|---|---|---|
| call_setup | pass | pass (connected 230 ms, first frame 277 ms, gap 34 ms, STUN with SOFTWARE 0 of 4 per side) | pass | pass | pass |
| an_ice_restart_follows_a_machine (freeze <= 2 s after restore) | pass | pass: freeze 500 / 400 ms (caller / callee); target after the move 242 / 274 kbit/s | pass: 500 / 394 ms | **fail: callee froze 7 s**; target after the move 121 kbit/s | pass: 700 / 700 ms; target restarts at 300 k, then 151 k |
| the_estimate_climbs_on_an_open_link | pass | pass: 1 Mbit/s at 16.1 s, then 2.5 Mbit/s, no downward step | pass | pass | pass |
| the_estimate_settles_under_a_cap | pass | pass: median 189 / 190 kbit/s, high 382 k, carried 224 k, drops 123 / 6216 | pass | pass | pass: median 189 / 192 k, drops 144 / 6216 |
| the_estimate_follows_a_cap_that_comes_and_goes (> 800 kbit/s 20 s after; freeze <= 2 s) | **fail: froze 6.86 s**; about 530 kbit/s at +20 s | **pass**: 436 / 641 / 942 / 1384 kbit/s at +5/10/15/20 s; freeze 1.22 s (while capped) | pass: 437 / 643 / 944 / 1388 k; freeze 1.22 s | **fail**: 145 / 213 / 313 / 460 k; freeze 1.69 / 2.08 s | **fail**: 183 / 269 / 395 / 581 k (second run 149 / 219 / 321 / 472 k); freeze 1.66 / 1.96 s |
| profile_300_kbps_cap (freeze <= 2 s; audio >= 92 %) | pass | pass: freeze <= 1.50 s, audio 93.4 to 94.5 % | **fail: seed 3 caller audio 89.1 %** (freeze 1.58 s) | **fail: seed 1 callee audio 91.6 %** | pass: freeze <= 1.04 s, audio 92.8 to 94.2 % |
| profile_two_percent_loss | pass | pass: freeze <= 627 ms, audio >= 97.9 % | pass | pass | pass |
| profile_100_ms_jitter | pass | pass: freeze <= 131 ms, audio 100 % | pass | pass | pass |
| renegotiation / restart that cannot be signalled / without a restart | pass | pass | pass | pass | pass |
| srtp_re_keying_by_one_side_keeps_the_call (new) | n/a | n/a | **pass**: re-keys at 39 s and 65 s, new ports each time (49152, 49153, 49154), freeze 34 ms | n/a | pass: re-keys at 39 s and 77.8 s, freeze 34 / 121 ms |
| srtp_re_keying_keeps_the_call (both sides; the offers cross) | n/a | fail | **fail**: both offer at 39 s, the polite side rolls back and answers at 39.05 s, no DTLS association completes, both Failed at 40.73 s (key exhausted) | fail | fail (Failed at 44.1 / 44.4 s) |

Two runs of the same seed differ slightly on the gcc-2 branch (the test step, with tests in
parallel, against the figures step with one thread): the simulated time is the same, but
the order of tokio tasks is not.
