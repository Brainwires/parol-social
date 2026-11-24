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
| `with_srtp_automatic_rekeying` | default (on) | Re-keying is handled: after a lifetime warning, the offer follows the engine's own negotiation-needed (engine tie-break from `conf/rekey-1-glare`: the DTLS client asks at 1/16 of the lifetime left, the server at 1/32, one renewal at a time), with an ICE restart on new ports (PNP-011 v0.2 section 7.6). `m1::srtp_re_keying_by_one_side_keeps_the_call`, `m1::srtp_re_keying_keeps_the_call`. |
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
| profile_300_kbps_cap (freeze <= 2 s; audio >= 92 %) | pass | pass: freeze <= 1.50 s, audio 93.4 to 94.5 % | fail once: seed 3 caller audio 89.1 % (freeze 1.58 s). **Not a regression**: run-to-run variation, see 3.1 | **fail: seed 1 callee audio 91.6 %** | pass: freeze <= 1.04 s, audio 92.8 to 94.2 % |
| profile_two_percent_loss | pass | pass: freeze <= 627 ms, audio >= 97.9 % | pass | pass | pass |
| profile_100_ms_jitter | pass | pass: freeze <= 131 ms, audio 100 % | pass | pass | pass |
| renegotiation / restart that cannot be signalled / without a restart | pass | pass | pass | pass | pass |
| srtp_re_keying_by_one_side_keeps_the_call (new) | n/a | n/a | **pass**: re-keys at 39 s and 65 s, new ports each time (49152, 49153, 49154), freeze 34 ms | n/a | pass: re-keys at 39 s and 77.8 s, freeze 34 / 121 ms |
| srtp_re_keying_keeps_the_call (both sides; the offers cross) | n/a | fail | **fail**: both offer at 39 s, the polite side rolls back and answers at 39.05 s, no DTLS association completes, both Failed at 40.73 s (key exhausted) | fail | fail (Failed at 44.1 / 44.4 s) |

Two runs of the same seed differ slightly on the gcc-2 branch (the test step, with tests in
parallel, against the figures step with one thread): the simulated time is the same, but
the order of tokio tasks is not.

### 3.1 `profile_300_kbps_cap` across engine train 13 (no regression)

Probe PR #54, run 45305849593: the measure-only sweep (`sweep_profile_300_kbps_cap`, seeds 1 to
8, caller and callee, each run twice in separate processes) on every first-parent revision of
train 13 between master 81e2253e and df82663c. Audio good %, `caller/callee` per seed:

```
audio good % per seed (caller/callee), run1 | run2 ; min over 16 = worst
81e2253e: min 92.1 mean 93.72 below92 0/32 run1==run2 False
   r1: 94.4/93.1 94.1/93.9 94.9/94.1 93.8/93.7 94.2/93.5 94.0/94.4 94.7/92.9 94.3/93.4
   r2: 93.1/92.7 94.1/94.2 94.3/93.9 93.9/93.2 93.7/92.1 92.8/92.9 93.5/93.2 94.4/93.8
cd69d504: min 91.6 mean 93.74 below92 2/32 run1==run2 False
   r1: 92.8/93.0 94.1/93.0 93.7/92.7 93.6/92.4 94.4/94.4 95.9/95.8 93.1/93.6 96.1/95.9
   r2: 93.4/93.4 93.4/91.9 93.9/93.9 93.5/91.6 94.8/94.3 94.2/93.6 94.1/93.6 92.4/93.2
95fb09a4: min 91.5 mean 94.06 below92 1/32 run1==run2 False
   r1: 94.1/92.9 94.2/94.4 95.2/96.1 93.9/93.6 96.4/96.1 94.7/93.3 93.4/93.3 93.4/93.9
   r2: 94.6/94.4 95.6/95.7 93.6/91.5 94.7/94.5 93.1/92.6 93.1/93.1 94.1/93.4 94.1/92.9
dfc9561f: min 91.7 mean 93.57 below92 3/32 run1==run2 False
   r1: 92.9/92.8 94.1/92.6 93.9/92.9 93.1/93.8 91.8/91.8 94.1/93.1 94.3/93.2 93.7/94.1
   r2: 94.1/93.1 94.9/93.9 93.4/91.7 93.9/92.8 94.7/93.7 96.5/95.1 94.1/92.2 94.6/93.3
2dcf2689: min 91.9 mean 93.45 below92 1/32 run1==run2 False
   r1: 94.3/93.9 94.3/93.7 93.4/94.6 92.3/93.1 94.1/93.4 93.9/94.2 92.6/91.9 93.3/92.5
   r2: 94.0/92.8 92.7/92.6 93.4/94.4 93.9/93.6 94.0/93.0 93.9/94.0 93.1/93.1 93.1/93.2
   asserting step: ['300 kbit/s cap, seed 2, caller: 91.7% of the played audio is the tone']
fd0943cc: min 93.1 mean 93.98 below92 0/32 run1==run2 False
   r1: 94.0/94.4 95.4/95.5 93.2/93.4 95.3/94.2 94.1/93.9 94.0/93.1 93.1/93.6 94.2/93.5
   r2: 93.6/94.1 95.1/93.6 94.2/93.7 94.2/93.9 94.1/93.2 93.4/93.9 94.3/94.4 93.5/93.4
   asserting step: ['300 kbit/s cap, seed 2, caller: 91.4% of the played audio is the tone']
0391c4c8: min 90.4 mean 93.74 below92 1/32 run1==run2 False
   r1: 93.6/93.5 92.9/90.4 93.4/93.7 93.6/93.7 94.1/92.6 94.4/93.8 94.5/93.4 93.9/92.3
   r2: 93.9/94.0 92.7/92.7 94.4/93.9 95.8/95.9 94.3/93.1 94.3/93.5 92.9/94.5 95.0/95.1
3829ab36: min 92.3 mean 93.91 below92 0/32 run1==run2 False
   r1: 94.6/93.9 94.1/93.2 94.1/93.4 92.3/93.5 95.5/96.1 93.1/93.3 93.6/93.4 93.3/93.9
   r2: 94.5/93.4 94.2/92.6 93.3/92.4 94.2/94.1 96.1/96.4 93.3/94.1 94.2/93.6 93.6/93.7
ae773045: min 92.6 mean 93.78 below92 0/32 run1==run2 False
   r1: 94.9/93.7 93.9/93.8 93.6/94.0 94.1/92.9 93.5/93.8 93.5/93.7 94.9/93.4 93.7/93.1
   r2: 93.8/93.9 94.0/93.6 94.4/93.6 93.8/93.9 94.0/92.6 93.6/94.1 94.1/93.9 93.5/93.6
5ea96f81: min 89.9 mean 93.53 below92 3/32 run1==run2 False
   r1: 94.4/93.5 94.1/93.9 94.1/93.7 91.4/89.9 93.6/93.1 92.5/93.8 94.4/93.3 93.0/93.2
   r2: 93.3/93.1 97.0/95.6 92.8/93.3 93.6/93.3 93.6/91.9 93.6/94.2 93.6/94.5 94.1/93.4
   asserting step: ['300 kbit/s cap, seed 1, caller: 91.1% of the played audio is the tone']
5c209231: min 92.6 mean 93.89 below92 0/32 run1==run2 False
   r1: 93.6/93.9 93.9/93.6 94.7/93.9 94.1/94.4 92.6/92.6 93.9/92.8 93.6/94.3 94.4/94.4
   r2: 93.8/93.4 93.3/92.7 93.9/93.4 93.4/93.5 96.1/94.0 94.9/93.6 95.6/95.1 93.8/93.2
737507c9: min 92.6 mean 93.92 below92 0/32 run1==run2 False
   r1: 92.6/93.1 93.7/94.8 94.9/94.4 94.9/93.8 93.8/93.5 94.3/93.9 94.3/94.1 94.4/93.6
   r2: 93.1/93.3 93.4/94.1 94.9/94.0 93.6/92.7 94.2/93.9 94.0/94.2 94.1/93.5 94.1/94.4
df82663c: min 90.7 mean 93.76 below92 2/32 run1==run2 False
   r1: 94.6/94.6 93.6/93.1 93.3/94.1 94.5/94.4 93.9/94.1 93.9/93.5 93.2/94.0 93.7/93.6
   r2: 94.1/93.7 91.3/93.2 93.7/93.1 95.6/96.2 92.1/90.7 95.0/94.3 93.7/94.2 93.9/93.5
```

Means stay between 93.45 and 94.06 % on every revision (81e2253e 93.72, df82663c 93.76); no
revision is worse than another beyond the spread of one seed between two runs (up to 3.4
points). The 92 % bar sits about 1.7 points under the mean, so the asserting test fails
now and then on any revision (in this run: 2dcf2689, fd0943cc, 5ea96f81; not df82663c).

### 3.2 Reproducible runs (engine `conf/det-1-wall-clock`)

Two runs of one seed never gave the same figures, even one after the other in fresh processes.
The engine maps instants to NTP times from a process-wide anchor taken at its first use, so
report timestamps, the round trip they give, and with it the NACK and congestion timing,
depend on real time elapsed. With `conf/det-1-wall-clock` (c26acab4) the simnet can make runs
identical once that branch is on master:

- a per-connection wall-clock anchor (`with_wall_clock`) on the RTCP session ParolNet installs
  (`configure_rtcp_reports`; a `RtcConfig` field, set by the simnet at the call's start);
- the setting engine's seeded crypto provider and `rtcp_random`, seeded from
  `CallConfig::seed` (ICE credentials, DTLS randoms, RTCP intervals, CNAME);
- ParolNet's own randomness made injectable in the same way: `rand_ssrc` (time and counter
  hash), the RTP sequence start (`new_random_sequencer`), and STUN transaction ids.

The SRTP and DTLS ephemeral keys stay unseeded (no seed reaches them), but they don't change
timing or sizes. Not done yet: the branch is not on engine master.

### 3.3 gcc-2 recovery series (for the congestion owner)

Probe PR #55: `the_estimate_follows_a_cap_that_comes_and_goes` alone twice, then in the full
suite. Median under the cap | target at +5/+10/+15/+20 s (kbit/s) | longest freeze; ICE restart
freeze (caller / callee).

| Engine | NACK limit | Under cap | +5 / +10 / +15 / +20 | Freeze | Restart freeze |
|---|---|---|---|---|---|
| master df82663c | default | 183 | 437 / 643 / 944 / 1388 (all runs) | 1.22 s | 479 / 400 ms |
| gcc-2 53a17d35 | default | 197 | 152-171 / 224-250 / 329-368 / 484-541 | 1.45-1.66 s | 700 / 700 ms |
| gcc-2 53a17d35 | UpToTarget | 198 | 151-178 / 221-260 / 326-383 / 478-562 | 1.45-2.01 s | 306 / 350 ms |
| 4983efcc (master's twcc_gcc) | default | 159 | 380 / 558 / 820 / 1203 | **3.22-3.26 s** | 600 ms / **6.29 s** |
| gcc-2 dabddd92 | default | 199 | 143-152 / 210-224 / 308-329 / 453-484 | 1.48-1.52 s | 700 / 700 ms |
| gcc-2 dabddd92 | UpToTarget | 199 | 222-309 / 326-454 / 480-668 / 705-981 | 1.49-1.66 s | 306 / 350 ms |

### 3.4 Relay candidates' hidden related address

`raddr 0.0.0.0 rport 9` (RFC 8827 section 6.4, the engine's released `0.22.0+brainwires.6`
entry) stands on master df82663c: `turn::relay_only_on_both_sides_goes_through_the_turn_server`
asserts it and passes there.

### 3.5 Re-keying with crossing offers (finding 1): closed by engine `conf/rekey-1-glare`

Probe PR #57, run 45316993809, engine daa6c684 (rekey-1-glare merged with master 4431dda0),
ParolNet re-keying on the engine's negotiation-needed. Three runs of each test, all pass:

- `srtp_re_keying_keeps_the_call` (both sides' keys have the short lifetime): renewals at
  39.05 s and 65.08 s, connected again 120 ms after each, longest freeze 34 ms, audio 100 %.
- `srtp_re_keying_by_one_side_keeps_the_call`: renewals at 39.97 s and 66.9 s, same figures.

On df82663c the crossing test still fails (the engine fix is not on master yet).

### 3.6 `file_tamper` timeouts: an engine data-channel delivery stall

Probe PR #57, runs 45316993809, 45318163107 and 45319549406. `parolnet-app`'s `file_tamper`
was run 30 times per job, three at a time. Failure rate:

- df82663c, debug logging: 3 / 30.
- daa6c684, debug logging: 5 / 30.
- daa6c684, trace logging (more load): 11 / 30 and 8 / 30.
- Earlier, one timeout on gcc-2 77185407, which is based on master 81e2253e, so the stall may predate train 13.

What hangs: the second attempt of the first transfer.

1. One record was corrupted on purpose, so the receiver ended the attempt and closed channel 1.
2. It opened channel 2 and sent its resume (next record 7). The sender started at that record
   and handed every record (to 1,310,457 bytes) to the channel.
3. The sender's SCTP reported all of them acknowledged within a second (`buffered_amount` 0).

The receiving side, in all 8 failed runs of the last job:

- The driver got 10 or 11 messages on channel 2 from the engine's `poll_read`. The attempt
  needed about 15 (the start message and records 7 to 20).
- Every message the driver got was forwarded to the worker (none dropped), and the worker
  stored each record.
- The receiver's SCTP SACKs show its advertised receive window shrinking to about 705 KB and
  staying there. About 320 KB, roughly five 64 KiB messages, was acknowledged and buffered in
  the engine and never delivered.

`parolnet-rtc` drains `poll_read` on every pass of its loop and drives `poll_timeout` /
`handle_timeout`. Nothing more arrives after the last DATA chunk, and the messages never come
out. Engine finding: complete messages that SCTP acknowledged stay undelivered on a data
channel opened right after another channel of the connection was closed (stream reset). The
full per-run logs are in the run's `tamper-logs` artifact.
