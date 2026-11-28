//! The M1 simulation checks: a call between two `parolnet-rtc` drivers on the simulated
//! network, in virtual time.
//!
//! - call setup;
//! - renegotiation (an audio call that gains and loses video) on a lossy link;
//! - a stall that follows a loss: the receiver gives the gap up on its timer, asks for a key
//!   frame and stops asking for retransmissions it can no longer use, and video resumes;
//! - an ICE restart when one machine changes networks mid-call, and what happens without it;
//! - the bandwidth estimate: where it goes on an open link, under a cap, and when the cap
//!   comes and goes;
//! - the M1 profiles (2% loss, a 300 kbit/s cap, 100 ms jitter) with the exit bar's two
//!   assertions as measurements: **video adapts without freezing longer than 2 s** (the
//!   longest time without a usable frame, and the video bitrate following the estimate) and
//!   **audio stays intelligible** (the share of played 20 ms windows that are still the tone
//!   at its level, and the longest run that is not).
//!
//! Every test runs on a paused clock: thirty seconds of call take a few seconds of CPU and do
//! not depend on the machine's load.

use std::time::Duration;

use parolnet_app::call::{DISCONNECT_GRACE, PathWatch};
use parolnet_rtc::rtci::peer_connection::state::RTCPeerConnectionState;
use parolnet_rtc::rtci::rtp_transceiver::rtp_sender::RtpCodecKind;
use parolnet_rtc::rtci::statistics::report::RTCStatsReportEntry;
use parolnet_rtc::{CandidateKind, MediaKind, NetworkMonitor};
use parolnet_simnet::call::{
    CallConfig, Metrics, SimCall, SimPeer, VideoSourceKind, video_bitrate_for,
};
use parolnet_simnet::{LinkProfile, SimNet};

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// One measurement, printed before it is asserted on: `cargo test --test m1 -- --nocapture`
/// lists what each test measured, so a run against another engine can be compared figure by
/// figure, passing or not.
fn figure(test: &str, who: &str, what: &str, value: impl std::fmt::Debug) {
    eprintln!("figure {test} | {who} | {what} = {value:?}");
}

/// When the app's rule for a call without a path (PNP-011-MUST-037) ends the call, given one
/// side's connection states up to `until`: a grace timer of [`DISCONNECT_GRACE`] armed on
/// `disconnected`, run in the same (virtual) time as the states.
fn grace_ends_at(
    states: &[(Duration, RTCPeerConnectionState)],
    until: Duration,
) -> Option<Duration> {
    let mut watch = PathWatch::default();
    let mut timers: Vec<(u64, Duration)> = Vec::new();
    for &(at, state) in states.iter().filter(|s| s.0 <= until) {
        if let Some(&(_, due)) = timers
            .iter()
            .find(|(t, due)| *due <= at && watch.expired(*t))
        {
            return Some(due);
        }
        timers.retain(|(_, due)| *due > at);
        if let Some(timer) = watch.on_state(state) {
            timers.push((timer, at + DISCONNECT_GRACE));
        }
    }
    timers
        .into_iter()
        .find(|(t, due)| *due <= until && watch.expired(*t))
        .map(|(_, due)| due)
}

/// Both sides' descriptions end their gathering (`a=end-of-candidates`, PNP-011-MUST-035).
fn assert_descriptions_end_gathering(who: &str, m: &Metrics) {
    assert!(!m.descriptions.is_empty(), "{who}");
    for (at, kind, sdp) in &m.descriptions {
        assert!(
            sdp.lines().any(|l| l == "a=end-of-candidates"),
            "{who}: the {kind:?} at {at:?} does not end its gathering\n{sdp}"
        );
    }
}

/// A call on `profile` (both directions), connected.
async fn call_on(profile: LinkProfile, config: CallConfig) -> (SimCall, Duration) {
    let net = SimNet::new(config.seed);
    let hosts = [
        net.host(&config.addresses[0]),
        net.host(&config.addresses[1]),
    ];
    for host in &hosts {
        host.set_profile(profile);
    }
    let call = SimCall::start_on(net, hosts, config).await;
    let connected = call.until_connected(secs(10)).await;
    (call, connected)
}

/// Intelligible: at least 92% of what was played is the tone, and no dropout exceeds 0.4 s.
fn assert_audio_intelligible(who: &str, m: &Metrics, from: Duration, to: Duration) {
    let (good, dropout) = (
        m.audio.good_ratio(from, to),
        m.audio.longest_dropout(from, to),
    );
    assert!(
        m.audio.windows.len() > 100,
        "{who}: audio was played ({} windows)",
        m.audio.windows.len()
    );
    assert!(
        good >= 0.92,
        "{who}: {:.1}% of the played audio is the tone",
        good * 100.0
    );
    assert!(dropout <= ms(400), "{who}: an audio dropout of {dropout:?}");
}

/// No freeze: never more than 2 s without a usable frame.
fn assert_video_does_not_freeze(who: &str, m: &Metrics, from: Duration, to: Duration) {
    let gap = m.video.longest_gap(from, to);
    assert!(gap <= secs(2), "{who}: video froze for {gap:?}");
    assert!(
        m.video.usable_between(from, to) > 0,
        "{who}: no usable video at all"
    );
}

/// No STUN message a peer sent (ICE checks and responses, nominations, consent checks)
/// carries SOFTWARE: no implementation fingerprint on the path (THREAT_MODEL.md).
fn assert_no_stun_software(who: &str, stats: &parolnet_simnet::LinkStats) {
    assert!(stats.sent_stun > 0, "{who}: no STUN at all: {stats:?}");
    assert_eq!(stats.sent_stun_with_software, 0, "{who}: {stats:?}");
}

#[tokio::test(start_paused = true)]
async fn call_setup() {
    let real = std::time::Instant::now();
    let (call, connected) = call_on(LinkProfile::default(), CallConfig::default()).await;
    // Offer and answer cross the signaling channel (50 ms each), then ICE and DTLS over a
    // 10 ms link: well under a second.
    figure("call_setup", "-", "connected", connected);
    assert!(connected < secs(1), "connected after {connected:?}");
    call.run_for(secs(5)).await;
    let end = call.elapsed();
    for (who, peer) in [("caller", &call.caller), ("callee", &call.callee)] {
        let m = peer.snapshot();
        assert_eq!(m.closed, None, "{who}");
        assert_eq!(
            m.states.iter().map(|s| s.1).collect::<Vec<_>>(),
            [
                RTCPeerConnectionState::Connecting,
                RTCPeerConnectionState::Connected
            ],
            "{who}"
        );
        // One description each: non-trickle, every candidate inside.
        assert_eq!(m.offers() + m.answers(), 1, "{who}");
        assert!(m.descriptions[0].2.contains("typ host"), "{who}");
        // Media both ways from the start: the first usable frame within half a second of
        // the connection, then 30 a second with no gap over 100 ms.
        let first = m.video.usable_at.first().copied().expect("video");
        figure("call_setup", who, "first frame", first);
        figure(
            "call_setup",
            who,
            "longest gap",
            m.video.longest_gap(first, end),
        );
        figure("call_setup", who, "stun", peer.host.stats());
        assert!(
            first < connected + ms(500),
            "{who}: first frame at {first:?}"
        );
        assert!(
            m.video.longest_gap(first, end) < ms(100),
            "{who}: {:?}",
            m.video.longest_gap(first, end)
        );
        assert!(
            m.video.usable_between(first, end) as f64 >= (end - first).as_secs_f64() * 29.0,
            "{who}: {} frames",
            m.video.usable_at.len()
        );
        assert_eq!(m.video.unusable, 0, "{who}");
        assert!(
            m.audio.good_ratio(connected + secs(1), end) > 0.99,
            "{who}: {}",
            m.audio.good_ratio(connected + secs(1), end)
        );
        assert_eq!(m.remote_sends(MediaKind::Video), Some(true), "{who}");
        assert_eq!(m.local_sends(MediaKind::Audio), Some(true), "{who}");
        let quality = &m.quality.last().expect("a digest").1;
        assert_eq!(quality.local_candidate, Some(CandidateKind::Host), "{who}");
        assert_eq!(quality.loss_received, Some(0.0), "{who}");
        assert!(
            quality.rtt_ms.is_some_and(|rtt| (15..=40).contains(&rtt)),
            "{who}: {quality:?}"
        );
        assert_no_stun_software(who, &peer.host.stats());
    }
    // Six virtual seconds, a fraction of that in real time.
    assert!(call.elapsed() >= secs(5));
    assert!(real.elapsed() < secs(60));
    call.close().await;
}

#[tokio::test(start_paused = true)]
async fn renegotiation_on_a_lossy_link() {
    let config = CallConfig {
        video: [false, false],
        ..Default::default()
    };
    let (call, connected) = call_on(LinkProfile::lossy(), config).await;
    call.run_for(secs(3)).await;
    assert!(call.caller.snapshot().video.usable_at.is_empty());
    assert!(!call.caller.metrics().descriptions[0].2.contains("m=video"));

    // The caller turns its camera on.
    let upgrade = call.elapsed();
    call.caller.set_video(true);
    call.until("the callee sees the caller's video", secs(3), |c| {
        c.callee.metrics().remote_sends(MediaKind::Video) == Some(true)
            && !c.callee.metrics().video.usable_at.is_empty()
    })
    .await;
    let first = call.callee.snapshot().video.usable_at[0];
    assert!(
        first - upgrade < secs(2),
        "video after {:?}",
        first - upgrade
    );
    assert_eq!(call.caller.metrics().offers(), 2);
    assert_eq!(call.callee.metrics().answers(), 2);
    call.run_for(secs(3)).await;

    // The callee turns its own on: the same section, the other direction.
    call.callee.set_video(true);
    call.until("the caller sees the callee's video", secs(3), |c| {
        !c.caller.metrics().video.usable_at.is_empty()
    })
    .await;
    assert_eq!(call.callee.metrics().offers(), 1);
    let both = call.elapsed();
    call.run_for(secs(5)).await;

    // The caller turns its camera off: the callee is told, and nothing more arrives.
    call.caller.set_video(false);
    call.until("the callee sees the caller's video end", secs(3), |c| {
        c.callee.metrics().remote_sends(MediaKind::Video) == Some(false)
    })
    .await;
    let off = call.elapsed();
    call.run_for(secs(3)).await;
    let end = call.elapsed();

    let (caller, callee) = (call.caller.snapshot(), call.callee.snapshot());
    assert_video_does_not_freeze("callee, while the caller sent", &callee, first, off);
    assert_video_does_not_freeze("caller", &caller, both + secs(1), end);
    assert_eq!(
        callee.video.usable_between(off + ms(500), end),
        0,
        "no video from the caller after it was turned off"
    );
    assert_eq!(caller.remote_sends(MediaKind::Video), Some(true));
    // The audio never noticed.
    assert_audio_intelligible("caller", &caller, connected + secs(1), end);
    assert_audio_intelligible("callee", &callee, connected + secs(1), end);
    for m in [&caller, &callee] {
        assert_eq!(m.closed, None);
        assert!(
            m.states
                .iter()
                .all(|s| s.1 != RTCPeerConnectionState::Failed)
        );
    }
    call.close().await;
}

/// Runs the call until `at` (since it started).
async fn run_to(call: &SimCall, at: Duration) {
    call.run_for(at.saturating_sub(call.elapsed())).await;
}

/// The NACKs a peer sent for the video it receives (`inbound-rtp` `nackCount`).
async fn video_nacks_sent(peer: &SimPeer) -> u32 {
    let (report, _) = peer.handle.stats().await.expect("stats");
    report
        .iter()
        .filter_map(|entry| match entry {
            RTCStatsReportEntry::InboundRtp(inbound)
                if inbound.received_rtp_stream_stats.rtp_stream_stats.kind
                    == RtpCodecKind::Video =>
            {
                Some(inbound.nack_count)
            }
            _ => None,
        })
        .sum()
}

/// What [`stall_after_a_gap`] measured on the callee (which receives the caller's video) and
/// the caller (which sends it).
struct Stall {
    call: SimCall,
    /// When the caller's link healed.
    heal: Duration,
    /// The callee's key-frame requests, after the last packet before the stall had arrived
    /// and when the link healed.
    requests: (u64, u64),
    /// The caller's key frames sent, at the same two instants.
    keyframes_sent: (u64, u64),
    /// The callee's video NACKs: before it could know of the gap, before the gap's time
    /// bound ran out, after it, and when the link healed.
    nacks: [u32; 4],
}

/// A gap that the receiver knows of, then nothing at all for longer than the gap bound
/// (300 ms), then the link heals. Phases on the caller's uplink (the caller's media to the
/// callee) and the callee's (its RTCP back):
///
/// 1. `t0 .. t0+200 ms`: the caller's link drops everything (about six frames);
/// 2. `t0+200 .. t0+300 ms`: it carries again (three frame intervals at 30 a second), so
///    the callee learns of the gap; the callee's link drops everything, so no NACK reaches
///    the caller and nothing repairs the gap;
/// 3. `t0+300 ms .. t0+1750 ms`: the caller's link drops everything again; the callee's
///    carries (its PLI and NACKs reach the caller, whose answers are lost);
/// 4. from `t0+1750 ms`: both carry.
///
/// No packet reaches the callee in phase 3, so only a timer can give the gap up there.
async fn stall_after_a_gap() -> Stall {
    let (call, _) = call_on(LinkProfile::default(), CallConfig::default()).await;
    call.run_for(secs(3)).await;
    let t0 = call.elapsed();
    let dead = LinkProfile {
        loss: 1.0,
        ..Default::default()
    };
    call.caller.host.set_profile(dead);
    run_to(&call, t0 + ms(200)).await;
    // Nothing after the gap has arrived yet: no NACK can name it.
    let nacks_unknown = video_nacks_sent(&call.callee).await;
    call.caller.host.set_profile(LinkProfile::default());
    call.callee.host.set_profile(dead);
    run_to(&call, t0 + ms(300)).await;
    call.caller.host.set_profile(dead);
    call.callee.host.set_profile(LinkProfile::default());
    // The gap became known with the first frame after t0+200 ms (it arrives by t0+245 ms):
    // its bound runs out between t0+510 and t0+545 ms. The last packet of phase 2 arrives by
    // about t0+310 ms.
    run_to(&call, t0 + ms(400)).await;
    let requests_before = call.callee.metrics().video.keyframes_requested;
    let keyframes_before = call.caller.metrics().video.keyframes_sent;
    // About 300 ms of asking for the gap (the generator runs every 100 ms), all before its
    // bound.
    run_to(&call, t0 + ms(500)).await;
    let nacks_before = video_nacks_sent(&call.callee).await;
    // At least 250 ms after the bound.
    run_to(&call, t0 + ms(800)).await;
    let nacks_after = video_nacks_sent(&call.callee).await;
    let heal = t0 + ms(1750);
    run_to(&call, heal).await;
    let requests_at_heal = call.callee.metrics().video.keyframes_requested;
    let keyframes_at_heal = call.caller.metrics().video.keyframes_sent;
    let nacks_at_heal = video_nacks_sent(&call.callee).await;
    call.caller.host.set_profile(LinkProfile::default());
    run_to(&call, heal + secs(3)).await;
    Stall {
        call,
        heal,
        requests: (requests_before, requests_at_heal),
        keyframes_sent: (keyframes_before, keyframes_at_heal),
        nacks: [nacks_unknown, nacks_before, nacks_after, nacks_at_heal],
    }
}

#[tokio::test(start_paused = true)]
async fn a_stall_after_a_gap_asks_for_a_key_frame_and_video_resumes() {
    let stall = stall_after_a_gap().await;
    let test = "a_stall_after_a_gap_asks_for_a_key_frame_and_video_resumes";
    figure(test, "callee", "key-frame requests", stall.requests);
    figure(test, "caller", "key frames sent", stall.keyframes_sent);
    // Nothing arrived in the stall: only the builder's timer can have given the gap up.
    assert!(
        stall.requests.1 > stall.requests.0,
        "no key-frame request while nothing arrived: {:?}",
        stall.requests
    );
    // The request went out: the caller answered with a key frame (lost on its link).
    assert!(
        stall.keyframes_sent.1 > stall.keyframes_sent.0,
        "the caller sent no key frame in the stall: {:?}",
        stall.keyframes_sent
    );
    // Once the link heals, video resumes and does not freeze again.
    let end = stall.call.elapsed();
    let callee = stall.call.callee.snapshot();
    let first = callee
        .video
        .usable_at
        .iter()
        .copied()
        .find(|at| *at > stall.heal)
        .expect("video after the link healed");
    figure(
        test,
        "callee",
        "first frame after healing",
        first - stall.heal,
    );
    assert!(
        first - stall.heal < ms(1500),
        "video resumed {:?} after the link healed",
        first - stall.heal
    );
    let gap = callee.video.longest_gap(first, end);
    assert!(gap < secs(1), "video froze for {gap:?} after it resumed");
    stall.call.close().await;
}

#[tokio::test(start_paused = true)]
async fn a_gap_given_up_is_no_longer_asked_for() {
    let stall = stall_after_a_gap().await;
    let test = "a_gap_given_up_is_no_longer_asked_for";
    let [unknown, before, after, at_heal] = stall.nacks;
    figure(test, "callee", "video NACKs", stall.nacks);
    // The callee asked for the gap while it could still be used...
    assert!(
        before > unknown,
        "no NACK for the gap before its bound: {:?}",
        stall.nacks
    );
    // ...and stopped once the builder gave it up (RFC 4588 section 6.3): its horizon moved
    // past it, and nothing newer is missing.
    assert_eq!(
        at_heal, after,
        "NACKs for packets the builder gave up: {:?}",
        stall.nacks
    );
    stall.call.close().await;
}

#[tokio::test(start_paused = true)]
async fn an_ice_restart_follows_a_machine_to_another_network() {
    let (call, connected) = call_on(LinkProfile::default(), CallConfig::default()).await;
    call.run_for(secs(5)).await;

    // The caller's machine moves: its old address is gone, it has a new one. The monitor
    // notices on its next polls (2 s apart, two that agree), and the call restarts ICE.
    let mut monitor = NetworkMonitor::start(call.caller.host.network(), secs(2));
    call.run_for(ms(100)).await;
    let moved = call.elapsed();
    call.caller.host.set_addresses(&["10.0.9.1"]);
    let changed = tokio::time::timeout(secs(10), monitor.changed())
        .await
        .expect("the monitor reports the change")
        .expect("the monitor runs");
    assert_eq!(changed, ["10.0.9.1".parse::<std::net::IpAddr>().unwrap()]);
    let noticed = call.elapsed();
    assert!(
        noticed - moved <= secs(4) + ms(100),
        "{:?}",
        noticed - moved
    );
    call.caller.restart_ice();

    call.until("the restart's answer", secs(3), |c| {
        c.caller.metrics().offers() == 2 && c.callee.metrics().answers() == 2
    })
    .await;
    call.until("connected on the new network", secs(5), |c| {
        c.caller.metrics().connected() && c.callee.metrics().connected()
    })
    .await;
    let restored = call.elapsed();
    const RESTART: &str = "an_ice_restart_follows_a_machine_to_another_network";
    figure(RESTART, "-", "noticed after move", noticed - moved);
    figure(RESTART, "-", "restored after notice", restored - noticed);
    assert!(restored - noticed < secs(2), "{:?}", restored - noticed);
    call.run_for(secs(8)).await;
    let end = call.elapsed();

    let (caller, callee) = (call.caller.snapshot(), call.callee.snapshot());
    let offer = &caller.descriptions[1].2;
    assert!(
        offer.contains("10.0.9.1") && !offer.contains("10.0.0.1 "),
        "{offer}"
    );
    // The restart gathered again, and its offer and answer end that gathering too.
    for (who, m) in [("caller", &caller), ("callee", &callee)] {
        assert_descriptions_end_gathering(who, m);
        // The path came back well within the grace period: the call stays.
        assert_eq!(grace_ends_at(&m.states, end), None, "{who}: {:?}", m.states);
    }
    for (who, m) in [("caller", &caller), ("callee", &callee)] {
        assert_eq!(m.closed, None, "{who}: the connection survived");
        assert!(
            m.states
                .iter()
                .all(|s| s.1 != RTCPeerConnectionState::Failed),
            "{who}: {:?}",
            m.states
        );
        // The outage is the time it took to notice, plus the restart: video is back within
        // two seconds of the restart, and runs without a freeze afterwards.
        let after = m.video.usable_at.iter().find(|t| **t > noticed).copied();
        figure(
            RESTART,
            who,
            "video back after notice",
            after.map(|t| t - noticed),
        );
        figure(
            RESTART,
            who,
            "longest freeze after restore+1s",
            m.video.longest_gap(restored + secs(1), end),
        );
        figure(
            RESTART,
            who,
            "audio good / longest dropout after restore+1s",
            (
                m.audio.good_ratio(restored + secs(1), end),
                m.audio.longest_dropout(restored + secs(1), end),
            ),
        );
        figure(
            RESTART,
            who,
            "targets after the move",
            m.targets
                .iter()
                .filter(|t| t.0 >= moved)
                .map(|t| (t.0.as_millis(), t.1))
                .collect::<Vec<_>>(),
        );
        assert!(
            after.is_some_and(|t| t - noticed < secs(2)),
            "{who}: video back at {after:?}, restart at {noticed:?}"
        );
        assert_video_does_not_freeze(who, m, restored + secs(1), end);
        assert_audio_intelligible(who, m, restored + secs(1), end);
        assert_audio_intelligible(who, m, connected + secs(1), moved);
    }
    // The restart's checks and the consent checks on both networks.
    assert_no_stun_software("caller", &call.caller.host.stats());
    assert_no_stun_software("callee", &call.callee.host.stats());
    call.close().await;
}

#[tokio::test(start_paused = true)]
async fn without_a_restart_the_same_move_ends_the_call() {
    let (call, _) = call_on(LinkProfile::default(), CallConfig::default()).await;
    call.run_for(secs(5)).await;
    call.caller.host.set_addresses(&["10.0.9.1"]);
    call.until("the connection to fail", secs(60), |c| {
        let failed = |m: &Metrics| {
            m.closed.is_some()
                || m.states
                    .iter()
                    .any(|s| s.1 == RTCPeerConnectionState::Failed)
        };
        failed(&c.caller.metrics()) && failed(&c.callee.metrics())
    })
    .await;
    call.close().await;
}

/// PNP-011-MUST-037 in virtual time: the same move without a restart leaves both sides
/// `disconnected`, and the grace period ends the call from there, whether or not the ICE
/// agent ever reports `failed` (which an agent that follows W3C webrtc-pc 5.6.4 does only
/// with the peer's end of candidates).
#[tokio::test(start_paused = true)]
async fn a_call_without_a_path_ends_when_the_grace_period_runs_out() {
    let (call, _) = call_on(LinkProfile::default(), CallConfig::default()).await;
    call.run_for(secs(5)).await;
    let moved = call.elapsed();
    call.caller.host.set_addresses(&["10.0.9.1"]);
    call.until("both sides to lose the path", secs(30), |c| {
        let lost = |m: &Metrics| {
            m.states
                .iter()
                .any(|s| s.0 >= moved && s.1 == RTCPeerConnectionState::Disconnected)
        };
        lost(&c.caller.metrics()) && lost(&c.callee.metrics())
    })
    .await;
    call.run_for(DISCONNECT_GRACE + secs(1)).await;
    let end = call.elapsed();
    for (who, m) in [
        ("caller", call.caller.snapshot()),
        ("callee", call.callee.snapshot()),
    ] {
        let lost = m
            .states
            .iter()
            .find(|s| s.0 >= moved && s.1 == RTCPeerConnectionState::Disconnected)
            .map(|s| s.0)
            .expect("disconnected");
        let ends = grace_ends_at(&m.states, end);
        figure(
            "a_call_without_a_path_ends_when_the_grace_period_runs_out",
            who,
            "lost after move / ends after move",
            (lost - moved, ends.map(|e| e - moved)),
        );
        assert_eq!(ends, Some(lost + DISCONNECT_GRACE), "{who}: {:?}", m.states);
        // Nothing connected again in between.
        assert!(
            !m.states
                .iter()
                .any(|s| s.0 > lost && s.1 == RTCPeerConnectionState::Connected),
            "{who}: {:?}",
            m.states
        );
        assert_descriptions_end_gathering(who, &m);
    }
    call.close().await;
}

#[tokio::test(start_paused = true)]
async fn a_restart_that_cannot_be_signalled_leaves_the_old_path_in_use() {
    // A new interface appears (nothing is lost); the restart's offer never reaches the peer.
    let (call, connected) = call_on(LinkProfile::default(), CallConfig::default()).await;
    call.run_for(secs(3)).await;
    call.caller.host.set_addresses(&["10.0.0.1", "10.0.9.1"]);
    call.caller.set_signaling(false);
    call.caller.restart_ice();
    call.run_for(secs(10)).await;
    let end = call.elapsed();
    let (caller, callee) = (call.caller.snapshot(), call.callee.snapshot());
    assert_eq!(caller.offers(), 2, "the restart was offered");
    assert_eq!(callee.answers(), 1, "and never answered");
    // Media kept flowing on the pair the session had.
    for (who, m) in [("caller", &caller), ("callee", &callee)] {
        assert_eq!(m.closed, None, "{who}");
        assert_video_does_not_freeze(who, m, connected + secs(1), end);
        assert_audio_intelligible(who, m, connected + secs(1), end);
    }
    // Taking the offer back and trying again, with signaling restored, completes.
    call.caller.handle.rollback().unwrap();
    call.caller.set_signaling(true);
    call.caller.restart_ice();
    call.until("the second attempt", secs(5), |c| {
        c.callee.metrics().answers() == 2
            && c.caller.metrics().connected()
            && c.callee.metrics().connected()
    })
    .await;
    call.run_for(secs(3)).await;
    let m = call.callee.snapshot();
    assert_video_does_not_freeze("callee, after the restart", &m, end, call.elapsed());
    call.close().await;
}

/// The host candidate ports of a description.
fn host_ports(sdp: &str) -> Vec<u16> {
    sdp.lines()
        .filter(|l| l.contains("typ host"))
        .filter_map(|l| l.split_whitespace().nth(5)?.parse().ok())
        .collect()
}

/// SRTP re-keying in a call (RFC 3711 section 9.2, RFC 5764 section 4.4; PNP-011 section
/// 7.6) with a key lifetime of 8000 packets on `sides`, for 90 s. The engine asks for the
/// new association when a sixteenth of the lifetime is left: 500 packets, about 2 s at the
/// 2.5 Mbit/s the estimate reaches, ample for an offer, an answer, ICE checks and a DTLS
/// handshake. Each re-keying is an ICE restart with a new DTLS association on new ports (RFC
/// 8842 section 5.1). The call goes on through every one of them: no failure, no freeze over
/// 2 s, intelligible audio.
async fn re_keying(test: &str, sides: [bool; 2]) {
    use parolnet_rtc::rtci::srtp::keying::KeyLifetime;
    let lifetime = KeyLifetime {
        srtp_packets: 8_000,
        ..KeyLifetime::MAX
    };
    let config = CallConfig {
        srtp_key_lifetime: sides.map(|on| on.then_some(lifetime)),
        ..Default::default()
    };
    let (call, connected) = call_on(LinkProfile::default(), config).await;
    call.run_for(secs(90)).await;
    let end = call.elapsed();
    let mut renewals = 0;
    let mut same_ports = Vec::new();
    for (who, peer) in [("caller", &call.caller), ("callee", &call.callee)] {
        let m = peer.snapshot();
        // Each new association is a new `a=tls-id` in this side's descriptions, and its
        // candidates are on new ports.
        let ids: Vec<&str> = m
            .descriptions
            .iter()
            .filter_map(|d| parolnet_rtc::tls_id(&d.2))
            .collect();
        let changes = ids.windows(2).filter(|w| w[0] != w[1]).count();
        renewals += changes;
        for w in m.descriptions.windows(2) {
            let (before, after) = (&w[0].2, &w[1].2);
            if parolnet_rtc::tls_id(before) != parolnet_rtc::tls_id(after)
                && host_ports(after)
                    .iter()
                    .any(|p| host_ports(before).contains(p))
            {
                same_ports.push((who, w[1].0));
            }
        }
        figure(test, who, "tls-id changes", changes);
        figure(test, who, "states", &m.states);
        figure(
            test,
            who,
            "descriptions (at, type, tls-id, host ports)",
            m.descriptions
                .iter()
                .map(|d| {
                    (
                        d.0,
                        d.1,
                        parolnet_rtc::tls_id(&d.2).map(|t| t[..8].to_owned()),
                        host_ports(&d.2),
                    )
                })
                .collect::<Vec<_>>(),
        );
        figure(
            test,
            who,
            "longest freeze",
            m.video.longest_gap(connected + secs(1), end),
        );
        figure(
            test,
            who,
            "audio good / longest dropout",
            (
                m.audio.good_ratio(connected + secs(1), end),
                m.audio.longest_dropout(connected + secs(1), end),
            ),
        );
        figure(test, who, "closed", &m.closed);
    }
    for (who, peer) in [("caller", &call.caller), ("callee", &call.callee)] {
        let m = peer.snapshot();
        assert_eq!(m.closed, None, "{who}");
        assert!(
            m.states
                .iter()
                .all(|s| s.1 != RTCPeerConnectionState::Failed),
            "{who}: {:?}",
            m.states
        );
        assert_video_does_not_freeze(who, &m, connected + secs(1), end);
        assert_audio_intelligible(who, &m, connected + secs(1), end);
    }
    assert!(renewals >= 2, "{renewals} new DTLS associations in 90 s");
    assert!(
        same_ports.is_empty(),
        "a new association on a previous port: {same_ports:?}"
    );
    call.close().await;
}

/// Only the caller's keys have the short lifetime: the caller re-keys, the callee answers.
#[tokio::test(start_paused = true)]
async fn srtp_re_keying_by_one_side_keeps_the_call() {
    re_keying("srtp_re_keying_by_one_side_keeps_the_call", [true, false]).await;
}

/// Both sides' keys have it: their re-keying offers cross (PNP-011-MUST-022) and one new
/// association serves both.
#[tokio::test(start_paused = true)]
async fn srtp_re_keying_keeps_the_call() {
    re_keying("srtp_re_keying_keeps_the_call", [true, true]).await;
}

/// The median of the estimates in force between `from` and `to`, sampled every 100 ms.
fn median_target(m: &Metrics, from: Duration, to: Duration) -> u32 {
    let mut samples = Vec::new();
    let mut at = from;
    while at <= to {
        samples.extend(m.target_at(at));
        at += ms(100);
    }
    samples.sort_unstable();
    samples[samples.len() / 2]
}

#[tokio::test(start_paused = true)]
async fn the_estimate_climbs_on_an_open_link() {
    let (call, _) = call_on(LinkProfile::default(), CallConfig::default()).await;
    call.run_for(secs(35)).await;
    for (who, peer) in [("caller", &call.caller), ("callee", &call.callee)] {
        let m = peer.snapshot();
        const CLIMBS: &str = "the_estimate_climbs_on_an_open_link";
        figure(CLIMBS, who, "first target", m.targets[0].1);
        figure(CLIMBS, who, "last target", m.targets.last().map(|t| t.1));
        figure(
            CLIMBS,
            who,
            "reached 1 Mbit/s at",
            m.targets.iter().find(|t| t.1 >= 1_000_000).map(|t| t.0),
        );
        figure(
            CLIMBS,
            who,
            "downward steps",
            m.targets.windows(2).filter(|w| w[1].1 < w[0].1).count(),
        );
        figure(CLIMBS, who, "video bits", m.video.bytes_sent * 8);
        assert_eq!(
            m.targets[0].1, 300_000,
            "{who}: starts at the initial estimate"
        );
        assert!(
            m.targets.windows(2).all(|w| w[1].1 >= w[0].1),
            "{who}: never down on a link without loss or queueing"
        );
        assert_eq!(
            m.targets.last().unwrap().1,
            2_500_000,
            "{who}: up to the maximum"
        );
        let at_1m = m.targets.iter().find(|t| t.1 >= 1_000_000).unwrap().0;
        // The engine probes for bandwidth at start-up on both sides. Under rtci 0.2.0 only the
        // callee did: 1 Mbit/s at 620 ms (CI 45841495800), where 0.1.0 climbed at about 8% a
        // second and took some sixteen seconds. The caller, whose first packet is audio and
        // whose chain has no pacer, lost its start-up probe and climbed as in 0.1.0 (15.61 s),
        // so it was held to 12 s..=22 s. rtci 0.2.1 asks for that probe again once a stream
        // can pad it: the engine measures 0.27-0.37 s to 1 Mbit/s in every chain and order.
        // Both sides now get the callee's bound, 2 s: over three times the 620 ms this test
        // measured for a probing side (connection set-up, under 1 s by `call_setup`, and the
        // 100 ms estimate sampling are inside that figure), and an eighth of the old 15.6 s,
        // so a side that loses its probe again fails here.
        assert!(at_1m <= secs(2), "{who}: {at_1m:?}");
        // The video followed it.
        let sent = m.video.bytes_sent as f64 * 8.0;
        assert!(sent > 20e6, "{who}: {sent} bits of video in 35 s");
    }
    call.close().await;
}

#[tokio::test(start_paused = true)]
async fn the_estimate_settles_under_a_cap() {
    let (call, connected) = call_on(LinkProfile::capped_300k(), CallConfig::default()).await;
    call.run_for(secs(60)).await;
    let end = call.elapsed();
    for (who, peer) in [("caller", &call.caller), ("callee", &call.callee)] {
        let m = peer.snapshot();
        let (low, high) = m.target_range(connected + secs(10), end).unwrap();
        let median = median_target(&m, connected + secs(10), end);
        let stats = peer.host.stats();
        const SETTLES: &str = "the_estimate_settles_under_a_cap";
        figure(SETTLES, who, "low / median / high", (low, median, high));
        figure(
            SETTLES,
            who,
            "carried bit/s",
            (stats.delivered_bytes as f64 * 8.0 / end.as_secs_f64()) as u64,
        );
        figure(
            SETTLES,
            who,
            "queue drops / sent",
            (stats.queue_drops, stats.sent),
        );
        // It probes above the cap, is pushed back under it, and spends its time around it.
        assert!(high <= 450_000, "{who}: the estimate reached {high}");
        assert!(low >= 100_000, "{who}: {low}");
        assert!(
            (150_000..=330_000).contains(&median),
            "{who}: a median estimate of {median} on a 300 kbit/s link"
        );
        // What the link carried: most of its capacity, and little of it was dropped.
        let carried = stats.delivered_bytes as f64 * 8.0 / end.as_secs_f64();
        assert!(
            (150_000.0..=300_000.0).contains(&carried),
            "{who}: the link carried {carried:.0} bit/s"
        );
        assert!(
            (stats.queue_drops as f64) < stats.sent as f64 * 0.06,
            "{who}: {} of {} datagrams dropped at the cap",
            stats.queue_drops,
            stats.sent
        );
    }
    call.close().await;
}

/// Measure only: the cap of `the_estimate_follows_a_cap_that_comes_and_goes`, held `hold`
/// after the estimate went under 400 kbit/s, then lifted; the recovery series. Prints, as
/// `figure cap_length | hold <n> s | ...`: the estimate when the cap lifts, the target 5, 10,
/// 15 and 20 s later, the median under the cap and the callee's longest freeze.
async fn cap_length(hold: Duration) {
    let (call, _) = call_on(LinkProfile::default(), CallConfig::default()).await;
    call.run_for(secs(20)).await;
    call.caller.host.set_profile(LinkProfile::capped_300k());
    let capped = call.elapsed();
    call.until("the estimate to come down", secs(5), |c| {
        c.caller
            .metrics()
            .target_at(c.elapsed())
            .is_some_and(|t| t < 400_000)
    })
    .await;
    call.run_for(hold).await;
    let opened = call.elapsed();
    let at_lift = call.caller.metrics().target_at(opened);
    let under = median_target(&call.caller.snapshot(), capped + secs(8), opened);
    call.caller.host.set_profile(LinkProfile::default());
    call.run_for(secs(20)).await;
    let m = call.callee.snapshot();
    let series: Vec<Option<u32>> = {
        let caller = call.caller.metrics();
        [5, 10, 15, 20]
            .into_iter()
            .map(|at| caller.target_at(opened + secs(at)))
            .collect()
    };
    let who = format!("hold {} s", hold.as_secs());
    figure(
        "cap_length",
        &who,
        "at lift | +5/+10/+15/+20 | median under the cap | longest freeze",
        (
            at_lift,
            series,
            under,
            m.video.longest_gap(secs(2), call.elapsed()),
        ),
    );
    call.close().await;
}

/// The cap lengths of `M1_CAP_HOLDS` (seconds, comma-separated; default 14,17,20,23,26).
#[tokio::test(start_paused = true)]
#[ignore = "a measurement sweep for engine comparisons, not a check"]
async fn sweep_cap_length() {
    let holds = std::env::var("M1_CAP_HOLDS").unwrap_or_else(|_| "14,17,20,23,26".into());
    for hold in holds
        .split(',')
        .filter_map(|h| h.trim().parse::<u64>().ok())
    {
        cap_length(secs(hold)).await;
    }
}

#[tokio::test(start_paused = true)]
async fn the_estimate_follows_a_cap_that_comes_and_goes() {
    let (call, _) = call_on(LinkProfile::default(), CallConfig::default()).await;
    call.run_for(secs(20)).await;
    let before = call.caller.metrics().target_at(call.elapsed()).unwrap();
    const CAP: &str = "the_estimate_follows_a_cap_that_comes_and_goes";
    figure(CAP, "caller", "target before the cap", before);
    assert!(before > 900_000, "{before}");

    // The path drops to 300 kbit/s.
    call.caller.host.set_profile(LinkProfile::capped_300k());
    let capped = call.elapsed();
    call.until("the estimate to come down", secs(5), |c| {
        c.caller
            .metrics()
            .target_at(c.elapsed())
            .is_some_and(|t| t < 400_000)
    })
    .await;
    let reacted = call.elapsed() - capped;
    figure(CAP, "caller", "below 400 kbit/s after", reacted);
    assert!(reacted < secs(4), "{reacted:?}");
    call.run_for(secs(20)).await;
    let under = median_target(&call.caller.snapshot(), capped + secs(8), call.elapsed());
    figure(CAP, "caller", "median under the cap", under);
    assert!((150_000..=330_000).contains(&under), "{under}");
    // The other direction never had a cap.
    assert!(call.callee.metrics().target_at(call.elapsed()).unwrap() > 1_500_000);

    // And opens up again.
    call.caller.host.set_profile(LinkProfile::default());
    let opened = call.elapsed();
    call.run_for(secs(20)).await;
    let after = call.caller.metrics().target_at(call.elapsed()).unwrap();
    let m = call.callee.snapshot();
    for at in [5, 10, 15, 20] {
        figure(
            CAP,
            "caller",
            &format!("target {at} s after the cap went"),
            call.caller.metrics().target_at(opened + secs(at)),
        );
    }
    figure(
        CAP,
        "callee",
        "longest freeze (whole call)",
        m.video.longest_gap(secs(2), call.elapsed()),
    );
    figure(
        CAP,
        "callee",
        "longest freeze while capped",
        m.video.longest_gap(capped, opened),
    );
    figure(
        CAP,
        "callee",
        "longest freeze after the cap went",
        m.video.longest_gap(opened, call.elapsed()),
    );
    assert!(after > 800_000, "{after} twenty seconds after the cap went");
    assert_video_does_not_freeze("callee", &m, secs(2), call.elapsed());
    call.close().await;
}

/// Measure only: one M1 profile on `seeds`, every figure of the exit bar printed and nothing
/// asserted, so that a sweep runs to its end. For engine comparisons (several seeds, several
/// engine revisions): `cargo test -p parolnet-simnet --test m1 -- --ignored --nocapture sweep`.
async fn sweep(name: &str, link: LinkProfile, seeds: std::ops::RangeInclusive<u64>) {
    for seed in seeds {
        let config = CallConfig {
            seed,
            ..Default::default()
        };
        let (call, connected) = call_on(link, config).await;
        call.run_for(secs(30)).await;
        let end = call.elapsed();
        let from = connected + secs(2);
        for (side, peer) in [("caller", &call.caller), ("callee", &call.callee)] {
            let who = format!("{name}, seed {seed}, {side}");
            let m = peer.snapshot();
            let good = m.audio.good_ratio(from, end);
            let dropout = m.audio.longest_dropout(from, end);
            let freeze = m.video.longest_gap(from, end);
            figure(
                "sweep",
                &who,
                "audio good % / longest dropout / longest freeze / failed",
                (
                    format!("{:.1}", good * 100.0),
                    dropout,
                    freeze,
                    m.closed.is_some()
                        || m.states
                            .iter()
                            .any(|s| s.1 == RTCPeerConnectionState::Failed),
                ),
            );
            figure(
                "sweep",
                &who,
                "meets the bar (audio >= 92 %, dropout <= 0.4 s, freeze <= 2 s)",
                good >= 0.92 && dropout <= ms(400) && freeze <= secs(2),
            );
        }
        call.close().await;
    }
}

#[tokio::test(start_paused = true)]
#[ignore = "a measurement sweep for engine comparisons, not a check"]
async fn sweep_profile_300_kbps_cap() {
    sweep("300 kbit/s cap", LinkProfile::capped_300k(), 1..=8).await;
}

/// One M1 profile, on three seeds: the exit bar's two assertions.
async fn profile(name: &str, link: LinkProfile, source: VideoSourceKind) {
    for seed in [1, 2, 3] {
        let config = CallConfig {
            seed,
            video_source: source,
            ..Default::default()
        };
        let (call, connected) = call_on(link, config).await;
        call.run_for(secs(30)).await;
        let end = call.elapsed();
        let from = connected + secs(2);
        for (side, peer) in [("caller", &call.caller), ("callee", &call.callee)] {
            let who = format!("{name}, seed {seed}, {side}");
            let m = peer.snapshot();
            {
                let (_, highest) = m.target_range(Duration::ZERO, end).unwrap_or_default();
                let rate = m.video.bytes_sent as f64 * 8.0 / (end - connected).as_secs_f64();
                figure(
                    "profile",
                    &who,
                    "longest freeze",
                    m.video.longest_gap(from, end),
                );
                figure(
                    "profile",
                    &who,
                    "video bit/s / allowed by highest estimate",
                    (rate as u64, video_bitrate_for(highest)),
                );
                figure(
                    "profile",
                    &who,
                    "usable frames",
                    m.video.usable_between(from, end),
                );
                figure(
                    "profile",
                    &who,
                    "audio good / longest dropout",
                    (
                        m.audio.good_ratio(from, end),
                        m.audio.longest_dropout(from, end),
                    ),
                );
            }
            assert_eq!(m.closed, None, "{who}");
            assert!(
                m.states
                    .iter()
                    .all(|s| s.1 != RTCPeerConnectionState::Failed),
                "{who}"
            );
            // Video adapts without freezing longer than 2 s.
            assert_video_does_not_freeze(&who, &m, from, end);
            let (_, highest) = m.target_range(Duration::ZERO, end).unwrap();
            let video_rate = m.video.bytes_sent as f64 * 8.0 / (end - connected).as_secs_f64();
            assert!(
                video_rate <= f64::from(video_bitrate_for(highest)) * 1.1,
                "{who}: video at {video_rate:.0} bit/s, estimate at most {highest}"
            );
            assert!(
                video_rate >= 25_000.0,
                "{who}: video at {video_rate:.0} bit/s"
            );
            // Most of what was sent became a usable frame on the other side.
            let usable = m.video.usable_between(from, end);
            assert!(usable >= 25 * 20, "{who}: {usable} usable frames in 30 s");
            // Audio stays intelligible.
            assert_audio_intelligible(&who, &m, from, end);
        }
        call.close().await;
    }
}

#[tokio::test(start_paused = true)]
async fn profile_two_percent_loss() {
    profile("2% loss", LinkProfile::lossy(), VideoSourceKind::Model).await;
}

#[tokio::test(start_paused = true)]
async fn profile_300_kbps_cap() {
    profile(
        "300 kbit/s cap",
        LinkProfile::capped_300k(),
        VideoSourceKind::Model,
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn profile_100_ms_jitter() {
    profile(
        "100 ms jitter",
        LinkProfile::jittery(),
        VideoSourceKind::Model,
    )
    .await;
}

/// The same three with the real encoder: the test pattern through libvpx, its bitrate set
/// from the estimate, decoded on the other side.
#[cfg(feature = "vpx")]
mod with_libvpx {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn profile_two_percent_loss() {
        profile(
            "2% loss (libvpx)",
            LinkProfile::lossy(),
            VideoSourceKind::Pattern,
        )
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn profile_300_kbps_cap() {
        profile(
            "300 kbit/s cap (libvpx)",
            LinkProfile::capped_300k(),
            VideoSourceKind::Pattern,
        )
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn profile_100_ms_jitter() {
        profile(
            "100 ms jitter (libvpx)",
            LinkProfile::jittery(),
            VideoSourceKind::Pattern,
        )
        .await;
    }
}
