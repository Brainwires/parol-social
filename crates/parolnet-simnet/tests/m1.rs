//! The M1 simulation checks: a call between two `parolnet-rtc` drivers on the simulated
//! network, in virtual time.
//!
//! - call setup;
//! - renegotiation (an audio call that gains and loses video) on a lossy link;
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

use parolnet_rtc::rtc::peer_connection::state::RTCPeerConnectionState;
use parolnet_rtc::{CandidateKind, MediaKind, NetworkMonitor};
use parolnet_simnet::call::{CallConfig, Metrics, SimCall, VideoSourceKind, video_bitrate_for};
use parolnet_simnet::{LinkProfile, SimNet};

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
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

#[tokio::test(start_paused = true)]
async fn call_setup() {
    let real = std::time::Instant::now();
    let (call, connected) = call_on(LinkProfile::default(), CallConfig::default()).await;
    // Offer and answer cross the signaling channel (50 ms each), then ICE and DTLS over a
    // 10 ms link: well under a second.
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
    assert!(restored - noticed < secs(2), "{:?}", restored - noticed);
    call.run_for(secs(8)).await;
    let end = call.elapsed();

    let (caller, callee) = (call.caller.snapshot(), call.callee.snapshot());
    let offer = &caller.descriptions[1].2;
    assert!(
        offer.contains("10.0.9.1") && !offer.contains("10.0.0.1 "),
        "{offer}"
    );
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
        assert!(
            after.is_some_and(|t| t - noticed < secs(2)),
            "{who}: video back at {after:?}, restart at {noticed:?}"
        );
        assert_video_does_not_freeze(who, m, restored + secs(1), end);
        assert_audio_intelligible(who, m, restored + secs(1), end);
        assert_audio_intelligible(who, m, connected + secs(1), moved);
    }
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
        // About 8% a second: one megabit after some sixteen seconds.
        let at_1m = m.targets.iter().find(|t| t.1 >= 1_000_000).unwrap().0;
        assert!((secs(12)..=secs(22)).contains(&at_1m), "{who}: {at_1m:?}");
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
        // It probes above the cap, is pushed back under it, and spends its time around it.
        assert!(high <= 450_000, "{who}: the estimate reached {high}");
        assert!(low >= 100_000, "{who}: {low}");
        assert!(
            (150_000..=330_000).contains(&median),
            "{who}: a median estimate of {median} on a 300 kbit/s link"
        );
        // What the link carried: most of its capacity, and little of it was dropped.
        let stats = peer.host.stats();
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

#[tokio::test(start_paused = true)]
async fn the_estimate_follows_a_cap_that_comes_and_goes() {
    let (call, _) = call_on(LinkProfile::default(), CallConfig::default()).await;
    call.run_for(secs(20)).await;
    let before = call.caller.metrics().target_at(call.elapsed()).unwrap();
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
    assert!(reacted < secs(4), "{reacted:?}");
    call.run_for(secs(20)).await;
    let under = median_target(&call.caller.snapshot(), capped + secs(8), call.elapsed());
    assert!((150_000..=330_000).contains(&under), "{under}");
    // The other direction never had a cap.
    assert!(call.callee.metrics().target_at(call.elapsed()).unwrap() > 1_500_000);

    // And opens up again.
    call.caller.host.set_profile(LinkProfile::default());
    let opened = call.elapsed();
    call.run_for(secs(20)).await;
    let after = call.caller.metrics().target_at(call.elapsed()).unwrap();
    // Since engine v0.22.0+brainwires.6 GCC climbs back as draft-ietf-rmcat-gcc-02 section
    // 5.5 has it: the delay-based estimate stays below 1.5 times the received rate, and
    // increases additively while that rate is "close to convergence" (engine CHANGELOG,
    // "gcc: the delay-based estimate stays below 1.5 times the received rate"). A sender
    // that follows its target therefore reopens over tens of seconds, not the 20 s this
    // asserted before (it measured about 530 kbit/s here, from about 300). The engine's
    // remedy, bandwidth probing (RFC 8836 requirement 4), is not adopted yet. What is
    // asserted is that the estimate climbs well clear of the cap.
    assert!(
        after as f64 > under as f64 * 1.5,
        "{after} twenty seconds after the cap went (capped median {under})"
    );
    let m = call.callee.snapshot();
    assert_video_does_not_freeze("callee", &m, secs(2), call.elapsed());
    let _ = opened;
    call.close().await;
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
