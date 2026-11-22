//! Renegotiation between two drivers on loopback (real sockets): an ICE restart that keeps
//! the session and its data flowing, offers that cross, an audio call that gains and loses
//! video in both directions, and what the congestion controller and the statistics report.

mod support;

use std::time::Duration;

use parolnet_rtc::rtc::peer_connection::sdp::RTCSdpType;
use parolnet_rtc::{CongestionConfig, MediaConfig, MediaKind, RtcConfig};
use support::{Pair, ufrag};

fn data_config(offerer: bool) -> RtcConfig {
    RtcConfig {
        data_channel: offerer.then(|| "pn-test".to_owned()),
        // The side that answered the first offer yields when later offers cross.
        polite: !offerer,
        ..Default::default()
    }
}

fn audio_call(polite: bool) -> RtcConfig {
    RtcConfig {
        media: MediaConfig {
            recv_opus: true,
            send_opus: true,
            ..Default::default()
        },
        polite,
        ..Default::default()
    }
}

/// A message each way on the data channel.
async fn ping_pong(pair: &mut Pair, what: &str) {
    let (a_channel, b_channel) = (
        pair.a.seen.channel.expect("a's channel"),
        pair.b.seen.channel.expect("b's channel"),
    );
    let (a_before, b_before) = (pair.a.seen.messages.len(), pair.b.seen.messages.len());
    let to_b = format!("{what} / a to b").into_bytes();
    let to_a = format!("{what} / b to a").into_bytes();
    pair.a.handle.send_data(a_channel, &to_b[..]).unwrap();
    pair.b.handle.send_data(b_channel, &to_a[..]).unwrap();
    pair.until(what, 10, |p| {
        p.a.seen.messages.len() > a_before && p.b.seen.messages.len() > b_before
    })
    .await;
    assert_eq!(pair.b.seen.messages.last(), Some(&to_b), "{what}");
    assert_eq!(pair.a.seen.messages.last(), Some(&to_a), "{what}");
}

#[tokio::test]
async fn an_ice_restart_keeps_the_session_and_its_data() {
    let mut pair = Pair::new(data_config(true), data_config(false)).await;
    pair.connect().await;
    pair.until("the data channel", 10, |p| {
        p.a.seen.channel.is_some() && p.b.seen.channel.is_some()
    })
    .await;
    ping_pong(&mut pair, "before the restart").await;
    let first = (
        ufrag(&pair.a.seen.descriptions[0]),
        ufrag(&pair.b.seen.descriptions[0]),
    );

    // The answerer of the first exchange restarts: either side may.
    pair.b.handle.restart_ice().unwrap();
    pair.until("the restart's offer and answer", 10, |p| {
        p.b.seen.offers() == 1 && p.a.seen.answers() == 1
    })
    .await;
    let restart_offer = pair.b.seen.descriptions.last().unwrap().clone();
    let restart_answer = pair.a.seen.descriptions.last().unwrap().clone();
    assert_eq!(restart_offer.sdp_type, RTCSdpType::Offer);
    assert_eq!(restart_answer.sdp_type, RTCSdpType::Answer);
    assert_ne!(
        ufrag(&restart_offer),
        first.1,
        "new credentials in the offer"
    );
    assert_ne!(ufrag(&restart_answer), first.0, "and in the answer");
    assert!(
        restart_offer.sdp.contains("typ host") && restart_answer.sdp.contains("typ host"),
        "both descriptions carry the candidates gathered for the restart"
    );
    // The DTLS session is the same one: same fingerprints.
    let fingerprint = |sdp: &str| {
        sdp.lines()
            .find(|l| l.starts_with("a=fingerprint:"))
            .map(str::to_owned)
    };
    assert_eq!(
        fingerprint(&restart_offer.sdp),
        fingerprint(&pair.b.seen.descriptions[0].sdp)
    );
    assert_eq!(
        fingerprint(&restart_answer.sdp),
        fingerprint(&pair.a.seen.descriptions[0].sdp)
    );

    // Data flows while the new generation's checks run, and after.
    ping_pong(&mut pair, "during the restart").await;
    pair.until("connected again", 15, |p| {
        p.a.seen.connected() && p.b.seen.connected()
    })
    .await;
    ping_pong(&mut pair, "after the restart").await;

    // And again, from the other side.
    pair.a.handle.restart_ice().unwrap();
    pair.until("the second restart", 10, |p| {
        p.a.seen.offers() == 2 && p.b.seen.answers() == 2
    })
    .await;
    assert_ne!(
        ufrag(pair.a.seen.descriptions.last().unwrap()),
        ufrag(&restart_answer)
    );
    pair.until("connected after the second restart", 15, |p| {
        p.a.seen.connected() && p.b.seen.connected()
    })
    .await;
    ping_pong(&mut pair, "after the second restart").await;
    pair.close().await;
}

#[tokio::test]
async fn restarts_that_cross_are_settled_by_politeness() {
    let mut pair = Pair::new(data_config(true), data_config(false)).await;
    pair.connect().await;
    pair.until("the data channel", 10, |p| {
        p.a.seen.channel.is_some() && p.b.seen.channel.is_some()
    })
    .await;

    // Both sides see the network change at once: each offers before it has the other's.
    pair.signal = false;
    pair.a.handle.restart_ice().unwrap();
    pair.b.handle.restart_ice().unwrap();
    pair.until("both restart offers", 10, |p| {
        p.a.seen.offers() == 2 && p.b.seen.offers() == 1
    })
    .await;
    let a_offer = pair.a.seen.descriptions.last().unwrap().clone();
    let b_offer = pair.b.seen.descriptions.last().unwrap().clone();
    pair.signal = true;
    // `a` (not polite) drops b's offer; `b` (polite) rolls its own back and answers a's.
    pair.a.handle.set_remote_description(b_offer).unwrap();
    pair.b
        .handle
        .set_remote_description(a_offer.clone())
        .unwrap();
    pair.until("the polite side's answer", 10, |p| {
        p.a.seen.ignored_offers == 1 && p.b.seen.answers() == 2
    })
    .await;
    pair.until("connected on the surviving offer", 15, |p| {
        p.a.seen.connected() && p.b.seen.connected()
    })
    .await;
    ping_pong(&mut pair, "after the crossed restarts").await;
    // The polite side's own restart was satisfied by the one it answered: no third offer.
    pair.settle(500).await;
    assert_eq!(pair.b.seen.offers(), 1, "b made one offer (rolled back)");
    assert_eq!(
        pair.a.seen.offers(),
        2,
        "a made the first offer and one restart"
    );
    assert_eq!(pair.a.seen.answers(), 0);
    pair.close().await;
}

/// Feed opaque frames of the given kinds for `millis`.
async fn feed(pair: &mut Pair, millis: u64, a: &[MediaKind], b: &[MediaKind]) {
    let rounds = millis / 20;
    for _ in 0..rounds {
        for (peer, kinds) in [(&pair.a, a), (&pair.b, b)] {
            for kind in kinds {
                let (data, samples) = match kind {
                    MediaKind::Audio => (vec![0xf8u8; 60], 960),
                    MediaKind::Video => (vec![0x10u8; 2500], 1800),
                };
                peer.handle.send_frame(*kind, data, samples).unwrap();
            }
        }
        pair.settle(20).await;
    }
}

#[tokio::test]
async fn an_audio_call_gains_and_loses_video_by_renegotiation() {
    use MediaKind::{Audio, Video};
    let mut pair = Pair::new(audio_call(false), audio_call(true)).await;
    pair.connect().await;
    assert!(!pair.a.seen.descriptions[0].sdp.contains("m=video"));
    feed(&mut pair, 300, &[Audio, Video], &[Audio, Video]).await;
    assert!(pair.a.seen.rtp_of(Audio) > 5 && pair.b.seen.rtp_of(Audio) > 5);
    assert_eq!(
        pair.b.seen.rtp_of(Video),
        0,
        "no video sender yet: frames are dropped"
    );
    assert_eq!(pair.b.seen.remote(Video), None);

    // `a` turns its camera on: a video section is added by renegotiation.
    pair.a.handle.set_sending(Video, true).unwrap();
    pair.until("the upgrade's offer and answer", 10, |p| {
        p.a.seen.offers() == 2 && p.b.seen.answers() == 2
    })
    .await;
    let upgrade = pair.a.seen.descriptions.last().unwrap().clone();
    assert!(upgrade.sdp.contains("m=video"), "{}", upgrade.sdp);
    assert_eq!(
        ufrag(&upgrade),
        ufrag(&pair.a.seen.descriptions[0]),
        "a media change is not an ICE restart"
    );
    pair.until("b learns that a sends video", 10, |p| {
        p.b.seen.remote(Video) == Some(true) && p.a.seen.local(Video) == Some(true)
    })
    .await;
    assert_eq!(
        pair.a.seen.remote(Video),
        Some(false),
        "b does not send video"
    );
    feed(&mut pair, 600, &[Audio, Video], &[Audio, Video]).await;
    assert!(pair.b.seen.rtp_of(Video) > 10, "{:?}", pair.b.seen.rtp);
    assert_eq!(pair.a.seen.rtp_of(Video), 0, "b has not turned video on");
    let audio_before = (pair.a.seen.rtp_of(Audio), pair.b.seen.rtp_of(Audio));

    // `b` turns its camera on too: the section a's offer created gets b's track.
    pair.b.handle.set_sending(Video, true).unwrap();
    pair.until("b's video is negotiated", 10, |p| {
        p.a.seen.remote(Video) == Some(true) && p.b.seen.local(Video) == Some(true)
    })
    .await;
    let b_offer = pair
        .b
        .seen
        .descriptions
        .iter()
        .rev()
        .find(|d| d.sdp_type == RTCSdpType::Offer);
    assert_eq!(
        b_offer.unwrap().sdp.matches("m=video").count(),
        1,
        "no second video section"
    );
    feed(&mut pair, 600, &[Audio, Video], &[Audio, Video]).await;
    assert!(pair.a.seen.rtp_of(Video) > 10, "{:?}", pair.a.seen.rtp);
    assert!(
        pair.a.seen.rtp_of(Audio) > audio_before.0 && pair.b.seen.rtp_of(Audio) > audio_before.1,
        "audio went on through both renegotiations"
    );

    // `a` turns its camera off: b is told, and no more video arrives from a.
    pair.a.handle.set_sending(Video, false).unwrap();
    pair.until("a's video is off", 10, |p| {
        p.b.seen.remote(Video) == Some(false) && p.a.seen.local(Video) == Some(false)
    })
    .await;
    pair.settle(200).await;
    let (b_video, a_video) = (pair.b.seen.rtp_of(Video), pair.a.seen.rtp_of(Video));
    feed(&mut pair, 500, &[Audio, Video], &[Audio, Video]).await;
    assert_eq!(pair.b.seen.rtp_of(Video), b_video, "a sends no video");
    assert!(
        pair.a.seen.rtp_of(Video) > a_video,
        "b's video still arrives"
    );
    assert_eq!(pair.a.seen.remote(Video), Some(true));

    // And on again.
    pair.a.handle.set_sending(Video, true).unwrap();
    pair.until("a's video is back", 10, |p| {
        p.b.seen.remote(Video) == Some(true) && p.a.seen.local(Video) == Some(true)
    })
    .await;
    feed(&mut pair, 500, &[Audio, Video], &[Audio, Video]).await;
    assert!(pair.b.seen.rtp_of(Video) > b_video);
    pair.close().await;
}

#[tokio::test]
async fn an_unanswered_renegotiation_can_be_taken_back() {
    use MediaKind::{Audio, Video};
    let mut pair = Pair::new(audio_call(false), audio_call(true)).await;
    pair.connect().await;
    // The peer never answers (it does not renegotiate).
    pair.signal = false;
    pair.a.handle.set_sending(Video, true).unwrap();
    pair.until("the unanswered offer", 10, |p| p.a.seen.offers() == 2)
        .await;
    pair.a.handle.rollback().unwrap();
    pair.settle(200).await;
    // The call goes on as it was, and a later exchange still works.
    pair.signal = true;
    feed(&mut pair, 300, &[Audio], &[Audio]).await;
    assert!(pair.a.seen.rtp_of(Audio) > 5 && pair.b.seen.rtp_of(Audio) > 5);
    assert_ne!(pair.a.seen.local(Video), Some(true));
    pair.b.handle.restart_ice().unwrap();
    pair.until("a later exchange", 10, |p| p.a.seen.answers() == 1)
        .await;
    pair.until("connected again", 15, |p| {
        p.a.seen.connected() && p.b.seen.connected()
    })
    .await;
    pair.close().await;
}

#[tokio::test]
async fn the_estimate_and_a_statistics_digest_are_reported() {
    use MediaKind::{Audio, Video};
    let config = |polite| RtcConfig {
        media: MediaConfig {
            recv_opus: true,
            send_opus: true,
            recv_vp8: true,
            send_vp8: true,
        },
        congestion: Some(CongestionConfig::default()),
        quality_interval: Some(Duration::from_millis(500)),
        polite,
        ..Default::default()
    };
    let mut pair = Pair::new(config(false), config(true)).await;
    pair.connect().await;
    for sdp in [
        &pair.a.seen.descriptions[0].sdp,
        &pair.b.seen.descriptions[0].sdp,
    ] {
        assert!(
            sdp.contains("transport-cc"),
            "transport-wide feedback is negotiated: {sdp}"
        );
        assert!(
            sdp.contains("transport-wide-cc-extensions"),
            "and its header extension: {sdp}"
        );
    }
    feed(&mut pair, 2500, &[Audio, Video], &[Audio, Video]).await;
    for peer in [&pair.a, &pair.b] {
        // The initial estimate at once, then the controller's own on loopback (no loss, no
        // delay: it only rises).
        assert_eq!(
            peer.seen.targets.first(),
            Some(&300_000),
            "{:?}",
            peer.seen.targets
        );
        assert!(peer.seen.targets.len() > 1, "{:?}", peer.seen.targets);
        assert!(
            peer.seen.targets.last().unwrap() > &300_000,
            "{:?}",
            peer.seen.targets
        );
        let q = peer.seen.quality.last().expect("a digest");
        assert!(peer.seen.quality.len() >= 3);
        assert_eq!(q.local_candidate, Some(parolnet_rtc::CandidateKind::Host));
        assert!(!q.relayed());
        assert!(q.send_bps > 100_000, "{q:?}");
        assert!(q.recv_bps > 100_000, "{q:?}");
        assert!(q.rtt_ms.is_some_and(|ms| ms < 100), "{q:?}");
        assert_eq!(q.loss_received, Some(0.0), "{q:?}");
        assert!(q.available_bps.is_some(), "{q:?}");
    }
    // On request too.
    let q = pair.a.handle.quality().await.unwrap();
    assert!(q.local_candidate.is_some());
    pair.close().await;
}
