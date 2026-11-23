//! PNP-011 "1:1 Calls": the call signals, call setup, the media session's descriptions, the
//! candidate policy, renegotiation, ICE restart, adaptation and quality.
//!
//! The signal formats and the decisions (ring or busy, which of two crossing offers stands,
//! whether a second `rtc_offer` is a restart) are the functions `parolnet-app`'s core calls;
//! the descriptions and the restart behaviour come from two real `parolnet-rtc` connections
//! on loopback, configured as the core configures a call. The end-to-end behaviour (two
//! clients and a relay; a simulated network) is exercised in `parolnet-app/tests/two_peers.rs`
//! and `parolnet-simnet/tests/m1.rs`.

use std::time::Duration;

use parolnet_app::call::{
    self, CallQuality, CallSignal, FEATURE_RENEGOTIATE, OfferDecision, ReofferDecision,
    VideoChange, Weakness, connection_config, local_features, new_call_id, on_offer, on_reoffer,
    renegotiates, video_bitrate_for, video_change, weaknesses,
};
use parolnet_app::wire::{
    self, DcFrame, FEATURE_ICE_RESTART, RestartExpiry, RestartOffer, msg_type, on_restart_expiry,
    on_restart_offer, restarts, same_dtls_session, should_initiate,
};
use parolnet_clause::clause;
use parolnet_protocol::message::MessageType;
use parolnet_rtc::jitter::AudioJitterBuffer;
use parolnet_rtc::net::{
    ChangeDetector, LocalAddress, candidate_priority, local_preference, select_addresses,
};
use parolnet_rtc::rtc::peer_connection::sdp::{RTCSdpType, RTCSessionDescription};
use parolnet_rtc::rtc::peer_connection::state::RTCPeerConnectionState;
use parolnet_rtc::{
    ConnectionQuality, MediaKind, RtcConfig, RtcEvent, RtcHandle, ice_ufrag, media_directions,
};
use serde_json::{Value, json};
use tokio::sync::mpsc::Receiver;

// ── Signals (section 3) ─────────────────────────────────────────────────────────────────

#[clause("PNP-011-MUST-001")]
#[test]
fn a_call_signal_is_a_json_object_with_action_and_call_id() {
    assert_eq!(msg_type::CALL_SIGNAL, 0x0B);
    assert_eq!(MessageType::from_u8(0x0B), Some(MessageType::CallSignal));
    let hangup = CallSignal::Hangup {
        call_id: "ab".into(),
    };
    let body: Value = serde_json::from_str(&hangup.to_json()).unwrap();
    assert_eq!(body, json!({"action": "hangup", "callId": "ab"}));
    assert_eq!(CallSignal::parse(hangup.to_json().as_bytes()), Some(hangup));
    // Not an object, no action, no call id, an empty or oversized call id: ignored.
    let long = "a".repeat(65);
    for body in [
        "".to_owned(),
        "hangup".to_owned(),
        "[\"hangup\",\"ab\"]".to_owned(),
        r#"{"callId":"ab"}"#.to_owned(),
        r#"{"action":"hangup"}"#.to_owned(),
        r#"{"action":7,"callId":"ab"}"#.to_owned(),
        r#"{"action":"hangup","callId":7}"#.to_owned(),
        r#"{"action":"hangup","callId":""}"#.to_owned(),
        format!(r#"{{"action":"hangup","callId":"{long}"}}"#),
    ] {
        assert_eq!(CallSignal::parse(body.as_bytes()), None, "{body}");
    }
    let longest = "a".repeat(64);
    assert!(
        CallSignal::parse(format!(r#"{{"action":"hangup","callId":"{longest}"}}"#).as_bytes())
            .is_some()
    );
    assert_eq!(CallSignal::parse(&[0xff, 0xfe]), None, "not UTF-8");
}

#[clause("PNP-011-MUST-002")]
#[test]
fn call_ids_are_sixteen_random_bytes_in_lowercase_hex() {
    let ids: Vec<String> = (0..64).map(|_| new_call_id()).collect();
    for id in &ids {
        assert_eq!(id.len(), 32);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{id}"
        );
    }
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), ids.len());
}

#[clause("PNP-011-MUST-003")]
#[test]
fn offer_and_answer_carry_the_description_and_with_video_defaults_to_false() {
    let offer = br#"{"action":"offer","callId":"ab","withVideo":true,"sdp":"v=0"}"#;
    assert_eq!(
        CallSignal::parse(offer),
        Some(CallSignal::Offer {
            call_id: "ab".into(),
            video: true,
            sdp: "v=0".into(),
            features: vec![],
        })
    );
    match CallSignal::parse(br#"{"action":"answer","callId":"ab","sdp":"v=0"}"#) {
        Some(CallSignal::Answer { video, sdp, .. }) => {
            assert!(!video, "an absent withVideo is false");
            assert_eq!(sdp, "v=0");
        }
        other => panic!("{other:?}"),
    }
    for body in [
        r#"{"action":"offer","callId":"ab","withVideo":true}"#,
        r#"{"action":"answer","callId":"ab"}"#,
        r#"{"action":"offer","callId":"ab","sdp":{"type":"offer"}}"#,
        r#"{"action":"answer","callId":"ab","sdp":null}"#,
    ] {
        assert_eq!(CallSignal::parse(body.as_bytes()), None, "{body}");
    }
}

#[clause("PNP-011-MUST-004")]
#[test]
fn unknown_actions_and_unknown_members_are_ignored() {
    for body in [
        r#"{"action":"dance","callId":"ab"}"#,
        r#"{"action":"OFFER","callId":"ab","sdp":"v=0"}"#,
        r#"{"action":"upgrade","callId":"ab","sdp":"v=0"}"#,
    ] {
        assert_eq!(CallSignal::parse(body.as_bytes()), None, "{body}");
    }
    // A signal of a newer peer with members we do not know is the signal we know.
    let newer = br#"{"action":"hangup","callId":"ab","reason":"battery","v":2,"x":{"y":[1]}}"#;
    assert_eq!(
        CallSignal::parse(newer),
        Some(CallSignal::Hangup {
            call_id: "ab".into()
        })
    );
    let newer = br#"{"action":"ice","callId":"ab","generation":3,"candidate":{"candidate":"candidate:1 1 udp 1 192.0.2.1 9 typ host","sdpMid":"0","sdpMLineIndex":0}}"#;
    assert!(matches!(
        CallSignal::parse(newer),
        Some(CallSignal::Ice { .. })
    ));
}

#[clause("PNP-011-MUST-005")]
#[test]
fn features_are_a_list_of_strings_and_anything_else_is_no_feature() {
    let features = |body: &str| match CallSignal::parse(body.as_bytes()) {
        Some(CallSignal::Offer { features, .. }) => features,
        other => panic!("{body}: {other:?}"),
    };
    let with =
        |f: &str| format!(r#"{{"action":"offer","callId":"ab","sdp":"v=0","features":{f}}}"#);
    assert_eq!(features(&with(r#"["renegotiate"]"#)), ["renegotiate"]);
    // Names we do not know are carried and decide nothing.
    let newer = features(&with(r#"["hologram","renegotiate"]"#));
    assert_eq!(newer, ["hologram", "renegotiate"]);
    assert!(renegotiates(true, &newer));
    assert!(!renegotiates(true, &features(&with(r#"["hologram"]"#))));
    // Not a list: empty. Entries that are not strings: skipped.
    for odd in [
        r#""renegotiate""#,
        r#"{"renegotiate":true}"#,
        "true",
        "null",
        "7",
    ] {
        assert!(features(&with(odd)).is_empty(), "{odd}");
    }
    assert_eq!(
        features(&with(r#"[1,"renegotiate",null,["renegotiate"],""]"#)),
        ["renegotiate"]
    );
    assert!(features(r#"{"action":"offer","callId":"ab","sdp":"v=0"}"#).is_empty());
}

#[clause("PNP-011-MUST-006")]
#[test]
fn renegotiate_is_listed_by_those_who_accept_reoffers_and_only_by_them() {
    assert_eq!(FEATURE_RENEGOTIATE, "renegotiate");
    assert_eq!(local_features(true), ["renegotiate"]);
    for (answer, video) in [(false, true), (true, false)] {
        let make = |features: Vec<String>| {
            let (call_id, sdp) = ("ab".to_owned(), "v=0".to_owned());
            let signal = if answer {
                CallSignal::Answer {
                    call_id,
                    video,
                    sdp,
                    features,
                }
            } else {
                CallSignal::Offer {
                    call_id,
                    video,
                    sdp,
                    features,
                }
            };
            serde_json::from_str::<Value>(&signal.to_json()).unwrap()
        };
        let listed = make(local_features(true));
        assert_eq!(listed["features"], json!(["renegotiate"]));
        // A peer that does not renegotiate lists nothing, and its signal is the PWA's.
        assert!(local_features(false).is_empty());
        let plain = make(local_features(false));
        assert_eq!(
            plain,
            json!({
                "action": if answer { "answer" } else { "offer" },
                "callId": "ab",
                "withVideo": video,
                "sdp": "v=0",
            })
        );
    }
}

#[clause("PNP-011-MUST-007")]
#[test]
fn reoffer_and_reanswer_carry_a_description() {
    let reoffer = CallSignal::Reoffer {
        call_id: "ab".into(),
        sdp: "v=0\r\no=- 1 2 IN IP4 0.0.0.0\r\n".into(),
    };
    let body: Value = serde_json::from_str(&reoffer.to_json()).unwrap();
    assert_eq!(
        body,
        json!({"action": "reoffer", "callId": "ab", "sdp": "v=0\r\no=- 1 2 IN IP4 0.0.0.0\r\n"})
    );
    assert_eq!(
        CallSignal::parse(reoffer.to_json().as_bytes()),
        Some(reoffer)
    );
    let reanswer = CallSignal::Reanswer {
        call_id: "ab".into(),
        sdp: "v=0".into(),
    };
    assert_eq!(
        serde_json::from_str::<Value>(&reanswer.to_json()).unwrap()["action"],
        "reanswer"
    );
    assert_eq!(
        CallSignal::parse(reanswer.to_json().as_bytes()),
        Some(reanswer)
    );
    for body in [
        r#"{"action":"reoffer","callId":"ab"}"#,
        r#"{"action":"reanswer","callId":"ab"}"#,
        r#"{"action":"reoffer","callId":"ab","sdp":7}"#,
        r#"{"action":"reanswer","callId":"ab","sdp":["v=0"]}"#,
    ] {
        assert_eq!(CallSignal::parse(body.as_bytes()), None, "{body}");
    }
}

// ── Call setup (section 4) ──────────────────────────────────────────────────────────────

#[clause("PNP-011-MUST-008")]
#[test]
fn an_offer_for_a_call_already_held_is_ignored() {
    assert_eq!(on_offer(true, false), OfferDecision::Duplicate);
    // Also when that very call is what makes us busy: no `reject` for our own call.
    assert_eq!(on_offer(true, true), OfferDecision::Duplicate);
}

#[clause("PNP-011-MUST-009")]
#[test]
fn a_busy_peer_rejects_and_does_not_ring() {
    assert_eq!(on_offer(false, true), OfferDecision::Busy);
    assert_eq!(on_offer(false, false), OfferDecision::Ring);
    let reject = CallSignal::Reject {
        call_id: "ab".into(),
    };
    assert_eq!(
        serde_json::from_str::<Value>(&reject.to_json()).unwrap(),
        json!({"action": "reject", "callId": "ab"})
    );
}

#[clause("PNP-011-MUST-010")]
#[test]
fn an_unanswered_call_ends_after_sixty_seconds() {
    assert_eq!(call::RING_TIMEOUT, Duration::from_secs(60));
}

#[clause("PNP-011-MUST-011")]
#[test]
fn the_media_connection_has_thirty_seconds_to_come_up() {
    assert_eq!(call::CONNECT_TIMEOUT, Duration::from_secs(30));
}

#[clause("PNP-011-SHOULD-001")]
#[test]
fn early_candidates_are_kept_up_to_sixty_four() {
    assert_eq!(call::MAX_PENDING_CANDIDATES, 64);
    // What is kept is the candidate as signalled.
    let ice = br#"{"action":"ice","callId":"ab","candidate":{"candidate":"candidate:1 1 udp 2122260223 x.local 5000 typ host","sdpMid":"0","sdpMLineIndex":0,"usernameFragment":"u"}}"#;
    match CallSignal::parse(ice) {
        Some(CallSignal::Ice { candidate, .. }) => {
            assert!(candidate.candidate.ends_with("typ host"));
            assert_eq!(candidate.sdp_mid.as_deref(), Some("0"));
        }
        other => panic!("{other:?}"),
    }
}

// ── The media session (section 5): two call connections on loopback ─────────────────────

struct Peer {
    handle: RtcHandle,
    events: Receiver<RtcEvent>,
    descriptions: Vec<RTCSessionDescription>,
    states: Vec<RTCPeerConnectionState>,
    channel: Option<usize>,
    messages: usize,
}

impl Peer {
    async fn new(config: RtcConfig) -> Peer {
        let (handle, events) = parolnet_rtc::spawn(config).await.expect("spawn");
        Peer {
            handle,
            events,
            descriptions: Vec::new(),
            states: Vec::new(),
            channel: None,
            messages: 0,
        }
    }

    fn connected(&self) -> bool {
        self.states.last() == Some(&RTCPeerConnectionState::Connected)
    }
}

/// Two connections with the signaling between them (every description is delivered to the
/// other side, unless `signal` is off).
struct Pair {
    a: Peer,
    b: Peer,
    signal: bool,
}

impl Pair {
    /// A call as the core configures it: `a` calls `b`.
    async fn call(video: bool) -> Pair {
        Pair {
            a: Peer::new(connection_config(video, false, RtcConfig::default())).await,
            b: Peer::new(connection_config(video, true, RtcConfig::default())).await,
            signal: true,
        }
    }

    /// A data connection: `a` offers the channel.
    async fn data() -> Pair {
        Pair {
            a: Peer::new(RtcConfig {
                data_channel: Some("parolnet".into()),
                ..Default::default()
            })
            .await,
            b: Peer::new(RtcConfig {
                polite: true,
                ..Default::default()
            })
            .await,
            signal: true,
        }
    }

    async fn step(&mut self, wait: Duration) {
        let (from_a, event) = tokio::select! {
            e = self.a.events.recv() => (true, e),
            e = self.b.events.recv() => (false, e),
            _ = tokio::time::sleep(wait) => return,
        };
        let (from, to) = if from_a {
            (&mut self.a, &mut self.b)
        } else {
            (&mut self.b, &mut self.a)
        };
        match event.expect("events") {
            RtcEvent::LocalDescription(desc) => {
                from.descriptions.push((*desc).clone());
                if self.signal {
                    to.handle.set_remote_description(*desc).unwrap();
                }
            }
            RtcEvent::ConnectionState(state) => from.states.push(state),
            RtcEvent::DataChannelOpen { id, .. } => from.channel = Some(id),
            RtcEvent::DataChannelMessage { .. } => from.messages += 1,
            RtcEvent::Closed { error } => panic!("closed: {error:?}"),
            _ => {}
        }
    }

    async fn until(&mut self, what: &str, mut done: impl FnMut(&Pair) -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while !done(self) {
            assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
            self.step(Duration::from_millis(50)).await;
        }
    }

    async fn connect(&mut self) {
        self.a.handle.create_offer().unwrap();
        self.until("connecting", |p| p.a.connected() && p.b.connected())
            .await;
    }

    async fn close(self) {
        self.a.handle.close().await;
        self.b.handle.close().await;
    }
}

fn lines<'a>(sdp: &'a str, prefix: &str) -> Vec<&'a str> {
    sdp.lines().filter(|l| l.starts_with(prefix)).collect()
}

fn fingerprints(sdp: &str) -> Vec<&str> {
    lines(sdp, "a=fingerprint:")
}

/// The first offer and answer of a video call and of an audio call.
async fn call_descriptions(video: bool) -> (String, String) {
    let mut pair = Pair::call(video).await;
    pair.connect().await;
    let descriptions = (
        pair.a.descriptions[0].sdp.clone(),
        pair.b.descriptions[0].sdp.clone(),
    );
    assert_eq!(pair.a.descriptions[0].sdp_type, RTCSdpType::Offer);
    assert_eq!(pair.b.descriptions[0].sdp_type, RTCSdpType::Answer);
    pair.close().await;
    descriptions
}

#[clause("PNP-011-MUST-012")]
#[tokio::test]
async fn a_call_has_a_connection_of_its_own_without_a_data_channel() {
    let base = RtcConfig {
        // Whatever the data connection's configuration says, a call opens no channel.
        data_channel: Some("parolnet".into()),
        ..Default::default()
    };
    for (video, incoming) in [(false, false), (true, true)] {
        let config = connection_config(video, incoming, base.clone());
        assert_eq!(config.data_channel, None);
        assert!(config.media.send_opus && config.media.recv_opus);
        assert_eq!(
            (config.media.send_vp8, config.media.recv_vp8),
            (video, video)
        );
        assert_eq!(
            config.polite, incoming,
            "the callee yields when offers cross"
        );
    }
    let (offer, answer) = call_descriptions(true).await;
    for sdp in [&offer, &answer] {
        assert!(lines(sdp, "m=application").is_empty(), "{sdp}");
        assert!(!lines(sdp, "m=audio").is_empty(), "{sdp}");
    }
}

#[clause("PNP-011-MUST-013")]
#[tokio::test]
async fn descriptions_are_dtls_srtp_with_a_sha256_fingerprint_and_no_sdes() {
    let (offer, answer) = call_descriptions(true).await;
    for sdp in [&offer, &answer] {
        let prints = fingerprints(sdp);
        assert!(!prints.is_empty(), "{sdp}");
        for print in prints {
            let value = print.strip_prefix("a=fingerprint:sha-256 ").expect(print);
            assert_eq!(value.split(':').count(), 32, "{print}");
        }
        let media = lines(sdp, "m=");
        assert_eq!(media.len(), 2, "{sdp}");
        for section in media {
            assert!(section.contains(" UDP/TLS/RTP/SAVPF "), "{section}");
        }
        assert!(lines(sdp, "a=crypto").is_empty(), "no SDES keys: {sdp}");
        assert!(!lines(sdp, "a=setup:").is_empty(), "a DTLS role: {sdp}");
    }
    // Each side has its own certificate.
    assert_ne!(fingerprints(&offer), fingerprints(&answer));
}

#[clause("PNP-011-MUST-014")]
#[tokio::test]
async fn media_sections_are_bundled_and_rtcp_is_multiplexed() {
    let (offer, answer) = call_descriptions(true).await;
    for sdp in [&offer, &answer] {
        let group = lines(sdp, "a=group:BUNDLE");
        assert_eq!(group.len(), 1, "{sdp}");
        let mids: Vec<&str> = lines(sdp, "a=mid:")
            .into_iter()
            .map(|l| l.trim_start_matches("a=mid:").trim())
            .collect();
        assert_eq!(mids.len(), 2);
        for mid in mids {
            assert!(
                group[0].split_ascii_whitespace().skip(1).any(|m| m == mid),
                "{mid} in {}",
                group[0]
            );
        }
        // `a=rtcp-mux` itself, not the `a=rtcp-mux-only` (RFC 8858) the engine also writes
        // in new sections of an offer under the `require` policy since v0.22.0+brainwires.6.
        let mux = lines(sdp, "a=rtcp-mux")
            .into_iter()
            .filter(|l| l.trim_end() == "a=rtcp-mux")
            .count();
        assert_eq!(mux, 2, "{sdp}");
    }
}

#[clause("PNP-011-MUST-015")]
#[tokio::test]
async fn audio_is_the_first_section_and_is_opus() {
    for video in [false, true] {
        let (offer, answer) = call_descriptions(video).await;
        for sdp in [&offer, &answer] {
            let media = lines(sdp, "m=");
            assert!(media[0].starts_with("m=audio "), "{media:?}");
            assert!(
                sdp.lines()
                    .any(|l| l.starts_with("a=rtpmap:") && l.ends_with(" opus/48000/2")),
                "{sdp}"
            );
        }
    }
}

#[clause("PNP-011-MUST-016")]
#[tokio::test]
async fn a_video_call_has_one_vp8_section_after_the_audio_and_an_audio_call_none() {
    let (offer, answer) = call_descriptions(true).await;
    for sdp in [&offer, &answer] {
        let media = lines(sdp, "m=");
        assert_eq!(media.len(), 2);
        assert!(media[1].starts_with("m=video "), "{media:?}");
        assert!(
            sdp.lines()
                .any(|l| l.starts_with("a=rtpmap:") && l.ends_with(" VP8/90000")),
            "{sdp}"
        );
    }
    let (offer, answer) = call_descriptions(false).await;
    for sdp in [&offer, &answer] {
        assert!(lines(sdp, "m=video").is_empty(), "{sdp}");
        assert_eq!(lines(sdp, "m=").len(), 1);
    }
}

#[clause("PNP-011-SHOULD-002")]
#[tokio::test]
async fn video_offers_rtx_for_vp8() {
    let (offer, answer) = call_descriptions(true).await;
    for sdp in [&offer, &answer] {
        let payload = |codec: &str| -> String {
            sdp.lines()
                .find(|l| l.starts_with("a=rtpmap:") && l.ends_with(codec))
                .and_then(|l| l.trim_start_matches("a=rtpmap:").split(' ').next())
                .unwrap_or_else(|| panic!("no {codec} in {sdp}"))
                .to_owned()
        };
        let (vp8, rtx) = (payload(" VP8/90000"), payload(" rtx/90000"));
        assert!(
            sdp.lines()
                .any(|l| l.trim() == format!("a=fmtp:{rtx} apt={vp8}")),
            "rtx {rtx} repairs VP8 {vp8}: {sdp}"
        );
    }
    // The offerer announces the retransmission stream's SSRC next to the video's.
    assert!(
        offer.lines().any(|l| l.starts_with("a=ssrc-group:FID ")),
        "{offer}"
    );
}

#[clause("PNP-011-SHOULD-003")]
#[tokio::test]
async fn both_sections_negotiate_transport_wide_feedback() {
    const EXTENSION: &str =
        "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
    let (offer, answer) = call_descriptions(true).await;
    for sdp in [&offer, &answer] {
        // Per media section: the feedback on its codec and the header extension.
        let sections: Vec<&str> = sdp.split("\r\nm=").skip(1).collect();
        assert_eq!(sections.len(), 2);
        for section in sections {
            assert!(
                section
                    .lines()
                    .any(|l| l.starts_with("a=rtcp-fb:") && l.ends_with(" transport-cc")),
                "{section}"
            );
            assert!(
                section
                    .lines()
                    .any(|l| l.starts_with("a=extmap:") && l.ends_with(EXTENSION)),
                "{section}"
            );
        }
    }
}

#[clause("PNP-011-MUST-017")]
#[tokio::test]
async fn a_description_contains_the_candidates_gathered_for_it() {
    let (offer, answer) = call_descriptions(false).await;
    for sdp in [&offer, &answer] {
        let hosts: Vec<&str> = sdp
            .lines()
            .filter(|l| l.starts_with("a=candidate:") && l.contains(" typ host"))
            .collect();
        assert!(!hosts.is_empty(), "{sdp}");
        // The socket the connection bound (the default configuration binds 127.0.0.1).
        assert!(hosts.iter().all(|l| l.contains(" 127.0.0.1 ")), "{hosts:?}");
        assert!(ice_ufrag(sdp).is_some());
    }
}

fn address(interface: &str, ip: &str, prefix_len: u8) -> LocalAddress {
    LocalAddress {
        interface: interface.to_owned(),
        ip: ip.parse().unwrap(),
        prefix_len,
    }
}

fn ips(list: &[&str]) -> Vec<std::net::IpAddr> {
    list.iter().map(|s| s.parse().unwrap()).collect()
}

#[clause("PNP-011-MUST-018")]
#[test]
fn loopback_and_link_local_addresses_are_not_host_candidates() {
    let machine = [
        address("lo0", "127.0.0.1", 8),
        address("lo0", "::1", 128),
        address("lo0", "fe80::1", 64),
        address("en0", "fe80::1c2d:3e4f:5a6b:7c8d", 64),
        address("en0", "169.254.10.3", 16),
        address("en0", "0.0.0.0", 0),
        address("en0", "ff02::1", 8),
        address("en0", "224.0.0.251", 4),
        address("en0", "192.168.1.20", 24),
    ];
    assert_eq!(
        select_addresses(&machine, [None, None]),
        ips(&["192.168.1.20"])
    );
    // The exception: nothing but loopback.
    let alone = [
        address("lo0", "127.0.0.1", 8),
        address("lo0", "::1", 128),
        address("lo0", "fe80::1", 64),
    ];
    assert_eq!(
        select_addresses(&alone, [None, None]),
        ips(&["::1", "127.0.0.1"])
    );
}

#[clause("PNP-011-MUST-019")]
#[test]
fn one_ipv6_address_per_interface_and_prefix_and_not_the_hardware_derived_one() {
    let stable = "2a01:db9:1:2:021e:c2ff:fe9a:4d5e"; // modified EUI-64
    let temporary = "2a01:db9:1:2:b0c1:4a5e:91d3:7f02";
    let older = "2a01:db9:1:2:5d11:8e0a:c477:3b6c";
    let interface = [
        address("en0", stable, 64),
        address("en0", older, 64),
        address("en0", temporary, 64),
    ];
    // The system's source address is the one signalled.
    let preferred = Some(temporary.parse().unwrap());
    assert_eq!(
        select_addresses(&interface, [preferred, None]),
        ips(&[temporary])
    );
    // Without one: an address that is not derived from the hardware address.
    let chosen = select_addresses(&interface, [None, None]);
    assert_eq!(chosen.len(), 1);
    assert_ne!(chosen, ips(&[stable]));
    // The hardware-derived address only when the prefix has no other.
    assert_eq!(
        select_addresses(&[address("en0", stable, 64)], [None, None]),
        ips(&[stable])
    );
    // Another prefix, and another interface, are other networks.
    let two = [
        address("en0", temporary, 64),
        address("en0", "fd00:1:2:3::9", 64),
        address("en1", older, 64),
    ];
    assert_eq!(select_addresses(&two, [None, None]).len(), 3);
}

#[clause("PNP-011-SHOULD-004")]
#[test]
fn the_default_route_comes_first_ipv6_before_ipv4_with_distinct_priorities() {
    let machine = [
        address("utun3", "10.8.0.2", 32),
        address("en0", "192.168.1.20", 24),
        address("en0", "2a01:db9:1:2:b0c1:4a5e:91d3:7f02", 64),
        address("en5", "10.0.0.7", 24),
    ];
    let order = select_addresses(
        &machine,
        [
            Some("2a01:db9:1:2:b0c1:4a5e:91d3:7f02".parse().unwrap()),
            Some("192.168.1.20".parse().unwrap()),
        ],
    );
    assert_eq!(
        order,
        ips(&[
            "2a01:db9:1:2:b0c1:4a5e:91d3:7f02",
            "192.168.1.20",
            "10.8.0.2",
            "10.0.0.7"
        ])
    );
    let host: Vec<u32> = (0..order.len())
        .map(|i| candidate_priority(126, local_preference(i)))
        .collect();
    assert!(host.windows(2).all(|w| w[0] > w[1]), "{host:?}");
    let reflexive = candidate_priority(100, local_preference(0));
    let relayed = candidate_priority(0, local_preference(0));
    assert!(host.iter().all(|p| *p > reflexive) && reflexive > relayed);
}

// ── Renegotiation (section 7) ───────────────────────────────────────────────────────────

#[clause("PNP-011-MUST-020")]
#[test]
fn reoffers_go_only_between_two_peers_that_listed_renegotiate() {
    let listed = vec!["renegotiate".to_owned()];
    assert!(renegotiates(true, &listed));
    assert!(!renegotiates(false, &listed), "we did not list it");
    assert!(!renegotiates(true, &[]), "the peer did not list it");
    assert!(!renegotiates(true, &["Renegotiate".to_owned()]));
    // What that decides: a change of our video with a peer that renegotiates is a reoffer,
    // with any other it is not.
    assert_eq!(
        video_change(true, false, true),
        Some(VideoChange::Renegotiating)
    );
    assert_ne!(
        video_change(false, true, false),
        Some(VideoChange::Renegotiating)
    );
}

#[clause("PNP-011-MUST-021")]
#[test]
fn a_reoffer_for_a_call_that_cannot_be_changed_is_ignored() {
    // (renegotiation, established, over, ours, incoming)
    assert_eq!(
        on_reoffer(true, false, false, false, true),
        ReofferDecision::Ignore
    );
    assert_eq!(
        on_reoffer(true, true, true, false, false),
        ReofferDecision::Ignore
    );
    assert_eq!(
        on_reoffer(false, true, false, false, true),
        ReofferDecision::Ignore
    );
    assert_eq!(
        on_reoffer(false, true, false, true, false),
        ReofferDecision::Ignore
    );
    // A call that is set up and not over takes it.
    for incoming in [false, true] {
        assert_eq!(
            on_reoffer(true, true, false, false, incoming),
            ReofferDecision::Answer
        );
    }
}

#[clause("PNP-011-MUST-022")]
#[tokio::test]
async fn when_reoffers_cross_the_callers_stands_and_the_callee_yields() {
    assert_eq!(
        on_reoffer(true, true, false, true, false),
        ReofferDecision::KeepOurs
    );
    assert_eq!(
        on_reoffer(true, true, false, true, true),
        ReofferDecision::Yield
    );

    // On two call connections: both sides offer before either has the other's.
    let mut pair = Pair::call(false).await;
    pair.connect().await;
    pair.signal = false;
    pair.a.handle.set_sending(MediaKind::Video, true).unwrap();
    pair.b.handle.set_sending(MediaKind::Video, true).unwrap();
    pair.until("both reoffers", |p| {
        p.a.descriptions.len() == 2 && p.b.descriptions.len() == 2
    })
    .await;
    let (caller_offer, callee_offer) = (
        pair.a.descriptions[1].clone(),
        pair.b.descriptions[1].clone(),
    );
    assert_eq!(callee_offer.sdp_type, RTCSdpType::Offer);
    pair.signal = true;
    pair.a.handle.set_remote_description(callee_offer).unwrap();
    pair.b.handle.set_remote_description(caller_offer).unwrap();
    // The callee answers the caller's offer, then offers what it wanted again, and the
    // caller answers that: the caller never answered the offer that crossed.
    pair.until("the callee's answer and its second offer", |p| {
        p.b.descriptions.len() == 4 && p.a.descriptions.len() == 3
    })
    .await;
    let kinds =
        |peer: &Peer| -> Vec<RTCSdpType> { peer.descriptions.iter().map(|d| d.sdp_type).collect() };
    use RTCSdpType::{Answer, Offer};
    assert_eq!(kinds(&pair.a), [Offer, Offer, Answer]);
    assert_eq!(kinds(&pair.b), [Answer, Offer, Answer, Offer]);
    // Both videos are negotiated in the end.
    for sdp in [&pair.a.descriptions[2].sdp, &pair.b.descriptions[3].sdp] {
        assert_eq!(
            media_directions(sdp),
            [(MediaKind::Audio, true), (MediaKind::Video, true)]
        );
    }
    pair.close().await;
}

#[clause("PNP-011-MUST-023", "PNP-011-MUST-024")]
#[tokio::test]
async fn a_media_change_keeps_the_dtls_session_and_the_ice_credentials() {
    let mut pair = Pair::call(false).await;
    pair.connect().await;
    let (first_offer, first_answer) = (
        pair.a.descriptions[0].sdp.clone(),
        pair.b.descriptions[0].sdp.clone(),
    );
    pair.a.handle.set_sending(MediaKind::Video, true).unwrap();
    pair.until("the reoffer and its answer", |p| {
        p.a.descriptions.len() == 2 && p.b.descriptions.len() == 2
    })
    .await;
    let (reoffer, reanswer) = (&pair.a.descriptions[1], &pair.b.descriptions[1]);
    assert_eq!(
        (reoffer.sdp_type, reanswer.sdp_type),
        (RTCSdpType::Offer, RTCSdpType::Answer)
    );
    assert!(reoffer.sdp.contains("m=video"), "the section was added");
    // MUST-023: the same certificates.
    assert!(same_dtls_session(Some(&first_offer), &reoffer.sdp));
    assert!(same_dtls_session(Some(&first_answer), &reanswer.sdp));
    // MUST-024: the same ICE credentials.
    let password = |sdp: &str| lines(sdp, "a=ice-pwd:").first().map(|l| l.to_string());
    assert_eq!(ice_ufrag(&reoffer.sdp), ice_ufrag(&first_offer));
    assert_eq!(password(&reoffer.sdp), password(&first_offer));
    assert_eq!(ice_ufrag(&reanswer.sdp), ice_ufrag(&first_answer));
    assert_eq!(password(&reanswer.sdp), password(&first_answer));
    pair.close().await;
}

#[clause("PNP-011-MUST-025")]
#[test]
fn who_sends_video_is_read_from_the_descriptions_video_section() {
    let sdp = |video: &str| {
        format!(
            "v=0\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\na=sendrecv\r\n{video}"
        )
    };
    let video = |port: u16, direction: &str| {
        format!("m=video {port} UDP/TLS/RTP/SAVPF 96\r\na=mid:1\r\n{direction}")
    };
    let sends = |description: String| -> Option<bool> {
        media_directions(&description)
            .into_iter()
            .find(|(kind, _)| *kind == MediaKind::Video)
            .map(|(_, sending)| sending)
    };
    assert_eq!(sends(sdp("")), None, "no video section");
    assert_eq!(sends(sdp(&video(9, "a=sendrecv\r\n"))), Some(true));
    assert_eq!(sends(sdp(&video(9, "a=sendonly\r\n"))), Some(true));
    assert_eq!(sends(sdp(&video(9, "a=recvonly\r\n"))), Some(false));
    assert_eq!(sends(sdp(&video(9, "a=inactive\r\n"))), Some(false));
    assert_eq!(
        sends(sdp(&video(9, ""))),
        Some(true),
        "no attribute is sendrecv"
    );
    assert_eq!(
        sends(sdp(&video(0, "a=sendrecv\r\n"))),
        Some(false),
        "a rejected section"
    );
    // The audio section is read the same way and independently.
    assert_eq!(
        media_directions(&sdp(&video(9, "a=recvonly\r\n"))),
        [(MediaKind::Audio, true), (MediaKind::Video, false)]
    );
    // `withVideo` says how the call started, not who sends now: a signal has no say.
    let started_with_video = CallSignal::Answer {
        call_id: "ab".into(),
        video: true,
        sdp: sdp(&video(9, "a=recvonly\r\n")),
        features: vec![],
    };
    let CallSignal::Answer { sdp: answer, .. } = started_with_video else {
        unreachable!()
    };
    assert_eq!(sends(answer), Some(false));
}

#[clause("PNP-011-MUST-026")]
#[tokio::test]
async fn an_unanswered_reoffer_is_taken_back_after_ten_seconds_and_the_call_goes_on() {
    assert_eq!(call::REOFFER_TIMEOUT, Duration::from_secs(10));

    let mut pair = Pair::call(false).await;
    pair.connect().await;
    // The peer never answers.
    pair.signal = false;
    pair.a.handle.set_sending(MediaKind::Video, true).unwrap();
    pair.until("the reoffer", |p| p.a.descriptions.len() == 2)
        .await;
    pair.a.handle.rollback().unwrap();
    pair.signal = true;
    // The connection is as it was, and what was asked for is not pending: the next exchange
    // (here an ICE restart from the other side) carries no video.
    pair.b.handle.restart_ice().unwrap();
    pair.until("a later exchange", |p| {
        p.a.descriptions.len() == 3 && p.b.descriptions.len() == 2
    })
    .await;
    let answer = &pair.a.descriptions[2];
    assert_eq!(answer.sdp_type, RTCSdpType::Answer);
    assert!(!answer.sdp.contains("m=video"), "{}", answer.sdp);
    pair.until("connected again", |p| p.a.connected() && p.b.connected())
        .await;
    // Asking again offers it again.
    pair.a.handle.set_sending(MediaKind::Video, true).unwrap();
    pair.until("the second reoffer", |p| p.a.descriptions.len() == 4)
        .await;
    assert!(pair.a.descriptions[3].sdp.contains("m=video"));
    pair.close().await;
}

#[clause("PNP-011-MUST-027")]
#[test]
fn a_call_with_a_peer_that_does_not_renegotiate_stays_as_it_was_set_up() {
    // (renegotiable, we send video, turn it on?)
    assert_eq!(
        video_change(false, false, true),
        None,
        "an audio call stays audio"
    );
    assert_eq!(
        video_change(false, true, false),
        Some(VideoChange::Unchanged),
        "the video stream stays; black is sent"
    );
    assert_eq!(
        video_change(false, true, true),
        Some(VideoChange::Unchanged)
    );
    assert_eq!(
        video_change(false, false, false),
        Some(VideoChange::Unchanged)
    );
    for (local, on) in [(false, true), (true, false), (true, true), (false, false)] {
        assert_eq!(
            video_change(true, local, on),
            Some(VideoChange::Renegotiating)
        );
    }
}

// ── ICE restart (section 8) ─────────────────────────────────────────────────────────────

#[clause("PNP-011-MUST-028", "PNP-011-MUST-029")]
#[tokio::test]
async fn an_ice_restart_has_new_credentials_and_candidates_and_does_not_interrupt_the_session() {
    let mut pair = Pair::data().await;
    pair.connect().await;
    pair.until("the channel", |p| {
        p.a.channel.is_some() && p.b.channel.is_some()
    })
    .await;
    let (first_offer, first_answer) = (
        pair.a.descriptions[0].sdp.clone(),
        pair.b.descriptions[0].sdp.clone(),
    );

    // The restart's offer is made but not delivered yet.
    pair.signal = false;
    pair.a.handle.restart_ice().unwrap();
    pair.until("the restart's offer", |p| p.a.descriptions.len() == 2)
        .await;
    let offer = pair.a.descriptions[1].clone();
    // MUST-029: the session goes on, on the pair it had, while the restart is under way.
    let (a_channel, b_channel) = (pair.a.channel.unwrap(), pair.b.channel.unwrap());
    pair.a.handle.send_data(a_channel, &b"during"[..]).unwrap();
    pair.b.handle.send_data(b_channel, &b"during"[..]).unwrap();
    pair.until("data while the offer is out", |p| {
        p.a.messages == 1 && p.b.messages == 1
    })
    .await;
    pair.signal = true;
    pair.b.handle.set_remote_description(offer.clone()).unwrap();
    pair.until("the restart's answer", |p| p.b.descriptions.len() == 2)
        .await;
    pair.a
        .handle
        .send_data(a_channel, &b"answered"[..])
        .unwrap();
    pair.until("data while the new checks run", |p| p.b.messages == 2)
        .await;
    pair.until("connected on the new generation", |p| {
        p.a.connected() && p.b.connected()
    })
    .await;
    pair.b.handle.send_data(b_channel, &b"after"[..]).unwrap();
    pair.until("data after the restart", |p| p.a.messages == 2)
        .await;

    // MUST-028: new credentials and the candidates gathered for the restart, both ways.
    let answer = &pair.b.descriptions[1];
    let password = |sdp: &str| lines(sdp, "a=ice-pwd:").first().map(|l| l.to_string());
    for (new, old) in [(&offer.sdp, &first_offer), (&answer.sdp, &first_answer)] {
        assert_ne!(ice_ufrag(new), ice_ufrag(old));
        assert_ne!(password(new), password(old));
        assert!(
            new.lines()
                .any(|l| l.starts_with("a=candidate:") && l.contains(" typ host")),
            "{new}"
        );
        // And the same DTLS session.
        assert!(same_dtls_session(Some(old), new));
    }
    assert_eq!(
        (offer.sdp_type, answer.sdp_type),
        (RTCSdpType::Offer, RTCSdpType::Answer)
    );
    pair.close().await;
}

#[clause("PNP-011-MUST-030")]
#[test]
fn ice_restart_of_the_data_connection_is_announced_in_the_identity_frame() {
    assert_eq!(FEATURE_ICE_RESTART, "ice-restart");
    let frame: Value = serde_json::from_str(&DcFrame::identity("ab", true)).unwrap();
    assert_eq!(
        frame,
        json!({"type": "identity", "peerId": "ab", "features": ["ice-restart"]})
    );
    // A peer that does not take restarts sends the PWA's frame.
    let plain: Value = serde_json::from_str(&DcFrame::identity("ab", false)).unwrap();
    assert_eq!(plain, json!({"type": "identity", "peerId": "ab"}));
    let features = |frame: &str| match DcFrame::parse(frame.as_bytes()) {
        DcFrame::Identity { features, .. } => features,
        other => panic!("{other:?}"),
    };
    let listed = features(&DcFrame::identity("ab", true));
    assert!(restarts(true, &listed));
    assert!(!restarts(false, &listed), "we did not list it");
    assert!(!restarts(true, &features(&DcFrame::identity("ab", false))));
    assert!(!restarts(
        true,
        &features(r#"{"type":"identity","peerId":"ab","features":"ice-restart"}"#)
    ));
}

const SESSION: &str = "v=0\r\n\
a=fingerprint:sha-256 3F:0A:91:BC:2E:44:7D:10:EE:5B:C2:89:01:6A:73:FE:12:34:56:78:9A:BC:DE:F0:11:22:33:44:55:66:77:88\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=ice-ufrag:aaaa\r\n";
/// The same certificate (written in lower case, at media level), other ICE credentials.
const SESSION_RESTARTED: &str = "v=0\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=ice-ufrag:bbbb\r\n\
a=fingerprint:sha-256 3f:0a:91:bc:2e:44:7d:10:ee:5b:c2:89:01:6a:73:fe:12:34:56:78:9a:bc:de:f0:11:22:33:44:55:66:77:88\r\n";
const OTHER_SESSION: &str = "v=0\r\n\
a=fingerprint:sha-256 AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=ice-ufrag:cccc\r\n";

#[clause("PNP-011-MUST-031")]
#[test]
fn a_restart_is_applied_only_under_the_fingerprints_the_binding_covers() {
    assert!(same_dtls_session(Some(SESSION), SESSION_RESTARTED));
    assert!(!same_dtls_session(Some(SESSION), OTHER_SESSION));
    assert!(
        !same_dtls_session(None, SESSION_RESTARTED),
        "nothing is bound yet"
    );
    assert!(
        !same_dtls_session(
            Some(SESSION),
            "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
        ),
        "a description without a fingerprint"
    );
    // One fingerprint more than the bound ones is another session too.
    let extra = format!(
        "{SESSION_RESTARTED}{}",
        OTHER_SESSION.lines().nth(1).unwrap()
    );
    assert!(!same_dtls_session(Some(SESSION), &extra));

    // (renegotiation, verified, same session, ours, designated)
    let same = same_dtls_session(Some(SESSION), SESSION_RESTARTED);
    assert_eq!(
        on_restart_offer(true, true, same, false, false),
        RestartOffer::Apply
    );
    // Another certificate, a connection that is not verified, or a peer that does not take
    // restarts: an offer for a new connection, as before restarts existed.
    let other = same_dtls_session(Some(SESSION), OTHER_SESSION);
    for designated in [false, true] {
        for ours in [false, true] {
            assert_eq!(
                on_restart_offer(true, true, other, ours, designated),
                RestartOffer::NewConnection
            );
            assert_eq!(
                on_restart_offer(true, false, same, ours, designated),
                RestartOffer::NewConnection
            );
            assert_eq!(
                on_restart_offer(false, true, same, ours, designated),
                RestartOffer::NewConnection
            );
        }
    }
}

#[clause("PNP-011-MUST-032")]
#[test]
fn when_restarts_cross_the_designated_initiators_stands() {
    // (renegotiation, verified, same session, ours, designated)
    assert_eq!(
        on_restart_offer(true, true, true, true, true),
        RestartOffer::KeepOurs
    );
    assert_eq!(
        on_restart_offer(true, true, true, true, false),
        RestartOffer::Yield
    );
    // Exactly one of two peers is the designated initiator: the lower PeerId.
    let (low, high) = ("0a".repeat(32), "f0".repeat(32));
    assert!(should_initiate(&low, &high));
    assert!(!should_initiate(&high, &low));
}

#[clause("PNP-011-MUST-033")]
#[test]
fn a_restart_has_fifteen_seconds_and_then_the_connection_is_rebuilt_or_kept() {
    assert_eq!(wire::RESTART_TIMEOUT, Duration::from_secs(15));
    // (connected, answered)
    assert_eq!(on_restart_expiry(false, false), RestartExpiry::Rebuild);
    assert_eq!(on_restart_expiry(false, true), RestartExpiry::Rebuild);
    assert_eq!(on_restart_expiry(true, false), RestartExpiry::TakeBack);
    assert_eq!(on_restart_expiry(true, true), RestartExpiry::Done);
}

#[clause("PNP-011-SHOULD-005")]
#[test]
fn a_network_change_is_a_new_address_set_seen_twice() {
    assert_eq!(
        parolnet_rtc::net::DEFAULT_POLL_INTERVAL,
        Duration::from_secs(2)
    );
    let mut watch = ChangeDetector::new(ips(&["192.168.1.20"]));
    assert_eq!(watch.observe(ips(&["192.168.1.20"])), None);
    // Another network: its addresses arrive one at a time; reported once they settle.
    assert_eq!(watch.observe(ips(&[])), None);
    assert_eq!(watch.observe(ips(&["10.20.0.5"])), None);
    assert_eq!(watch.observe(ips(&["2a01:db9::5", "10.20.0.5"])), None);
    assert_eq!(
        watch.observe(ips(&["2a01:db9::5", "10.20.0.5"])),
        Some(ips(&["2a01:db9::5", "10.20.0.5"]))
    );
    // The same set in another order is no change; a blip that reverts is none either.
    assert_eq!(watch.observe(ips(&["10.20.0.5", "2a01:db9::5"])), None);
    assert_eq!(watch.observe(ips(&["10.20.0.5"])), None);
    assert_eq!(watch.observe(ips(&["2a01:db9::5", "10.20.0.5"])), None);
}

// ── Adapting to the path (section 9) and quality (section 10) ───────────────────────────

#[clause("PNP-011-SHOULD-006")]
#[test]
fn a_call_connection_runs_congestion_control_from_300_kbit_between_its_bounds() {
    for video in [false, true] {
        let cc = connection_config(video, false, RtcConfig::default())
            .congestion
            .expect("congestion control on a call connection");
        assert_eq!((cc.min_bps, cc.max_bps), (100_000, 2_500_000));
        assert_eq!(cc.initial_bps(), 300_000);
    }
    // The data connection carries no media and runs none.
    assert_eq!(RtcConfig::default().congestion, None);
}

#[clause("PNP-011-MUST-034")]
#[test]
fn the_video_encoder_gets_nine_tenths_of_what_the_audio_leaves() {
    assert_eq!(call::AUDIO_SHARE_BPS, 80_000);
    assert_eq!(video_bitrate_for(300_000), 198_000);
    assert_eq!(video_bitrate_for(1_080_000), 900_000);
    assert_eq!(video_bitrate_for(2_500_000), 2_178_000);
    // Never above the formula, for any estimate, and never under the floor.
    for estimate in (0..3_000_000u32).step_by(7_919) {
        let video = video_bitrate_for(estimate);
        let formula = u64::from(estimate.saturating_sub(80_000)) * 9 / 10;
        assert_eq!(u64::from(video), formula.max(30_000), "{estimate}");
        assert!(video >= 30_000);
    }
    assert_eq!(
        video_bitrate_for(100_000),
        30_000,
        "at the estimate's floor"
    );
}

#[clause("PNP-011-SHOULD-007")]
#[test]
fn received_audio_is_delivered_in_order_at_the_pace_it_was_sent() {
    assert!(connection_config(false, true, RtcConfig::default()).jitter_buffer);
    assert!(!RtcConfig::default().jitter_buffer);

    // Packets sent every 20 ms that arrive 30 to 110 ms later, overtaking each other.
    let start = std::time::Instant::now();
    let mut buffer = AudioJitterBuffer::new(48_000);
    let mut arrivals: Vec<(u64, u16)> = (0..300u64)
        .map(|i| (i * 20 + 30 + (i * 37) % 81, i as u16))
        .collect();
    arrivals.sort();
    let (mut next, mut out) = (0, Vec::new());
    for ms in 0..7_000u64 {
        let now = start + Duration::from_millis(ms);
        while next < arrivals.len() && arrivals[next].0 == ms {
            let mut packet = parolnet_rtc::rtc::rtp::Packet::default();
            packet.header.sequence_number = arrivals[next].1;
            packet.header.timestamp = u32::from(arrivals[next].1) * 960;
            buffer.push(now, packet);
            next += 1;
        }
        while let Some(packet) = buffer.pop(now) {
            out.push((packet.header.sequence_number, ms));
        }
    }
    assert!(out.windows(2).all(|w| w[1].0 > w[0].0), "in sequence order");
    // Once it has seen how late packets get: nothing is missing and the pace is the
    // sender's.
    let settled: Vec<&(u16, u64)> = out.iter().filter(|(seq, _)| *seq >= 50).collect();
    assert_eq!(settled.len(), 250);
    for pair in settled.windows(2) {
        let apart = pair[1].1 - pair[0].1;
        assert!((15..=25).contains(&apart), "{apart} ms between packets");
    }
    assert!(
        buffer.hold() >= Duration::from_millis(75),
        "{:?}",
        buffer.hold()
    );
    // A packet that comes after its successors were delivered is given up.
    let late = buffer.late_drops();
    let mut packet = parolnet_rtc::rtc::rtp::Packet::default();
    packet.header.sequence_number = 100;
    packet.header.timestamp = 100 * 960;
    buffer.push(start + Duration::from_secs(8), packet);
    assert_eq!(buffer.late_drops(), late + 1);
    assert!(buffer.pop(start + Duration::from_secs(9)).is_none());
}

fn quality(
    rtt_ms: u32,
    loss_sent: f32,
    loss_received: f32,
    available_bps: u32,
) -> ConnectionQuality {
    ConnectionQuality {
        rtt_ms: Some(rtt_ms),
        loss_sent: Some(loss_sent),
        loss_received: Some(loss_received),
        available_bps: Some(available_bps),
        ..Default::default()
    }
}

#[clause("PNP-011-SHOULD-008")]
#[test]
fn quality_is_reported_every_second_and_weak_means_loss_delay_or_little_bandwidth() {
    assert_eq!(call::QUALITY_INTERVAL, Duration::from_secs(1));
    assert_eq!(
        connection_config(true, false, RtcConfig::default()).quality_interval,
        Some(Duration::from_secs(1))
    );
    assert!(weaknesses(&quality(60, 0.01, 0.0, 900_000)).is_empty());
    // At the thresholds: not weak. Beyond them: weak.
    assert!(weaknesses(&quality(400, 0.05, 0.05, 200_000)).is_empty());
    assert_eq!(
        weaknesses(&quality(60, 0.051, 0.0, 900_000)),
        [Weakness::Loss]
    );
    assert_eq!(
        weaknesses(&quality(60, 0.0, 0.2, 900_000)),
        [Weakness::Loss],
        "either direction"
    );
    assert_eq!(
        weaknesses(&quality(401, 0.0, 0.0, 900_000)),
        [Weakness::Delay]
    );
    assert_eq!(
        weaknesses(&quality(60, 0.0, 0.0, 199_999)),
        [Weakness::Bandwidth]
    );
    assert_eq!(
        weaknesses(&quality(900, 0.3, 0.0, 100_000)),
        [Weakness::Loss, Weakness::Delay, Weakness::Bandwidth]
    );
    // Nothing measured yet is not weak.
    assert!(weaknesses(&ConnectionQuality::default()).is_empty());
}

#[clause("PNP-011-MAY-001")]
#[test]
fn a_fine_connection_says_nothing_and_a_weak_one_one_line() {
    assert_eq!(
        CallQuality::new(quality(60, 0.0, 0.0, 900_000)).summary(),
        None
    );
    let weak = CallQuality::new(quality(700, 0.09, 0.0, 150_000));
    let line = weak.summary().expect("a line");
    assert!(!line.contains('\n'));
    assert_eq!(
        line,
        "Weak connection: packets are being lost, long delay, low bandwidth"
    );
    assert_eq!(
        weak.weak,
        [Weakness::Loss, Weakness::Delay, Weakness::Bandwidth]
    );
}
