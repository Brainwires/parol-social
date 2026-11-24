//! SRTP re-keying of a relay-only call through the in-process test TURN server: a new DTLS
//! association runs on a new 3-tuple (RFC 8842 section 5.1), so each side allocates a new
//! relayed address for it, and releases the previous one once the new pair carries the call.

mod support;

use std::time::Duration;

use parolnet_rtc::rtci::srtp::keying::KeyLifetime;
use parolnet_rtc::test_turn::TestTurnServer;
use parolnet_rtc::{IcePolicy, MediaConfig, MediaKind, RtcConfig, TurnServer, tls_id};
use support::Pair;

const USER: &str = "pat";
const PASS: &str = "a long test password";

/// A relay-only call peer; `sends` sends audio and video, the other only receives.
fn relay_only_call(
    server: &TestTurnServer,
    sends: bool,
    lifetime: Option<KeyLifetime>,
) -> RtcConfig {
    RtcConfig {
        turn: Some(TurnServer {
            uri: server.uri(),
            username: USER.into(),
            password: PASS.into(),
        }),
        ice_policy: IcePolicy::Relay,
        media: MediaConfig {
            recv_opus: true,
            send_opus: sends,
            recv_vp8: true,
            send_vp8: sends,
        },
        polite: !sends,
        srtp_key_lifetime: lifetime,
        ..Default::default()
    }
}

/// The relay candidates of a description, as `address:port`.
fn relayed(sdp: &str) -> Vec<String> {
    let mut found: Vec<String> = sdp
        .lines()
        .filter_map(|l| l.trim().strip_prefix("a=candidate:"))
        .filter(|l| l.contains("typ relay"))
        .map(|l| {
            let f: Vec<&str> = l.split_ascii_whitespace().collect();
            format!("{}:{}", f[4], f[5])
        })
        .collect();
    found.sort();
    found.dedup();
    found
}

/// Audio and video frames from `a` for `millis`.
async fn feed(pair: &mut Pair, millis: u64) {
    for _ in 0..millis / 20 {
        pair.a
            .handle
            .send_frame(MediaKind::Audio, vec![0xf8u8; 60], 960)
            .unwrap();
        pair.a
            .handle
            .send_frame(MediaKind::Video, vec![0x10u8; 2500], 1800)
            .unwrap();
        pair.settle(20).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_only_call_re_keys_on_new_allocations() {
    // The driver's own log (debug), shown when the test fails.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();
    let server = TestTurnServer::start(USER, PASS).await.unwrap();
    // About 180 packets a second from `a`: its key nears its end (15/16 of 9600) after about
    // 50 s, and the last 600 packets leave about 3 s for the re-keying. Through the TURN
    // server a new ICE generation takes about 2 s to select a pair (the first exchange did
    // too: the peer's first checks reach an allocation before it has a permission for the
    // sender); with 1600 packets the old key ran out after 0.55 s, first.
    let lifetime = KeyLifetime {
        srtp_packets: 9_600,
        ..KeyLifetime::MAX
    };
    let mut pair = Pair::new(
        relay_only_call(&server, true, Some(lifetime)),
        relay_only_call(&server, false, None),
    )
    .await;
    pair.connect().await;
    assert_eq!(server.allocations_made(), 2);
    let first = (
        relayed(&pair.a.seen.descriptions[0].sdp),
        relayed(&pair.b.seen.descriptions[0].sdp),
    );

    // Media until `a` has re-keyed and the call runs on the new association.
    let renewed = |p: &Pair| {
        let ids: Vec<Option<&str>> =
            p.a.seen
                .descriptions
                .iter()
                .map(|d| tls_id(&d.sdp))
                .collect();
        ids.windows(2).any(|w| w[0] != w[1])
    };
    for _ in 0..180 {
        feed(&mut pair, 500).await;
        if renewed(&pair) {
            break;
        }
    }
    assert!(
        renewed(&pair),
        "no re-keying offer: {:?}",
        pair.a.seen.descriptions.len()
    );
    let video_at_renewal = pair.b.seen.rtp_of(MediaKind::Video);
    // The previous sockets and allocations close 5 s after the new pair is selected.
    feed(&mut pair, 7_000).await;

    // Both sides allocated anew (the offerer of the re-keying and the answerer), and their
    // later descriptions name only the new relayed addresses.
    assert_eq!(server.allocations_made(), 4, "a new allocation per side");
    let a_last = relayed(&pair.a.seen.descriptions.last().unwrap().sdp);
    let b_last = relayed(&pair.b.seen.descriptions.last().unwrap().sdp);
    assert_eq!(a_last.len(), 1, "{a_last:?}");
    assert_eq!(b_last.len(), 1, "{b_last:?}");
    assert_ne!(a_last, first.0, "a's relayed address is new");
    assert_ne!(b_last, first.1, "b's relayed address is new");
    // The call went on through it, and the previous allocations were released.
    assert!(pair.a.seen.connected() && pair.b.seen.connected());
    assert!(
        pair.b.seen.rtp_of(MediaKind::Video) > video_at_renewal + 100,
        "video after the re-keying: {} then {}",
        video_at_renewal,
        pair.b.seen.rtp_of(MediaKind::Video)
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while server.live_allocations() > 2 && tokio::time::Instant::now() < deadline {
        pair.settle(100).await;
    }
    assert_eq!(
        server.live_allocations(),
        2,
        "the previous allocations are released"
    );
    pair.close().await;
}
