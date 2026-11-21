//! Relay candidates from a user-supplied TURN server: two drivers through the in-process
//! test TURN server (`parolnet_rtc::test_turn`), and the failure modes of relay-only.
//!
//! `relay_only_through_an_external_turn_server` runs the same exchange against a real TURN
//! server (coturn in the CI job `turn-coturn`) when `PAROLNET_TEST_TURN_URI`,
//! `PAROLNET_TEST_TURN_USER` and `PAROLNET_TEST_TURN_PASS` are set, binding to
//! `PAROLNET_TEST_BIND_IP` (default loopback); with `PAROLNET_TEST_TURN_REQUIRED` a missing
//! URI fails instead of skipping.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use parolnet_rtc::rtc::peer_connection::sdp::RTCSessionDescription;
use parolnet_rtc::test_turn::TestTurnServer;
use parolnet_rtc::{IcePolicy, RtcConfig, RtcError, RtcEvent, RtcHandle, TurnServer, spawn};
use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;

const USER: &str = "pat";
const PASS: &str = "a long test password";

fn turn(server: &TestTurnServer) -> TurnServer {
    TurnServer {
        uri: server.uri(),
        username: USER.into(),
        password: PASS.into(),
    }
}

fn relay_only(turn: TurnServer, data_channel: bool) -> RtcConfig {
    RtcConfig {
        turn: Some(turn),
        ice_policy: IcePolicy::Relay,
        data_channel: data_channel.then(|| "pn-turn".to_owned()),
        ..Default::default()
    }
}

async fn description(events: &mut Receiver<RtcEvent>) -> RTCSessionDescription {
    loop {
        match events.recv().await.expect("events") {
            RtcEvent::LocalDescription(desc) => return *desc,
            RtcEvent::Closed { error } => panic!("closed before describing: {error:?}"),
            _ => {}
        }
    }
}

async fn open(events: &mut Receiver<RtcEvent>) -> usize {
    loop {
        match events.recv().await.expect("events") {
            RtcEvent::DataChannelOpen { id, .. } => return id,
            RtcEvent::Closed { error } => panic!("closed before open: {error:?}"),
            _ => {}
        }
    }
}

async fn message(events: &mut Receiver<RtcEvent>) -> Vec<u8> {
    loop {
        match events.recv().await.expect("events") {
            RtcEvent::DataChannelMessage { payload, .. } => return payload.to_vec(),
            RtcEvent::Closed { error } => panic!("closed before message: {error:?}"),
            _ => {}
        }
    }
}

/// The distinct candidates of an SDP as (address, port, type). (The engine writes each one
/// for the RTP and the RTCP component.)
fn candidates(sdp: &str) -> Vec<(String, u16, String)> {
    let mut found: Vec<(String, u16, String)> = sdp
        .lines()
        .filter_map(|l| l.trim().strip_prefix("a=candidate:"))
        .map(|l| {
            let f: Vec<&str> = l.split_ascii_whitespace().collect();
            (f[4].to_owned(), f[5].parse().unwrap(), f[7].to_owned())
        })
        .collect();
    found.sort();
    found.dedup();
    found
}

/// Offer / answer, then one data-channel message each way. Returns both descriptions.
async fn exchange(
    offerer: &RtcHandle,
    offerer_events: &mut Receiver<RtcEvent>,
    answerer: &RtcHandle,
    answerer_events: &mut Receiver<RtcEvent>,
) -> (String, String) {
    offerer.create_offer().unwrap();
    let offer = description(offerer_events).await;
    let offer_sdp = offer.sdp.clone();
    answerer.set_remote_description(offer).unwrap();
    let answer = description(answerer_events).await;
    let answer_sdp = answer.sdp.clone();
    offerer.set_remote_description(answer).unwrap();

    let offerer_channel = open(offerer_events).await;
    let answerer_channel = open(answerer_events).await;
    offerer
        .send_data(offerer_channel, &b"through the relay"[..])
        .unwrap();
    assert_eq!(message(answerer_events).await, b"through the relay");
    answerer.send_text(answerer_channel, "and back").unwrap();
    assert_eq!(message(offerer_events).await, b"and back");
    (offer_sdp, answer_sdp)
}

async fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    for _ in 0..200 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_only_on_both_sides_goes_through_the_turn_server() {
    let server = TestTurnServer::start(USER, PASS).await.unwrap();
    let (a, mut a_events) = spawn(relay_only(turn(&server), true)).await.expect("a");
    let (b, mut b_events) = spawn(relay_only(turn(&server), false)).await.expect("b");
    assert_eq!(server.live_allocations(), 2);
    let (a_relayed, b_relayed) = (a.relayed_addr().unwrap(), b.relayed_addr().unwrap());

    let (offer, answer) = timeout(
        Duration::from_secs(30),
        exchange(&a, &mut a_events, &b, &mut b_events),
    )
    .await
    .expect("relayed exchange timed out");

    // Each description names the relayed address and nothing else: no host or
    // server-reflexive candidate, no socket port, no related address.
    for (sdp, handle, relayed) in [(&offer, &a, a_relayed), (&answer, &b, b_relayed)] {
        let found = candidates(sdp);
        assert_eq!(
            found,
            vec![(relayed.ip().to_string(), relayed.port(), "relay".to_owned())],
            "{sdp}"
        );
        assert!(
            !sdp.contains(&format!(" {} ", handle.local_addr().port())),
            "the socket's port is in the description: {sdp}"
        );
        assert!(sdp.contains("raddr 0.0.0.0 rport 0"), "{sdp}");
    }
    assert!(
        server.relayed_datagrams() > 20,
        "ICE, DTLS and SCTP went through the relay"
    );

    // Closing releases the allocations on the server.
    a.close().await;
    b.close().await;
    wait_until("the allocations to be released", || {
        server.live_allocations() == 0
    })
    .await;
    assert_eq!(server.allocations_made(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_only_peer_reaches_a_direct_peer() {
    let server = TestTurnServer::start(USER, PASS).await.unwrap();
    let (a, mut a_events) = spawn(relay_only(turn(&server), true)).await.expect("a");
    let (b, mut b_events) = spawn(RtcConfig::default()).await.expect("b");
    let before = server.relayed_datagrams();
    timeout(
        Duration::from_secs(30),
        exchange(&a, &mut a_events, &b, &mut b_events),
    )
    .await
    .expect("exchange timed out");
    assert!(server.relayed_datagrams() > before + 20);
    a.close().await;
    b.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_allocation_is_refreshed_while_the_connection_lives() {
    let server = TestTurnServer::start(USER, PASS).await.unwrap();
    let config = |data_channel: bool| RtcConfig {
        turn_keepalive: Duration::from_secs(1),
        ..relay_only(turn(&server), data_channel)
    };
    let (a, mut a_events) = spawn(config(true)).await.expect("a");
    let (b, mut b_events) = spawn(config(false)).await.expect("b");
    a.create_offer().unwrap();
    let offer = description(&mut a_events).await;
    b.set_remote_description(offer).unwrap();
    a.set_remote_description(description(&mut b_events).await)
        .unwrap();
    let channel = timeout(Duration::from_secs(30), open(&mut a_events))
        .await
        .unwrap();
    open(&mut b_events).await;

    // Both allocations are refreshed (every second here) and keep relaying.
    wait_until("refreshes", || server.refreshes() >= 4).await;
    assert_eq!(server.live_allocations(), 2);
    a.send_text(channel, "still relayed").unwrap();
    let got = timeout(Duration::from_secs(10), message(&mut b_events))
        .await
        .unwrap();
    assert_eq!(got, b"still relayed");
    a.close().await;
    b.close().await;
    wait_until("release", || server.live_allocations() == 0).await;
}

#[tokio::test]
async fn policy_all_adds_the_relay_candidate_to_the_direct_ones() {
    let server = TestTurnServer::start(USER, PASS).await.unwrap();
    let (a, mut a_events) = spawn(RtcConfig {
        turn: Some(turn(&server)),
        data_channel: Some("pn-turn".into()),
        ..Default::default()
    })
    .await
    .expect("a");
    a.create_offer().unwrap();
    let offer = timeout(Duration::from_secs(10), description(&mut a_events))
        .await
        .unwrap();
    let found = candidates(&offer.sdp);
    let relayed = a.relayed_addr().unwrap();
    assert!(found.contains(&("127.0.0.1".into(), a.local_addr().port(), "host".into())));
    assert!(found.contains(&(relayed.ip().to_string(), relayed.port(), "relay".into())));
    a.close().await;
    wait_until("release", || server.live_allocations() == 0).await;
}

#[tokio::test]
async fn a_wrong_password_fails_relay_only_and_only_costs_the_candidate_otherwise() {
    let server = TestTurnServer::start(USER, PASS).await.unwrap();
    let mut wrong = turn(&server);
    wrong.password = "not the password".into();
    let err = match spawn(relay_only(wrong.clone(), true)).await {
        Err(e) => e,
        Ok(_) => panic!("relay-only started without an allocation"),
    };
    assert!(matches!(err, RtcError::Turn(_)), "{err:?}");
    assert!(!err.to_string().contains("not the password"), "{err}");
    assert_eq!(server.live_allocations(), 0);
    assert!(server.refused_requests() >= 2);

    let (a, mut a_events) = spawn(RtcConfig {
        turn: Some(wrong),
        data_channel: Some("pn-turn".into()),
        ..Default::default()
    })
    .await
    .expect("policy `all` starts without the relay candidate");
    assert_eq!(a.relayed_addr(), None);
    a.create_offer().unwrap();
    let offer = description(&mut a_events).await;
    assert!(
        candidates(&offer.sdp)
            .iter()
            .all(|(_, _, typ)| typ == "host")
    );
    a.close().await;
}

#[tokio::test]
async fn relay_only_without_a_reachable_turn_server_does_not_start() {
    // Nothing configured.
    let err = spawn(RtcConfig {
        ice_policy: IcePolicy::Relay,
        ..Default::default()
    })
    .await
    .err()
    .expect("refused");
    assert!(matches!(err, RtcError::Turn(_)), "{err:?}");

    // A server that never answers.
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut config = relay_only(
        TurnServer {
            uri: format!("turn:{}", silent.local_addr().unwrap()),
            username: USER.into(),
            password: PASS.into(),
        },
        true,
    );
    config.turn_timeout = Duration::from_millis(700);
    let started = std::time::Instant::now();
    let err = spawn(config).await.err().expect("no allocation");
    assert!(matches!(err, RtcError::Turn(_)), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(5));

    // TCP and TLS are refused by name, not attempted.
    for uri in ["turn:127.0.0.1:3478?transport=tcp", "turns:127.0.0.1:5349"] {
        let err = spawn(relay_only(
            TurnServer {
                uri: uri.into(),
                username: USER.into(),
                password: PASS.into(),
            },
            true,
        ))
        .await
        .err()
        .expect("refused");
        assert!(matches!(err, RtcError::TurnUri(_)), "{uri}: {err:?}");
    }
}

/// Against a real TURN server (coturn in CI); skipped without `PAROLNET_TEST_TURN_URI`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_only_through_an_external_turn_server() {
    let Ok(uri) = std::env::var("PAROLNET_TEST_TURN_URI") else {
        // The CI job that starts coturn sets this so a lost variable cannot pass as a skip.
        assert!(
            std::env::var_os("PAROLNET_TEST_TURN_REQUIRED").is_none(),
            "PAROLNET_TEST_TURN_REQUIRED is set but PAROLNET_TEST_TURN_URI is not"
        );
        eprintln!("PAROLNET_TEST_TURN_URI is not set: skipping the external TURN test");
        return;
    };
    let server = TurnServer {
        uri,
        username: std::env::var("PAROLNET_TEST_TURN_USER").expect("PAROLNET_TEST_TURN_USER"),
        password: std::env::var("PAROLNET_TEST_TURN_PASS").expect("PAROLNET_TEST_TURN_PASS"),
    };
    let bind_ip: IpAddr = std::env::var("PAROLNET_TEST_BIND_IP")
        .ok()
        .map(|ip| ip.parse().expect("PAROLNET_TEST_BIND_IP"))
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));
    let config = |data_channel: bool| RtcConfig {
        bind: SocketAddr::new(bind_ip, 0),
        ..relay_only(server.clone(), data_channel)
    };
    let (a, mut a_events) = spawn(config(true)).await.expect("a: allocation");
    let (b, mut b_events) = spawn(config(false)).await.expect("b: allocation");
    let (offer, answer) = timeout(
        Duration::from_secs(40),
        exchange(&a, &mut a_events, &b, &mut b_events),
    )
    .await
    .expect("relayed exchange timed out");
    for sdp in [&offer, &answer] {
        let found = candidates(sdp);
        assert_eq!(found.len(), 1, "{sdp}");
        assert_eq!(found[0].2, "relay", "{sdp}");
    }
    a.close().await;
    b.close().await;
}
