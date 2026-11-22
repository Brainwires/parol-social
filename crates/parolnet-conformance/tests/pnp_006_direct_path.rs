//! PNP-006 as the shipped client applies it to what it sends: the real headless client
//! (`parolnet-app`) against the real relay binary and a scripted peer holding the other end
//! of its direct data channel (see `common`). What leaves the client is observed on that
//! channel, with the time each envelope arrived.
//!
//! These tests run in real time: the client's connection is real WebRTC over loopback.

mod common;

use std::time::Duration;

use common::{App, RawPeer, Relay, unique_dir};
use parolnet_app::{
    AppConfig, AppEvent, AppHandle, BandwidthMode, DeliveryState, PathState, RelayState,
};
use parolnet_clause::clause;
use parolnet_core::envelope::decrypt_from_envelope;
use parolnet_rtc::RtcEvent;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::Instant;

const TEXT: u8 = 0x01;
const CHANNEL_BINDING: u8 = 0x14;

fn is_path(ev: &AppEvent, want: PathState) -> bool {
    matches!(ev, AppEvent::Path { state, .. } if *state == want)
}

type Events = UnboundedReceiver<AppEvent>;

/// The next event matching `pred`.
async fn wait(
    events: &mut Events,
    what: &str,
    secs: u64,
    mut pred: impl FnMut(&AppEvent) -> bool,
) -> AppEvent {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        match tokio::time::timeout_at(deadline, events.recv()).await {
            Ok(Some(ev)) if pred(&ev) => return ev,
            Ok(Some(_)) => {}
            Ok(None) => panic!("event channel closed while waiting for {what}"),
            Err(_) => panic!("timed out after {secs}s waiting for {what}"),
        }
    }
}

/// Complete the pairing on the channel both ways: afterwards the app shows the path as
/// direct and sends content.
async fn verify(app: &mut Events, peer: &mut RawPeer) {
    peer.send_bootstrap();
    wait(app, "the contact", 20, |e| {
        matches!(e, AppEvent::ContactAdded(_))
    })
    .await;
    let got = peer
        .receive(Duration::from_secs(20), |d| d.msg_type == CHANNEL_BINDING)
        .await;
    assert_eq!(got.len(), 1, "the app's binding");
    let ours = peer.binding().encode();
    peer.send(CHANNEL_BINDING, &ours);
    wait(app, "a direct path", 20, |e| is_path(e, PathState::Direct)).await;
}

/// The next `n` TEXT envelopes the app sends, each with the moment it arrived.
async fn texts(peer: &mut RawPeer, n: usize, secs: u64) -> Vec<(Instant, String)> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut out = Vec::new();
    while out.len() < n {
        let ev = tokio::time::timeout_at(deadline, peer.events.recv())
            .await
            .unwrap_or_else(|_| panic!("only {} of {n} messages arrived in {secs} s", out.len()))
            .expect("the connection is up");
        let RtcEvent::DataChannelMessage { payload, .. } = ev else {
            continue;
        };
        let at = Instant::now();
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&payload) else {
            continue;
        };
        if v["type"] != "chat" {
            continue;
        }
        let bytes = hex::decode(v["payload"].as_str().unwrap()).unwrap();
        let d = decrypt_from_envelope(&mut peer.session, &bytes).expect("decrypts");
        if d.msg_type == TEXT {
            out.push((at, String::from_utf8(d.plaintext).unwrap()));
        }
    }
    out
}

fn gaps(arrivals: &[(Instant, String)]) -> Vec<Duration> {
    arrivals.windows(2).map(|w| w[1].0 - w[0].0).collect()
}

/// Send `n` messages as fast as the app takes them and return how they arrived.
async fn burst(app: &AppHandle, peer: &mut RawPeer, tag: &str, n: usize) -> Vec<(Instant, String)> {
    let to = peer.id.peer_id.clone();
    for i in 0..n {
        let msg = app.send_text(&to, &format!("{tag}{i}")).await.unwrap();
        assert_eq!(
            msg.state,
            DeliveryState::Queued,
            "a message waits for its send slot"
        );
    }
    let arrivals = texts(peer, n, 60).await;
    let order: Vec<String> = arrivals.iter().map(|(_, t)| t.clone()).collect();
    let sent: Vec<String> = (0..n).map(|i| format!("{tag}{i}")).collect();
    assert_eq!(order, sent, "the queue is served in the order of sending");
    arrivals
}

// §4.2 on the direct path. The user sends eight messages at once; the client does not put
// them on the channel at once. They leave one per send slot, at the padding rate of the
// mode in force (NORMAL, the default: one per 500 ms plus up to 100 ms of jitter), in the
// order they were sent.
#[clause("PNP-006-MUST-007", "PNP-006-MUST-008", "PNP-006-MUST-009")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_of_messages_leaves_the_client_at_the_padding_rate() {
    let relay = Relay::start(&[]).await;
    let mut app = App::start(&relay).await;
    let code = app.handle.create_pairing_code().await.unwrap();
    let mut peer = RawPeer::connect(&relay, &code).await;
    verify(&mut app.events, &mut peer).await;

    let n = 8;
    let sent_at = Instant::now();
    let arrivals = burst(&app.handle, &mut peer, "burst", n).await;
    let span = arrivals[n - 1].0 - arrivals[0].0;
    // Seven intervals of 500 to 600 ms. The bounds leave room for a loaded machine, and
    // still tell this from "all at once" (no span) by seconds.
    assert!(
        span >= Duration::from_millis(7 * 500 - 300),
        "eight messages arrived within {span:?}: they were not spread over the padding rate"
    );
    assert!(
        span <= Duration::from_millis(7 * 600 + 2500),
        "eight messages took {span:?}: slower than the padding rate"
    );
    for gap in gaps(&arrivals) {
        assert!(
            gap >= Duration::from_millis(250),
            "two messages {gap:?} apart: two sends in one slot"
        );
    }
    // The app tells the user as each one leaves.
    let mut marked = 0;
    while marked < n {
        app.wait("a message marked sent", 20, |e| {
            matches!(
                e,
                AppEvent::MessageState {
                    state: DeliveryState::Sent,
                    ..
                }
            )
        })
        .await;
        marked += 1;
    }
    assert!(sent_at.elapsed() >= Duration::from_secs(3));
}

/// A client on `relay` whose data lives in `dir` (so that it can be started again).
async fn start_in(dir: &std::path::Path, relay: &Relay) -> (AppHandle, Events) {
    let mut cfg = AppConfig::new(dir.join("data"), relay.ws_url());
    cfg.stun_servers = Some(Vec::new());
    cfg.bind_ip = Some("127.0.0.1".parse().unwrap());
    let (handle, mut events) = parolnet_app::start(cfg).await.expect("start app");
    wait(&mut events, "registered", 20, |e| {
        matches!(e, AppEvent::Relay(RelayState::Registered { .. }))
    })
    .await;
    (handle, events)
}

// §3 and §6.6 in the client. A fresh client is in NORMAL mode. The user can choose LOW,
// NORMAL or HIGH (and nothing else); the choice changes the rate at which the client's
// messages leave, is remembered across a restart, and each time the client says what the
// mode costs in bandwidth, both as the answer to the choice and as a notice.
#[clause(
    "PNP-006-MUST-001",
    "PNP-006-MUST-002",
    "PNP-006-MUST-003",
    "PNP-006-MUST-042",
    "PNP-006-MUST-043"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_user_selects_the_bandwidth_mode_and_is_told_its_cost() {
    let relay = Relay::start(&[]).await;
    let dir = unique_dir("app-modes");
    let (app, mut events) = start_in(&dir, &relay).await;

    // MUST-003 / MUST-043: nobody chose anything yet.
    assert_eq!(app.bandwidth_mode().await.unwrap(), BandwidthMode::Normal);
    assert_eq!(
        app.snapshot().await.unwrap().bandwidth_mode,
        BandwidthMode::Normal
    );

    // MUST-042: each mode's warning names the mode and its bandwidth, and reaches the user.
    for (mode, kb, name) in [
        (BandwidthMode::Low, "2 KB/s", "LOW"),
        (BandwidthMode::Normal, "8 KB/s", "NORMAL"),
        (BandwidthMode::High, "40 KB/s", "HIGH"),
    ] {
        let warning = app.set_bandwidth_mode(mode).await.unwrap();
        assert!(
            warning.contains(kb) && warning.contains(name),
            "{mode:?}: the warning does not state the mode's bandwidth: {warning}"
        );
        assert_eq!(app.bandwidth_mode().await.unwrap(), mode);
        let notice = wait(&mut events, "the bandwidth notice", 10, |e| {
            matches!(e, AppEvent::Notice(_))
        })
        .await;
        assert!(matches!(notice, AppEvent::Notice(text) if text == warning));
    }
    // The three warnings are three different texts: one per mode, not one for all.
    let high = BandwidthMode::High.bandwidth_warning();
    assert_ne!(high, BandwidthMode::Low.bandwidth_warning());
    assert!(
        high.contains("metered"),
        "HIGH says what it means on a metered connection: {high}"
    );
    // The call mode is not the user's to choose.
    assert!(
        app.set_bandwidth_mode(BandwidthMode::MediaCall)
            .await
            .is_err()
    );
    assert_eq!(app.bandwidth_mode().await.unwrap(), BandwidthMode::High);

    // MUST-001 / MUST-002: the choice is what the client then does. In HIGH mode six
    // messages leave 100 to 130 ms apart; in LOW mode three leave 2 to 2.5 s apart.
    let code = app.create_pairing_code().await.unwrap();
    let mut peer = RawPeer::connect(&relay, &code).await;
    verify(&mut events, &mut peer).await;

    let high = burst(&app, &mut peer, "high", 6).await;
    let span = high[5].0 - high[0].0;
    assert!(
        span >= Duration::from_millis(5 * 100 - 100) && span <= Duration::from_millis(1900),
        "HIGH: six messages over {span:?}; the mode's rate is one per 100 to 130 ms"
    );

    app.set_bandwidth_mode(BandwidthMode::Normal).await.unwrap();
    let normal = burst(&app, &mut peer, "normal", 5).await;
    let span = normal[4].0 - normal[0].0;
    assert!(
        span >= Duration::from_millis(4 * 500 - 200) && span <= Duration::from_millis(4500),
        "NORMAL: five messages over {span:?}; the mode's rate is one per 500 to 600 ms"
    );

    app.set_bandwidth_mode(BandwidthMode::Low).await.unwrap();
    let low = burst(&app, &mut peer, "low", 3).await;
    let span = low[2].0 - low[0].0;
    assert!(
        span >= Duration::from_millis(2 * 2000 - 200) && span <= Duration::from_millis(7500),
        "LOW: three messages over {span:?}; the mode's rate is one per 2 to 2.5 s"
    );

    // MUST-002: the choice outlives the process.
    peer.disconnect().await;
    app.shutdown().await;
    drop(events);
    let (app, _events) = start_in(&dir, &relay).await;
    assert_eq!(app.bandwidth_mode().await.unwrap(), BandwidthMode::Low);
    app.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}
