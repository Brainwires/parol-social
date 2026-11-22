//! PNP-001 §10.3 and §10.5 clauses about what a relay does over time and what it writes
//! down, observed on the real relay binary in its default (signaling-only) configuration.

mod common;

use std::time::Duration;

use common::{Identity, Relay, register, ws_recv, ws_recv_type, ws_send};
use futures_util::StreamExt as _;
use parolnet_clause::clause;
use serde_json::json;
use tokio_tungstenite::tungstenite::Message;

// A registered client that goes silent is disconnected by the relay, and not before 60
// seconds of silence. (The reference relay checks every 30 seconds, so the close comes
// between 60 and about 95 seconds after the last frame.)
#[clause("PNP-001-SHOULD-014")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_client_socket_is_closed_after_60_seconds() {
    let relay = Relay::start(&[]).await;
    let id = Identity::new();
    let mut ws = relay.ws().await;
    assert_eq!(register(&mut ws, &id).await["type"], "registered");
    // A second client that keeps talking stays connected the whole time.
    let chatty = Identity::new();
    let mut chatty_ws = relay.ws().await;
    assert_eq!(
        register(&mut chatty_ws, &chatty).await["type"],
        "registered"
    );

    let silent_since = tokio::time::Instant::now();
    let limit = silent_since + Duration::from_secs(110);
    let mut ping = tokio::time::interval(Duration::from_secs(20));
    let closed_after = loop {
        tokio::select! {
            // tungstenite answers the relay's WebSocket pings by itself; those pongs are
            // control frames, not the client frames the clause counts.
            frame = ws.next() => match frame {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break silent_since.elapsed(),
                Some(Ok(_)) => {}
            },
            _ = ping.tick() => {
                ws_send(&mut chatty_ws, json!({"type": "ping", "ts": 1})).await;
                assert!(
                    ws_recv_type(&mut chatty_ws, "pong", Duration::from_secs(5)).await.is_some(),
                    "a client that pings every 20 s was dropped"
                );
            }
            _ = tokio::time::sleep_until(limit) => panic!("still connected after 110 s of silence"),
        }
    };
    assert!(
        closed_after >= Duration::from_secs(59),
        "closed after only {closed_after:?} of silence"
    );
    // The silent peer is gone from the relay: a signal to it is answered `peer_offline`.
    ws_send(
        &mut chatty_ws,
        json!({"type": "rtc_offer", "to": id.peer_id, "payload": "{}"}),
    )
    .await;
    let err = ws_recv_type(&mut chatty_ws, "error", Duration::from_secs(5))
        .await
        .expect("an answer");
    assert_eq!(err["code"], "peer_offline");
}

// A whole client session (register, watch, signaling both ways, an offline recipient, a
// refused frame, disconnect) leaves no PeerId in the relay's log at its default level, and
// `/bootstrap` names no peer whatever its `exclude` parameter says.
#[clause("PNP-001-SHOULD-017")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_default_log_and_bootstrap_name_no_peer() {
    let relay = Relay::start(&[]).await;
    let (a, b, absent) = (Identity::new(), Identity::new(), Identity::new());
    let mut wa = relay.ws().await;
    let mut wb = relay.ws().await;
    assert_eq!(register(&mut wa, &a).await["type"], "registered");
    assert_eq!(register(&mut wb, &b).await["type"], "registered");

    ws_send(&mut wa, json!({"type": "watch", "peer_ids": [b.peer_id]})).await;
    ws_send(&mut wb, json!({"type": "watch", "peer_ids": [a.peer_id]})).await;
    assert!(
        ws_recv_type(&mut wa, "presence", Duration::from_secs(5))
            .await
            .is_some()
    );
    ws_send(
        &mut wa,
        json!({"type": "rtc_offer", "to": b.peer_id, "payload": "offer"}),
    )
    .await;
    let got = ws_recv_type(&mut wb, "rtc_offer", Duration::from_secs(5))
        .await
        .expect("the offer is forwarded");
    assert_eq!(got["from"], a.peer_id);
    ws_send(
        &mut wb,
        json!({"type": "rtc_answer", "to": a.peer_id, "payload": "answer"}),
    )
    .await;
    assert!(
        ws_recv_type(&mut wa, "rtc_answer", Duration::from_secs(5))
            .await
            .is_some()
    );
    ws_send(
        &mut wa,
        json!({"type": "rtc_offer", "to": absent.peer_id, "payload": "offer"}),
    )
    .await;
    assert_eq!(
        ws_recv_type(&mut wa, "error", Duration::from_secs(5))
            .await
            .unwrap()["code"],
        "peer_offline"
    );
    ws_send(
        &mut wa,
        json!({"type": "message", "to": b.peer_id, "payload": "00", "token": "00"}),
    )
    .await;
    assert_eq!(
        ws_recv_type(&mut wa, "error", Duration::from_secs(5))
            .await
            .unwrap()["code"],
        "signaling_only"
    );

    // `/bootstrap` lists nobody, with or without `exclude`, while two peers are online.
    for path in [
        "/bootstrap".to_owned(),
        format!("/bootstrap?exclude={}", absent.peer_id),
        format!("/bootstrap?exclude={}", a.peer_id),
    ] {
        let (status, body) = relay.http_get(&path).await;
        assert_eq!(status, 200, "{path}");
        let v: serde_json::Value = serde_json::from_str(body.trim()).expect(&body);
        let listed = v
            .as_array()
            .or_else(|| v["peers"].as_array())
            .unwrap_or_else(|| panic!("no list in {body}"));
        assert!(listed.is_empty(), "{path} listed {body}");
    }

    drop(wb);
    assert!(
        ws_recv_type(&mut wa, "presence", Duration::from_secs(10))
            .await
            .is_some(),
        "the watcher learns the peer left"
    );
    drop(wa);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = ws_recv; // (helper shared with other tests of this binary)

    let log = relay.log().to_ascii_lowercase();
    assert!(
        !log.is_empty(),
        "the relay logged nothing at all; is the log captured?"
    );
    for (who, id) in [("a", &a), ("b", &b), ("absent", &absent)] {
        // The full id, and the 16-hex-digit prefix a "short id" would be.
        assert!(
            !log.contains(&id.peer_id),
            "the log names peer {who}:\n{log}"
        );
        assert!(
            !log.contains(&id.peer_id[..16]),
            "the log names a prefix of peer {who}:\n{log}"
        );
        assert!(!log.contains(&hex::encode(id.public)));
    }
}
