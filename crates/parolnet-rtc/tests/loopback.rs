//! Two drivers on loopback: offer / answer, ICE + DTLS + SCTP, one data-channel message
//! each way. Real sockets on 127.0.0.1; the virtual-time variant comes with parolnet-simnet.

use std::time::Duration;

use parolnet_rtc::{RtcConfig, RtcEvent, spawn};
use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;

async fn next_description(
    events: &mut Receiver<RtcEvent>,
) -> parolnet_rtc::rtc::peer_connection::sdp::RTCSessionDescription {
    loop {
        match events.recv().await.expect("events") {
            RtcEvent::LocalDescription(desc) => return *desc,
            RtcEvent::Closed { error } => panic!("closed before describing: {error:?}"),
            _ => {}
        }
    }
}

async fn next_open(events: &mut Receiver<RtcEvent>) -> usize {
    loop {
        match events.recv().await.expect("events") {
            RtcEvent::DataChannelOpen { id } => return id,
            RtcEvent::Closed { error } => panic!("closed before open: {error:?}"),
            _ => {}
        }
    }
}

async fn next_message(events: &mut Receiver<RtcEvent>) -> Vec<u8> {
    loop {
        match events.recv().await.expect("events") {
            RtcEvent::DataChannelMessage { payload, .. } => return payload.to_vec(),
            RtcEvent::Closed { error } => panic!("closed before message: {error:?}"),
            _ => {}
        }
    }
}

#[tokio::test]
async fn data_channel_round_trip_on_loopback() {
    let (offerer, mut offerer_events) = spawn(RtcConfig {
        data_channel: Some("pn-test".into()),
        ..Default::default()
    })
    .await
    .expect("offerer");
    let (answerer, mut answerer_events) = spawn(RtcConfig::default()).await.expect("answerer");

    let result = timeout(Duration::from_secs(20), async {
        offerer.create_offer().unwrap();
        let offer = next_description(&mut offerer_events).await;
        answerer.set_remote_description(offer).unwrap();
        let answer = next_description(&mut answerer_events).await;
        offerer.set_remote_description(answer).unwrap();

        let offerer_channel = next_open(&mut offerer_events).await;
        let answerer_channel = next_open(&mut answerer_events).await;

        offerer
            .send_data(offerer_channel, &b"hello from the offerer"[..])
            .unwrap();
        assert_eq!(
            next_message(&mut answerer_events).await,
            b"hello from the offerer"
        );
        answerer
            .send_data(answerer_channel, &b"hello back"[..])
            .unwrap();
        assert_eq!(next_message(&mut offerer_events).await, b"hello back");

        let (_, dropped) = offerer.stats().await.unwrap();
        assert_eq!(dropped, 0);
    })
    .await;

    offerer.close().await;
    answerer.close().await;
    result.expect("the connection did not complete within 20 s");
}

#[tokio::test]
async fn unspecified_bind_is_refused() {
    let err = spawn(RtcConfig {
        bind: "0.0.0.0:0".parse().unwrap(),
        ..Default::default()
    })
    .await
    .err()
    .expect("refused");
    assert!(matches!(err, parolnet_rtc::RtcError::UnspecifiedBind(_)));
}
