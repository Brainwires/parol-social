//! More data channels on one connection: opened in-band by either side after the first is
//! up, 64 KiB messages streamed with backpressure, and closed without touching the rest.

use std::time::{Duration, Instant};

use parolnet_rtc::rtci::peer_connection::sdp::RTCSessionDescription;
use parolnet_rtc::{RtcConfig, RtcEvent, RtcHandle, spawn};
use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;

const MESSAGE: usize = 65_536;
const HIGH: usize = 4 << 20;
const LOW: u32 = 1 << 20;

async fn description(events: &mut Receiver<RtcEvent>) -> RTCSessionDescription {
    loop {
        match events.recv().await.expect("events") {
            RtcEvent::LocalDescription(desc) => return *desc,
            RtcEvent::Closed { error } => panic!("closed before describing: {error:?}"),
            _ => {}
        }
    }
}

async fn open(events: &mut Receiver<RtcEvent>, want: &str) -> usize {
    loop {
        match events.recv().await.expect("events") {
            RtcEvent::DataChannelOpen { id, label } if label == want => return id,
            RtcEvent::Closed { error } => panic!("closed before {want} opened: {error:?}"),
            _ => {}
        }
    }
}

async fn connected() -> (
    (RtcHandle, Receiver<RtcEvent>, usize),
    (RtcHandle, Receiver<RtcEvent>, usize),
) {
    let (offerer, mut offerer_events) = spawn(RtcConfig {
        data_channel: Some("parolnet".into()),
        // Small, as the app sets it for data connections: a slow reader holds the driver
        // back instead of piling messages up.
        event_capacity: 32,
        ..Default::default()
    })
    .await
    .expect("offerer");
    let (answerer, mut answerer_events) = spawn(RtcConfig {
        event_capacity: 32,
        ..Default::default()
    })
    .await
    .expect("answerer");
    offerer.create_offer().unwrap();
    let offer = description(&mut offerer_events).await;
    answerer.set_remote_description(offer).unwrap();
    let answer = description(&mut answerer_events).await;
    offerer.set_remote_description(answer).unwrap();
    let a = open(&mut offerer_events, "parolnet").await;
    let b = open(&mut answerer_events, "parolnet").await;
    ((offerer, offerer_events, a), (answerer, answerer_events, b))
}

fn message(n: u32) -> Vec<u8> {
    let mut m = vec![(n % 251) as u8; MESSAGE];
    m[..4].copy_from_slice(&n.to_be_bytes());
    m
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_channel_streams_with_backpressure_and_closes_alone() {
    let megabytes: u32 = std::env::var("PAROLNET_CHANNEL_TEST_MIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(48);
    let count = megabytes * 16;
    let ((offerer, mut offerer_events, main_a), (answerer, mut answerer_events, _main_b)) =
        timeout(Duration::from_secs(20), connected())
            .await
            .expect("connect");

    // The answering side opens the extra channel (as a PNP-010 receiver does).
    let label = "pn-file/00112233445566778899aabbccddeeff";
    answerer.open_data_channel(label).unwrap();
    let on_answerer = timeout(Duration::from_secs(10), open(&mut answerer_events, label))
        .await
        .expect("the opener sees its channel open");
    let on_offerer = timeout(Duration::from_secs(10), open(&mut offerer_events, label))
        .await
        .expect("the other side sees the channel");

    // The offerer streams on it; the answerer reads. The first channel stays usable.
    let sender = offerer.data_sender();
    sender.set_buffered_low(on_offerer, LOW).unwrap();
    let started = Instant::now();
    let reader = tokio::spawn(async move {
        let mut next = 0u32;
        let mut chat = 0;
        let mut closed = false;
        while !(next == count && chat == 1 && closed) {
            match timeout(Duration::from_secs(30), answerer_events.recv())
                .await
                .expect("the stream stalled")
                .expect("events")
            {
                RtcEvent::DataChannelMessage { id, payload } if id == on_answerer => {
                    assert_eq!(payload.len(), MESSAGE);
                    assert_eq!(&payload[..], &message(next)[..], "message {next}");
                    next += 1;
                }
                RtcEvent::DataChannelMessage { payload, .. } => {
                    assert_eq!(&payload[..], b"still here");
                    chat += 1;
                }
                RtcEvent::DataChannelClose { id } => {
                    assert_eq!(id, on_answerer);
                    assert_eq!(next, count, "closed before everything arrived");
                    closed = true;
                }
                RtcEvent::Closed { error } => panic!("connection closed: {error:?}"),
                _ => {}
            }
        }
        answerer_events
    });

    let mut high_water = 0usize;
    let mut waits = 0u32;
    for n in 0..count {
        let buffered = sender.send(on_offerer, message(n)).await.unwrap();
        high_water = high_water.max(buffered);
        if n == count / 2 {
            offerer.send_data(main_a, &b"still here"[..]).unwrap();
        }
        if buffered > HIGH {
            waits += 1;
            // Wait for the low mark. The event wakes the loop (one from an earlier crossing
            // may still be queued), the amount decides.
            loop {
                match timeout(Duration::from_millis(50), offerer_events.recv()).await {
                    Ok(Some(RtcEvent::Closed { error })) => panic!("closed: {error:?}"),
                    Ok(None) => panic!("events ended"),
                    Ok(Some(_)) | Err(_) => {}
                }
                if sender.buffered_amount(on_offerer).await.unwrap() <= LOW as usize {
                    break;
                }
            }
        }
    }
    // Everything is acknowledged before the channel is closed.
    timeout(Duration::from_secs(30), async {
        while sender.buffered_amount(on_offerer).await.unwrap() > 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the channel drained");
    let secs = started.elapsed().as_secs_f64();
    eprintln!(
        "{megabytes} MiB in {secs:.2} s = {:.1} MiB/s; buffered at most {} KiB; paused {waits} times",
        f64::from(megabytes) / secs,
        high_water / 1024
    );
    assert!(
        high_water <= HIGH + MESSAGE,
        "backpressure bounds the buffer"
    );

    // A send the channel cannot carry is an error for that send, not for the connection.
    assert!(
        sender
            .send(on_offerer, vec![0u8; MESSAGE + 1])
            .await
            .is_err()
    );
    assert!(sender.send(9_999, b"x".to_vec()).await.is_err());

    sender.close_channel(on_offerer).unwrap();
    let mut answerer_events = timeout(Duration::from_secs(30), reader)
        .await
        .expect("the reader finished")
        .unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            match offerer_events.recv().await.expect("events") {
                RtcEvent::DataChannelClose { id } if id == on_offerer => break,
                RtcEvent::Closed { error } => panic!("connection closed: {error:?}"),
                _ => {}
            }
        }
    })
    .await
    .expect("the closing side sees the close");
    assert!(sender.send(on_offerer, b"late".to_vec()).await.is_err());

    // The connection and its first channel live on, and another channel can be opened.
    offerer
        .open_data_channel("pn-file/ffeeddccbbaa99887766554433221100")
        .unwrap();
    let again = timeout(
        Duration::from_secs(10),
        open(
            &mut answerer_events,
            "pn-file/ffeeddccbbaa99887766554433221100",
        ),
    )
    .await
    .expect("a channel after a closed one");
    assert_ne!(again, on_answerer);

    offerer.close().await;
    answerer.close().await;
}

/// The next text or binary message on channel `id`.
async fn next_message(events: &mut Receiver<RtcEvent>, id: usize) -> Vec<u8> {
    loop {
        match events.recv().await.expect("events") {
            RtcEvent::DataChannelMessage { id: on, payload } if on == id => {
                return payload.to_vec();
            }
            RtcEvent::Closed { error } => panic!("closed before a message: {error:?}"),
            _ => {}
        }
    }
}

// `send_text_acked` answers when the peer has acknowledged the message, each message for
// itself whatever else is sent on the channel around it, and never for a message sent to a
// peer that is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_acknowledged_send_answers_when_the_peer_has_the_message_and_never_for_a_lost_one() {
    let ((offerer, _offerer_events, a), (answerer, mut answerer_events, b)) =
        timeout(Duration::from_secs(20), connected())
            .await
            .expect("connect");

    let acked = offerer.send_text_acked(a, "one").unwrap();
    timeout(Duration::from_secs(10), acked)
        .await
        .expect("acknowledged in time")
        .expect("acknowledged");
    let got = timeout(
        Duration::from_secs(10),
        next_message(&mut answerer_events, b),
    )
    .await
    .expect("delivered");
    assert_eq!(got, b"one");

    // Acknowledged and plain sends mixed: every acknowledged one is answered.
    let two = offerer.send_text_acked(a, "two").unwrap();
    offerer.send_text(a, "plain").unwrap();
    offerer.send_data(a, &[7u8; 2000][..]).unwrap();
    let three = offerer.send_text_acked(a, "three").unwrap();
    for (name, acked) in [("two", two), ("three", three)] {
        timeout(Duration::from_secs(10), acked)
            .await
            .unwrap_or_else(|_| panic!("{name} was not acknowledged in time"))
            .unwrap_or_else(|_| panic!("{name} was dropped unacknowledged"));
    }
    for want in [&b"two"[..], b"plain", &[7u8; 2000], b"three"] {
        let got = timeout(
            Duration::from_secs(10),
            next_message(&mut answerer_events, b),
        )
        .await
        .expect("delivered");
        assert_eq!(got, want);
    }

    // The peer goes away. Whatever this side learns of it, and whenever, a message sent
    // now is not reported as acknowledged.
    answerer.close().await;
    drop(answerer_events);
    if let Ok(lost) = offerer.send_text_acked(a, "lost") {
        let outcome = timeout(Duration::from_secs(6), lost).await;
        assert!(
            !matches!(outcome, Ok(Ok(()))),
            "a message nobody received was reported as acknowledged"
        );
    }
    offerer.close().await;
}
