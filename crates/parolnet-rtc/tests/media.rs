//! Two drivers on loopback send each other VP8 and Opus tracks (opaque payloads: the test
//! checks negotiation, packetization, SRTP and delivery, not the codecs).

use std::collections::HashMap;
use std::time::Duration;

use parolnet_rtc::rtc::peer_connection::sdp::{RTCSdpType, RTCSessionDescription};
use parolnet_rtc::rtc::peer_connection::state::RTCPeerConnectionState;
use parolnet_rtc::rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use parolnet_rtc::{MediaConfig, MediaKind, RtcConfig, RtcEvent, RtcHandle};
use tokio::sync::mpsc::Receiver;

fn config() -> RtcConfig {
    RtcConfig {
        media: MediaConfig {
            recv_vp8: true,
            recv_opus: true,
            send_vp8: true,
            send_opus: true,
        },
        ..Default::default()
    }
}

async fn description(rx: &mut Receiver<RtcEvent>) -> RTCSessionDescription {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), rx.recv()).await {
            Ok(Some(RtcEvent::LocalDescription(d))) => return *d,
            Ok(Some(_)) => {}
            other => panic!("no local description: {other:?}"),
        }
    }
}

#[derive(Default)]
struct Seen {
    connected: bool,
    kinds: HashMap<String, RtpCodecKind>,
    packets: HashMap<RtpCodecKind, usize>,
}

fn note(seen: &mut Seen, ev: RtcEvent) {
    match ev {
        RtcEvent::ConnectionState(RTCPeerConnectionState::Connected) => seen.connected = true,
        RtcEvent::Track { track_id, kind, .. } => {
            seen.kinds.insert(track_id, kind);
        }
        RtcEvent::Rtp { track_id, .. } => {
            if let Some(kind) = seen.kinds.get(&track_id) {
                *seen.packets.entry(*kind).or_default() += 1;
            } else {
                *seen.packets.entry(RtpCodecKind::Unspecified).or_default() += 1;
            }
        }
        RtcEvent::Closed { error } => panic!("connection closed: {error:?}"),
        _ => {}
    }
}

async fn send_some(h: &RtcHandle) {
    let _ = h.send_frame(MediaKind::Audio, vec![0xf8u8; 60], 960);
    let _ = h.send_frame(MediaKind::Video, vec![0x10u8; 2500], 3000);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vp8_and_opus_flow_both_ways() {
    let (a, mut a_rx) = parolnet_rtc::spawn(config()).await.unwrap();
    let (b, mut b_rx) = parolnet_rtc::spawn(config()).await.unwrap();
    a.create_offer().unwrap();
    let offer = description(&mut a_rx).await;
    assert_eq!(offer.sdp_type, RTCSdpType::Offer);
    assert!(offer.sdp.contains("m=audio") && offer.sdp.contains("m=video"));
    assert!(offer.sdp.contains("a=sendrecv"));
    b.set_remote_description(offer).unwrap();
    let answer = description(&mut b_rx).await;
    a.set_remote_description(answer).unwrap();

    let (mut sa, mut sb) = (Seen::default(), Seen::default());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    loop {
        tokio::select! {
            ev = a_rx.recv() => note(&mut sa, ev.expect("a events")),
            ev = b_rx.recv() => note(&mut sb, ev.expect("b events")),
            _ = tick.tick() => {
                send_some(&a).await;
                send_some(&b).await;
            }
        }
        let done = |s: &Seen| {
            s.packets.get(&RtpCodecKind::Audio).copied().unwrap_or(0) >= 20
                && s.packets.get(&RtpCodecKind::Video).copied().unwrap_or(0) >= 20
        };
        if done(&sa) && done(&sb) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "media did not flow: a {:?} (connected {}), b {:?} (connected {})",
            sa.packets,
            sa.connected,
            sb.packets,
            sb.connected
        );
    }
    a.close().await;
    b.close().await;
}
