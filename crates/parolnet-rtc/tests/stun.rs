//! Server-reflexive gathering: a loopback STUN responder answers the driver's binding
//! request with a made-up mapped address, which must appear in the offer as a `srflx`
//! candidate (non-trickle). An unreachable server is skipped within the timeout.

use std::time::Duration;

use parolnet_rtc::rtc::stun::message::{BINDING_SUCCESS, Message, TransactionId};
use parolnet_rtc::rtc::stun::xoraddr::XorMappedAddress;
use parolnet_rtc::{RtcConfig, RtcEvent, spawn};
use tokio::net::UdpSocket;

const MAPPED: &str = "203.0.113.7:40000";

async fn fake_stun_server() -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let mut req = Message::new();
            req.raw = buf[..n].to_vec();
            if req.decode().is_err() {
                continue;
            }
            let mapped: std::net::SocketAddr = MAPPED.parse().unwrap();
            let mut resp = Message::new();
            resp.build(&[
                Box::new(TransactionId(req.transaction_id.0)),
                Box::new(BINDING_SUCCESS),
                Box::new(XorMappedAddress {
                    ip: mapped.ip(),
                    port: mapped.port(),
                }),
            ])
            .unwrap();
            let _ = socket.send_to(&resp.raw, from).await;
        }
    });
    addr
}

async fn offer_sdp(config: RtcConfig) -> String {
    let (handle, mut events) = spawn(config).await.unwrap();
    handle.create_offer().unwrap();
    let sdp = loop {
        match tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("offer in time")
            .expect("events")
        {
            RtcEvent::LocalDescription(desc) => break desc.sdp.clone(),
            RtcEvent::Closed { error } => panic!("closed: {error:?}"),
            _ => {}
        }
    };
    handle.close().await;
    sdp
}

#[tokio::test]
async fn srflx_candidate_from_stun_is_in_the_offer() {
    let server = fake_stun_server().await;
    let sdp = offer_sdp(RtcConfig {
        stun_servers: vec![format!("stun:{server}")],
        data_channel: Some("parolnet".into()),
        ..Default::default()
    })
    .await;
    let srflx: Vec<&str> = sdp.lines().filter(|l| l.contains("typ srflx")).collect();
    // The engine lists each candidate for both components of the bundled section.
    assert!(!srflx.is_empty(), "{sdp}");
    for line in &srflx {
        assert!(line.contains("203.0.113.7 40000"), "{line}");
        assert!(line.contains("raddr 127.0.0.1"), "{line}");
    }
    assert!(sdp.lines().any(|l| l.contains("typ host")), "{sdp}");
}

#[tokio::test]
async fn unreachable_stun_is_skipped() {
    // A bound socket that never answers.
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let started = std::time::Instant::now();
    let sdp = offer_sdp(RtcConfig {
        stun_servers: vec![silent.local_addr().unwrap().to_string()],
        stun_timeout: Duration::from_millis(300),
        data_channel: Some("parolnet".into()),
        ..Default::default()
    })
    .await;
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(!sdp.contains("typ srflx"), "{sdp}");
    assert!(sdp.contains("typ host"), "{sdp}");
}
