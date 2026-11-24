//! Two drivers and the signaling between them, for the negotiation tests: every local
//! description one side produces is handed to the other, as an application would through its
//! signaling channel, and what each side reports is recorded.

#![allow(dead_code)]

use std::collections::HashMap;
use std::time::Duration;

use parolnet_rtc::rtc::peer_connection::sdp::{RTCSdpType, RTCSessionDescription};
use parolnet_rtc::rtc::peer_connection::state::RTCPeerConnectionState;
use parolnet_rtc::rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use parolnet_rtc::{ConnectionQuality, MediaKind, RtcConfig, RtcEvent, RtcHandle, spawn};
use tokio::sync::mpsc::Receiver;

#[derive(Default)]
pub struct Seen {
    /// Every local description, in order.
    pub descriptions: Vec<RTCSessionDescription>,
    pub states: Vec<RTCPeerConnectionState>,
    pub channel: Option<usize>,
    pub messages: Vec<Vec<u8>>,
    pub kinds: HashMap<String, RtpCodecKind>,
    pub rtp: HashMap<MediaKind, usize>,
    pub remote_media: Vec<(MediaKind, bool)>,
    pub local_media: Vec<(MediaKind, bool)>,
    pub targets: Vec<u32>,
    pub quality: Vec<ConnectionQuality>,
    pub ignored_offers: usize,
    pub keyframe_requests: usize,
}

impl Seen {
    pub fn connected(&self) -> bool {
        self.states.last() == Some(&RTCPeerConnectionState::Connected)
    }

    pub fn offers(&self) -> usize {
        self.descriptions
            .iter()
            .filter(|d| d.sdp_type == RTCSdpType::Offer)
            .count()
    }

    pub fn answers(&self) -> usize {
        self.descriptions
            .iter()
            .filter(|d| d.sdp_type == RTCSdpType::Answer)
            .count()
    }

    pub fn rtp_of(&self, kind: MediaKind) -> usize {
        self.rtp.get(&kind).copied().unwrap_or(0)
    }

    pub fn remote(&self, kind: MediaKind) -> Option<bool> {
        self.remote_media
            .iter()
            .rev()
            .find(|(k, _)| *k == kind)
            .map(|(_, sending)| *sending)
    }

    pub fn local(&self, kind: MediaKind) -> Option<bool> {
        self.local_media
            .iter()
            .rev()
            .find(|(k, _)| *k == kind)
            .map(|(_, sending)| *sending)
    }
}

pub struct Peer {
    pub handle: RtcHandle,
    pub events: Receiver<RtcEvent>,
    pub seen: Seen,
}

impl Peer {
    pub async fn new(config: RtcConfig) -> Peer {
        let (handle, events) = spawn(config).await.expect("spawn");
        Peer {
            handle,
            events,
            seen: Seen::default(),
        }
    }

    /// Record an event; returns the local description it carried, if any.
    fn note(&mut self, event: RtcEvent) -> Option<RTCSessionDescription> {
        match event {
            RtcEvent::LocalDescription(desc) => {
                self.seen.descriptions.push((*desc).clone());
                return Some(*desc);
            }
            RtcEvent::ConnectionState(state) => self.seen.states.push(state),
            RtcEvent::DataChannelOpen { id, .. } => self.seen.channel = Some(id),
            RtcEvent::DataChannelMessage { payload, .. } => {
                self.seen.messages.push(payload.to_vec())
            }
            RtcEvent::Track { track_id, kind, .. } => {
                self.seen.kinds.insert(track_id, kind);
            }
            RtcEvent::Rtp { track_id, .. } => {
                if let Some(kind) = self
                    .seen
                    .kinds
                    .get(&track_id)
                    .and_then(|k| MediaKind::of(*k))
                {
                    *self.seen.rtp.entry(kind).or_default() += 1;
                }
            }
            RtcEvent::RemoteMedia { kind, sending } => self.seen.remote_media.push((kind, sending)),
            RtcEvent::LocalMedia { kind, sending } => self.seen.local_media.push((kind, sending)),
            RtcEvent::TargetBitrate { bps } => self.seen.targets.push(bps),
            RtcEvent::Quality(q) => self.seen.quality.push(q),
            RtcEvent::RemoteOfferIgnored => self.seen.ignored_offers += 1,
            RtcEvent::KeyframeRequested => self.seen.keyframe_requests += 1,
            RtcEvent::Closed { error } => panic!(
                "connection closed: {error:?}; states {:?}; descriptions {:?}",
                self.seen.states,
                self.seen
                    .descriptions
                    .iter()
                    .map(|d| (d.sdp_type, parolnet_rtc::tls_id(&d.sdp).map(str::to_owned)))
                    .collect::<Vec<_>>()
            ),
            RtcEvent::IceConnectionState(_)
            | RtcEvent::SelectedCandidatePairChanged
            | RtcEvent::DataChannelClose { .. }
            | RtcEvent::DataChannelBufferedLow { .. } => {}
        }
        None
    }
}

pub struct Pair {
    pub a: Peer,
    pub b: Peer,
    /// When false, descriptions are recorded but not delivered (the test signals by hand).
    pub signal: bool,
}

impl Pair {
    pub async fn new(a: RtcConfig, b: RtcConfig) -> Pair {
        Pair {
            a: Peer::new(a).await,
            b: Peer::new(b).await,
            signal: true,
        }
    }

    /// Handle one event from either side (forwarding descriptions); false when none came
    /// within `wait`.
    pub async fn step(&mut self, wait: Duration) -> bool {
        let (from_a, event) = tokio::select! {
            e = self.a.events.recv() => (true, e),
            e = self.b.events.recv() => (false, e),
            _ = tokio::time::sleep(wait) => return false,
        };
        let event = event.expect("event channel");
        let (from, to) = if from_a {
            (&mut self.a, &mut self.b)
        } else {
            (&mut self.b, &mut self.a)
        };
        if let Some(desc) = from.note(event)
            && self.signal
        {
            to.handle.set_remote_description(desc).expect("signal");
        }
        true
    }

    /// Run until `done`, at most `secs` seconds.
    pub async fn until(&mut self, what: &str, secs: u64, mut done: impl FnMut(&Pair) -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        while !done(self) {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            assert!(!left.is_zero(), "timed out waiting for {what}");
            self.step(left.min(Duration::from_millis(100))).await;
        }
    }

    /// Run for `millis`, handling whatever happens.
    pub async fn settle(&mut self, millis: u64) {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(millis);
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return;
            }
            self.step(left).await;
        }
    }

    /// The first offer / answer exchange, `a` offering, until both are connected.
    pub async fn connect(&mut self) {
        self.a.handle.create_offer().expect("offer");
        self.until("the first connection", 20, |p| {
            p.a.seen.connected() && p.b.seen.connected()
        })
        .await;
    }

    pub async fn close(self) {
        self.a.handle.close().await;
        self.b.handle.close().await;
    }
}

/// The ICE username fragment of a description.
pub fn ufrag(desc: &RTCSessionDescription) -> String {
    parolnet_rtc::ice_ufrag(&desc.sdp)
        .expect("a=ice-ufrag")
        .to_owned()
}

/// The addresses of a description's host candidates.
pub fn host_addresses(sdp: &str) -> Vec<String> {
    let mut out: Vec<String> = sdp
        .lines()
        .filter(|l| l.contains("candidate:") && l.contains("typ host"))
        .filter_map(|l| l.split_ascii_whitespace().nth(4).map(str::to_owned))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Whether this machine delivers UDP between two of its own sockets on `ip`. Not a given:
/// macOS's local-network privacy drops datagrams to the machine's own LAN and global
/// addresses for a process without that permission (a test run from an agent or over SSH),
/// while loopback always works. Tests on the real interfaces skip where it does not.
pub fn delivers_to_itself(ip: std::net::IpAddr) -> bool {
    let bind = |ip| std::net::UdpSocket::bind(std::net::SocketAddr::new(ip, 0));
    let (Ok(a), Ok(b)) = (bind(ip), bind(ip)) else {
        return false;
    };
    let Ok(to) = b.local_addr() else {
        return false;
    };
    let _ = b.set_read_timeout(Some(Duration::from_millis(500)));
    let mut buf = [0u8; 8];
    a.send_to(b"probe", to).is_ok() && b.recv_from(&mut buf).is_ok_and(|(n, _)| n == 5)
}
