//! A PNP-010 file transfer across an ICE restart, on the simulated network in virtual time.
//!
//! Two `parolnet-rtc` drivers hold a data connection with the `parolnet` channel and one
//! `pn-file/<id>` channel, as `parolnet-app` sets them up. Half of the file's records are
//! delivered, then the sending machine moves to another network: its old address is gone,
//! and the rest of the records are handed to a channel that has no path. Nothing arrives
//! until ICE is restarted; then the same channel of the same SCTP association delivers
//! the rest, in order, and the receiver's final check passes. No RESUME, no second
//! channel: for a transfer an ICE restart is a pause.

use std::collections::HashMap;
use std::time::Duration;

use parolnet_rtc::rtc::peer_connection::sdp::{RTCSdpType, RTCSessionDescription};
use parolnet_rtc::rtc::peer_connection::state::RTCPeerConnectionState;
use parolnet_rtc::{Gather, RtcConfig, RtcEvent, RtcHandle};
use parolnet_simnet::{SimHost, SimNet};
use parolnet_transfer::{
    CHUNK_SIZE, FileHasher, FileKey, Offer, Received, Receiver, Sender, TransferId, random_bytes,
    record_count,
};
use tokio::sync::mpsc::Receiver as Events;
use tokio::time::Instant;

const MAIN: &str = "parolnet";

/// One end: its driver, and what it reported.
struct End {
    host: SimHost,
    handle: RtcHandle,
    events: Events<RtcEvent>,
    descriptions: Vec<RTCSessionDescription>,
    states: Vec<RTCPeerConnectionState>,
    /// Open channels by label.
    channels: HashMap<String, usize>,
    closed_channels: Vec<usize>,
    /// Messages of every channel but `parolnet`, in order.
    messages: Vec<Vec<u8>>,
}

impl End {
    async fn new(host: SimHost, offerer: bool) -> End {
        let (handle, events) = parolnet_rtc::spawn(RtcConfig {
            bind: "0.0.0.0:0".parse().expect("an address"),
            gather: Gather::Interfaces,
            network: host.network(),
            data_channel: offerer.then(|| MAIN.to_owned()),
            // As the app sets a data connection up.
            polite: !offerer,
            mdns: false,
            ..Default::default()
        })
        .await
        .expect("spawn");
        End {
            host,
            handle,
            events,
            descriptions: Vec::new(),
            states: Vec::new(),
            channels: HashMap::new(),
            closed_channels: Vec::new(),
            messages: Vec::new(),
        }
    }

    /// Record an event; returns the local description it carried, if any.
    fn note(&mut self, event: RtcEvent) -> Option<RTCSessionDescription> {
        match event {
            RtcEvent::LocalDescription(desc) => {
                self.descriptions.push((*desc).clone());
                return Some(*desc);
            }
            RtcEvent::ConnectionState(state) => self.states.push(state),
            RtcEvent::DataChannelOpen { id, label } => {
                self.channels.insert(label, id);
            }
            RtcEvent::DataChannelMessage { id, payload } => {
                if self.channels.get(MAIN) != Some(&id) {
                    self.messages.push(payload.to_vec());
                }
            }
            RtcEvent::DataChannelClose { id } => self.closed_channels.push(id),
            RtcEvent::Closed { error } => panic!("connection closed: {error:?}"),
            _ => {}
        }
        None
    }

    fn connected(&self) -> bool {
        self.states.last() == Some(&RTCPeerConnectionState::Connected)
    }

    fn offers(&self) -> usize {
        self.descriptions
            .iter()
            .filter(|d| d.sdp_type == RTCSdpType::Offer)
            .count()
    }
}

struct Pair {
    a: End,
    b: End,
}

impl Pair {
    /// Handle one event from either end, carrying descriptions across; false when none
    /// came within `wait`.
    async fn step(&mut self, wait: Duration) -> bool {
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
        if let Some(desc) = from.note(event) {
            to.handle.set_remote_description(desc).expect("signal");
        }
        true
    }

    async fn until(&mut self, what: &str, secs: u64, mut done: impl FnMut(&Pair) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while !done(self) {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "timed out waiting for {what}");
            self.step(left.min(Duration::from_millis(100))).await;
        }
    }

    /// Run for `time`, handling whatever happens.
    async fn settle(&mut self, time: Duration) {
        let deadline = Instant::now() + time;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            self.step(left).await;
        }
    }
}

fn file(size: usize) -> Vec<u8> {
    (0..size)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_be_bytes()[0])
        .collect()
}

/// Feed what arrived on the receiving end's file channel to the receiver's state machine;
/// every record must verify at its position.
fn absorb(end: &mut End, receiver: &mut Receiver, stored: &mut Vec<u8>) {
    for message in end.messages.drain(..) {
        match receiver
            .on_message(&message)
            .expect("a record that verifies")
        {
            Received::Started => {}
            Received::Chunk { offset, data, .. } => {
                assert_eq!(offset as usize, stored.len(), "records arrive in order");
                stored.extend_from_slice(&data);
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn a_transfer_goes_on_through_an_ice_restart_on_the_same_channel() {
    let net = SimNet::new(11);
    let mut pair = Pair {
        a: End::new(net.host(&["10.0.0.1"]), true).await,
        b: End::new(net.host(&["10.0.0.2"]), false).await,
    };
    pair.a.handle.create_offer().expect("offer");
    pair.until("the connection and its first channel", 20, |p| {
        p.a.connected()
            && p.b.connected()
            && p.a.channels.contains_key(MAIN)
            && p.b.channels.contains_key(MAIN)
    })
    .await;

    // The offer and its accept went through the session; what is left is the channel.
    let data = file(31 * CHUNK_SIZE + 1000);
    let mut hasher = FileHasher::new();
    hasher.update(&data);
    let offer = Offer {
        id: TransferId::generate(),
        name: "data.bin".into(),
        size: data.len() as u64,
        mime: "application/octet-stream".into(),
        sha256: hasher.finalize(),
        key: FileKey::generate(),
    };
    let records = record_count(offer.size) as usize;
    assert_eq!(records, 32);
    let label = offer.id.label();
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let mut receiver = Receiver::new(&offer);
    let mut stored = Vec::new();

    // The receiver opens the channel and says where it is; the sender answers with START.
    pair.b
        .handle
        .open_data_channel(label.clone())
        .expect("open");
    pair.until("the transfer's channel", 10, |p| {
        p.a.channels.contains_key(&label) && p.b.channels.contains_key(&label)
    })
    .await;
    let (on_a, on_b) = (pair.a.channels[&label], pair.b.channels[&label]);
    let (to_b, to_a) = (pair.a.handle.data_sender(), pair.b.handle.data_sender());
    let resume = receiver.begin(random_bytes()).expect("RESUME");
    to_a.send(on_b, resume).await.expect("RESUME sent");
    pair.until("RESUME", 10, |p| !p.a.messages.is_empty()).await;
    let resume = pair.a.messages.remove(0);
    let start = sender.begin(&resume, random_bytes()).expect("START");
    to_b.send(on_a, start).await.expect("START sent");

    // The first half arrives on the path the connection was made on.
    let mut sent = 0;
    while sent < records / 2 {
        let (offset, len) = sender.next_chunk().expect("a record to send");
        let record = sender
            .seal(&data[offset as usize..offset as usize + len])
            .expect("sealed");
        to_b.send(on_a, record).await.expect("queued");
        sent += 1;
    }
    let half = records / 2 * CHUNK_SIZE;
    for _ in 0..200 {
        absorb(&mut pair.b, &mut receiver, &mut stored);
        if stored.len() == half {
            break;
        }
        pair.settle(Duration::from_millis(50)).await;
    }
    assert_eq!(stored.len(), half, "the first half arrived");

    // The sender's machine moves to another network. The rest is handed to the channel
    // all the same: it has nowhere to go.
    pair.a.host.set_addresses(&["10.0.9.1"]);
    while let Some((offset, len)) = sender.next_chunk() {
        let record = sender
            .seal(&data[offset as usize..offset as usize + len])
            .expect("sealed");
        to_b.send(on_a, record)
            .await
            .expect("queued without a path");
        sent += 1;
    }
    assert_eq!(sent, records);
    assert!(sender.is_finished());
    pair.settle(Duration::from_secs(2)).await;
    absorb(&mut pair.b, &mut receiver, &mut stored);
    assert_eq!(stored.len(), half, "nothing arrives without a path");
    assert!(
        to_b.buffered_amount(on_a).await.expect("the channel lives") > 0,
        "the records wait in the channel"
    );

    // ICE restarts on the address the machine has now; the session and its channels stay.
    pair.a.handle.restart_ice().expect("restart");
    pair.until("the restart's offer and answer", 10, |p| {
        p.a.offers() == 2 && p.b.descriptions.len() == 2
    })
    .await;
    let restart_offer = &pair.a.descriptions[1].sdp;
    assert!(
        restart_offer.contains("10.0.9.1") && !restart_offer.contains("10.0.0.1 "),
        "{restart_offer}"
    );
    for _ in 0..600 {
        absorb(&mut pair.b, &mut receiver, &mut stored);
        if receiver.is_complete() {
            break;
        }
        pair.settle(Duration::from_millis(50)).await;
    }
    assert!(
        receiver.is_complete(),
        "the rest arrived after the restart: {} of {} bytes",
        stored.len(),
        data.len()
    );
    receiver.finish().expect("the file's hash");
    assert_eq!(stored, data);
    assert_eq!(receiver.record_failures(), 0);

    // The same channel carried all of it: none was closed, none was opened, and neither
    // connection failed on the way.
    pair.settle(Duration::from_millis(500)).await;
    for (who, end) in [("sender", &pair.a), ("receiver", &pair.b)] {
        assert!(
            end.closed_channels.is_empty(),
            "{who}: {:?}",
            end.closed_channels
        );
        assert_eq!(end.channels.len(), 2, "{who}: {:?}", end.channels);
        assert!(end.connected(), "{who}: {:?}", end.states);
        assert!(
            end.states.iter().all(|s| !matches!(
                s,
                RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed
            )),
            "{who}: {:?}",
            end.states
        );
    }
    assert_eq!(
        to_b.buffered_amount(on_a).await.expect("the channel lives"),
        0
    );
    // A data-only connection has no RTP session, so it sends no RTCP (and no RTP) at all:
    // the engine starts an RTCP session only for a negotiated RTP section with SRTP keys
    // (webrtc-rs-rtc v0.22.0+brainwires.6; before it each end sent an SRTCP report about
    // every 0.4 s).
    for (who, end) in [("sender", &pair.a), ("receiver", &pair.b)] {
        let stats = end.host.stats();
        assert!(stats.sent > 0, "{who}: {stats:?}");
        assert_eq!(stats.sent_rtp_or_rtcp, 0, "{who}: {stats:?}");
    }

    pair.a.handle.close().await;
    pair.b.handle.close().await;
}
