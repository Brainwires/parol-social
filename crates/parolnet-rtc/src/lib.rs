//! Async driver for the sans-I/O [`rtc`] peer connection (`Brainwires/webrtc-rs-rtc`).
//!
//! The engine does no I/O of its own: it is fed datagrams and timeouts and hands back
//! datagrams to send, events and decrypted messages. This crate owns that loop. Each
//! connection runs as one tokio task that owns its sockets and timers; the application
//! talks to it through a command channel ([`RtcHandle`]) and an event channel
//! ([`RtcEvent`]).
//!
//! What the driver does:
//!
//! - **Candidates.** One UDP socket per local address: the one address of
//!   [`RtcConfig::bind`], or with [`Gather::Interfaces`] every usable address of every
//!   interface, IPv4 and IPv6 ([`net::select_addresses`] says which and in what order). Each
//!   socket is a host candidate; each asks the STUN servers (those of its own family) for a
//!   server-reflexive one; the user's TURN server ([`RtcConfig::turn`], over UDP) gives a relay
//!   candidate, the only one with [`IcePolicy::Relay`]. Remote mDNS host candidates
//!   (`<uuid>.local`, what Chromium and Safari announce instead of a private address) are
//!   resolved with an mDNS query: the engine asks, and this driver opens the multicast socket
//!   (`224.0.0.251:5353`) the first time a remote description or candidate names a `.local`
//!   host, so a connection that never sees one never touches multicast.
//! - **Negotiation.** A non-trickle offer or answer first; afterwards renegotiation in either
//!   direction: an ICE restart ([`RtcHandle::restart_ice`], which binds the addresses the
//!   machine has now and gathers again) and turning a local track on or off
//!   ([`RtcHandle::set_sending`], which adds the sender when there is none). Offers that cross
//!   are settled by [`RtcConfig::polite`] (the polite side rolls its own back).
//! - **Media.** It sends VP8 and Opus tracks (encoded frames in, packetized here), delivers
//!   RTP packets and data-channel messages (binary and text), requests keyframes, and with
//!   [`RtcConfig::congestion`] runs the engine's congestion controller and reports its target
//!   bitrate ([`RtcEvent::TargetBitrate`]) for the encoder to follow. Video is repaired over
//!   RTX (RFC 4588); received audio can be de-jittered ([`RtcConfig::jitter_buffer`]).
//! - **Stats.** The engine's report on request ([`RtcHandle::stats`]) and a digest of it at
//!   an interval ([`RtcEvent::Quality`]).
//!
//! Sockets and the interface list come through [`net::Network`], and every instant given to
//! the engine is tokio's clock ([`now`]): on a paused runtime with an in-memory network
//! (`parolnet-simnet`) the same loop runs in virtual time. Still to come: TURN over TCP and
//! TLS.

use std::collections::HashMap;
use std::future::poll_fn;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use rtc::ice::NominationAcceptance;
use rtc::ice::mdns::MulticastDnsMode;
use rtc::interceptor::{
    GccHandle, GccInterceptorBuilder, Interceptor as _, PassThroughInterceptor, Registry, Slot,
};
use rtc::mdns::{MDNS_PORT, MulticastSocket};
use rtc::media_stream::{MediaStreamTrack, MediaStreamTrackId};
use rtc::peer_connection::configuration::interceptor_registry::{
    configure_key_frame_requests, configure_nack, configure_receiver_reference_time,
    configure_rtcp_reports, configure_simulcast_extension_headers, configure_twcc,
    configure_twcc_receiver_only,
};
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceTransportPolicy};
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::sdp::{RTCSdpType, RTCSessionDescription};
use rtc::peer_connection::srflx::ReflexiveGathering;
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, CandidateRelayConfig, CandidateServerReflexiveConfig,
    RTCDtlsRole, RTCIceCandidate, RTCIceCandidateInit, RTCIceCandidateType, RTCIceServer,
};
use rtc::peer_connection::turn_streams::RelayGathering;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
use rtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtc::rtp::packetizer::Packetizer;
use rtc::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters,
    RTCRtpEncodingParameters, RTCRtpRtxParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{
    RTCRtpReceiverId, RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverId,
    RTCRtpTransceiverInit,
};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::statistics::StatsSelector;
use rtc::statistics::report::{RTCStatsReport, RTCStatsReportEntry};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

pub use rtc;

pub mod jitter;
pub mod net;
#[cfg(feature = "test-turn")]
pub mod test_turn;
mod turn;

pub use net::{DatagramSocket, Network, NetworkMonitor, SystemNetwork};
pub use turn::{TurnServer, parse_turn_uri};

/// The clock every instant handed to the engine is read from: tokio's. It is the system's
/// monotonic clock on an ordinary runtime and the virtual one on a paused runtime, which is
/// what lets `parolnet-simnet` run this driver in virtual time.
pub fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// Errors from the driver.
#[derive(Debug, thiserror::Error)]
pub enum RtcError {
    #[error("socket: {0}")]
    Io(#[from] std::io::Error),
    #[error("engine: {0}")]
    Engine(#[from] rtc::shared::error::Error),
    #[error("the bind address must name an interface, not {0}")]
    UnspecifiedBind(SocketAddr),
    #[error("the connection task has stopped")]
    Stopped,
    #[error("TURN server address: {0}")]
    TurnUri(String),
    /// No relay candidate could be gathered although [`IcePolicy::Relay`] needs one.
    #[error("TURN: {0}")]
    Turn(String),
    /// A send on a data channel that is not open (any more), or a message it cannot carry.
    #[error("data channel: {0}")]
    Channel(String),
    /// No local address could be bound.
    #[error("no usable network interface")]
    NoInterface,
}

/// Which local candidates a connection uses (W3C `iceTransportPolicy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IcePolicy {
    /// Host, server-reflexive and (with [`RtcConfig::turn`]) relay candidates.
    #[default]
    All,
    /// Relay candidates only: every datagram goes through the configured TURN server, so the
    /// peer sees that server's address, never ours. Needs [`RtcConfig::turn`]; a connection
    /// whose allocation fails does not start.
    Relay,
}

/// Which local addresses a connection binds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Gather {
    /// The one address of [`RtcConfig::bind`].
    #[default]
    Bound,
    /// Every usable address of every interface, IPv4 and IPv6, as
    /// [`net::select_addresses`] picks and orders them; the port is [`RtcConfig::bind`]'s.
    /// An ICE restart looks again, so it follows the machine from one network to another.
    Interfaces,
}

/// Media this connection sends and receives.
#[derive(Debug, Clone, Default)]
pub struct MediaConfig {
    /// Receive VP8 video (a receive-only transceiver unless `send_vp8` is set too).
    pub recv_vp8: bool,
    /// Receive Opus audio (a receive-only transceiver unless `send_opus` is set too).
    pub recv_opus: bool,
    /// Send a VP8 video track: encoded frames through [`RtcHandle::send_frame`].
    pub send_vp8: bool,
    /// Send an Opus audio track: encoded packets through [`RtcHandle::send_frame`].
    pub send_opus: bool,
}

/// The kind of a local track.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediaKind {
    Audio,
    Video,
}

impl MediaKind {
    fn codec_kind(self) -> RtpCodecKind {
        match self {
            MediaKind::Audio => RtpCodecKind::Audio,
            MediaKind::Video => RtpCodecKind::Video,
        }
    }

    /// The kind of an engine track (`None` for a kind that is neither).
    pub fn of(kind: RtpCodecKind) -> Option<MediaKind> {
        match kind {
            RtpCodecKind::Audio => Some(MediaKind::Audio),
            RtpCodecKind::Video => Some(MediaKind::Video),
            _ => None,
        }
    }
}

/// Send-side congestion control for a connection that carries media: the engine's
/// TWCC-driven GCC (a trendline filter on the delay the peer's transport-wide feedback
/// reports, and AIMD: about 8% a second up, to 85% on overuse, down on loss above 10%). The
/// estimate is reported as [`RtcEvent::TargetBitrate`], and nothing here enforces it: the
/// encoder has to follow it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CongestionConfig {
    /// The estimate never goes under this, in bits per second. It has to cover the audio and
    /// a picture that is still one: at the floor the encoder sends that much whatever the
    /// path does.
    pub min_bps: u32,
    pub max_bps: u32,
}

impl CongestionConfig {
    /// Where the estimate starts (the controller's own start, 300 kbit/s, within the
    /// bounds), and stays with a peer that sends no transport-wide feedback.
    pub fn initial_bps(&self) -> u32 {
        300_000.clamp(self.min_bps, self.max_bps.max(self.min_bps))
    }
}

impl Default for CongestionConfig {
    /// Never under 100 kbit/s (Opus plus a small picture), at most 2.5 Mbit/s.
    fn default() -> Self {
        CongestionConfig {
            min_bps: 100_000,
            max_bps: 2_500_000,
        }
    }
}

/// Payload size of an outgoing RTP packet (headers and SRTP stay under a 1280-byte path MTU).
const RTP_OUTBOUND_MTU: usize = 1200;
/// How often the congestion controller's estimate is read.
const ESTIMATE_INTERVAL: Duration = Duration::from_millis(100);
/// A socket that fails this many receives in a row is closed.
const SOCKET_ERROR_LIMIT: u32 = 32;

/// One connection's configuration.
#[derive(Debug, Clone)]
pub struct RtcConfig {
    /// The address to bind: the one host candidate with [`Gather::Bound`], so it must name an
    /// interface then (`127.0.0.1:0` for loopback tests). With [`Gather::Interfaces`] only
    /// its port is used (0: any).
    pub bind: SocketAddr,
    /// Which addresses get a socket and a host candidate.
    pub gather: Gather,
    /// Where sockets and the interface list come from ([`SystemNetwork`] unless a test
    /// supplies its own).
    pub network: Arc<dyn Network>,
    /// ICE servers recorded in the engine's configuration. The engine gathers nothing itself:
    /// candidates come from [`RtcConfig::stun_servers`] and [`RtcConfig::turn`].
    pub ice_servers: Vec<RTCIceServer>,
    /// STUN servers (`host:port`, or `stun:host:port` URIs) to learn server-reflexive
    /// candidates from before the connection starts (and again on an ICE restart). Each
    /// socket asks the servers' addresses of its own family. Unreachable servers are skipped
    /// after [`RtcConfig::stun_timeout`].
    pub stun_servers: Vec<String>,
    /// How long STUN gathering may take in total.
    pub stun_timeout: Duration,
    /// The user's own TURN server: a relay candidate is allocated on it before the connection
    /// starts and released when it closes. With [`IcePolicy::All`] an unreachable server only
    /// costs that candidate.
    pub turn: Option<TurnServer>,
    /// How long the TURN allocation may take.
    pub turn_timeout: Duration,
    /// The allocation is refreshed at least this often (and at half its lifetime). Short
    /// enough to keep a NAT mapping towards the server alive while the relay carries no
    /// traffic because a direct pair is selected.
    pub turn_keepalive: Duration,
    /// Which candidates are gathered and used.
    pub ice_policy: IcePolicy,
    /// Receive transceivers.
    pub media: MediaConfig,
    /// Run congestion control on what this connection sends (see [`CongestionConfig`]).
    pub congestion: Option<CongestionConfig>,
    /// De-jitter received audio: its RTP packets are delivered in sequence order at an even
    /// pace, held just long enough to cover how late packets have recently been (see
    /// [`jitter::AudioJitterBuffer`]). For connections whose audio is played. Video is never
    /// held: its receiver reassembles frames and has to see late retransmissions.
    pub jitter_buffer: bool,
    /// When making an offer, open a data channel with this label first.
    pub data_channel: Option<String>,
    /// DTLS role taken when answering (the engine's default when `None`).
    pub answering_dtls_role: Option<RTCDtlsRole>,
    /// When our offer and the peer's cross after the connection is established: the polite
    /// side drops its own and answers the peer's, the other side ignores the peer's. The two
    /// ends must be configured differently.
    pub polite: bool,
    /// Capacity of the event channel. RTP events are dropped (and counted) when it is full;
    /// control events wait for room.
    pub event_capacity: usize,
    /// Resolve the peer's mDNS (`*.local`) host candidates with an mDNS query on the local
    /// network. Off: such candidates are dropped (the connection can still succeed through a
    /// server-reflexive or peer-reflexive candidate).
    pub mdns: bool,
    /// Report [`RtcEvent::Quality`] this often once connected (`None`: never).
    pub quality_interval: Option<Duration>,
}

impl Default for RtcConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            gather: Gather::Bound,
            network: Arc::new(SystemNetwork),
            ice_servers: Vec::new(),
            stun_servers: Vec::new(),
            stun_timeout: Duration::from_millis(1500),
            turn: None,
            turn_timeout: Duration::from_secs(5),
            turn_keepalive: Duration::from_secs(25),
            ice_policy: IcePolicy::All,
            media: MediaConfig::default(),
            congestion: None,
            jitter_buffer: false,
            data_channel: None,
            answering_dtls_role: None,
            polite: false,
            event_capacity: 4096,
            mdns: true,
            quality_interval: None,
        }
    }
}

/// The type of one end of the selected candidate pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateKind {
    /// An address of an interface: the two ends are on one network (or one is reachable
    /// directly).
    Host,
    /// The address a NAT gave, learned from a STUN server.
    ServerReflexive,
    /// The address a NAT gave, learned from the peer's connectivity checks.
    PeerReflexive,
    /// An address on a TURN server: the path goes through it.
    Relay,
}

impl CandidateKind {
    fn of(kind: RTCIceCandidateType) -> Option<CandidateKind> {
        match kind {
            RTCIceCandidateType::Host => Some(CandidateKind::Host),
            RTCIceCandidateType::Srflx => Some(CandidateKind::ServerReflexive),
            RTCIceCandidateType::Prflx => Some(CandidateKind::PeerReflexive),
            RTCIceCandidateType::Relay => Some(CandidateKind::Relay),
            _ => None,
        }
    }
}

/// A digest of the engine's statistics, for a connection-quality indicator. Rates and loss
/// cover the time since the previous digest.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ConnectionQuality {
    /// Round trip time of the selected pair (from the last consent or connectivity check),
    /// or of the media (from RTCP), in milliseconds.
    pub rtt_ms: Option<u32>,
    /// The share of what we sent that the peer reported lost (0.0 to 1.0), from its RTCP
    /// receiver reports. `None` before the first report.
    pub loss_sent: Option<f32>,
    /// The share of what the peer sent that did not arrive (0.0 to 1.0) in this interval.
    /// `None` when nothing was expected.
    pub loss_received: Option<f32>,
    /// What we sent and received as RTP, in bits per second.
    pub send_bps: u32,
    pub recv_bps: u32,
    /// The congestion controller's estimate of what the path carries, when it runs.
    pub available_bps: Option<u32>,
    /// The selected pair's two ends.
    pub local_candidate: Option<CandidateKind>,
    pub remote_candidate: Option<CandidateKind>,
    /// How often the transport moved to another candidate pair (1 once connected; an ICE
    /// restart that selects a pair adds one).
    pub path_changes: u32,
}

impl ConnectionQuality {
    /// The path goes through a TURN server.
    pub fn relayed(&self) -> bool {
        self.local_candidate == Some(CandidateKind::Relay)
            || self.remote_candidate == Some(CandidateKind::Relay)
    }
}

/// What the connection reports.
#[derive(Debug)]
pub enum RtcEvent {
    /// A local description to send to the peer through signaling: the first offer or answer
    /// with every gathered candidate in it (non-trickle), and later every offer or answer of
    /// a renegotiation or ICE restart (its `sdp_type` says which).
    LocalDescription(Box<RTCSessionDescription>),
    /// The peer connection's state changed.
    ConnectionState(RTCPeerConnectionState),
    /// The ICE connection state changed.
    IceConnectionState(RTCIceConnectionState),
    /// ICE selected another candidate pair (W3C `selectedcandidatepairchange`). This is how
    /// an ICE restart begun while connected completes: the connection state stays connected
    /// through it (W3C webrtc-pc 5.6.4), and the new generation's pair is selected.
    SelectedCandidatePairChanged,
    /// The first RTP packet of a track arrived; names its kind and negotiated codec.
    Track {
        track_id: MediaStreamTrackId,
        kind: RtpCodecKind,
        mime_type: String,
    },
    /// An RTP packet of a track (after SRTP and the interceptors).
    Rtp {
        track_id: MediaStreamTrackId,
        packet: rtc::rtp::Packet,
    },
    /// A data channel opened.
    DataChannelOpen { id: usize, label: String },
    /// A data-channel message.
    DataChannelMessage { id: usize, payload: BytesMut },
    /// A data channel closed (either side closed it, or the connection is going down).
    DataChannelClose { id: usize },
    /// A data channel's buffered amount fell to its low threshold
    /// ([`DataSender::set_buffered_low`]): the sender may continue.
    DataChannelBufferedLow { id: usize },
    /// The peer asked for a keyframe of our video track (RTCP PLI or FIR).
    KeyframeRequested,
    /// The peer's description changed whether it sends media of `kind` (a video section was
    /// added, or its direction changed): reported after each remote description that changes
    /// it, and for every kind the first one offers.
    RemoteMedia { kind: MediaKind, sending: bool },
    /// The negotiated state of a local track changed: whether the peer accepts our media of
    /// `kind` (false after it was turned off, or when the peer answered without receiving).
    LocalMedia { kind: MediaKind, sending: bool },
    /// The congestion controller's estimate of what may be sent in total, in bits per second
    /// ([`RtcConfig::congestion`]): once when the connection is up and on every change.
    TargetBitrate { bps: u32 },
    /// A digest of the statistics ([`RtcConfig::quality_interval`]).
    Quality(ConnectionQuality),
    /// The peer's offer crossed ours and was dropped (we are not [`RtcConfig::polite`]):
    /// the peer answers ours instead.
    RemoteOfferIgnored,
    /// The task stopped; `error` is set when it stopped on an error.
    Closed { error: Option<String> },
}

enum Command {
    CreateOffer,
    SetRemoteDescription(Box<RTCSessionDescription>),
    AddRemoteCandidate(RTCIceCandidateInit),
    RestartIce,
    SetSending {
        kind: MediaKind,
        enabled: bool,
    },
    Rollback,
    SendData {
        id: usize,
        data: BytesMut,
    },
    SendText {
        id: usize,
        text: String,
    },
    /// Like `SendText`; `acked` is answered once the peer has acknowledged the message.
    SendTextAcked {
        id: usize,
        text: String,
        acked: oneshot::Sender<()>,
    },
    RequestKeyframe {
        track_id: MediaStreamTrackId,
    },
    RequestKeyframes,
    SendFrame {
        kind: MediaKind,
        data: bytes::Bytes,
        samples: u32,
    },
    Stats(oneshot::Sender<(RTCStatsReport, u64)>),
    OpenDataChannel {
        label: String,
    },
    CloseDataChannel {
        id: usize,
    },
    /// Like `SendData`, answered with the bytes the channel then holds unsent.
    SendDataFlow {
        id: usize,
        data: BytesMut,
        reply: oneshot::Sender<Result<usize, RtcError>>,
    },
    SetBufferedLow {
        id: usize,
        bytes: u32,
    },
    BufferedAmount {
        id: usize,
        reply: oneshot::Sender<usize>,
    },
    Quality(oneshot::Sender<ConnectionQuality>),
    LocalAddrs(oneshot::Sender<Vec<SocketAddr>>),
    Close,
}

/// A cloneable handle for one connection's data channels beyond the first: sending with
/// backpressure, and closing. For tasks that stream on a channel of their own (file
/// transfer, PNP-010) while the connection's owner keeps the [`RtcHandle`].
#[derive(Clone)]
pub struct DataSender {
    commands: mpsc::UnboundedSender<Command>,
}

impl DataSender {
    /// Send a binary message on an open channel. Returns the bytes the channel holds unsent
    /// afterwards (W3C `bufferedAmount`, counted until the peer acknowledged them): above
    /// the caller's high mark, wait for [`RtcEvent::DataChannelBufferedLow`] or poll
    /// [`DataSender::buffered_amount`]. An error means the message was not queued.
    pub async fn send(&self, id: usize, data: Vec<u8>) -> Result<usize, RtcError> {
        let (reply, rx) = oneshot::channel();
        self.commands
            .send(Command::SendDataFlow {
                id,
                // No copy: the vector's buffer becomes the message.
                data: BytesMut::from(bytes::Bytes::from(data)),
                reply,
            })
            .map_err(|_| RtcError::Stopped)?;
        rx.await.map_err(|_| RtcError::Stopped)?
    }

    /// The bytes the channel holds unsent; 0 for a channel that is gone.
    pub async fn buffered_amount(&self, id: usize) -> Result<usize, RtcError> {
        let (reply, rx) = oneshot::channel();
        self.commands
            .send(Command::BufferedAmount { id, reply })
            .map_err(|_| RtcError::Stopped)?;
        rx.await.map_err(|_| RtcError::Stopped)
    }

    /// Ask for [`RtcEvent::DataChannelBufferedLow`] whenever the buffered amount falls from
    /// above `bytes` to `bytes` or below.
    pub fn set_buffered_low(&self, id: usize, bytes: u32) -> Result<(), RtcError> {
        self.commands
            .send(Command::SetBufferedLow { id, bytes })
            .map_err(|_| RtcError::Stopped)
    }

    /// Close a data channel; [`RtcEvent::DataChannelClose`] follows on both sides.
    pub fn close_channel(&self, id: usize) -> Result<(), RtcError> {
        self.commands
            .send(Command::CloseDataChannel { id })
            .map_err(|_| RtcError::Stopped)
    }
}

/// A cloneable handle that only sends media frames (for capture / encode threads).
#[derive(Clone)]
pub struct FrameSender {
    commands: mpsc::UnboundedSender<Command>,
}

impl FrameSender {
    /// See [`RtcHandle::send_frame`].
    pub fn send_frame(
        &self,
        kind: MediaKind,
        data: impl Into<bytes::Bytes>,
        samples: u32,
    ) -> Result<(), RtcError> {
        self.commands
            .send(Command::SendFrame {
                kind,
                data: data.into(),
                samples,
            })
            .map_err(|_| RtcError::Stopped)
    }

    /// Ask the sender of every remote video track for a keyframe (RTCP PLI), e.g. when the
    /// decoder lost its reference.
    pub fn request_keyframes(&self) -> Result<(), RtcError> {
        self.commands
            .send(Command::RequestKeyframes)
            .map_err(|_| RtcError::Stopped)
    }
}

/// The application's end of a connection.
pub struct RtcHandle {
    commands: mpsc::UnboundedSender<Command>,
    local_addr: SocketAddr,
    relayed_addr: Option<SocketAddr>,
    task: JoinHandle<()>,
}

impl RtcHandle {
    /// The address of the connection's first (most preferred) UDP socket when it started.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The addresses of the connection's sockets right now, most preferred first.
    pub async fn local_addrs(&self) -> Result<Vec<SocketAddr>, RtcError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::LocalAddrs(tx))?;
        rx.await.map_err(|_| RtcError::Stopped)
    }

    /// The address allocated on the TURN server (the relay candidate), when there is one.
    pub fn relayed_addr(&self) -> Option<SocketAddr> {
        self.relayed_addr
    }

    fn send(&self, command: Command) -> Result<(), RtcError> {
        self.commands.send(command).map_err(|_| RtcError::Stopped)
    }

    /// Make an offer; it arrives as [`RtcEvent::LocalDescription`].
    pub fn create_offer(&self) -> Result<(), RtcError> {
        self.send(Command::CreateOffer)
    }

    /// Apply the peer's description. An offer is answered at once: the answer arrives as
    /// [`RtcEvent::LocalDescription`]. An offer that crosses ours is settled by
    /// [`RtcConfig::polite`]; an answer nobody waits for is dropped.
    pub fn set_remote_description(&self, desc: RTCSessionDescription) -> Result<(), RtcError> {
        self.send(Command::SetRemoteDescription(Box::new(desc)))
    }

    /// Add a trickled remote candidate.
    pub fn add_remote_candidate(&self, candidate: RTCIceCandidateInit) -> Result<(), RtcError> {
        self.send(Command::AddRemoteCandidate(candidate))
    }

    /// Restart ICE (the network changed, or the path stopped working): bind the addresses
    /// the machine has now, gather again, and offer with new ICE credentials. The offer
    /// arrives as [`RtcEvent::LocalDescription`] once the connection's first negotiation is
    /// done and no other exchange is in flight. The session (DTLS, SRTP, SCTP) is kept, and
    /// so is the path it had until the restart selects a new one.
    pub fn restart_ice(&self) -> Result<(), RtcError> {
        self.send(Command::RestartIce)
    }

    /// Start or stop sending our track of `kind` and renegotiate. Starting adds the sender
    /// when the connection has none of that kind (an audio call that gains video); stopping
    /// keeps receiving. The offer arrives as [`RtcEvent::LocalDescription`]; frames of a
    /// stopped kind are dropped.
    pub fn set_sending(&self, kind: MediaKind, enabled: bool) -> Result<(), RtcError> {
        self.send(Command::SetSending { kind, enabled })
    }

    /// Take back our unanswered renegotiation offer (the peer did not answer in time). What
    /// it asked for is forgotten: restart or change the track again to retry.
    pub fn rollback(&self) -> Result<(), RtcError> {
        self.send(Command::Rollback)
    }

    /// Send a binary message on an open data channel.
    pub fn send_data(&self, id: usize, data: impl Into<BytesMut>) -> Result<(), RtcError> {
        self.send(Command::SendData {
            id,
            data: data.into(),
        })
    }

    /// Send a text (UTF-8, WebRTC string PPID) message on an open data channel. Browsers
    /// deliver it to `onmessage` as a string.
    pub fn send_text(&self, id: usize, text: impl Into<String>) -> Result<(), RtcError> {
        self.send(Command::SendText {
            id,
            text: text.into(),
        })
    }

    /// Send a text message on an open data channel and learn when it has arrived: the
    /// returned receiver resolves once the peer's SCTP has acknowledged every byte of the
    /// message (on a reliable channel, which is what [`RtcHandle::open_data_channel`] and
    /// browsers open by default; a channel with limited retransmissions also releases what
    /// it gave up on). It resolves with an error, the sender dropped, when the channel or
    /// the connection ended first: the message may then not have arrived.
    pub fn send_text_acked(
        &self,
        id: usize,
        text: impl Into<String>,
    ) -> Result<oneshot::Receiver<()>, RtcError> {
        let (acked, rx) = oneshot::channel();
        self.send(Command::SendTextAcked {
            id,
            text: text.into(),
            acked,
        })?;
        Ok(rx)
    }

    /// Send one encoded frame on the local track of `kind`: a VP8 frame (`samples` in the
    /// 90 kHz clock, 3000 for 30 fps) or an Opus packet (`samples` at 48 kHz, 960 for 20 ms).
    /// It is packetized and sent once the track is negotiated and the connection is up;
    /// before that it is dropped.
    pub fn send_frame(
        &self,
        kind: MediaKind,
        data: impl Into<bytes::Bytes>,
        samples: u32,
    ) -> Result<(), RtcError> {
        self.send(Command::SendFrame {
            kind,
            data: data.into(),
            samples,
        })
    }

    /// Open one more data channel (reliable, ordered) on a connection whose first channel
    /// is up: it is set up in-band, without a new offer. [`RtcEvent::DataChannelOpen`] names
    /// its id on both sides once it is usable.
    pub fn open_data_channel(&self, label: impl Into<String>) -> Result<(), RtcError> {
        self.send(Command::OpenDataChannel {
            label: label.into(),
        })
    }

    /// Close a data channel; [`RtcEvent::DataChannelClose`] follows.
    pub fn close_data_channel(&self, id: usize) -> Result<(), RtcError> {
        self.send(Command::CloseDataChannel { id })
    }

    /// A handle for streaming on this connection's data channels from another task.
    pub fn data_sender(&self) -> DataSender {
        DataSender {
            commands: self.commands.clone(),
        }
    }

    /// A sender of media frames that can move to another task or thread.
    pub fn frame_sender(&self) -> FrameSender {
        FrameSender {
            commands: self.commands.clone(),
        }
    }

    /// Ask the sender of a video track for a keyframe (RTCP PLI).
    pub fn request_keyframe(&self, track_id: MediaStreamTrackId) -> Result<(), RtcError> {
        self.send(Command::RequestKeyframe { track_id })
    }

    /// The engine's stats report, plus the number of RTP events dropped because the event
    /// channel was full.
    pub async fn stats(&self) -> Result<(RTCStatsReport, u64), RtcError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::Stats(tx))?;
        rx.await.map_err(|_| RtcError::Stopped)
    }

    /// A digest of the stats now (see [`RtcEvent::Quality`] for the periodic one; both share
    /// the interval their rates cover).
    pub async fn quality(&self) -> Result<ConnectionQuality, RtcError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::Quality(tx))?;
        rx.await.map_err(|_| RtcError::Stopped)
    }

    /// Close the connection and wait for its task to finish.
    pub async fn close(self) {
        let _ = self.commands.send(Command::Close);
        let _ = self.task.await;
    }
}

/// One bound socket: a host candidate and what STUN learned for it.
struct Sock {
    socket: Box<dyn DatagramSocket>,
    local: SocketAddr,
    /// RFC 8445 local preference (the address's place in the preference order).
    preference: u16,
    /// Server-reflexive addresses mapping `local`.
    srflx: Vec<SocketAddr>,
    /// Consecutive failed receives.
    errors: u32,
}

fn bind_all(
    network: &dyn Network,
    addrs: &[IpAddr],
    port: u16,
    socks: &mut Vec<Sock>,
) -> Result<(), RtcError> {
    let mut last_error = None;
    for (index, ip) in addrs.iter().enumerate() {
        let preference = net::local_preference(index);
        if let Some(existing) = socks.iter_mut().find(|s| s.local.ip() == *ip) {
            existing.preference = preference;
            continue;
        }
        match network
            .bind(SocketAddr::new(*ip, port))
            .and_then(|socket| Ok((socket.local_addr()?, socket)))
        {
            Ok((local, socket)) => socks.push(Sock {
                socket,
                local,
                preference,
                srflx: Vec::new(),
                errors: 0,
            }),
            Err(err) => {
                tracing::debug!(%ip, %err, "cannot bind a local address");
                last_error = Some(err);
            }
        }
    }
    socks.sort_by(|a, b| b.preference.cmp(&a.preference));
    if socks.is_empty() {
        return Err(last_error.map_or(RtcError::NoInterface, RtcError::Io));
    }
    Ok(())
}

/// Receive on whichever socket has a datagram first (starting at `start`, so that one busy
/// socket does not starve the others): the socket's index and the result.
async fn recv_any(
    socks: &[Sock],
    start: usize,
    buf: &mut [u8],
) -> (usize, std::io::Result<(usize, SocketAddr)>) {
    poll_fn(|cx| {
        for k in 0..socks.len() {
            let i = (start + k) % socks.len();
            if let Poll::Ready(result) = socks[i].socket.poll_recv_from(cx, buf) {
                return Poll::Ready((i, result));
            }
        }
        Poll::Pending
    })
    .await
}

/// Bind the sockets, gather candidates, build the peer connection and start its task.
pub async fn spawn(config: RtcConfig) -> Result<(RtcHandle, mpsc::Receiver<RtcEvent>), RtcError> {
    let relay_only = config.ice_policy == IcePolicy::Relay;
    if relay_only && config.turn.is_none() {
        return Err(RtcError::Turn(
            "relay-only connections need a TURN server".into(),
        ));
    }
    let addrs = match config.gather {
        Gather::Bound => {
            if config.bind.ip().is_unspecified() {
                return Err(RtcError::UnspecifiedBind(config.bind));
            }
            vec![config.bind.ip()]
        }
        Gather::Interfaces => {
            let addrs = net::local_addresses(config.network.as_ref());
            if addrs.is_empty() {
                return Err(RtcError::NoInterface);
            }
            addrs
        }
    };
    let mut socks = Vec::new();
    bind_all(
        config.network.as_ref(),
        &addrs,
        config.bind.port(),
        &mut socks,
    )?;
    let local_addr = socks[0].local;

    // Relay-only talks to nobody but the TURN server: no STUN either.
    let stun_targets = if relay_only {
        Vec::new()
    } else {
        resolve_stun(&config.stun_servers, config.stun_timeout).await
    };
    if let Some(mut gather) = StunGather::new(&socks, &stun_targets, config.stun_timeout, None) {
        gather.run(&socks).await;
        gather.apply(&mut socks);
    }

    let relay = match &config.turn {
        Some(server) => {
            let mut outcome = Err(RtcError::Turn(
                "the TURN server has no address we can reach".into(),
            ));
            // The first socket whose family the server has an address in.
            for sock in &socks {
                outcome = turn::allocate(
                    sock.socket.as_ref(),
                    server,
                    config.turn_timeout,
                    config.turn_keepalive,
                )
                .await;
                if !matches!(&outcome, Err(RtcError::Turn(why)) if why.contains("no address")) {
                    break;
                }
            }
            match outcome {
                Ok(relay) => Some(relay),
                Err(err) if relay_only => return Err(err),
                Err(err) => {
                    tracing::warn!(%err, "no relay candidate; continuing with direct candidates");
                    None
                }
            }
        }
        None => None,
    };
    let relayed_addr = relay.as_ref().map(turn::Relay::relayed);
    let built = build_peer_connection(&config)?;

    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (ev_tx, ev_rx) = mpsc::channel(config.event_capacity.max(16));
    let driver = Driver {
        pc: built.pc,
        socks,
        next_sock: 0,
        gather_mode: config.gather,
        network: config.network.clone(),
        port: config.bind.port(),
        stun_targets,
        stun_timeout: config.stun_timeout,
        gather: None,
        events: ev_tx,
        data_channel: config.data_channel,
        tracks: HashMap::new(),
        audio_jitter: config.jitter_buffer.then(HashMap::new),
        dropped_rtp: 0,
        ack_waits: Vec::new(),
        senders: built
            .senders
            .into_iter()
            .map(|(kind, id)| {
                (
                    kind,
                    LocalSender {
                        id,
                        packetizer: None,
                        enabled: true,
                    },
                )
            })
            .collect(),
        codecs: built.codecs,
        ever_connected: false,
        mdns_enabled: config.mdns && !relay_only,
        mdns: None,
        mdns_answers: 0,
        relay,
        relay_only,
        polite: config.polite,
        negotiation: Negotiation::default(),
        remote_sending: HashMap::new(),
        local_sending: HashMap::new(),
        congestion: config.congestion,
        estimate: built.estimate,
        last_target: None,
        next_estimate: None,
        quality_interval: config.quality_interval,
        next_quality: None,
        quality_base: QualityBase::default(),
    };
    let task = tokio::spawn(driver.run(cmd_rx));
    Ok((
        RtcHandle {
            commands: cmd_tx,
            local_addr,
            relayed_addr,
            task,
        },
        ev_rx,
    ))
}

fn video_feedback() -> Vec<RTCPFeedback> {
    [
        ("goog-remb", ""),
        ("ccm", "fir"),
        ("nack", ""),
        ("nack", "pli"),
    ]
    .into_iter()
    .map(|(typ, parameter)| RTCPFeedback {
        typ: typ.to_owned(),
        parameter: parameter.to_owned(),
    })
    .collect()
}

type Senders = Vec<(MediaKind, RTCRtpSenderId)>;

/// The two codecs a connection speaks.
struct Codecs {
    vp8: RTCRtpCodec,
    opus: RTCRtpCodec,
}

impl Codecs {
    fn of(&self, kind: MediaKind) -> &RTCRtpCodec {
        match kind {
            MediaKind::Audio => &self.opus,
            MediaKind::Video => &self.vp8,
        }
    }
}

struct Built {
    pc: RTCPeerConnection,
    senders: Senders,
    codecs: Codecs,
    /// The congestion controller's estimate, when it runs.
    estimate: Option<GccHandle>,
}

fn local_track(kind: MediaKind, codec: &RTCRtpCodec) -> MediaStreamTrack {
    let name = match kind {
        MediaKind::Audio => "audio",
        MediaKind::Video => "video",
    };
    MediaStreamTrack::new(
        "parolnet".to_owned(),
        format!("parolnet-{name}"),
        format!("parolnet-{name}"),
        kind.codec_kind(),
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(rand_ssrc()),
                // Video is repaired on a retransmission stream of its own (RFC 4588), when
                // the peer negotiates it.
                rtx: (kind == MediaKind::Video).then(|| RTCRtpRtxParameters { ssrc: rand_ssrc() }),
                ..Default::default()
            },
            codec: codec.clone(),
            ..Default::default()
        }],
    )
}

/// A random SSRC (RFC 3550 §8.1) without pulling in a RNG crate: the std hasher is seeded
/// randomly per process, mixed with the time and a counter.
fn rand_ssrc() -> u32 {
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    );
    (h.finish() as u32).max(1)
}

fn build_peer_connection(config: &RtcConfig) -> Result<Built, RtcError> {
    let vp8 = RTCRtpCodec {
        mime_type: MIME_TYPE_VP8.to_owned(),
        clock_rate: 90_000,
        channels: 0,
        sdp_fmtp_line: String::new(),
        rtcp_feedback: video_feedback(),
    };
    let opus = RTCRtpCodec {
        mime_type: MIME_TYPE_OPUS.to_owned(),
        clock_rate: 48_000,
        channels: 2,
        sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
        rtcp_feedback: vec![],
    };
    let mut media_engine = MediaEngine::default();
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: vp8.clone(),
            payload_type: 96,
        },
        RtpCodecKind::Video,
    )?;
    // RTX for VP8 (RFC 4588), as browsers offer it. A retransmission then travels as a new
    // packet of its own stream. Without it a lost packet is sent again under its old sequence
    // number, which the engine's SRTP refuses once the packet's bytes differ from the first
    // transmission, and with transport-wide sequence numbers they always do.
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: MIME_TYPE_RTX.to_owned(),
                clock_rate: 90_000,
                channels: 0,
                sdp_fmtp_line: "apt=96".to_owned(),
                rtcp_feedback: vec![],
            },
            payload_type: 97,
        },
        RtpCodecKind::Video,
    )?;
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: opus.clone(),
            payload_type: 111,
        },
        RtpCodecKind::Audio,
    )?;
    // The engine's default set (`register_default_interceptors`), spelled out so that the
    // transport-wide feedback half can be the receiver alone or, with congestion control,
    // both halves under the congestion controller.
    let registry = configure_nack(Registry::new(), &mut media_engine);
    configure_simulcast_extension_headers(&mut media_engine)?;
    let registry = configure_rtcp_reports(registry);
    configure_receiver_reference_time(&mut media_engine);
    let registry = configure_key_frame_requests(registry);
    let mut estimate = None;
    let registry = match config.congestion {
        Some(cc) => {
            // The fork's TWCC-driven GCC (trendline filter and AIMD): it numbers nothing and
            // paces nothing, it reads the transport-wide feedback and publishes an estimate.
            let (gcc, handle) = GccInterceptorBuilder::new();
            estimate = Some(handle);
            configure_twcc(registry, &mut media_engine)?.with(
                Slot::CongestionControl,
                // Around a pass-through: a `NoopInterceptor` there would end the inbound
                // RTCP of every slot after this one.
                PassThroughInterceptor::new().with(
                    gcc.with_min_bitrate(cc.min_bps)
                        .with_max_bitrate(cc.max_bps)
                        .build(),
                ),
            )
        }
        None => configure_twcc_receiver_only(registry, &mut media_engine)?,
    };

    let relay_only = config.ice_policy == IcePolicy::Relay;
    // A relay cannot reach a `.local` host on the peer's network: no mDNS when relay-only.
    let mut settings = SettingEngineBuilder::new()
        .with_multicast_dns_mode(if config.mdns && !relay_only {
            MulticastDnsMode::QueryOnly
        } else {
            MulticastDnsMode::Disabled
        })
        // A restart announces the sockets bound then, not those of the network left behind.
        .with_discard_local_candidates_during_ice_restart(true)
        // This driver gathers every candidate itself (host sockets, STUN, its own TURN
        // client). The engine's own gathering, on by default since v0.22.0+brainwires.6, is
        // kept off so nothing changes behind it: no TCP candidates or ICE-TCP listeners
        // (`with_tcp_candidate_gathering`), no TURN over TCP / TLS
        // (`with_turn_over_streams`, `with_turn_tcp_relay`), no Binding requests or TURN
        // allocations from our sockets to the configuration's servers
        // (`with_server_reflexive_gathering`, `with_relay_gathering`).
        .with_tcp_candidate_gathering(false)
        .with_turn_over_streams(false)
        .with_turn_tcp_relay(false)
        .with_server_reflexive_gathering(ReflexiveGathering::Application)
        .with_relay_gathering(RelayGathering::Application)
        // Data-channel messages keep their size: PNP-010 records are up to 64 KiB and a chat
        // frame carries a hex envelope of up to 16 KiB (about 32 KiB of text), so the RFC
        // 8831 section 6.6 limit of 16 KB without interleaving, on by default since
        // v0.22.0+brainwires.6, would refuse them towards every browser
        // (`with_sctp_message_size_limit_without_interleaving(false)`: what browsers do).
        // Interleaving (RFC 8260) is not announced, so two ParolNet peers keep sending DATA
        // chunks as before (`with_sctp_message_interleaving(false)`).
        .with_sctp_message_size_limit_without_interleaving(false)
        .with_sctp_message_interleaving(false)
        // As controlled agent, follow the latest nomination (libwebrtc's rule) as the engine
        // did since v0.22.0+brainwires.5: Chromium moves to another pair a moment after
        // connecting and stops answering on the one it left, which under the RFC 8445
        // section 8.1.1 default (the highest-priority nominated pair) stopped the PWA's calls
        // (`with_ice_nomination_acceptance`).
        .with_ice_nomination_acceptance(NominationAcceptance::Latest);
    if let Some(role) = config.answering_dtls_role {
        settings = settings.with_answering_dtls_role(role);
    }
    let rtc_config = RTCConfigurationBuilder::new()
        .with_ice_servers(config.ice_servers.clone())
        .with_ice_transport_policy(if relay_only {
            RTCIceTransportPolicy::Relay
        } else {
            RTCIceTransportPolicy::All
        })
        .build();

    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(rtc_config)
        .with_setting_engine(settings.build())
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(now())?;

    let recvonly = || {
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            ..Default::default()
        })
    };
    // Audio before video, as browsers order getUserMedia's tracks.
    let mut senders = Vec::new();
    if config.media.send_opus {
        let id = pc.add_track(local_track(MediaKind::Audio, &opus))?;
        senders.push((MediaKind::Audio, id));
    } else if config.media.recv_opus {
        pc.add_transceiver_from_kind(RtpCodecKind::Audio, recvonly())?;
    }
    if config.media.send_vp8 {
        let id = pc.add_track(local_track(MediaKind::Video, &vp8))?;
        senders.push((MediaKind::Video, id));
    } else if config.media.recv_vp8 {
        pc.add_transceiver_from_kind(RtpCodecKind::Video, recvonly())?;
    }
    Ok(Built {
        pc,
        senders,
        codecs: Codecs { vp8, opus },
        estimate,
    })
}

/// A local track's sender.
struct LocalSender {
    id: RTCRtpSenderId,
    /// Made once the track is negotiated.
    packetizer: Option<Box<dyn Packetizer>>,
    /// The application wants this track sent.
    enabled: bool,
}

/// What an offer of ours carries beyond the session as it is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Wanted {
    /// New ICE credentials and candidates.
    restart: bool,
    /// A track or direction changed.
    media: bool,
}

impl Wanted {
    fn any(self) -> bool {
        self.restart || self.media
    }
}

/// Where the offer / answer exchange is.
#[derive(Default)]
struct Negotiation {
    /// The first exchange finished: both descriptions are applied.
    established: bool,
    /// Our offer is out and unanswered: what it asked for.
    in_flight: Option<Wanted>,
    /// The peer's offer is applied and our answer is not made yet (gathering).
    answering: bool,
    /// What the next offer has to carry.
    wanted: Wanted,
}

/// What follows a STUN gathering round that runs inside the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AfterGather {
    Offer,
    Answer,
}

/// Counters the quality digest takes differences of.
#[derive(Default)]
struct QualityBase {
    at: Option<Instant>,
    bytes_sent: u64,
    bytes_received: u64,
    packets_received: u64,
    packets_lost: i64,
    last: ConnectionQuality,
}

/// A message whose acknowledgement someone waits for.
struct AckWait {
    /// The data channel it was sent on.
    id: usize,
    /// Bytes given to that channel after this message. The channel's outstanding bytes
    /// (sent and not yet acknowledged) are released in the order they were sent, so the
    /// message is acknowledged once no more than these are outstanding.
    after: usize,
    acked: oneshot::Sender<()>,
}

struct Driver {
    pc: RTCPeerConnection,
    /// The bound sockets, most preferred first.
    socks: Vec<Sock>,
    /// Where the next receive starts looking.
    next_sock: usize,
    gather_mode: Gather,
    network: Arc<dyn Network>,
    port: u16,
    /// The STUN servers' addresses (both families), resolved when the connection started.
    stun_targets: Vec<SocketAddr>,
    stun_timeout: Duration,
    /// STUN gathering for an ICE restart, running inside the loop.
    gather: Option<StunGather>,
    events: mpsc::Sender<RtcEvent>,
    data_channel: Option<String>,
    /// track id → (receiver, whether its first packet was reported)
    tracks: HashMap<MediaStreamTrackId, (RTCRtpReceiverId, bool)>,
    /// Audio tracks whose packets are de-jittered before they are delivered.
    audio_jitter: Option<HashMap<MediaStreamTrackId, jitter::AudioJitterBuffer>>,
    dropped_rtp: u64,
    /// Messages sent with [`RtcHandle::send_text_acked`] that the peer has not acknowledged
    /// yet, oldest first.
    ack_waits: Vec<AckWait>,
    /// Local tracks.
    senders: HashMap<MediaKind, LocalSender>,
    codecs: Codecs,
    /// The peer connection reached `connected` once (SRTP keys exist). An ICE restart takes
    /// the state back to `connecting` while the session, and the path it had, stay usable.
    ever_connected: bool,
    /// Whether remote `.local` candidates are resolved.
    mdns_enabled: bool,
    /// The multicast socket for mDNS queries, opened on the first remote `.local` candidate.
    mdns: Option<UdpSocket>,
    /// mDNS datagrams received (answers to our queries, and other hosts' traffic).
    mdns_answers: u64,
    /// The allocation on the user's TURN server, when there is one.
    relay: Option<turn::Relay>,
    /// [`IcePolicy::Relay`]: nothing is sent to, or accepted from, anyone but the TURN server.
    relay_only: bool,
    polite: bool,
    negotiation: Negotiation,
    /// Whether the peer's description sends each kind, as last reported.
    remote_sending: HashMap<MediaKind, bool>,
    /// Whether our tracks are negotiated to send, as last reported.
    local_sending: HashMap<MediaKind, bool>,
    congestion: Option<CongestionConfig>,
    estimate: Option<GccHandle>,
    /// The last estimate reported.
    last_target: Option<u32>,
    next_estimate: Option<Instant>,
    quality_interval: Option<Duration>,
    next_quality: Option<Instant>,
    quality_base: QualityBase,
}

/// The longest the loop sleeps when the engine names no deadline.
const IDLE_WAKE: Duration = Duration::from_secs(1);

/// Why the loop woke.
enum Wake {
    Command(Option<Command>),
    Timer,
    Datagram(usize, std::io::Result<(usize, SocketAddr)>),
    Mdns(std::io::Result<(usize, SocketAddr)>),
}

impl Driver {
    async fn run(mut self, mut commands: mpsc::UnboundedReceiver<Command>) {
        let error = self
            .event_loop(&mut commands)
            .await
            .err()
            .map(|e| e.to_string());
        let _ = self.pc.close();
        if let Some(relay) = self.relay.take()
            && let Some(sock) = self.socks.iter().find(|s| s.local == relay.local())
        {
            relay.release(sock.socket.as_ref()).await;
        }
        let _ = self.events.send(RtcEvent::Closed { error }).await;
    }

    async fn event_loop(
        &mut self,
        commands: &mut mpsc::UnboundedReceiver<Command>,
    ) -> Result<(), RtcError> {
        let mut buf = vec![0u8; 2048];
        let mut mdns_buf = vec![0u8; 2048];
        loop {
            self.flush_writes().await;
            if self.drain_events().await? {
                return Ok(());
            }
            self.drain_reads().await;
            self.release_acks();

            let now = now();
            let relay_deadline = self.relay.as_mut().and_then(turn::Relay::poll_timeout);
            if let Some(relay) = self.relay.as_mut()
                && relay_deadline.is_some_and(|t| t <= now)
            {
                relay.handle_timeout(now);
                continue;
            }
            if self.gather.as_ref().is_some_and(|g| g.wake() <= now) {
                self.drive_gather(now).await?;
                continue;
            }
            self.release_audio(now);
            if self.next_estimate.is_some_and(|t| t <= now) {
                self.report_estimate(now).await;
                continue;
            }
            if self.next_quality.is_some_and(|t| t <= now) {
                let quality = self.digest(now);
                self.next_quality = self.quality_interval.map(|every| now + every);
                self.emit(RtcEvent::Quality(quality)).await;
                continue;
            }
            let deadline = self.pc.poll_timeout().unwrap_or(now + IDLE_WAKE);
            if deadline <= now {
                self.pc.handle_timeout(now)?;
                continue;
            }
            let deadline = [
                relay_deadline,
                self.gather.as_ref().map(StunGather::wake),
                self.next_estimate,
                self.next_quality,
                self.next_audio_release(),
            ]
            .into_iter()
            .flatten()
            .fold(deadline, Instant::min);

            let start = self.next_sock;
            let wake = tokio::select! {
                biased;
                command = commands.recv() => Wake::Command(command),
                // The loop's next pass runs whichever timer is due.
                _ = tokio::time::sleep_until(deadline.into()) => Wake::Timer,
                (index, received) = recv_any(&self.socks, start, &mut buf) => {
                    Wake::Datagram(index, received)
                }
                received = recv_optional(self.mdns.as_ref(), &mut mdns_buf) => Wake::Mdns(received),
            };
            match wake {
                Wake::Command(None | Some(Command::Close)) => return Ok(()),
                Wake::Command(Some(command)) => self.handle_command(command).await?,
                Wake::Timer => {}
                Wake::Datagram(index, received) => {
                    self.next_sock = index + 1;
                    match received {
                        Ok((n, peer_addr)) => {
                            self.socks[index].errors = 0;
                            self.on_datagram(index, peer_addr, &buf[..n]);
                        }
                        Err(err) => self.on_socket_error(index, err)?,
                    }
                }
                Wake::Mdns(received) => {
                    let (n, peer_addr) = received?;
                    self.mdns_answers += 1;
                    if self.mdns_answers == 1 {
                        tracing::info!(%peer_addr, "mDNS traffic received");
                    }
                    let local_addr = self
                        .mdns
                        .as_ref()
                        .and_then(|s| s.local_addr().ok())
                        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], MDNS_PORT)));
                    // Other hosts' mDNS traffic arrives here too; the engine ignores it.
                    if let Err(err) = self.pc.handle_read(TaggedBytesMut {
                        now: crate::now(),
                        transport: TransportContext {
                            local_addr,
                            peer_addr,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: BytesMut::from(&mdns_buf[..n]),
                    }) {
                        tracing::trace!(%peer_addr, %err, "mDNS datagram rejected");
                    }
                }
            }
        }
    }

    /// A datagram on socket `index`: the TURN server's, a STUN server's answer to a gathering
    /// round, or the peer's.
    fn on_datagram(&mut self, index: usize, peer_addr: SocketAddr, data: &[u8]) {
        let local_addr = self.socks[index].local;
        if let Some(relay) = self.relay.as_mut()
            && relay.server() == peer_addr
            && relay.local() == local_addr
        {
            relay.handle_datagram(data);
            return;
        }
        if self.relay_only {
            // Answering would show the sender our address.
            return;
        }
        if let Some(gather) = self.gather.as_mut()
            && gather.handle(local_addr, peer_addr, data)
        {
            return;
        }
        // A malformed or unexpected datagram is the peer's problem, not ours.
        if let Err(err) = self.pc.handle_read(TaggedBytesMut {
            now: now(),
            transport: TransportContext {
                local_addr,
                peer_addr,
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(data),
        }) {
            tracing::debug!(%peer_addr, %err, "datagram rejected");
        }
    }

    /// A receive failed. One socket of several may go with its interface; the connection
    /// goes on with the others (and an ICE restart replaces it). The last one failing for
    /// good ends the connection.
    fn on_socket_error(&mut self, index: usize, err: std::io::Error) -> Result<(), RtcError> {
        let sock = &mut self.socks[index];
        sock.errors += 1;
        tracing::debug!(local = %sock.local, %err, errors = sock.errors, "receive failed");
        if sock.errors < SOCKET_ERROR_LIMIT {
            return Ok(());
        }
        if self.socks.len() == 1 {
            return Err(RtcError::Io(err));
        }
        let gone = self.socks.remove(index);
        if self
            .relay
            .as_ref()
            .is_some_and(|relay| relay.local() == gone.local)
        {
            self.relay = None;
            if self.relay_only {
                return Err(RtcError::Turn(
                    "the socket of the relay allocation failed".into(),
                ));
            }
        }
        Ok(())
    }

    fn sock_for(&self, local: SocketAddr) -> Option<&Sock> {
        self.socks.iter().find(|s| s.local == local)
    }

    async fn flush_writes(&mut self) {
        self.deliver_relayed();
        while let Some(msg) = self.pc.poll_write() {
            if let Some(relay) = self.relay.as_mut()
                && msg.transport.local_addr == relay.relayed()
            {
                relay.send(now(), msg.message, msg.transport.peer_addr);
                continue;
            }
            if self.relay_only {
                continue;
            }
            if msg.transport.peer_addr.port() == MDNS_PORT
                && msg.transport.peer_addr.ip().is_multicast()
            {
                // An mDNS query for a remote `.local` candidate.
                if let Some(mdns) = self.mdns.as_ref()
                    && let Err(err) = mdns.send_to(&msg.message, msg.transport.peer_addr).await
                {
                    tracing::debug!(%err, "mDNS query not sent");
                }
                continue;
            }
            // From the socket the engine names: the candidate pair's local end. A pair on a
            // socket that is gone (its interface left) has nowhere to go.
            let Some(sock) = self.sock_for(msg.transport.local_addr) else {
                continue;
            };
            if let Err(err) =
                net::send_to(sock.socket.as_ref(), &msg.message, msg.transport.peer_addr).await
            {
                tracing::debug!(peer = %msg.transport.peer_addr, %err, "send failed");
            }
        }
        if let Some(relay) = self.relay.as_mut() {
            let local = relay.local();
            let mut out = Vec::new();
            while let Some(datagram) = relay.poll_write() {
                out.push(datagram);
            }
            if let Some(sock) = self.socks.iter().find(|s| s.local == local) {
                for (data, to) in out {
                    if let Err(err) = net::send_to(sock.socket.as_ref(), &data, to).await {
                        tracing::debug!(%err, "send to the TURN server failed");
                    }
                }
            }
        }
    }

    /// Hand the engine what peers sent to the relayed address (it arrives there as if on a
    /// socket bound to that address).
    fn deliver_relayed(&mut self) {
        let Some(relay) = self.relay.as_mut() else {
            return;
        };
        let now = now();
        let local_addr = relay.relayed();
        for (peer_addr, message) in relay.poll_inbound(now) {
            if let Err(err) = self.pc.handle_read(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr,
                    peer_addr,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message,
            }) {
                tracing::debug!(%peer_addr, %err, "relayed datagram rejected");
            }
        }
    }

    /// `len` more bytes were given to data channel `id`: they are behind every message of
    /// that channel whose acknowledgement is still awaited.
    fn note_sent(&mut self, id: usize, len: usize) {
        for wait in self.ack_waits.iter_mut().filter(|w| w.id == id) {
            wait.after = wait.after.saturating_add(len);
        }
    }

    /// Answer the [`RtcHandle::send_text_acked`] messages the peer has acknowledged since
    /// the last pass, and forget those whose channel is gone (their senders are dropped:
    /// not acknowledged).
    fn release_acks(&mut self) {
        if self.ack_waits.is_empty() {
            return;
        }
        for wait in std::mem::take(&mut self.ack_waits) {
            match self.pc.data_channel(wait.id).map(|c| c.outstanding_bytes()) {
                Some(outstanding) if outstanding <= wait.after => {
                    let _ = wait.acked.send(());
                }
                Some(_) => self.ack_waits.push(wait),
                None => {}
            }
        }
    }

    async fn emit(&mut self, event: RtcEvent) {
        let _ = self.events.send(event).await;
    }

    /// Returns true when the connection failed or closed.
    async fn drain_events(&mut self) -> Result<bool, RtcError> {
        while let Some(event) = self.pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    if state == RTCPeerConnectionState::Connected && !self.ever_connected {
                        self.ever_connected = true;
                        let now = now();
                        if let Some(cc) = self.congestion {
                            let bps = cc.initial_bps();
                            self.last_target = Some(bps);
                            self.next_estimate = Some(now + ESTIMATE_INTERVAL);
                            self.emit(RtcEvent::TargetBitrate { bps }).await;
                        }
                        self.next_quality = self.quality_interval.map(|every| now + every);
                    }
                    self.emit(RtcEvent::ConnectionState(state)).await;
                    if matches!(
                        state,
                        RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed
                    ) {
                        return Ok(true);
                    }
                }
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                    self.emit(RtcEvent::IceConnectionState(state)).await;
                }
                RTCPeerConnectionEvent::OnSelectedCandidatePairChange(_) => {
                    self.emit(RtcEvent::SelectedCandidatePairChanged).await;
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                    self.tracks.insert(init.track_id, (init.receiver_id, false));
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnClose(track_id)) => {
                    self.tracks.remove(&track_id);
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                    let label = self
                        .pc
                        .data_channel(id)
                        .map(|dc| dc.label().to_owned())
                        .unwrap_or_default();
                    self.emit(RtcEvent::DataChannelOpen { id, label }).await;
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(id)) => {
                    self.emit(RtcEvent::DataChannelClose { id }).await;
                }
                RTCPeerConnectionEvent::OnDataChannel(
                    RTCDataChannelEvent::OnBufferedAmountLow(id),
                ) => {
                    self.emit(RtcEvent::DataChannelBufferedLow { id }).await;
                }
                _ => {}
            }
        }
        Ok(false)
    }

    async fn drain_reads(&mut self) {
        while let Some(TaggedRTCMessage { message, .. }) = self.pc.poll_read() {
            match message {
                RTCMessage::RtpPacket(track_id, packet) => {
                    let kind = self.report_track(&track_id).await;
                    if kind == Some(RtpCodecKind::Audio)
                        && let Some(buffers) = self.audio_jitter.as_mut()
                    {
                        let clock_rate = self.codecs.opus.clock_rate;
                        buffers
                            .entry(track_id)
                            .or_insert_with(|| jitter::AudioJitterBuffer::new(clock_rate))
                            .push(now(), packet);
                        continue;
                    }
                    let event = RtcEvent::Rtp { track_id, packet };
                    if self.events.try_send(event).is_err() {
                        self.dropped_rtp += 1;
                    }
                }
                RTCMessage::RtcpPacket(_track_id, packets) => {
                    let wants_keyframe = packets.iter().any(|p| {
                        p.as_any().is::<PictureLossIndication>()
                            || p.as_any().is::<FullIntraRequest>()
                    });
                    if wants_keyframe && self.senders.contains_key(&MediaKind::Video) {
                        self.emit(RtcEvent::KeyframeRequested).await;
                    }
                }
                RTCMessage::DataChannelMessage(id, message) => {
                    self.emit(RtcEvent::DataChannelMessage {
                        id,
                        payload: message.data,
                    })
                    .await;
                }
                _ => {}
            }
        }
    }

    /// Deliver the de-jittered audio packets whose time has come.
    fn release_audio(&mut self, now: Instant) {
        let Some(buffers) = self.audio_jitter.as_mut() else {
            return;
        };
        for (track_id, buffer) in buffers.iter_mut() {
            while let Some(packet) = buffer.pop(now) {
                let event = RtcEvent::Rtp {
                    track_id: track_id.clone(),
                    packet,
                };
                if self.events.try_send(event).is_err() {
                    self.dropped_rtp += 1;
                }
            }
        }
    }

    fn next_audio_release(&self) -> Option<Instant> {
        self.audio_jitter
            .as_ref()?
            .values()
            .filter_map(jitter::AudioJitterBuffer::next_release)
            .min()
    }

    /// Reports a track's kind and codec on its first packet (they are known only once the
    /// stream's SSRC is bound). Returns the track's kind.
    async fn report_track(&mut self, track_id: &MediaStreamTrackId) -> Option<RtpCodecKind> {
        let (receiver_id, reported) = self.tracks.get(track_id).copied()?;
        let receiver = self.pc.rtp_receiver(receiver_id)?;
        let track = receiver.track();
        let kind = track.kind();
        if reported {
            return Some(kind);
        }
        let mime_type = track
            .ssrcs()
            .next()
            .and_then(|ssrc| track.codec(ssrc))
            .map(|codec| codec.mime_type.clone())
            .unwrap_or_default();
        self.tracks.insert(track_id.clone(), (receiver_id, true));
        self.emit(RtcEvent::Track {
            track_id: track_id.clone(),
            kind,
            mime_type,
        })
        .await;
        Some(kind)
    }

    async fn handle_command(&mut self, command: Command) -> Result<(), RtcError> {
        let now = now();
        match command {
            Command::CreateOffer => {
                if self.negotiation.established || self.negotiation.in_flight.is_some() {
                    return Ok(());
                }
                if let Some(label) = self.data_channel.take() {
                    self.pc.create_data_channel(&label, None)?;
                }
                let offer = self.pc.create_offer(None)?;
                self.pc.set_local_description(now, offer)?;
                self.add_local_candidates()?;
                self.negotiation.in_flight = Some(Wanted::default());
                self.emit_local_description().await;
            }
            Command::SetRemoteDescription(desc) => self.on_remote_description(*desc).await?,
            Command::AddRemoteCandidate(candidate) => {
                if has_mdns_candidate(&candidate.candidate) {
                    self.open_mdns();
                }
                self.pc.add_remote_candidate(candidate)?;
            }
            Command::RestartIce => {
                self.negotiation.wanted.restart = true;
                self.negotiate_if_ready().await?;
            }
            Command::SetSending { kind, enabled } => {
                if self.set_sending(kind, enabled)? {
                    self.negotiation.wanted.media = true;
                    self.negotiate_if_ready().await?;
                }
            }
            Command::Rollback => {
                if self.negotiation.established && self.negotiation.in_flight.take().is_some() {
                    self.pc
                        .set_local_description(now, RTCSessionDescription::rollback(None)?)?;
                    self.forget_unnegotiated_tracks();
                    self.report_local_media().await;
                }
            }
            Command::SendData { id, data } => {
                if let Some(mut channel) = self.pc.data_channel(id) {
                    let len = data.len();
                    channel.send(now, data)?;
                    self.note_sent(id, len);
                }
            }
            Command::SendText { id, text } => {
                if let Some(mut channel) = self.pc.data_channel(id) {
                    let len = text.len();
                    channel.send_text(now, text)?;
                    self.note_sent(id, len);
                }
            }
            Command::SendTextAcked { id, text, acked } => {
                // Without the channel `acked` is dropped here: not sent, not acknowledged.
                if let Some(mut channel) = self.pc.data_channel(id) {
                    let len = text.len();
                    channel.send_text(now, text)?;
                    self.note_sent(id, len);
                    self.ack_waits.push(AckWait {
                        id,
                        after: 0,
                        acked,
                    });
                }
            }
            Command::RequestKeyframe { track_id } => {
                if let Some((receiver_id, _)) = self.tracks.get(&track_id).copied()
                    && let Some(mut receiver) = self.pc.rtp_receiver(receiver_id)
                    && let Some(media_ssrc) = { receiver.track().ssrcs().next() }
                {
                    receiver.write_rtcp(
                        now,
                        vec![Box::new(PictureLossIndication {
                            sender_ssrc: 0,
                            media_ssrc,
                        })],
                    )?;
                }
            }
            Command::RequestKeyframes => {
                let tracks: Vec<MediaStreamTrackId> = self.tracks.keys().cloned().collect();
                for track_id in tracks {
                    if let Some((receiver_id, _)) = self.tracks.get(&track_id).copied()
                        && let Some(mut receiver) = self.pc.rtp_receiver(receiver_id)
                        && receiver.track().kind() == RtpCodecKind::Video
                        && let Some(media_ssrc) = { receiver.track().ssrcs().next() }
                    {
                        receiver.write_rtcp(
                            now,
                            vec![Box::new(PictureLossIndication {
                                sender_ssrc: 0,
                                media_ssrc,
                            })],
                        )?;
                    }
                }
            }
            Command::SendFrame {
                kind,
                data,
                samples,
            } => {
                if self.ever_connected
                    && let Err(err) = self.send_frame(now, kind, &data, samples)
                {
                    tracing::debug!(?kind, %err, "frame not sent");
                }
            }
            Command::Stats(reply) => {
                let report = self.pc.get_stats(now, StatsSelector::None);
                let _ = reply.send((report, self.dropped_rtp));
            }
            // The commands below never end the connection: a channel that is gone, or a
            // message it cannot carry, is that channel's problem.
            Command::OpenDataChannel { label } => {
                if let Err(err) = self.pc.create_data_channel(&label, None) {
                    tracing::debug!(%err, "data channel not opened");
                }
            }
            Command::CloseDataChannel { id } => {
                if let Some(mut channel) = self.pc.data_channel(id)
                    && let Err(err) = channel.close()
                {
                    tracing::debug!(id, %err, "data channel not closed");
                }
            }
            Command::SendDataFlow { id, data, reply } => {
                let len = data.len();
                let result = match self.pc.data_channel(id) {
                    Some(mut channel) => channel
                        .send(now, data)
                        .map(|()| channel.outstanding_bytes())
                        .map_err(|e| RtcError::Channel(e.to_string())),
                    None => Err(RtcError::Channel("closed".into())),
                };
                if result.is_ok() {
                    self.note_sent(id, len);
                }
                let _ = reply.send(result);
            }
            Command::SetBufferedLow { id, bytes } => {
                if let Some(mut channel) = self.pc.data_channel(id) {
                    channel.set_buffered_amount_low_threshold(bytes);
                }
            }
            Command::BufferedAmount { id, reply } => {
                let amount = self
                    .pc
                    .data_channel(id)
                    .map_or(0, |channel| channel.outstanding_bytes());
                let _ = reply.send(amount);
            }
            Command::Quality(reply) => {
                let quality = self.digest(now);
                let _ = reply.send(quality);
            }
            Command::LocalAddrs(reply) => {
                let _ = reply.send(self.socks.iter().map(|s| s.local).collect());
            }
            Command::Close => {}
        }
        Ok(())
    }

    // ── Negotiation ───────────────────────────────────────────────

    /// The peer's description: its answer to our offer, or an offer (the first one, a
    /// renegotiation or an ICE restart) that we answer.
    async fn on_remote_description(&mut self, desc: RTCSessionDescription) -> Result<(), RtcError> {
        let now = now();
        match desc.sdp_type {
            RTCSdpType::Answer | RTCSdpType::Pranswer => {
                if self.negotiation.in_flight.is_none() {
                    tracing::debug!("an answer nobody waits for; dropped");
                    return Ok(());
                }
                if has_mdns_candidate(&desc.sdp) {
                    self.open_mdns();
                }
                let sdp = desc.sdp.clone();
                self.pc.set_remote_description(now, desc)?;
                self.negotiation.in_flight = None;
                self.negotiation.established = true;
                self.report_remote_media(&sdp).await;
                self.report_local_media().await;
                self.negotiate_if_ready().await
            }
            RTCSdpType::Offer => {
                if let Some(ours) = self.negotiation.in_flight {
                    // The offers crossed.
                    if !self.polite || !self.negotiation.established {
                        tracing::debug!("the peer's offer crossed ours; keeping ours");
                        self.emit(RtcEvent::RemoteOfferIgnored).await;
                        return Ok(());
                    }
                    tracing::debug!("the peer's offer crossed ours; taking theirs");
                    self.pc
                        .set_local_description(now, RTCSessionDescription::rollback(None)?)?;
                    self.negotiation.in_flight = None;
                    self.negotiation.wanted.restart |= ours.restart;
                    self.negotiation.wanted.media |= ours.media;
                }
                // Our own restart was still gathering: the peer's restart does its job.
                self.gather = None;
                if has_mdns_candidate(&desc.sdp) {
                    self.open_mdns();
                }
                let first = !self.negotiation.established;
                let restart = !first
                    && self
                        .pc
                        .remote_description()
                        .is_some_and(|current| ice_ufrag(&current.sdp) != ice_ufrag(&desc.sdp));
                if restart {
                    self.rebind()?;
                }
                let sdp = desc.sdp.clone();
                self.pc.set_remote_description(now, desc)?;
                self.negotiation.answering = true;
                self.report_remote_media(&sdp).await;
                if restart {
                    self.negotiation.wanted.restart = false;
                    if let Some(gather) = self.start_gather(AfterGather::Answer) {
                        self.gather = Some(gather);
                        return Ok(());
                    }
                }
                self.make_answer(first || restart).await
            }
            other => {
                tracing::debug!(?other, "remote description type not handled");
                Ok(())
            }
        }
    }

    async fn make_answer(&mut self, with_candidates: bool) -> Result<(), RtcError> {
        let now = now();
        if with_candidates {
            self.add_local_candidates()?;
        }
        let answer = self.pc.create_answer(None)?;
        self.pc.set_local_description(now, answer)?;
        self.negotiation.answering = false;
        self.negotiation.established = true;
        self.emit_local_description().await;
        self.report_local_media().await;
        // What we wanted while the peer's offer was in the way.
        if self.negotiation.wanted.any() {
            self.begin_offer().await?;
        }
        Ok(())
    }

    /// Offer what is wanted (an ICE restart, a track change) once nothing else is in the
    /// way: the first exchange is done, no offer of ours is unanswered, no answer is being
    /// made.
    async fn negotiate_if_ready(&mut self) -> Result<(), RtcError> {
        let n = &self.negotiation;
        if !n.established
            || n.in_flight.is_some()
            || n.answering
            || self.gather.is_some()
            || !n.wanted.any()
        {
            return Ok(());
        }
        self.begin_offer().await
    }

    async fn begin_offer(&mut self) -> Result<(), RtcError> {
        if self.negotiation.wanted.restart {
            self.rebind()?;
            if let Some(gather) = self.start_gather(AfterGather::Offer) {
                self.gather = Some(gather);
                return Ok(());
            }
        }
        self.make_offer().await
    }

    async fn make_offer(&mut self) -> Result<(), RtcError> {
        let now = now();
        let wanted = std::mem::take(&mut self.negotiation.wanted);
        if wanted.restart {
            self.pc.restart_ice();
        }
        let offer = self.pc.create_offer(None)?;
        self.pc.set_local_description(now, offer)?;
        if wanted.restart {
            self.add_local_candidates()?;
        }
        self.negotiation.in_flight = Some(wanted);
        self.emit_local_description().await;
        Ok(())
    }

    /// For an ICE restart: bind the addresses the machine has now, close the sockets whose
    /// address is gone. A connection bound to one address keeps it.
    fn rebind(&mut self) -> Result<(), RtcError> {
        if self.gather_mode == Gather::Bound {
            return Ok(());
        }
        let wanted = net::local_addresses(self.network.as_ref());
        if wanted.is_empty() {
            // No network right now: keep what there is; the restart is retried or fails.
            return Ok(());
        }
        self.socks.retain(|s| wanted.contains(&s.local.ip()));
        bind_all(self.network.as_ref(), &wanted, self.port, &mut self.socks)?;
        self.next_sock = 0;
        if let Some(relay) = self.relay.as_ref()
            && self.sock_for(relay.local()).is_none()
        {
            // The allocation belongs to the address that is gone.
            self.relay = None;
            if self.relay_only {
                return Err(RtcError::Turn(
                    "the relay allocation was lost with its network".into(),
                ));
            }
        }
        tracing::debug!(
            addrs = ?self.socks.iter().map(|s| s.local).collect::<Vec<_>>(),
            "sockets after a network change"
        );
        Ok(())
    }

    /// Ask the STUN servers again from the sockets that have no server-reflexive address
    /// yet. `None` when there is nothing to ask.
    fn start_gather(&mut self, then: AfterGather) -> Option<StunGather> {
        if self.relay_only {
            return None;
        }
        let fresh: Vec<&Sock> = self.socks.iter().filter(|s| s.srflx.is_empty()).collect();
        StunGather::for_socks(&fresh, &self.stun_targets, self.stun_timeout, Some(then))
    }

    /// A gathering round is due: send its requests again, or finish it.
    async fn drive_gather(&mut self, now: Instant) -> Result<(), RtcError> {
        let Some(gather) = self.gather.as_mut() else {
            return Ok(());
        };
        if !gather.done(now) {
            for (local, target, raw) in gather.due(now) {
                if let Some(sock) = self.socks.iter().find(|s| s.local == local) {
                    let _ = net::send_to(sock.socket.as_ref(), &raw, target).await;
                }
            }
            return Ok(());
        }
        let Some(gather) = self.gather.take() else {
            return Ok(());
        };
        gather.apply(&mut self.socks);
        match gather.then {
            Some(AfterGather::Offer) => self.make_offer().await,
            Some(AfterGather::Answer) => self.make_answer(true).await,
            None => Ok(()),
        }
    }

    /// Turn our track of `kind` on or off. Returns whether anything changed (and so has to
    /// be negotiated).
    fn set_sending(&mut self, kind: MediaKind, enabled: bool) -> Result<bool, RtcError> {
        if let Some(sender) = self.senders.get_mut(&kind) {
            if sender.enabled == enabled {
                return Ok(false);
            }
            sender.enabled = enabled;
            let id: RTCRtpTransceiverId = sender.id.into();
            if let Some(mut transceiver) = self.pc.rtp_transceiver(id) {
                let receive = transceiver.direction().has_recv();
                transceiver
                    .set_direction(RTCRtpTransceiverDirection::from_send_recv(enabled, receive))?;
            }
            return Ok(true);
        }
        if !enabled {
            return Ok(false);
        }
        // No sender of this kind yet. A transceiver the peer's offer created (it sends this
        // kind, we only receive it) gets our track; otherwise a new section is added.
        let track = local_track(kind, self.codecs.of(kind));
        let ids: Vec<RTCRtpTransceiverId> = self.pc.get_transceivers().collect();
        let mut reusable = None;
        for id in ids {
            let Some((stopped, sender_id, receiver_id)) = self
                .pc
                .rtp_transceiver(id)
                .map(|t| (t.stopped(), t.sender(), t.receiver()))
            else {
                continue;
            };
            // Every transceiver has a sender now (W3C webrtc-pc 5.4): the one we can give our
            // track to is a transceiver whose sender has no track.
            let has_track = sender_id
                .and_then(|sender| self.pc.rtp_sender(sender))
                .is_some_and(|sender| sender.track().is_some());
            if stopped || has_track {
                continue;
            }
            let Some(receiver_id) = receiver_id else {
                continue;
            };
            if self
                .pc
                .rtp_receiver(receiver_id)
                .is_some_and(|r| r.track().kind() == kind.codec_kind())
            {
                reusable = Some(id);
                break;
            }
        }
        let id = match reusable {
            Some(id) => self.pc.add_track_to_transceiver(id, track)?,
            None => self.pc.add_track(track)?,
        };
        self.senders.insert(
            kind,
            LocalSender {
                id,
                packetizer: None,
                enabled: true,
            },
        );
        Ok(true)
    }

    /// After our offer was taken back: every local track is wanted as it is negotiated, so
    /// that asking for the change again offers it again.
    fn forget_unnegotiated_tracks(&mut self) {
        let ids: Vec<(MediaKind, RTCRtpTransceiverId)> = self
            .senders
            .iter()
            .map(|(kind, sender)| (*kind, sender.id.into()))
            .collect();
        for (kind, id) in ids {
            let Some(mut transceiver) = self.pc.rtp_transceiver(id) else {
                continue;
            };
            // `None` before any exchange negotiated the transceiver: not negotiated to send.
            let negotiated = transceiver
                .current_direction()
                .is_some_and(|d| d.has_send());
            let receive = transceiver.direction().has_recv();
            // Refused only for a stopping transceiver (or a closed connection), whose
            // direction no longer matters.
            if let Err(err) = transceiver.set_direction(RTCRtpTransceiverDirection::from_send_recv(
                negotiated, receive,
            )) {
                tracing::debug!(%err, "transceiver direction left as it is");
            }
            if let Some(sender) = self.senders.get_mut(&kind) {
                sender.enabled = negotiated;
            }
        }
    }

    /// Report which kinds the peer's description sends, when that changed.
    async fn report_remote_media(&mut self, sdp: &str) {
        for (kind, sending) in media_directions(sdp) {
            if self.remote_sending.insert(kind, sending) != Some(sending) {
                self.emit(RtcEvent::RemoteMedia { kind, sending }).await;
            }
        }
    }

    /// Report which of our tracks are negotiated to send, when that changed.
    async fn report_local_media(&mut self) {
        let kinds: Vec<(MediaKind, RTCRtpTransceiverId, bool)> = self
            .senders
            .iter()
            .map(|(kind, sender)| (*kind, sender.id.into(), sender.enabled))
            .collect();
        for (kind, id, enabled) in kinds {
            let negotiated = self
                .pc
                .rtp_transceiver(id)
                .is_some_and(|t| t.current_direction().is_some_and(|d| d.has_send()));
            let sending = enabled && negotiated;
            if self.local_sending.insert(kind, sending) != Some(sending) {
                self.emit(RtcEvent::LocalMedia { kind, sending }).await;
            }
        }
    }

    /// Packetize one encoded frame and hand the packets to the engine (SRTP, interceptors).
    fn send_frame(
        &mut self,
        now: Instant,
        kind: MediaKind,
        data: &bytes::Bytes,
        samples: u32,
    ) -> Result<(), RtcError> {
        let Some(local) = self.senders.get_mut(&kind) else {
            return Ok(());
        };
        if !local.enabled {
            return Ok(());
        }
        let id: RTCRtpTransceiverId = local.id.into();
        // Only once the peer has agreed to receive it (a track added mid-call is not sent
        // before its answer; one turned off is not sent after it).
        if !self
            .pc
            .rtp_transceiver(id)
            .is_some_and(|t| t.current_direction().is_some_and(|d| d.has_send()))
        {
            return Ok(());
        }
        let Some(mut sender) = self.pc.rtp_sender(local.id) else {
            return Ok(());
        };
        if local.packetizer.is_none() {
            // Negotiated once the remote description is applied: the payload type is the
            // answer's (or the offer's, when we answer).
            let Some(ssrc) = sender.ssrcs().last() else {
                return Ok(());
            };
            // The media codec, not its retransmission format.
            let Some(codec) = sender
                .get_parameters()
                .rtp_parameters
                .codecs
                .iter()
                .find(|c| !c.rtp_codec.mime_type.eq_ignore_ascii_case(MIME_TYPE_RTX))
                .cloned()
            else {
                return Ok(());
            };
            local.packetizer = Some(Box::new(rtc::rtp::packetizer::new_packetizer(
                now,
                RTP_OUTBOUND_MTU,
                codec.payload_type,
                ssrc,
                codec.rtp_codec.payloader()?,
                Box::new(rtc::rtp::sequence::new_random_sequencer()),
                codec.rtp_codec.clock_rate,
            )));
        }
        let Some(packetizer) = local.packetizer.as_mut() else {
            return Ok(());
        };
        for packet in packetizer.packetize(now, data, samples)? {
            sender.write_rtp(now, packet)?;
        }
        Ok(())
    }

    /// Open the mDNS multicast socket (once) so the engine's queries for remote `.local`
    /// candidates go out and their answers come back. A failure (port in use without
    /// `SO_REUSEPORT`, no multicast route) only costs those candidates.
    fn open_mdns(&mut self) {
        if !self.mdns_enabled || self.mdns.is_some() {
            return;
        }
        let socket = MulticastSocket::new()
            .into_std()
            .and_then(UdpSocket::from_std);
        match socket {
            Ok(s) => {
                tracing::debug!(local = ?s.local_addr().ok(), "mDNS socket open");
                self.mdns = Some(s);
            }
            Err(err) => {
                tracing::warn!(%err, "cannot open the mDNS socket; .local candidates stay unresolved");
                self.mdns_enabled = false;
            }
        }
    }

    /// One host candidate per socket, the server-reflexive ones learned from STUN and the
    /// relay candidate; the relay candidate alone when relay-only. Priorities follow the
    /// sockets' order of preference.
    fn add_local_candidates(&mut self) -> Result<(), RtcError> {
        if let Some(relayed) = self.relay.as_ref().map(turn::Relay::relayed) {
            // No related address: it would name the address the relay exists to hide.
            let candidate = CandidateRelayConfig {
                base_config: CandidateConfig {
                    network: "udp".to_owned(),
                    address: relayed.ip().to_string(),
                    port: relayed.port(),
                    component: 1,
                    ..Default::default()
                },
                rel_addr: if relayed.is_ipv4() { "0.0.0.0" } else { "::" }.to_owned(),
                rel_port: 0,
                ..Default::default()
            }
            .new_candidate_relay()?;
            let init = RTCIceCandidate::from(&candidate).to_json()?;
            self.pc.add_local_candidate(init)?;
        }
        if self.relay_only {
            return Ok(());
        }
        // With one socket the engine's own priorities (RFC 8445's single-address values) are
        // kept; with several each address gets its own local preference.
        let several = self.socks.len() > 1;
        let locals: Vec<(SocketAddr, u16, Vec<SocketAddr>)> = self
            .socks
            .iter()
            .map(|s| (s.local, s.preference, s.srflx.clone()))
            .collect();
        for (local, preference, srflx) in locals {
            let priority = |type_preference| {
                if several {
                    net::candidate_priority(type_preference, preference)
                } else {
                    0
                }
            };
            let candidate = CandidateHostConfig {
                base_config: CandidateConfig {
                    network: "udp".to_owned(),
                    address: local.ip().to_string(),
                    port: local.port(),
                    component: 1,
                    priority: priority(126),
                    ..Default::default()
                },
                ..Default::default()
            }
            .new_candidate_host()?;
            let init = RTCIceCandidate::from(&candidate).to_json()?;
            self.pc.add_local_candidate(init)?;
            for addr in srflx {
                let candidate = CandidateServerReflexiveConfig {
                    base_config: CandidateConfig {
                        network: "udp".to_owned(),
                        address: addr.ip().to_string(),
                        port: addr.port(),
                        component: 1,
                        priority: priority(100),
                        ..Default::default()
                    },
                    rel_addr: local.ip().to_string(),
                    rel_port: local.port(),
                    ..Default::default()
                }
                .new_candidate_server_reflexive()?;
                let init = RTCIceCandidate::from(&candidate).to_json()?;
                self.pc.add_local_candidate(init)?;
            }
        }
        Ok(())
    }

    async fn emit_local_description(&mut self) {
        if let Some(desc) = self.pc.local_description() {
            self.emit(RtcEvent::LocalDescription(Box::new(desc))).await;
        }
    }

    // ── Estimate and statistics ───────────────────────────────────

    /// Read the congestion controller's estimate and report it when it moved.
    async fn report_estimate(&mut self, now: Instant) {
        self.next_estimate = Some(now + ESTIMATE_INTERVAL);
        let Some(bps) = self
            .estimate
            .as_ref()
            .and_then(GccHandle::target_bitrate_bps)
        else {
            return;
        };
        if self.last_target != Some(bps) {
            self.last_target = Some(bps);
            self.emit(RtcEvent::TargetBitrate { bps }).await;
        }
    }

    /// The statistics digest; rates and inbound loss cover the time since the last one.
    fn digest(&mut self, now: Instant) -> ConnectionQuality {
        let report = self.pc.get_stats(now, StatsSelector::None);
        let base = &mut self.quality_base;
        let elapsed = base.at.map(|at| now.saturating_duration_since(at));
        if elapsed.is_some_and(|d| d < Duration::from_millis(200)) {
            // Asked again right away: the last digest still stands.
            return base.last.clone();
        }

        let mut quality = ConnectionQuality {
            path_changes: report
                .transport()
                .map_or(0, |t| t.selected_candidate_pair_changes),
            ..Default::default()
        };
        let pair = selected_pair(&report);
        if let Some(pair) = pair {
            quality.rtt_ms = pair
                .current_round_trip_time
                .map(|s| (s * 1000.0).round().max(0.0) as u32);

            let kind_of = |id: &str| match report.get(id) {
                Some(
                    RTCStatsReportEntry::LocalCandidate(c)
                    | RTCStatsReportEntry::RemoteCandidate(c),
                ) => CandidateKind::of(c.candidate_type),
                _ => None,
            };
            quality.local_candidate = kind_of(&pair.local_candidate_id);
            quality.remote_candidate = kind_of(&pair.remote_candidate_id);
        }

        let (mut sent, mut received, mut packets, mut lost) = (0u64, 0u64, 0u64, 0i64);
        let mut worst_reported: Option<f64> = None;
        let mut media_rtt: Option<f64> = None;
        for entry in report.iter() {
            match entry {
                RTCStatsReportEntry::OutboundRtp(out) => {
                    sent += out.sent_rtp_stream_stats.bytes_sent;
                }
                RTCStatsReportEntry::InboundRtp(inbound) => {
                    received += inbound.bytes_received;
                    packets += inbound.received_rtp_stream_stats.packets_received;
                    lost += inbound.received_rtp_stream_stats.packets_lost;
                }
                RTCStatsReportEntry::RemoteInboundRtp(remote) => {
                    if remote.round_trip_time_measurements > 0 || remote.fraction_lost > 0.0 {
                        worst_reported =
                            Some(worst_reported.map_or(remote.fraction_lost, |w: f64| {
                                w.max(remote.fraction_lost)
                            }));
                    }
                    if let Some(rtt) = remote.round_trip_time {
                        media_rtt = Some(media_rtt.map_or(rtt, |m: f64| m.max(rtt)));
                    }
                }
                _ => {}
            }
        }
        quality.available_bps = self.last_target;
        quality.loss_sent = worst_reported.map(|f| f.clamp(0.0, 1.0) as f32);
        if quality.rtt_ms.is_none() {
            quality.rtt_ms = media_rtt.map(|s| (s * 1000.0).round().max(0.0) as u32);
        }
        if let Some(elapsed) = elapsed {
            let secs = elapsed.as_secs_f64().max(0.001);
            let rate =
                |now: u64, before: u64| (now.saturating_sub(before) as f64 * 8.0 / secs) as u32;
            quality.send_bps = rate(sent, base.bytes_sent);
            quality.recv_bps = rate(received, base.bytes_received);
            let got = packets.saturating_sub(base.packets_received) as f64;
            let missed = (lost - base.packets_lost).max(0) as f64;
            if got + missed > 0.0 {
                quality.loss_received = Some((missed / (got + missed)) as f32);
            }
        }
        base.at = Some(now);
        base.bytes_sent = sent;
        base.bytes_received = received;
        base.packets_received = packets;
        base.packets_lost = lost;
        base.last = quality.clone();
        quality
    }
}

/// The candidate pair the transport runs on.
fn selected_pair(
    report: &RTCStatsReport,
) -> Option<&rtc::statistics::stats::ice_candidate_pair::RTCIceCandidatePairStats> {
    let id = &report.transport()?.selected_candidate_pair_id;
    match report.get(id) {
        Some(RTCStatsReportEntry::IceCandidatePair(pair)) => Some(pair),
        _ => None,
    }
}

/// The `a=ice-ufrag` of a description (the first one: every section carries the same under
/// BUNDLE).
pub fn ice_ufrag(sdp: &str) -> Option<&str> {
    sdp.lines()
        .find_map(|line| line.trim().strip_prefix("a=ice-ufrag:"))
        .map(str::trim)
}

/// For each media kind a description has a section for: whether its sender sends it (the
/// section is not rejected and its direction is `sendrecv` or `sendonly`).
pub fn media_directions(sdp: &str) -> Vec<(MediaKind, bool)> {
    let mut out: Vec<(MediaKind, bool)> = Vec::new();
    // (kind, rejected, direction seen)
    let mut section: Option<(Option<MediaKind>, bool, Option<bool>)> = None;
    let close = |section: Option<(Option<MediaKind>, bool, Option<bool>)>,
                 out: &mut Vec<(MediaKind, bool)>| {
        if let Some((Some(kind), rejected, direction)) = section {
            // No direction attribute means sendrecv (RFC 8866 section 6.7).
            let sending = !rejected && direction.unwrap_or(true);
            match out.iter_mut().find(|(k, _)| *k == kind) {
                Some(entry) => entry.1 |= sending,
                None => out.push((kind, sending)),
            }
        }
    };
    for line in sdp.lines() {
        let line = line.trim();
        if let Some(media) = line.strip_prefix("m=") {
            close(section.take(), &mut out);
            let mut parts = media.split_ascii_whitespace();
            let kind = match parts.next() {
                Some("audio") => Some(MediaKind::Audio),
                Some("video") => Some(MediaKind::Video),
                _ => None,
            };
            let rejected = parts.next() == Some("0");
            section = Some((kind, rejected, None));
        } else if let Some((_, _, direction)) = section.as_mut() {
            match line {
                "a=sendrecv" | "a=sendonly" => *direction = Some(true),
                "a=recvonly" | "a=inactive" => *direction = Some(false),
                _ => {}
            }
        }
    }
    close(section.take(), &mut out);
    out
}

/// Receive on an optional socket; never resolves without one.
async fn recv_optional(
    socket: Option<&UdpSocket>,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    match socket {
        Some(s) => s.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

/// True when an SDP blob or a single candidate line names an mDNS (`*.local`) host
/// candidate: `candidate:<foundation> <component> <transport> <priority> <address> ...`.
pub fn has_mdns_candidate(sdp_or_candidate: &str) -> bool {
    sdp_or_candidate.lines().any(|line| {
        let line = line.trim();
        let line = line.strip_prefix("a=").unwrap_or(line);
        let Some(rest) = line.strip_prefix("candidate:") else {
            return false;
        };
        rest.split_ascii_whitespace()
            .nth(4)
            .is_some_and(|addr| addr.to_ascii_lowercase().ends_with(".local"))
    })
}

/// The address of the interface the default route leaves through, or `None` without a
/// route. Nothing is sent: connecting a UDP socket only selects the source address. Use it
/// as [`RtcConfig::bind`] (with port 0) so the host candidate names a reachable interface.
pub fn default_local_ip(v6: bool) -> Option<IpAddr> {
    let (bind, probe): (SocketAddr, SocketAddr) = if v6 {
        (
            "[::]:0".parse().ok()?,
            "[2001:4860:4860::8888]:53".parse().ok()?,
        )
    } else {
        ("0.0.0.0:0".parse().ok()?, "8.8.8.8:53".parse().ok()?)
    };
    let socket = std::net::UdpSocket::bind(bind).ok()?;
    socket.connect(probe).ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_unspecified()).then_some(ip)
}

/// `host:port` from a STUN server given as `stun:host[:port]` (RFC 7064; port 3478 when
/// absent) or a bare `host:port`. `stuns:` and `turn(s):` URIs give `None`: only plain STUN
/// over UDP is gathered here.
pub fn stun_host_port(uri: &str) -> Option<String> {
    let uri = uri.trim();
    let rest = match uri.split_once(':') {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("stun") => rest,
        Some((scheme, _))
            if scheme.eq_ignore_ascii_case("stuns")
                || scheme.eq_ignore_ascii_case("turn")
                || scheme.eq_ignore_ascii_case("turns") =>
        {
            return None;
        }
        _ => uri,
    };
    let rest = rest.split('?').next().unwrap_or(rest);
    if rest.is_empty() {
        return None;
    }
    // [v6]:port, [v6], host:port, host
    if let Some(stripped) = rest.strip_prefix('[') {
        let (host, after) = stripped.split_once(']')?;
        let port = after.strip_prefix(':').unwrap_or("3478");
        return Some(format!("[{host}]:{port}"));
    }
    match rest.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.parse::<u16>().is_ok() => {
            Some(format!("{host}:{port}"))
        }
        Some(_) => None,
        None => Some(format!("{rest}:3478")),
    }
}

/// The addresses of the STUN servers, every family each name resolves to (a socket asks the
/// ones of its own family). Names that do not resolve within `timeout` are skipped.
async fn resolve_stun(servers: &[String], timeout: Duration) -> Vec<SocketAddr> {
    let mut targets = Vec::new();
    for server in servers {
        let Some(host_port) = stun_host_port(server) else {
            continue;
        };
        let lookup = tokio::time::timeout(timeout, tokio::net::lookup_host(host_port));
        if let Ok(Ok(addrs)) = lookup.await {
            // One address per family and server is enough.
            let addrs: Vec<SocketAddr> = addrs.collect();
            for v4 in [true, false] {
                if let Some(addr) = addrs.iter().find(|a| a.is_ipv4() == v4)
                    && !targets.contains(addr)
                {
                    targets.push(*addr);
                }
            }
        }
    }
    targets
}

/// How often unanswered binding requests are sent again.
const STUN_RESEND: Duration = Duration::from_millis(400);
/// Once servers have answered, the round ends when no further answer came for this long: a
/// socket on an interface without a route to the servers (a virtual machine's bridge, a
/// tethering interface that is down) never gets one, and must not cost every connection the
/// whole timeout.
const STUN_SETTLE: Duration = Duration::from_millis(250);
/// That early end waits for a first answer in each address family that was asked, but no
/// longer than this from the start: a family without a route (IPv6 on a network that only
/// hands out local addresses) must not hold the other one up for the whole timeout either.
const STUN_FAMILY_WAIT: Duration = Duration::from_millis(600);

/// One round of STUN gathering (RFC 5389 binding requests): every socket asks every server
/// address of its own family for its mapped address. It runs before the connection's loop
/// starts, and inside the loop for an ICE restart.
struct StunGather {
    /// (the asking socket, the server, the request)
    requests: Vec<(SocketAddr, SocketAddr, Vec<u8>)>,
    /// transaction id → (the asking socket, the server asked)
    pending: HashMap<[u8; 12], (SocketAddr, SocketAddr)>,
    /// (the socket, its mapped address)
    found: Vec<(SocketAddr, SocketAddr)>,
    deadline: Instant,
    next_send: Instant,
    started: Instant,
    /// When the last answer came.
    last_answer: Option<Instant>,
    /// Per family (IPv4, IPv6): whether any request went out, and whether any was answered.
    asked: [bool; 2],
    answered: [bool; 2],
    then: Option<AfterGather>,
}

impl StunGather {
    fn new(
        socks: &[Sock],
        targets: &[SocketAddr],
        timeout: Duration,
        then: Option<AfterGather>,
    ) -> Option<StunGather> {
        let socks: Vec<&Sock> = socks.iter().collect();
        Self::for_socks(&socks, targets, timeout, then)
    }

    fn for_socks(
        socks: &[&Sock],
        targets: &[SocketAddr],
        timeout: Duration,
        then: Option<AfterGather>,
    ) -> Option<StunGather> {
        use rtc::stun::message::{BINDING_REQUEST, Message, TransactionId};

        let mut requests = Vec::new();
        let mut pending = HashMap::new();
        let mut asked = [false; 2];
        for sock in socks {
            for target in targets
                .iter()
                .filter(|t| t.is_ipv4() == sock.local.is_ipv4())
            {
                // A random transaction id per request: it is what ties an answer to its
                // socket and server, and what an off-path sender cannot guess.
                let mut msg = Message::new();
                if msg
                    .build(&[Box::new(TransactionId::new()), Box::new(BINDING_REQUEST)])
                    .is_err()
                {
                    continue;
                }
                pending.insert(msg.transaction_id.0, (sock.local, *target));
                requests.push((sock.local, *target, msg.raw.clone()));
                asked[usize::from(sock.local.is_ipv6())] = true;
            }
        }
        if requests.is_empty() {
            return None;
        }
        let now = now();
        Some(StunGather {
            requests,
            pending,
            found: Vec::new(),
            deadline: now + timeout,
            next_send: now,
            started: now,
            last_answer: None,
            asked,
            answered: [false; 2],
            then,
        })
    }

    /// When the round may end although requests are unanswered: [`STUN_SETTLE`] after the
    /// last answer, once every family that was asked has one (or [`STUN_FAMILY_WAIT`] has
    /// passed). `None` while nothing was answered: then only the timeout ends it.
    fn settled_at(&self) -> Option<Instant> {
        let last = self.last_answer?;
        let every_family = (0..2).all(|f| !self.asked[f] || self.answered[f]);
        let from = if every_family {
            last
        } else {
            last.max(self.started + STUN_FAMILY_WAIT)
        };
        Some(from + STUN_SETTLE)
    }

    fn done(&self, now: Instant) -> bool {
        self.pending.is_empty()
            || now >= self.deadline
            || self.settled_at().is_some_and(|at| now >= at)
    }

    /// When the round next needs attention.
    fn wake(&self) -> Instant {
        let wake = self.next_send.min(self.deadline);
        if self.pending.is_empty() {
            // Finished: now.
            return wake.min(now());
        }
        self.settled_at().map_or(wake, |at| at.min(wake))
    }

    /// The requests to (re)send now, when a resend is due.
    fn due(&mut self, now: Instant) -> Vec<(SocketAddr, SocketAddr, Vec<u8>)> {
        if now < self.next_send {
            return Vec::new();
        }
        self.next_send = now + STUN_RESEND;
        let pending = &self.pending;
        self.requests
            .iter()
            .filter(|(local, target, _)| pending.values().any(|(l, t)| l == local && t == target))
            .cloned()
            .collect()
    }

    /// A datagram that arrived on the socket bound to `local`. True when it was a server's
    /// answer to one of this round's requests (it is consumed); anything else is the
    /// connection's.
    fn handle(&mut self, local: SocketAddr, from: SocketAddr, data: &[u8]) -> bool {
        use rtc::stun::message::{Getter as _, Message};
        use rtc::stun::xoraddr::XorMappedAddress;

        if !self.requests.iter().any(|(_, target, _)| *target == from) {
            return false;
        }
        let mut msg = Message::new();
        msg.raw = data.to_vec();
        if msg.decode().is_err() {
            return false;
        }
        let Some((asked_from, server)) = self.pending.get(&msg.transaction_id.0).copied() else {
            return false;
        };
        if asked_from != local || server != from {
            return false;
        }
        self.pending.remove(&msg.transaction_id.0);
        self.last_answer = Some(now());
        self.answered[usize::from(local.is_ipv6())] = true;
        let mut xor = XorMappedAddress::default();
        if xor.get_from(&msg).is_ok() {
            let mapped = SocketAddr::new(xor.ip, xor.port);
            // A mapped address equal to the socket's own is the host candidate again.
            if mapped != local && !self.found.contains(&(local, mapped)) {
                self.found.push((local, mapped));
            }
        }
        true
    }

    /// Run the round to its end on `socks`, before the connection's loop reads them.
    async fn run(&mut self, socks: &[Sock]) {
        let mut buf = vec![0u8; 1500];
        let mut start = 0;
        loop {
            let now = now();
            if self.done(now) {
                return;
            }
            for (local, target, raw) in self.due(now) {
                if let Some(sock) = socks.iter().find(|s| s.local == local) {
                    let _ = net::send_to(sock.socket.as_ref(), &raw, target).await;
                }
            }
            let wake = tokio::time::Instant::from_std(self.wake());
            match tokio::time::timeout_at(wake, recv_any(socks, start, &mut buf)).await {
                Ok((index, Ok((n, from)))) => {
                    start = index + 1;
                    if !self.handle(socks[index].local, from, &buf[..n]) {
                        tracing::debug!(%from, "ignoring a non-matching datagram during STUN gathering");
                    }
                }
                Ok((_, Err(err))) => {
                    tracing::debug!(%err, "STUN receive failed");
                    // Do not spin on a socket that keeps failing.
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(_) => {}
            }
        }
    }

    /// Record what the round learned on the sockets.
    fn apply(&self, socks: &mut [Sock]) {
        for (local, mapped) in &self.found {
            if let Some(sock) = socks.iter_mut().find(|s| s.local == *local)
                && !sock.srflx.contains(mapped)
            {
                sock.srflx.push(*mapped);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{has_mdns_candidate, stun_host_port};

    #[test]
    fn mdns_candidates_are_recognized() {
        let chrome = "candidate:1840965416 1 udp 2122260223 \
                      2a4d4a5e-2cf8-4b2b-9a9f-3c1c3e52a7a1.local 54400 typ host generation 0";
        assert!(has_mdns_candidate(chrome));
        let sdp =
            format!("v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na={chrome}\r\n");
        assert!(has_mdns_candidate(&sdp));
        assert!(!has_mdns_candidate(
            "a=candidate:1 1 udp 2122260223 192.168.1.4 54400 typ host"
        ));
        assert!(!has_mdns_candidate("a=ice-ufrag:abc.local"));
        assert!(!has_mdns_candidate(""));
    }

    #[test]
    fn stun_uris_become_host_port() {
        assert_eq!(
            stun_host_port("stun:example.org").as_deref(),
            Some("example.org:3478")
        );
        assert_eq!(
            stun_host_port("stun:example.org:19302").as_deref(),
            Some("example.org:19302")
        );
        assert_eq!(
            stun_host_port("STUN:1.2.3.4:5").as_deref(),
            Some("1.2.3.4:5")
        );
        assert_eq!(
            stun_host_port("stun:[::1]:3478").as_deref(),
            Some("[::1]:3478")
        );
        assert_eq!(stun_host_port("stun:[::1]").as_deref(), Some("[::1]:3478"));
        assert_eq!(
            stun_host_port("127.0.0.1:3478").as_deref(),
            Some("127.0.0.1:3478")
        );
        assert_eq!(
            stun_host_port("stun:host:3478?transport=udp").as_deref(),
            Some("host:3478")
        );
        assert_eq!(stun_host_port("turn:example.org:3478"), None);
        assert_eq!(stun_host_port("stuns:example.org:5349"), None);
        assert_eq!(stun_host_port("stun:"), None);
    }
}
