//! Async driver for the sans-I/O [`rtc`] peer connection (`Brainwires/webrtc-rs-rtc`).
//!
//! The engine does no I/O of its own: it is fed datagrams and timeouts and hands back
//! datagrams to send, events and decrypted messages. This crate owns that loop. Each
//! connection runs as one tokio task that owns its UDP socket and timers; the application
//! talks to it through a command channel ([`RtcHandle`]) and an event channel
//! ([`RtcEvent`]).
//!
//! Status (M1): it gathers the host candidate of the socket it binds, when STUN servers
//! are given one server-reflexive candidate per server (a binding request on the same socket
//! before the loop starts), and when the user configured a TURN server a relay candidate from
//! it ([`RtcConfig::turn`], over UDP; see [`IcePolicy::Relay`] to use nothing else); it
//! answers or makes a non-trickle offer, delivers RTP packets and
//! data-channel messages (binary and text), sends VP8 and Opus tracks (encoded frames in,
//! packetized here), requests keyframes and reports stats. Remote mDNS
//! host candidates (`<uuid>.local`, what Chromium and Safari announce instead of a private
//! address) are resolved with an mDNS query: the engine asks, and this driver opens the
//! multicast socket (`224.0.0.251:5353`) the first time a remote description or candidate
//! names a `.local` host, so a connection that never sees one never touches multicast.
//! Still to come (see `docs/m0-spike.md`): TURN over TCP and TLS, IPv6 and several sockets
//! per connection, interface-change restarts, and the virtual-time mode that runs the same
//! loop over `parolnet-simnet`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use rtc::ice::mdns::MulticastDnsMode;
use rtc::interceptor::Registry;
use rtc::mdns::{MDNS_PORT, MulticastSocket};
use rtc::media_stream::{MediaStreamTrack, MediaStreamTrackId};
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceTransportPolicy};
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, CandidateRelayConfig, CandidateServerReflexiveConfig,
    RTCDtlsRole, RTCIceCandidate, RTCIceCandidateInit, RTCIceServer,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
use rtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtc::rtp::packetizer::Packetizer;
use rtc::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters,
    RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{
    RTCRtpReceiverId, RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit,
};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::statistics::StatsSelector;
use rtc::statistics::report::RTCStatsReport;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

pub use rtc;

#[cfg(feature = "test-turn")]
pub mod test_turn;
mod turn;

pub use turn::{TurnServer, parse_turn_uri};

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
}

/// Payload size of an outgoing RTP packet (headers and SRTP stay under a 1280-byte path MTU).
const RTP_OUTBOUND_MTU: usize = 1200;

/// One connection's configuration.
#[derive(Debug, Clone)]
pub struct RtcConfig {
    /// The UDP socket to bind. Its address is the host candidate, so it must name an
    /// interface (`127.0.0.1:0` for loopback tests).
    pub bind: SocketAddr,
    /// ICE servers recorded in the engine's configuration. The engine gathers nothing itself:
    /// candidates come from [`RtcConfig::stun_servers`] and [`RtcConfig::turn`].
    pub ice_servers: Vec<RTCIceServer>,
    /// STUN servers (`host:port`, or `stun:host:port` URIs) to learn a server-reflexive
    /// candidate from before the connection starts. Unreachable servers are skipped after
    /// [`RtcConfig::stun_timeout`].
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
    /// When making an offer, open a data channel with this label first.
    pub data_channel: Option<String>,
    /// DTLS role taken when answering (the engine's default when `None`).
    pub answering_dtls_role: Option<RTCDtlsRole>,
    /// Capacity of the event channel. RTP events are dropped (and counted) when it is full;
    /// control events wait for room.
    pub event_capacity: usize,
    /// Resolve the peer's mDNS (`*.local`) host candidates with an mDNS query on the local
    /// network. Off: such candidates are dropped (the connection can still succeed through a
    /// server-reflexive or peer-reflexive candidate).
    pub mdns: bool,
}

impl Default for RtcConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            ice_servers: Vec::new(),
            stun_servers: Vec::new(),
            stun_timeout: Duration::from_millis(1500),
            turn: None,
            turn_timeout: Duration::from_secs(5),
            turn_keepalive: Duration::from_secs(25),
            ice_policy: IcePolicy::All,
            media: MediaConfig::default(),
            data_channel: None,
            answering_dtls_role: None,
            event_capacity: 4096,
            mdns: true,
        }
    }
}

/// What the connection reports.
#[derive(Debug)]
pub enum RtcEvent {
    /// The local description with every gathered candidate in it (non-trickle). Send it to
    /// the peer through signaling.
    LocalDescription(Box<RTCSessionDescription>),
    /// The peer connection's state changed.
    ConnectionState(RTCPeerConnectionState),
    /// The ICE connection state changed.
    IceConnectionState(RTCIceConnectionState),
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
    /// The peer asked for a keyframe of our video track (RTCP PLI or FIR).
    KeyframeRequested,
    /// The task stopped; `error` is set when it stopped on an error.
    Closed { error: Option<String> },
}

enum Command {
    CreateOffer,
    SetRemoteDescription(Box<RTCSessionDescription>),
    AddRemoteCandidate(RTCIceCandidateInit),
    SendData {
        id: usize,
        data: BytesMut,
    },
    SendText {
        id: usize,
        text: String,
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
    Close,
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
    /// The address of the connection's UDP socket.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
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
    /// [`RtcEvent::LocalDescription`].
    pub fn set_remote_description(&self, desc: RTCSessionDescription) -> Result<(), RtcError> {
        self.send(Command::SetRemoteDescription(Box::new(desc)))
    }

    /// Add a trickled remote candidate.
    pub fn add_remote_candidate(&self, candidate: RTCIceCandidateInit) -> Result<(), RtcError> {
        self.send(Command::AddRemoteCandidate(candidate))
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

    /// Close the connection and wait for its task to finish.
    pub async fn close(self) {
        let _ = self.commands.send(Command::Close);
        let _ = self.task.await;
    }
}

/// Bind the socket, build the peer connection and start its task.
pub async fn spawn(config: RtcConfig) -> Result<(RtcHandle, mpsc::Receiver<RtcEvent>), RtcError> {
    if config.bind.ip().is_unspecified() {
        return Err(RtcError::UnspecifiedBind(config.bind));
    }
    let relay_only = config.ice_policy == IcePolicy::Relay;
    if relay_only && config.turn.is_none() {
        return Err(RtcError::Turn(
            "relay-only connections need a TURN server".into(),
        ));
    }
    let socket = UdpSocket::bind(config.bind).await?;
    let local_addr = socket.local_addr()?;
    // Relay-only talks to nobody but the TURN server: no STUN either.
    let srflx = if relay_only {
        Vec::new()
    } else {
        gather_srflx(&socket, &config.stun_servers, config.stun_timeout).await
    };
    let relay = match &config.turn {
        Some(server) => {
            match turn::allocate(&socket, server, config.turn_timeout, config.turn_keepalive).await
            {
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
    let (pc, senders) = build_peer_connection(&config)?;

    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (ev_tx, ev_rx) = mpsc::channel(config.event_capacity.max(16));
    let driver = Driver {
        pc,
        socket,
        local_addr,
        srflx,
        events: ev_tx,
        data_channel: config.data_channel,
        tracks: HashMap::new(),
        dropped_rtp: 0,
        senders: senders
            .into_iter()
            .map(|(kind, id)| (kind, (id, None)))
            .collect(),
        connected: false,
        mdns_enabled: config.mdns && !relay_only,
        mdns: None,
        mdns_answers: 0,
        relay,
        relay_only,
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

fn build_peer_connection(config: &RtcConfig) -> Result<(RTCPeerConnection, Senders), RtcError> {
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
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: opus.clone(),
            payload_type: 111,
        },
        RtpCodecKind::Audio,
    )?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;

    let relay_only = config.ice_policy == IcePolicy::Relay;
    // A relay cannot reach a `.local` host on the peer's network: no mDNS when relay-only.
    let mut settings =
        SettingEngineBuilder::new().with_multicast_dns_mode(if config.mdns && !relay_only {
            MulticastDnsMode::QueryOnly
        } else {
            MulticastDnsMode::Disabled
        });
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
        .build(Instant::now())?;

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
    Ok((pc, senders))
}

struct Driver {
    pc: RTCPeerConnection,
    socket: UdpSocket,
    local_addr: SocketAddr,
    /// Server-reflexive addresses learned from STUN, each mapping `local_addr`.
    srflx: Vec<SocketAddr>,
    events: mpsc::Sender<RtcEvent>,
    data_channel: Option<String>,
    /// track id → (receiver, whether its first packet was reported)
    tracks: HashMap<MediaStreamTrackId, (RTCRtpReceiverId, bool)>,
    dropped_rtp: u64,
    /// Local tracks: the sender and, once negotiated, its packetizer.
    senders: HashMap<MediaKind, (RTCRtpSenderId, Option<Box<dyn Packetizer>>)>,
    /// The peer connection reached `connected` (SRTP keys exist).
    connected: bool,
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
}

/// The longest the loop sleeps when the engine names no deadline.
const IDLE_WAKE: Duration = Duration::from_secs(1);

impl Driver {
    async fn run(mut self, mut commands: mpsc::UnboundedReceiver<Command>) {
        let error = self
            .event_loop(&mut commands)
            .await
            .err()
            .map(|e| e.to_string());
        let _ = self.pc.close();
        if let Some(relay) = self.relay.take() {
            relay.release(&self.socket).await;
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

            let now = Instant::now();
            let relay_deadline = self.relay.as_mut().and_then(turn::Relay::poll_timeout);
            if let Some(relay) = self.relay.as_mut()
                && relay_deadline.is_some_and(|t| t <= now)
            {
                relay.handle_timeout(now);
                continue;
            }
            let deadline = self.pc.poll_timeout().unwrap_or(now + IDLE_WAKE);
            if deadline <= now {
                self.pc.handle_timeout(now)?;
                continue;
            }
            let deadline = relay_deadline.map_or(deadline, |t| t.min(deadline));

            tokio::select! {
                biased;
                command = commands.recv() => match command {
                    None | Some(Command::Close) => return Ok(()),
                    Some(command) => self.handle_command(command).await?,
                },
                _ = tokio::time::sleep_until(deadline.into()) => {
                    // The loop's next pass runs whichever timer is due.
                }
                received = self.socket.recv_from(&mut buf) => {
                    let (n, peer_addr) = received?;
                    if let Some(relay) = self.relay.as_mut()
                        && relay.server() == peer_addr
                    {
                        relay.handle_datagram(&buf[..n]);
                        continue;
                    }
                    if self.relay_only {
                        // Answering would show the sender our address.
                        continue;
                    }
                    // A malformed or unexpected datagram is the peer's problem, not ours.
                    if let Err(err) = self.pc.handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr: self.local_addr,
                            peer_addr,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: BytesMut::from(&buf[..n]),
                    }) {
                        tracing::debug!(%peer_addr, %err, "datagram rejected");
                    }
                }
                received = recv_optional(self.mdns.as_ref(), &mut mdns_buf) => {
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
                        now: Instant::now(),
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

    async fn flush_writes(&mut self) {
        self.deliver_relayed();
        while let Some(msg) = self.pc.poll_write() {
            if let Some(relay) = self.relay.as_mut()
                && msg.transport.local_addr == relay.relayed()
            {
                relay.send(Instant::now(), msg.message, msg.transport.peer_addr);
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
            if let Err(err) = self
                .socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await
            {
                tracing::debug!(peer = %msg.transport.peer_addr, %err, "send failed");
            }
        }
        if let Some(relay) = self.relay.as_mut() {
            while let Some((data, to)) = relay.poll_write() {
                if let Err(err) = self.socket.send_to(&data, to).await {
                    tracing::debug!(%err, "send to the TURN server failed");
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
        let now = Instant::now();
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

    async fn emit(&mut self, event: RtcEvent) {
        let _ = self.events.send(event).await;
    }

    /// Returns true when the connection failed or closed.
    async fn drain_events(&mut self) -> Result<bool, RtcError> {
        while let Some(event) = self.pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    self.connected = state == RTCPeerConnectionState::Connected;
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
                _ => {}
            }
        }
        Ok(false)
    }

    async fn drain_reads(&mut self) {
        while let Some(TaggedRTCMessage { message, .. }) = self.pc.poll_read() {
            match message {
                RTCMessage::RtpPacket(track_id, packet) => {
                    self.report_track(&track_id).await;
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

    /// Reports a track's kind and codec on its first packet (they are known only once the
    /// stream's SSRC is bound).
    async fn report_track(&mut self, track_id: &MediaStreamTrackId) {
        let Some((receiver_id, reported)) = self.tracks.get(track_id).copied() else {
            return;
        };
        if reported {
            return;
        }
        let Some(receiver) = self.pc.rtp_receiver(receiver_id) else {
            return;
        };
        let track = receiver.track();
        let kind = track.kind();
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
    }

    async fn handle_command(&mut self, command: Command) -> Result<(), RtcError> {
        let now = Instant::now();
        match command {
            Command::CreateOffer => {
                if let Some(label) = self.data_channel.take() {
                    self.pc.create_data_channel(&label, None)?;
                }
                let offer = self.pc.create_offer(None)?;
                self.pc.set_local_description(now, offer)?;
                self.add_local_candidates()?;
                self.emit_local_description().await;
            }
            Command::SetRemoteDescription(desc) => {
                if has_mdns_candidate(&desc.sdp) {
                    self.open_mdns();
                }
                let is_offer = desc.sdp_type == rtc::peer_connection::sdp::RTCSdpType::Offer;
                self.pc.set_remote_description(now, *desc)?;
                if is_offer {
                    self.add_local_candidates()?;
                    let answer = self.pc.create_answer(None)?;
                    self.pc.set_local_description(now, answer)?;
                    self.emit_local_description().await;
                }
            }
            Command::AddRemoteCandidate(candidate) => {
                if has_mdns_candidate(&candidate.candidate) {
                    self.open_mdns();
                }
                self.pc.add_remote_candidate(candidate)?;
            }
            Command::SendData { id, data } => {
                if let Some(mut channel) = self.pc.data_channel(id) {
                    channel.send(now, data)?;
                }
            }
            Command::SendText { id, text } => {
                if let Some(mut channel) = self.pc.data_channel(id) {
                    channel.send_text(now, text)?;
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
                if self.connected
                    && let Err(err) = self.send_frame(now, kind, &data, samples)
                {
                    tracing::debug!(?kind, %err, "frame not sent");
                }
            }
            Command::Stats(reply) => {
                let report = self.pc.get_stats(now, StatsSelector::None);
                let _ = reply.send((report, self.dropped_rtp));
            }
            Command::Close => {}
        }
        Ok(())
    }

    /// Packetize one encoded frame and hand the packets to the engine (SRTP, interceptors).
    fn send_frame(
        &mut self,
        now: Instant,
        kind: MediaKind,
        data: &bytes::Bytes,
        samples: u32,
    ) -> Result<(), RtcError> {
        let Some((sender_id, packetizer)) = self.senders.get_mut(&kind) else {
            return Ok(());
        };
        let Some(mut sender) = self.pc.rtp_sender(*sender_id) else {
            return Ok(());
        };
        if packetizer.is_none() {
            // Negotiated once the remote description is applied: the payload type is the
            // answer's (or the offer's, when we answer).
            let Some(ssrc) = sender.track().ssrcs().last() else {
                return Ok(());
            };
            let Some(codec) = sender
                .get_parameters()
                .rtp_parameters
                .codecs
                .first()
                .cloned()
            else {
                return Ok(());
            };
            *packetizer = Some(Box::new(rtc::rtp::packetizer::new_packetizer(
                now,
                RTP_OUTBOUND_MTU,
                codec.payload_type,
                ssrc,
                codec.rtp_codec.payloader()?,
                Box::new(rtc::rtp::sequence::new_random_sequencer()),
                codec.rtp_codec.clock_rate,
            )));
        }
        let Some(packetizer) = packetizer.as_mut() else {
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

    /// The host candidate (the bound socket), the server-reflexive ones learned from STUN
    /// and the relay candidate; the relay candidate alone when relay-only.
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
        self.add_host_candidate()?;
        for addr in self.srflx.clone() {
            let candidate = CandidateServerReflexiveConfig {
                base_config: CandidateConfig {
                    network: "udp".to_owned(),
                    address: addr.ip().to_string(),
                    port: addr.port(),
                    component: 1,
                    ..Default::default()
                },
                rel_addr: self.local_addr.ip().to_string(),
                rel_port: self.local_addr.port(),
                ..Default::default()
            }
            .new_candidate_server_reflexive()?;
            let init = RTCIceCandidate::from(&candidate).to_json()?;
            self.pc.add_local_candidate(init)?;
        }
        Ok(())
    }

    /// The host candidate is the bound socket itself.
    fn add_host_candidate(&mut self) -> Result<(), RtcError> {
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: self.local_addr.ip().to_string(),
                port: self.local_addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        let init = RTCIceCandidate::from(&candidate).to_json()?;
        self.pc.add_local_candidate(init)?;
        Ok(())
    }

    async fn emit_local_description(&mut self) {
        if let Some(desc) = self.pc.local_description() {
            self.emit(RtcEvent::LocalDescription(Box::new(desc))).await;
        }
    }
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

/// Ask each STUN server for the socket's mapped address (RFC 5389 binding request), on the
/// connection's own socket before its loop starts. Gives up on servers that do not answer
/// within `timeout` in total; returns the distinct mapped addresses that differ from the
/// socket's own address.
async fn gather_srflx(
    socket: &UdpSocket,
    servers: &[String],
    timeout: Duration,
) -> Vec<SocketAddr> {
    use rtc::stun::message::{BINDING_REQUEST, Getter as _, Message, TransactionId};
    use rtc::stun::xoraddr::XorMappedAddress;

    let Ok(local) = socket.local_addr() else {
        return Vec::new();
    };
    let mut targets = Vec::new();
    for server in servers {
        let Some(host_port) = stun_host_port(server) else {
            continue;
        };
        let lookup = tokio::time::timeout(timeout, tokio::net::lookup_host(host_port.clone()));
        if let Ok(Ok(addrs)) = lookup.await
            && let Some(addr) = addrs.into_iter().find(|a| a.is_ipv4() == local.is_ipv4())
        {
            targets.push(addr);
        }
    }
    if targets.is_empty() {
        return Vec::new();
    }

    let mut pending: HashMap<[u8; 12], SocketAddr> = HashMap::new();
    let mut requests = Vec::new();
    for target in &targets {
        let mut msg = Message::new();
        if msg
            .build(&[Box::<TransactionId>::default(), Box::new(BINDING_REQUEST)])
            .is_err()
        {
            continue;
        }
        pending.insert(msg.transaction_id.0, *target);
        requests.push((msg.raw.clone(), *target));
    }

    let deadline = tokio::time::Instant::now() + timeout;
    let mut found = Vec::new();
    let mut buf = vec![0u8; 1500];
    let mut next_send = tokio::time::Instant::now();
    while !pending.is_empty() {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        if now >= next_send {
            for (raw, target) in &requests {
                let _ = socket.send_to(raw, target).await;
            }
            next_send = now + Duration::from_millis(400);
        }
        let wake = next_send.min(deadline);
        match tokio::time::timeout_at(wake, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => {
                let mut msg = Message::new();
                msg.raw = buf[..n].to_vec();
                if msg.decode().is_err() || pending.remove(&msg.transaction_id.0).is_none() {
                    tracing::debug!(%from, "ignoring a non-matching datagram during STUN gathering");
                    continue;
                }
                let mut xor = XorMappedAddress::default();
                if xor.get_from(&msg).is_ok() {
                    let mapped = SocketAddr::new(xor.ip, xor.port);
                    if mapped != local && !found.contains(&mapped) {
                        found.push(mapped);
                    }
                }
            }
            Ok(Err(err)) => {
                tracing::debug!(%err, "STUN receive failed");
            }
            Err(_) => {}
        }
    }
    found
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
