//! Async driver for the sans-I/O [`rtc`] peer connection (`Brainwires/webrtc-rs-rtc`).
//!
//! The engine does no I/O of its own: it is fed datagrams and timeouts and hands back
//! datagrams to send, events and decrypted messages. This crate owns that loop. Each
//! connection runs as one tokio task that owns its UDP socket and timers; the application
//! talks to it through a command channel ([`RtcHandle`]) and an event channel
//! ([`RtcEvent`]).
//!
//! Status (M1, first slice): it gathers the host candidate of the socket it binds and, when
//! STUN servers are given, one server-reflexive candidate per server (a binding request on the
//! same socket before the loop starts); it answers or makes a non-trickle offer, delivers RTP
//! packets and data-channel messages (binary and text), requests keyframes and reports stats.
//! Still to come in M1 (see `docs/m0-spike.md`): TURN candidates for a user-supplied TURN
//! server (`rtc-turn`), IPv6 and several sockets per connection, interface-change restarts,
//! and the virtual-time mode that runs the same loop over `parolnet-simnet`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use rtc::interceptor::Registry;
use rtc::media_stream::MediaStreamTrackId;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, CandidateServerReflexiveConfig, RTCDtlsRole,
    RTCIceCandidate, RTCIceCandidateInit, RTCIceServer,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtc::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpReceiverId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::statistics::StatsSelector;
use rtc::statistics::report::RTCStatsReport;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

pub use rtc;

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
}

/// Media this connection is willing to receive.
#[derive(Debug, Clone, Default)]
pub struct MediaConfig {
    /// Add a receive-only VP8 video transceiver.
    pub recv_vp8: bool,
    /// Add a receive-only Opus audio transceiver.
    pub recv_opus: bool,
}

/// One connection's configuration.
#[derive(Debug, Clone)]
pub struct RtcConfig {
    /// The UDP socket to bind. Its address is the host candidate, so it must name an
    /// interface (`127.0.0.1:0` for loopback tests).
    pub bind: SocketAddr,
    /// STUN / TURN servers handed to the engine's configuration (TURN gathering is not
    /// implemented yet; see [`RtcConfig::stun_servers`] for server-reflexive candidates).
    pub ice_servers: Vec<RTCIceServer>,
    /// STUN servers (`host:port`, or `stun:host:port` URIs) to learn a server-reflexive
    /// candidate from before the connection starts. Unreachable servers are skipped after
    /// [`RtcConfig::stun_timeout`].
    pub stun_servers: Vec<String>,
    /// How long STUN gathering may take in total.
    pub stun_timeout: Duration,
    /// Receive transceivers.
    pub media: MediaConfig,
    /// When making an offer, open a data channel with this label first.
    pub data_channel: Option<String>,
    /// DTLS role taken when answering (the engine's default when `None`).
    pub answering_dtls_role: Option<RTCDtlsRole>,
    /// Capacity of the event channel. RTP events are dropped (and counted) when it is full;
    /// control events wait for room.
    pub event_capacity: usize,
}

impl Default for RtcConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            ice_servers: Vec::new(),
            stun_servers: Vec::new(),
            stun_timeout: Duration::from_millis(1500),
            media: MediaConfig::default(),
            data_channel: None,
            answering_dtls_role: None,
            event_capacity: 4096,
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
    /// The task stopped; `error` is set when it stopped on an error.
    Closed { error: Option<String> },
}

enum Command {
    CreateOffer,
    SetRemoteDescription(Box<RTCSessionDescription>),
    AddRemoteCandidate(RTCIceCandidateInit),
    SendData { id: usize, data: BytesMut },
    SendText { id: usize, text: String },
    RequestKeyframe { track_id: MediaStreamTrackId },
    Stats(oneshot::Sender<(RTCStatsReport, u64)>),
    Close,
}

/// The application's end of a connection.
pub struct RtcHandle {
    commands: mpsc::UnboundedSender<Command>,
    local_addr: SocketAddr,
    task: JoinHandle<()>,
}

impl RtcHandle {
    /// The address of the connection's UDP socket.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
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
    let socket = UdpSocket::bind(config.bind).await?;
    let local_addr = socket.local_addr()?;
    let srflx = gather_srflx(&socket, &config.stun_servers, config.stun_timeout).await;
    let pc = build_peer_connection(&config)?;

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
    };
    let task = tokio::spawn(driver.run(cmd_rx));
    Ok((
        RtcHandle {
            commands: cmd_tx,
            local_addr,
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

fn build_peer_connection(config: &RtcConfig) -> Result<RTCPeerConnection, RtcError> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90_000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: video_feedback(),
            },
            payload_type: 96,
        },
        RtpCodecKind::Video,
    )?;
    media_engine.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: MIME_TYPE_OPUS.to_owned(),
                clock_rate: 48_000,
                channels: 2,
                sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
                rtcp_feedback: vec![],
            },
            payload_type: 111,
        },
        RtpCodecKind::Audio,
    )?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;

    let mut settings = SettingEngineBuilder::new();
    if let Some(role) = config.answering_dtls_role {
        settings = settings.with_answering_dtls_role(role);
    }
    let rtc_config = RTCConfigurationBuilder::new()
        .with_ice_servers(config.ice_servers.clone())
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
    if config.media.recv_opus {
        pc.add_transceiver_from_kind(RtpCodecKind::Audio, recvonly())?;
    }
    if config.media.recv_vp8 {
        pc.add_transceiver_from_kind(RtpCodecKind::Video, recvonly())?;
    }
    Ok(pc)
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
        let _ = self.events.send(RtcEvent::Closed { error }).await;
    }

    async fn event_loop(
        &mut self,
        commands: &mut mpsc::UnboundedReceiver<Command>,
    ) -> Result<(), RtcError> {
        let mut buf = vec![0u8; 2048];
        loop {
            self.flush_writes().await;
            if self.drain_events().await? {
                return Ok(());
            }
            self.drain_reads().await;

            let now = Instant::now();
            let deadline = self.pc.poll_timeout().unwrap_or(now + IDLE_WAKE);
            if deadline <= now {
                self.pc.handle_timeout(now)?;
                continue;
            }

            tokio::select! {
                biased;
                command = commands.recv() => match command {
                    None | Some(Command::Close) => return Ok(()),
                    Some(command) => self.handle_command(command).await?,
                },
                _ = tokio::time::sleep_until(deadline.into()) => {
                    self.pc.handle_timeout(Instant::now())?;
                }
                received = self.socket.recv_from(&mut buf) => {
                    let (n, peer_addr) = received?;
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
            }
        }
    }

    async fn flush_writes(&mut self) {
        while let Some(msg) = self.pc.poll_write() {
            if let Err(err) = self
                .socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await
            {
                tracing::debug!(peer = %msg.transport.peer_addr, %err, "send failed");
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
            Command::Stats(reply) => {
                let report = self.pc.get_stats(now, StatsSelector::None);
                let _ = reply.send((report, self.dropped_rtp));
            }
            Command::Close => {}
        }
        Ok(())
    }

    /// The host candidate (the bound socket) and the server-reflexive ones learned from STUN.
    fn add_local_candidates(&mut self) -> Result<(), RtcError> {
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
    use super::stun_host_port;

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
