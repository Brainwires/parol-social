//! Async driver for the sans-I/O [`rtc`] peer connection (`Brainwires/webrtc-rs-rtc`).
//!
//! The engine does no I/O of its own: it is fed datagrams and timeouts and hands back
//! datagrams to send, events and decrypted messages. This crate owns that loop. Each
//! connection runs as one tokio task that owns its UDP socket and timers; the application
//! talks to it through a command channel ([`RtcHandle`]) and an event channel
//! ([`RtcEvent`]).
//!
//! M0 status: skeleton. It gathers host candidates on the socket it binds, answers or makes
//! an offer, delivers RTP packets and data-channel messages, requests keyframes and reports
//! stats. Still to come in M1 (see `docs/m0-spike.md`): server-reflexive and TURN
//! candidates (`rtc-turn`), several sockets per connection, interface-change restarts, and
//! the virtual-time mode that runs the same loop over `parolnet-simnet`.

use std::collections::HashMap;
use std::net::SocketAddr;
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
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate, RTCIceCandidateInit,
    RTCIceServer,
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
    /// STUN / TURN servers (unused until srflx / relay gathering lands in M1).
    pub ice_servers: Vec<RTCIceServer>,
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
    DataChannelOpen { id: usize },
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
    let pc = build_peer_connection(&config)?;

    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (ev_tx, ev_rx) = mpsc::channel(config.event_capacity.max(16));
    let driver = Driver {
        pc,
        socket,
        local_addr,
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
                    self.emit(RtcEvent::DataChannelOpen { id }).await;
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
                self.add_host_candidate()?;
                self.emit_local_description().await;
            }
            Command::SetRemoteDescription(desc) => {
                let is_offer = desc.sdp_type == rtc::peer_connection::sdp::RTCSdpType::Offer;
                self.pc.set_remote_description(now, *desc)?;
                if is_offer {
                    self.add_host_candidate()?;
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
