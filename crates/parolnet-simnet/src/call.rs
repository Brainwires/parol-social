//! A 1:1 call between two `parolnet-rtc` drivers on a [`SimNet`], with synthetic media and
//! the measurements the M1 simulation checks are stated in.
//!
//! - **Audio** is `parolnet-media`'s tone through its Opus encoder, 20 ms frames. The receiver
//!   decodes with Opus into the desktop's [`PlayoutBuffer`] and "plays" it by popping 10 ms
//!   frames on the clock, as the sound card would. Every played 20 ms window is judged: is it
//!   still the tone, at about its level ([`AudioMetrics`]). That is the objective reading of
//!   "audio stays intelligible".
//! - **Video** is a rate-following source ([`VideoModel`]): 30 frames a second whose sizes
//!   add up to the bitrate the congestion controller allows, a larger keyframe on request.
//!   Frames carry a VP8 frame tag, so the engine's real VP8 payloader and depacketizer and
//!   its sample builder run. The receiver reassembles frames and applies a decoder's rule: a
//!   delta frame is usable only when the frame before it was, otherwise a keyframe is
//!   requested (PLI) and everything waits for it. The times of usable frames give the frame
//!   gaps ([`VideoMetrics::longest_gap`]): the objective reading of "without freezing".
//!   With the `vpx` feature, [`VideoSourceKind::Pattern`] encodes the real test pattern with
//!   libvpx and decodes it on the other side instead.
//!
//! Signaling (offer, answer) crosses a channel with its own delay, outside the simulated
//! links, as it does in the app (the relay, or the data connection).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use parolnet_media::duplex::PlayoutBuffer;
use parolnet_media::opus::{OpusDecoder, OpusEncoder};
use parolnet_media::source::Tone;
use parolnet_media::{FRAME_10MS, FRAME_20MS, SAMPLE_RATE};
use parolnet_rtc::rtc::media::io::sample_builder::SampleBuilder;
use parolnet_rtc::rtc::peer_connection::sdp::{RTCSdpType, RTCSessionDescription};
use parolnet_rtc::rtc::peer_connection::state::RTCPeerConnectionState;
use parolnet_rtc::rtc::rtp::codec::vp8::Vp8Packet;
use parolnet_rtc::{
    CongestionConfig, ConnectionQuality, Gather, MediaConfig, MediaKind, RtcConfig, RtcEvent,
    RtcHandle,
};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::{SimHost, SimNet};

/// The tone both sides send.
pub const TONE_HZ: f64 = 440.0;
/// Its amplitude (-20 dBFS).
pub const TONE_AMPLITUDE: f32 = 0.1;
/// Frames a second of the video source.
pub const VIDEO_FPS: u32 = 30;
/// What the audio takes of the total estimate: `parolnet-media`'s Opus encoder at its default
/// (about 60 kbit/s for this tone) plus RTP headers and the SRTP tag, 50 packets a second.
pub const AUDIO_SHARE_BPS: u32 = 80_000;

/// The video bitrate an encoder may use when the congestion controller allows `total_bps`
/// for everything: what is left after the audio, with a tenth held back for retransmissions
/// and the encoder's own overshoot. The desktop's call session uses the same rule.
pub fn video_bitrate_for(total_bps: u32) -> u32 {
    let left = total_bps.saturating_sub(AUDIO_SHARE_BPS);
    ((u64::from(left) * 9 / 10) as u32).max(30_000)
}

/// Where a peer's video frames come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VideoSourceKind {
    /// The rate-following model (no codec).
    #[default]
    Model,
    /// The test pattern through libvpx, decoded on the other side.
    #[cfg(feature = "vpx")]
    Pattern,
}

/// How a simulated call is set up.
#[derive(Debug, Clone)]
pub struct CallConfig {
    /// Seed of the network's losses and jitter.
    pub seed: u64,
    /// Whether each side sends video from the start (`[caller, callee]`).
    pub video: [bool; 2],
    /// How long an offer or answer takes to reach the other side.
    pub signaling_delay: Duration,
    pub congestion: Option<CongestionConfig>,
    /// Use the driver's adaptive jitter buffer (as calls do).
    pub jitter_buffer: bool,
    pub video_source: VideoSourceKind,
    /// The addresses of the two machines.
    pub addresses: [Vec<&'static str>; 2],
    /// Packets an SRTP master key protects before the connection re-keys (`None`: the
    /// profile's, which a call never reaches).
    pub srtp_key_lifetime: Option<parolnet_rtc::rtc::srtp::keying::KeyLifetime>,
}

impl Default for CallConfig {
    fn default() -> Self {
        CallConfig {
            seed: 1,
            video: [true, true],
            signaling_delay: Duration::from_millis(50),
            congestion: Some(CongestionConfig::default()),
            jitter_buffer: true,
            video_source: VideoSourceKind::Model,
            addresses: [vec!["10.0.0.1"], vec!["10.0.0.2"]],
            srtp_key_lifetime: None,
        }
    }
}

/// What one side sent and received as video.
#[derive(Debug, Clone, Default)]
pub struct VideoMetrics {
    pub frames_sent: u64,
    pub bytes_sent: u64,
    pub keyframes_sent: u64,
    pub packets_received: u64,
    /// Frames reassembled from RTP.
    pub frames_received: u64,
    /// When each usable (decodable) frame was complete, since the call started.
    pub usable_at: Vec<Duration>,
    /// Frames that arrived whole but could not be used (their reference was lost).
    pub unusable: u64,
    pub keyframes_requested: u64,
}

impl VideoMetrics {
    /// The longest time without a usable frame between `from` and `to` (counting the wait
    /// from `from` to the first frame and from the last frame to `to`).
    pub fn longest_gap(&self, from: Duration, to: Duration) -> Duration {
        let mut last = from;
        let mut longest = Duration::ZERO;
        for at in self.usable_at.iter().filter(|t| **t >= from && **t <= to) {
            longest = longest.max(*at - last);
            last = *at;
        }
        longest.max(to.saturating_sub(last))
    }

    /// Usable frames between `from` and `to`.
    pub fn usable_between(&self, from: Duration, to: Duration) -> usize {
        self.usable_at
            .iter()
            .filter(|t| **t >= from && **t <= to)
            .count()
    }
}

/// What one side played as audio, in 20 ms windows.
#[derive(Debug, Clone, Default)]
pub struct AudioMetrics {
    pub packets_sent: u64,
    pub packets_received: u64,
    /// (when the window ended, whether it was the tone at about its level)
    pub windows: Vec<(Duration, bool)>,
    /// The playout buffer ran empty this often.
    pub underruns: u64,
}

impl AudioMetrics {
    fn between(&self, from: Duration, to: Duration) -> impl Iterator<Item = &(Duration, bool)> {
        self.windows
            .iter()
            .filter(move |(at, _)| *at >= from && *at <= to)
    }

    /// The share of played windows between `from` and `to` that were the tone.
    pub fn good_ratio(&self, from: Duration, to: Duration) -> f64 {
        let (mut good, mut all) = (0u32, 0u32);
        for (_, ok) in self.between(from, to) {
            all += 1;
            good += u32::from(*ok);
        }
        if all == 0 {
            0.0
        } else {
            f64::from(good) / f64::from(all)
        }
    }

    /// The longest run of windows that were not the tone, as time.
    pub fn longest_dropout(&self, from: Duration, to: Duration) -> Duration {
        let (mut run, mut longest) = (0u32, 0u32);
        for (_, ok) in self.between(from, to) {
            run = if *ok { 0 } else { run + 1 };
            longest = longest.max(run);
        }
        Duration::from_millis(20) * longest
    }
}

/// Everything one side observed, with times since the call started.
#[derive(Debug, Clone, Default)]
pub struct Metrics {
    pub states: Vec<(Duration, RTCPeerConnectionState)>,
    /// Local descriptions: (when, type, SDP).
    pub descriptions: Vec<(Duration, RTCSdpType, String)>,
    /// The congestion controller's estimates.
    pub targets: Vec<(Duration, u32)>,
    pub remote_media: Vec<(Duration, MediaKind, bool)>,
    pub local_media: Vec<(Duration, MediaKind, bool)>,
    pub quality: Vec<(Duration, ConnectionQuality)>,
    pub video: VideoMetrics,
    pub audio: AudioMetrics,
    pub closed: Option<Option<String>>,
}

impl Metrics {
    pub fn connected(&self) -> bool {
        self.states.last().map(|s| s.1) == Some(RTCPeerConnectionState::Connected)
    }

    /// When the connection first reached `connected`.
    pub fn connected_at(&self) -> Option<Duration> {
        self.states
            .iter()
            .find(|s| s.1 == RTCPeerConnectionState::Connected)
            .map(|s| s.0)
    }

    pub fn offers(&self) -> usize {
        self.descriptions
            .iter()
            .filter(|d| d.1 == RTCSdpType::Offer)
            .count()
    }

    pub fn answers(&self) -> usize {
        self.descriptions
            .iter()
            .filter(|d| d.1 == RTCSdpType::Answer)
            .count()
    }

    /// The estimate in force at `at`.
    pub fn target_at(&self, at: Duration) -> Option<u32> {
        self.targets
            .iter()
            .take_while(|t| t.0 <= at)
            .last()
            .map(|t| t.1)
    }

    /// The lowest and highest estimate between `from` and `to` (including the one in force
    /// at `from`).
    pub fn target_range(&self, from: Duration, to: Duration) -> Option<(u32, u32)> {
        let mut values: Vec<u32> = self
            .targets
            .iter()
            .filter(|t| t.0 >= from && t.0 <= to)
            .map(|t| t.1)
            .collect();
        values.extend(self.target_at(from));
        Some((*values.iter().min()?, *values.iter().max()?))
    }

    pub fn remote_sends(&self, kind: MediaKind) -> Option<bool> {
        self.remote_media
            .iter()
            .rev()
            .find(|m| m.1 == kind)
            .map(|m| m.2)
    }

    pub fn local_sends(&self, kind: MediaKind) -> Option<bool> {
        self.local_media
            .iter()
            .rev()
            .find(|m| m.1 == kind)
            .map(|m| m.2)
    }
}

/// The rate-following video source: frames whose sizes add up to the target bitrate.
///
/// A frame is `[VP8 frame tag (3 bytes)] "PN" [frame number, u32] [length, u32] padding`.
/// The tag's first bit is what the engine and the receiver read as key or delta frame.
#[derive(Debug, Default)]
pub struct VideoModel {
    number: u32,
    /// Bytes owed or saved so far, so that keyframes are paid for by the frames after them.
    debt: i64,
}

/// A parsed model frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelFrame {
    pub number: u32,
    pub key: bool,
    /// The frame arrived whole.
    pub complete: bool,
}

impl VideoModel {
    const HEADER: usize = 13;

    /// The next frame at `bitrate` bits per second.
    pub fn next_frame(&mut self, bitrate: u32, key: bool) -> Vec<u8> {
        let budget = i64::from(bitrate / 8 / VIDEO_FPS);
        // A keyframe costs several frames' worth; the following frames shrink to pay for it.
        let wanted = if key { budget * 5 } else { budget };
        let size = (wanted - self.debt.clamp(0, budget * 3 / 4)).max(Self::HEADER as i64 + 3);
        self.debt += size - budget;
        self.debt = self.debt.max(-budget);
        let size = size as usize;
        let mut frame = vec![0xa5u8; size];
        // VP8 frame tag: bit 0 clear is a keyframe. Show-frame set, first partition size 0.
        frame[0] = if key { 0x10 } else { 0x11 };
        frame[1] = 0;
        frame[2] = 0;
        frame[3] = b'P';
        frame[4] = b'N';
        frame[5..9].copy_from_slice(&self.number.to_be_bytes());
        frame[9..13].copy_from_slice(&(size as u32).to_be_bytes());
        self.number = self.number.wrapping_add(1);
        frame
    }

    pub fn parse(frame: &[u8]) -> Option<ModelFrame> {
        if frame.len() < Self::HEADER || &frame[3..5] != b"PN" {
            return None;
        }
        let number = u32::from_be_bytes(frame[5..9].try_into().ok()?);
        let length = u32::from_be_bytes(frame[9..13].try_into().ok()?) as usize;
        Some(ModelFrame {
            number,
            key: frame[0] & 1 == 0,
            complete: frame.len() == length,
        })
    }
}

/// The receiving side of the model: which frames a decoder could use.
#[derive(Debug, Default)]
struct ModelDecoder {
    last: Option<u32>,
}

impl ModelDecoder {
    /// Whether this frame is usable. A delta frame needs the frame before it.
    fn accept(&mut self, frame: ModelFrame) -> bool {
        let usable = frame.complete
            && (frame.key || self.last.is_some_and(|l| frame.number == l.wrapping_add(1)));
        if usable {
            self.last = Some(frame.number);
        } else if frame.complete
            && self
                .last
                .is_some_and(|l| frame.number.wrapping_sub(l) > u32::MAX / 2 || frame.number == l)
        {
            // An old or repeated frame: not a loss of reference.
            return false;
        } else {
            self.last = None;
        }
        usable
    }

    fn has_reference(&self) -> bool {
        self.last.is_some()
    }
}

/// Goertzel power of `hz` in `samples`, as a share of their total power (1.0 for a pure tone
/// at `hz`), and their RMS.
pub fn tone_share(samples: &[f32], hz: f64) -> (f64, f64) {
    let n = samples.len() as f64;
    let w = std::f64::consts::TAU * hz / f64::from(SAMPLE_RATE);
    let coeff = 2.0 * w.cos();
    let (mut s1, mut s2, mut energy) = (0.0f64, 0.0f64, 0.0f64);
    for x in samples {
        let x = f64::from(*x);
        let s0 = x + coeff * s1 - s2;
        s2 = s1;
        s1 = s0;
        energy += x * x;
    }
    if energy <= f64::EPSILON {
        return (0.0, 0.0);
    }
    let power = s1 * s1 + s2 * s2 - coeff * s1 * s2;
    // A sinusoid of amplitude A has Goertzel power (A n / 2)^2 and energy A^2 n / 2.
    ((2.0 * power / (n * energy)).min(1.0), (energy / n).sqrt())
}

/// Whether a played 20 ms window is the tone at about its level: most of its power at the
/// tone's frequency, and its level within 6 dB of what was sent.
pub fn is_the_tone(window: &[f32]) -> bool {
    let (share, rms) = tone_share(window, TONE_HZ);
    let sent = f64::from(TONE_AMPLITUDE) / std::f64::consts::SQRT_2;
    share >= 0.8 && rms >= sent / 2.0 && rms <= sent * 2.0
}

/// What the test can change on a running peer.
struct Control {
    /// The source produces video frames (the driver drops them unless sending is negotiated).
    video_source: AtomicBool,
    /// Offers and answers are delivered to the other side.
    signaling: AtomicBool,
    force_key: AtomicBool,
    target_bps: AtomicU32,
}

/// One side of the call.
pub struct SimPeer {
    pub host: SimHost,
    pub handle: Arc<RtcHandle>,
    metrics: Arc<Mutex<Metrics>>,
    control: Arc<Control>,
    task: tokio::task::JoinHandle<()>,
}

impl SimPeer {
    pub fn metrics(&self) -> MutexGuard<'_, Metrics> {
        self.metrics.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A copy of everything observed so far.
    pub fn snapshot(&self) -> Metrics {
        self.metrics().clone()
    }

    /// Start or stop sending video (renegotiates).
    pub fn set_video(&self, on: bool) {
        self.control.video_source.store(on, Ordering::Relaxed);
        self.control.force_key.store(true, Ordering::Relaxed);
        self.handle
            .set_sending(MediaKind::Video, on)
            .expect("the connection runs");
    }

    pub fn restart_ice(&self) {
        self.handle.restart_ice().expect("the connection runs");
    }

    /// Whether this side's offers and answers reach the other (a signaling outage when off;
    /// what was produced meanwhile is lost).
    pub fn set_signaling(&self, on: bool) {
        self.control.signaling.store(on, Ordering::Relaxed);
    }
}

/// Two peers in a call on a simulated network.
pub struct SimCall {
    pub net: SimNet,
    pub caller: SimPeer,
    pub callee: SimPeer,
    started: Instant,
}

impl SimCall {
    /// Build the network and both peers and send the caller's offer. Run it with
    /// [`SimCall::run_for`] / [`SimCall::until`].
    pub async fn start(config: CallConfig) -> SimCall {
        let net = SimNet::new(config.seed);
        let hosts = [
            net.host(&config.addresses[0]),
            net.host(&config.addresses[1]),
        ];
        Self::start_on(net, hosts, config).await
    }

    /// The same on hosts the test prepared (their link profiles set).
    pub async fn start_on(net: SimNet, hosts: [SimHost; 2], config: CallConfig) -> SimCall {
        let started = Instant::now();
        let (to_caller, caller_inbox) = mpsc::unbounded_channel();
        let (to_callee, callee_inbox) = mpsc::unbounded_channel();
        let [caller_host, callee_host] = hosts;
        let caller = spawn_peer(&config, 0, caller_host, started, caller_inbox, to_callee).await;
        let callee = spawn_peer(&config, 1, callee_host, started, callee_inbox, to_caller).await;
        caller.handle.create_offer().expect("offer");
        SimCall {
            net,
            caller,
            callee,
            started,
        }
    }

    /// Time since the call started.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Let the call run for `time` (virtual time on a paused runtime).
    pub async fn run_for(&self, time: Duration) {
        tokio::time::sleep(time).await;
    }

    /// Run until `done` holds, checking every 10 ms; panics after `limit`.
    pub async fn until(&self, what: &str, limit: Duration, mut done: impl FnMut(&SimCall) -> bool) {
        let deadline = Instant::now() + limit;
        while !done(self) {
            assert!(
                Instant::now() < deadline,
                "{what}: not within {limit:?} (caller {:?}, callee {:?})",
                self.caller.metrics().states.last(),
                self.callee.metrics().states.last(),
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Run until both sides are connected; returns when that was.
    pub async fn until_connected(&self, limit: Duration) -> Duration {
        self.until("connecting", limit, |c| {
            c.caller.metrics().connected() && c.callee.metrics().connected()
        })
        .await;
        self.elapsed()
    }

    /// Stop both peers.
    pub async fn close(self) {
        for peer in [self.caller, self.callee] {
            peer.task.abort();
            let _ = peer.task.await;
            if let Ok(handle) = Arc::try_unwrap(peer.handle) {
                handle.close().await;
            }
        }
    }
}

async fn spawn_peer(
    config: &CallConfig,
    index: usize,
    host: SimHost,
    started: Instant,
    inbox: mpsc::UnboundedReceiver<RTCSessionDescription>,
    outbox: mpsc::UnboundedSender<RTCSessionDescription>,
) -> SimPeer {
    let video = config.video[index];
    let rtc_config = RtcConfig {
        bind: "0.0.0.0:0".parse().expect("an address"),
        gather: Gather::Interfaces,
        network: host.network(),
        media: MediaConfig {
            recv_opus: true,
            send_opus: true,
            recv_vp8: video,
            send_vp8: video,
        },
        congestion: config.congestion,
        jitter_buffer: config.jitter_buffer,
        // The callee yields when offers cross, as in the app.
        polite: index == 1,
        mdns: false,
        quality_interval: Some(Duration::from_secs(1)),
        srtp_key_lifetime: config.srtp_key_lifetime,
        ..Default::default()
    };
    let (handle, events) = parolnet_rtc::spawn(rtc_config).await.expect("spawn");
    let handle = Arc::new(handle);
    let metrics = Arc::new(Mutex::new(Metrics::default()));
    let control = Arc::new(Control {
        video_source: AtomicBool::new(video),
        signaling: AtomicBool::new(true),
        force_key: AtomicBool::new(true),
        target_bps: AtomicU32::new(config.congestion.map_or(1_000_000, |c| c.initial_bps())),
    });
    let peer = PeerTask {
        handle: handle.clone(),
        events,
        inbox,
        outbox,
        signaling_delay: config.signaling_delay,
        metrics: metrics.clone(),
        control: control.clone(),
        started,
        source: config.video_source,
    };
    let task = tokio::spawn(peer.run());
    SimPeer {
        host,
        handle,
        metrics,
        control,
        task,
    }
}

struct PeerTask {
    handle: Arc<RtcHandle>,
    events: mpsc::Receiver<RtcEvent>,
    inbox: mpsc::UnboundedReceiver<RTCSessionDescription>,
    outbox: mpsc::UnboundedSender<RTCSessionDescription>,
    signaling_delay: Duration,
    metrics: Arc<Mutex<Metrics>>,
    control: Arc<Control>,
    started: Instant,
    source: VideoSourceKind,
}

/// The sending side's video encoder.
enum VideoEncoder {
    Model(VideoModel),
    #[cfg(feature = "vpx")]
    Pattern {
        pattern: parolnet_media::pattern::TestPattern,
        encoder: parolnet_media::vp8::Vp8Encoder,
        kbps: u32,
    },
}

impl VideoEncoder {
    fn new(kind: VideoSourceKind) -> VideoEncoder {
        match kind {
            VideoSourceKind::Model => VideoEncoder::Model(VideoModel::default()),
            #[cfg(feature = "vpx")]
            VideoSourceKind::Pattern => VideoEncoder::Pattern {
                pattern: parolnet_media::pattern::TestPattern::new(320, 180),
                encoder: parolnet_media::vp8::Vp8Encoder::new(320, 180, VIDEO_FPS, 250)
                    .expect("libvpx"),
                kbps: 250,
            },
        }
    }

    /// The next frame at `bitrate`, and whether it is a keyframe.
    fn next(&mut self, bitrate: u32, key: bool) -> Option<(Vec<u8>, bool)> {
        match self {
            VideoEncoder::Model(model) => Some((model.next_frame(bitrate, key), key)),
            #[cfg(feature = "vpx")]
            VideoEncoder::Pattern {
                pattern,
                encoder,
                kbps,
            } => {
                let wanted = (bitrate / 1000).max(30);
                if wanted != *kbps {
                    *kbps = wanted;
                    let _ = encoder.set_bitrate(wanted);
                }
                let frame = pattern.next_frame();
                let encoded = encoder.encode(&frame, key).ok()??;
                Some((encoded.data, encoded.keyframe))
            }
        }
    }
}

/// The receiving side's video decoder: says whether a reassembled frame is usable.
enum VideoDecoder {
    Model(ModelDecoder),
    #[cfg(feature = "vpx")]
    Pattern {
        decoder: parolnet_media::vp8::Vp8Decoder,
        has_reference: bool,
    },
}

impl VideoDecoder {
    fn new(kind: VideoSourceKind) -> VideoDecoder {
        match kind {
            VideoSourceKind::Model => VideoDecoder::Model(ModelDecoder::default()),
            #[cfg(feature = "vpx")]
            VideoSourceKind::Pattern => VideoDecoder::Pattern {
                decoder: parolnet_media::vp8::Vp8Decoder::new(1).expect("libvpx"),
                has_reference: false,
            },
        }
    }

    /// Whether the frame is usable; `None` for something that is not a frame at all.
    fn accept(&mut self, data: &[u8]) -> Option<bool> {
        match self {
            VideoDecoder::Model(decoder) => Some(decoder.accept(VideoModel::parse(data)?)),
            #[cfg(feature = "vpx")]
            VideoDecoder::Pattern {
                decoder,
                has_reference,
            } => {
                let key = parolnet_media::vp8::is_keyframe(data);
                if !key && !*has_reference {
                    return Some(false);
                }
                let ok = decoder.decode(data).is_ok_and(|frames| !frames.is_empty());
                *has_reference = ok;
                Some(ok)
            }
        }
    }

    fn has_reference(&self) -> bool {
        match self {
            VideoDecoder::Model(decoder) => decoder.has_reference(),
            #[cfg(feature = "vpx")]
            VideoDecoder::Pattern { has_reference, .. } => *has_reference,
        }
    }
}

impl PeerTask {
    fn metrics(&self) -> MutexGuard<'_, Metrics> {
        self.metrics.lock().unwrap_or_else(|e| e.into_inner())
    }

    async fn run(mut self) {
        let mut audio_tick = tokio::time::interval(Duration::from_millis(20));
        let mut video_tick =
            tokio::time::interval(Duration::from_micros(1_000_000 / u64::from(VIDEO_FPS)));
        let mut playout_tick = tokio::time::interval(Duration::from_millis(10));
        for tick in [&mut audio_tick, &mut video_tick, &mut playout_tick] {
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
        }

        let mut tone = Tone::new(SAMPLE_RATE, TONE_HZ, TONE_AMPLITUDE);
        let mut pcm = Vec::with_capacity(FRAME_20MS);
        let mut opus_encoder = OpusEncoder::new().expect("Opus encoder");
        let mut opus_decoder = OpusDecoder::new().expect("Opus decoder");
        let mut video_encoder = VideoEncoder::new(self.source);
        let mut video_decoder = VideoDecoder::new(self.source);
        let mut builder = SampleBuilder::new(256, Vp8Packet::default(), 90_000);
        let playout = PlayoutBuffer::new();
        let mut played: Vec<f32> = Vec::with_capacity(FRAME_20MS);
        let mut playing = false;
        let mut kinds: HashMap<String, MediaKind> = HashMap::new();
        let mut connected = false;
        let mut last_keyframe_request: Option<Instant> = None;

        loop {
            tokio::select! {
                biased;
                event = self.events.recv() => {
                    let Some(event) = event else { return };
                    let at = self.started.elapsed();
                    match event {
                        RtcEvent::LocalDescription(desc) => {
                            self.metrics().descriptions.push((at, desc.sdp_type, desc.sdp.clone()));
                            if self.control.signaling.load(Ordering::Relaxed) {
                                let (outbox, delay) = (self.outbox.clone(), self.signaling_delay);
                                tokio::spawn(async move {
                                    tokio::time::sleep(delay).await;
                                    let _ = outbox.send(*desc);
                                });
                            }
                        }
                        RtcEvent::ConnectionState(state) => {
                            connected |= state == RTCPeerConnectionState::Connected;
                            self.metrics().states.push((at, state));
                        }
                        RtcEvent::Track { track_id, kind, .. } => {
                            if let Some(kind) = MediaKind::of(kind) {
                                kinds.insert(track_id, kind);
                                if kind == MediaKind::Video {
                                    let _ = self.handle.frame_sender().request_keyframes();
                                }
                            }
                        }
                        RtcEvent::Rtp { track_id, packet } => match kinds.get(&track_id) {
                            Some(MediaKind::Audio) => {
                                self.metrics().audio.packets_received += 1;
                                if let Ok(decoded) = opus_decoder.decode(&packet.payload) {
                                    playout.push(decoded);
                                }
                            }
                            Some(MediaKind::Video) => {
                                self.metrics().video.packets_received += 1;
                                let now = parolnet_rtc::now();
                                builder.push(now, packet);
                                while let Some(sample) = builder.pop(now) {
                                    let Some(usable) = video_decoder.accept(&sample.data) else {
                                        continue;
                                    };
                                    let mut m = self.metrics();
                                    m.video.frames_received += 1;
                                    if usable {
                                        m.video.usable_at.push(at);
                                    } else {
                                        m.video.unusable += 1;
                                    }
                                }
                                // A decoder without its reference asks for a keyframe, at
                                // most once a second (as the desktop's receive path does).
                                if !video_decoder.has_reference()
                                    && last_keyframe_request
                                        .is_none_or(|t| t.elapsed() >= Duration::from_secs(1))
                                {
                                    last_keyframe_request = Some(Instant::now());
                                    self.metrics().video.keyframes_requested += 1;
                                    let _ = self.handle.frame_sender().request_keyframes();
                                }
                            }
                            None => {}
                        },
                        RtcEvent::KeyframeRequested => {
                            self.control.force_key.store(true, Ordering::Relaxed);
                        }
                        RtcEvent::TargetBitrate { bps } => {
                            self.control.target_bps.store(bps, Ordering::Relaxed);
                            self.metrics().targets.push((at, bps));
                        }
                        RtcEvent::RemoteMedia { kind, sending } => {
                            self.metrics().remote_media.push((at, kind, sending));
                        }
                        RtcEvent::LocalMedia { kind, sending } => {
                            self.metrics().local_media.push((at, kind, sending));
                            if kind == MediaKind::Video && sending {
                                self.control.force_key.store(true, Ordering::Relaxed);
                            }
                        }
                        RtcEvent::Quality(quality) => self.metrics().quality.push((at, quality)),
                        RtcEvent::Closed { error } => {
                            self.metrics().closed = Some(error);
                            return;
                        }
                        RtcEvent::DataChannelOpen { .. }
                        | RtcEvent::DataChannelClose { .. }
                        | RtcEvent::DataChannelBufferedLow { .. }
                        | RtcEvent::DataChannelMessage { .. }
                        | RtcEvent::IceConnectionState(_)
                        | RtcEvent::SelectedCandidatePairChanged
                        | RtcEvent::RemoteOfferIgnored => {}
                    }
                }
                Some(desc) = self.inbox.recv() => {
                    let _ = self.handle.set_remote_description(desc);
                }
                _ = audio_tick.tick() => {
                    if connected {
                        pcm.clear();
                        tone.generate(FRAME_20MS, &mut pcm);
                        if let Ok(packet) = opus_encoder.encode(&pcm) {
                            let _ = self.handle.send_frame(
                                MediaKind::Audio,
                                packet.to_vec(),
                                FRAME_20MS as u32,
                            );
                            self.metrics().audio.packets_sent += 1;
                        }
                    }
                }
                _ = video_tick.tick() => {
                    if connected && self.control.video_source.load(Ordering::Relaxed) {
                        let key = self.control.force_key.swap(false, Ordering::Relaxed);
                        let bitrate =
                            video_bitrate_for(self.control.target_bps.load(Ordering::Relaxed));
                        if let Some((frame, is_key)) = video_encoder.next(bitrate, key) {
                            {
                                let mut m = self.metrics();
                                m.video.frames_sent += 1;
                                m.video.bytes_sent += frame.len() as u64;
                                m.video.keyframes_sent += u64::from(is_key);
                            }
                            let _ = self.handle.send_frame(
                                MediaKind::Video,
                                frame,
                                90_000 / VIDEO_FPS,
                            );
                        }
                    }
                }
                _ = playout_tick.tick() => {
                    // The sound card's pull: 10 ms at a time, judged in 20 ms windows from
                    // the moment audio first played.
                    let mut frame = [0.0f32; FRAME_10MS];
                    let got = playout.pop(&mut frame);
                    if !got && playing {
                        self.metrics().audio.underruns += 1;
                    }
                    playing |= got;
                    if playing {
                        played.extend_from_slice(&frame);
                        if played.len() >= FRAME_20MS {
                            let good = is_the_tone(&played[..FRAME_20MS]);
                            played.clear();
                            let at = self.started.elapsed();
                            self.metrics().audio.windows.push((at, good));
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_model_spends_its_bitrate_and_pays_for_keyframes() {
        let mut model = VideoModel::default();
        let mut total = 0usize;
        for i in 0..300 {
            // A keyframe at the start and one mid-way.
            let frame = model.next_frame(300_000, i == 0 || i == 150);
            let parsed = VideoModel::parse(&frame).unwrap();
            assert_eq!(parsed.number, i);
            assert_eq!(parsed.key, i == 0 || i == 150);
            assert!(parsed.complete);
            total += frame.len();
        }
        // Ten seconds at 300 kbit/s are 375000 bytes.
        let rate = total as f64 * 8.0 / 10.0;
        assert!((290_000.0..=315_000.0).contains(&rate), "{rate}");
        let truncated = &model.next_frame(300_000, false)[..100];
        assert!(!VideoModel::parse(truncated).unwrap().complete);
        assert_eq!(VideoModel::parse(b"not a frame"), None);
    }

    #[test]
    fn a_delta_frame_needs_the_frame_before_it() {
        let mut model = VideoModel::default();
        let frames: Vec<ModelFrame> = (0..10)
            .map(|i| VideoModel::parse(&model.next_frame(100_000, i == 0 || i == 6)).unwrap())
            .collect();
        let mut decoder = ModelDecoder::default();
        assert!(!decoder.accept(frames[1]), "no keyframe yet");
        assert!(decoder.accept(frames[0]));
        assert!(decoder.accept(frames[1]));
        assert!(decoder.accept(frames[2]));
        // Frame 3 is lost: 4 and 5 are useless, and the reference is gone.
        assert!(!decoder.accept(frames[4]));
        assert!(!decoder.has_reference());
        assert!(!decoder.accept(frames[5]));
        // The keyframe restores it.
        assert!(decoder.accept(frames[6]));
        assert!(decoder.accept(frames[7]));
        // A duplicate does not break the chain.
        assert!(!decoder.accept(frames[7]));
        assert!(decoder.has_reference());
        assert!(decoder.accept(frames[8]));
    }

    #[test]
    fn the_tone_is_told_from_silence_noise_and_other_tones() {
        let window = |hz: f64, amplitude: f32| {
            let mut out = Vec::new();
            Tone::new(SAMPLE_RATE, hz, amplitude).generate(FRAME_20MS, &mut out);
            out
        };
        assert!(is_the_tone(&window(TONE_HZ, TONE_AMPLITUDE)));
        assert!(is_the_tone(&window(TONE_HZ, TONE_AMPLITUDE * 0.7)));
        assert!(
            !is_the_tone(&window(TONE_HZ, TONE_AMPLITUDE * 0.2)),
            "too quiet"
        );
        assert!(
            !is_the_tone(&window(1000.0, TONE_AMPLITUDE)),
            "another tone"
        );
        assert!(!is_the_tone(&[0.0; FRAME_20MS]), "silence");
        // Half a window of tone, half of silence (a dropout).
        let mut half = window(TONE_HZ, TONE_AMPLITUDE);
        half[FRAME_20MS / 2..].fill(0.0);
        assert!(!is_the_tone(&half));
        // Noise.
        let mut seed = 1u32;
        let noise: Vec<f32> = (0..FRAME_20MS)
            .map(|_| {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (seed >> 8) as f32 / (1u32 << 24) as f32 * 0.2 - 0.1
            })
            .collect();
        assert!(!is_the_tone(&noise));
        // The tone through Opus is still the tone.
        let mut encoder = OpusEncoder::new().unwrap();
        let mut decoder = OpusDecoder::new().unwrap();
        let mut tone = Tone::new(SAMPLE_RATE, TONE_HZ, TONE_AMPLITUDE);
        let mut good = 0;
        for i in 0..50 {
            let mut pcm = Vec::new();
            tone.generate(FRAME_20MS, &mut pcm);
            let packet = encoder.encode(&pcm).unwrap().to_vec();
            let decoded = decoder.decode(&packet).unwrap();
            // The codec's first frames are its start-up.
            if i >= 5 && is_the_tone(decoded) {
                good += 1;
            }
        }
        assert!(good >= 43, "{good} of 45 decoded windows are the tone");
    }

    #[test]
    fn the_video_share_of_an_estimate() {
        assert_eq!(video_bitrate_for(300_000), 198_000);
        assert_eq!(video_bitrate_for(1_080_000), 900_000);
        assert_eq!(video_bitrate_for(50_000), 30_000);
        assert_eq!(video_bitrate_for(0), 30_000);
    }
}
