//! A call's media on the desktop, built from `parolnet-media`:
//!
//! - **video out** (`call-video` thread): the camera (or the test pattern when there is no
//!   camera or synthetic media is selected) → I420 at the send size → libvpx VP8 → the call's
//!   [`FrameSink`]; every other frame also goes to the self-view slot. The encoder's rate
//!   follows the congestion controller's estimate ([`MediaEvent::TargetBitrate`]). With the
//!   camera off the device is released; with a contact whose app renegotiates the stream is
//!   stopped (the window asks the core, see [`CallSession::set_renegotiated`]), with any
//!   other a black frame goes out once a second (what a browser sends for a disabled track),
//!   so the contact sees black instead of a frozen picture. An audio call gains video with
//!   [`CallSession::start_video`];
//! - **audio** (`call-audio` thread): microphone → echo cancellation, noise suppression and
//!   gain (AEC3) → Opus, and the contact's Opus → playout buffer → the processor's reverse
//!   stream → speakers ([`parolnet_media::duplex`]);
//! - **receive** (a tokio task): VP8 into the decoder thread and the video slot, Opus into the
//!   playout buffer.
//!
//! Devices can be switched while the call runs. A device that fails or disappears is closed
//! and reported in [`CallSession::status`]; the call goes on without it (audio falls back to
//! the system default once). Nothing here runs on the UI thread, and nothing panics on a
//! device error.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use parolnet_app::{CallMedia, FrameSink, MediaEvent, MediaKind};
use parolnet_media::duplex::{AudioDuplex, DuplexError, PlayoutBuffer};
use parolnet_media::opus::{OpusDecoder, OpusEncoder};
use parolnet_media::processing::{ProcessingConfig, new_processor};
use parolnet_media::source::{NullSink, PatternPixel, PatternSource, ToneSource};
use parolnet_media::vp8::Vp8Encoder;
use parolnet_media::{
    AudioSink, AudioSource, DeviceInfo, FRAME_20MS, I420Frame, MediaError, SAMPLE_RATE,
    VideoFormat, VideoSource, audio_io, camera,
};
use parolnet_rtc::rtci::media::io::sample_builder::SampleBuilder;
use parolnet_rtc::rtci::rtp::codec::vp8::Vp8Packet;

use crate::frame::{FrameSlot, Presentable};
use crate::receiver::{Stats, decode_loop};

/// The audio thread's cadence.
const AUDIO_TICK: Duration = Duration::from_millis(5);
/// How often a failed audio device is tried again (on the system default).
const AUDIO_RETRY: Duration = Duration::from_secs(2);
/// What a muted microphone sends.
static SILENCE: [f32; FRAME_20MS] = [0.0; FRAME_20MS];
/// With the camera off: one black frame per second.
const BLACK_INTERVAL: Duration = Duration::from_secs(1);

/// What the call sends as video: 640x360 by default, 1280x720 with `PAROLNET_VIDEO=720p`.
pub fn send_format() -> (VideoFormat, u32) {
    match std::env::var("PAROLNET_VIDEO").as_deref() {
        Ok("720p") | Ok("720") => (VideoFormat::P720, 1800),
        _ => (VideoFormat::P360, 900),
    }
}

/// Whether `PAROLNET_SYNTHETIC_MEDIA` selects the synthetic sources (test pattern, tone, no
/// devices) for the window's calls too. `--call-check` always uses them.
pub fn synthetic_from_env() -> bool {
    std::env::var("PAROLNET_SYNTHETIC_MEDIA").is_ok_and(|v| !v.is_empty() && v != "0")
}

/// Which devices a call uses.
#[derive(Clone, Debug, Default)]
pub struct MediaOptions {
    /// No devices: the test pattern, a tone, and playback into nothing (CI, `--call-check`).
    pub synthetic: bool,
    /// Device ids as the device lists give them; `None` is the system default.
    pub camera: Option<String>,
    pub microphone: Option<String>,
    pub speaker: Option<String>,
}

/// The devices to choose from.
#[derive(Clone, Debug, Default)]
pub struct DeviceLists {
    pub cameras: Vec<DeviceInfo>,
    pub microphones: Vec<DeviceInfo>,
    pub speakers: Vec<DeviceInfo>,
}

/// List the devices. Slow on some systems: call it off the UI thread.
pub fn list_devices() -> DeviceLists {
    DeviceLists {
        cameras: camera::cameras(),
        microphones: audio_io::input_devices(),
        speakers: audio_io::output_devices(),
    }
}

/// Counters for the call view and the headless check.
#[derive(Default)]
pub struct CallStats {
    pub video: Arc<Stats>,
    pub audio_packets: AtomicU64,
    pub audio_decoded: AtomicU64,
    pub video_sent: AtomicU64,
    pub audio_sent: AtomicU64,
}

/// What the call's devices are doing, for the call panel.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MediaStatus {
    /// What is being sent as video ("FaceTime HD Camera", "Test pattern", "Camera off", or
    /// why there is none). Empty for an audio call.
    pub camera: String,
    pub microphone: String,
    pub speaker: String,
}

struct Shared {
    muted: AtomicBool,
    camera_off: AtomicBool,
    /// The call is renegotiated when the camera goes off or on: nothing is sent while it is
    /// off (otherwise black is).
    renegotiated: AtomicBool,
    /// What the congestion controller allows for everything we send, in bits per second
    /// (0: not known yet).
    target_bps: AtomicU32,
    stop: AtomicBool,
    force_keyframe: AtomicBool,
    status: Mutex<MediaStatus>,
}

impl Shared {
    fn set_status(&self, update: impl FnOnce(&mut MediaStatus)) {
        update(&mut self.status.lock().unwrap_or_else(|e| e.into_inner()));
    }
}

enum VideoCmd {
    /// Capture from this camera (`None`: the default one).
    Camera(Option<String>),
}

enum AudioCmd {
    Microphone(Option<String>),
    Speaker(Option<String>),
}

/// A running call's media. Dropping it stops capture, encoding and playback.
pub struct CallSession {
    /// The contact's video.
    pub slot: FrameSlot,
    /// What we send, for the self-view.
    pub self_slot: FrameSlot,
    pub stats: Arc<CallStats>,
    shared: Arc<Shared>,
    video: bool,
    video_cmd: Option<Sender<VideoCmd>>,
    audio_cmd: Sender<AudioCmd>,
    /// For a video sender started later (an audio call that gains video).
    frames: FrameSink,
    options: MediaOptions,
}

impl CallSession {
    /// Start the media of an active (or connecting) call.
    pub fn start(
        media: CallMedia,
        video: bool,
        options: MediaOptions,
        runtime: &tokio::runtime::Handle,
    ) -> CallSession {
        let CallMedia { frames, events } = media;
        let slot = FrameSlot::default();
        let self_slot = FrameSlot::default();
        let stats = Arc::new(CallStats::default());
        let shared = Arc::new(Shared {
            muted: AtomicBool::new(false),
            camera_off: AtomicBool::new(false),
            renegotiated: AtomicBool::new(false),
            target_bps: AtomicU32::new(0),
            stop: AtomicBool::new(false),
            force_keyframe: AtomicBool::new(true),
            status: Mutex::default(),
        });
        let playout = PlayoutBuffer::new();

        let video_cmd =
            video.then(|| spawn_video_sender(&frames, &stats, &shared, &self_slot, &options));
        let (audio_cmd, audio_rx) = std::sync::mpsc::channel();
        {
            let worker = AudioWorker {
                frames: frames.clone(),
                stats: stats.clone(),
                shared: shared.clone(),
                playout: playout.clone(),
                synthetic: options.synthetic,
                cmds: audio_rx,
            };
            let (mic, speaker) = (options.microphone.clone(), options.speaker.clone());
            spawn("call-audio", move || worker.run(mic, speaker));
        }
        runtime.spawn(receive(
            events,
            frames.clone(),
            slot.clone(),
            stats.clone(),
            playout,
            shared.clone(),
        ));
        slot.set_status(if video {
            "connecting video"
        } else {
            "audio only"
        });
        CallSession {
            slot,
            self_slot,
            stats,
            shared,
            video,
            video_cmd,
            audio_cmd,
            frames,
            options,
        }
    }

    /// An audio call gains our video: start capturing and encoding (the core sends it once
    /// the contact has accepted it). No-op when video already runs.
    pub fn start_video(&mut self) {
        if self.video_cmd.is_none() {
            self.video_cmd = Some(spawn_video_sender(
                &self.frames,
                &self.stats,
                &self.shared,
                &self.self_slot,
                &self.options,
            ));
        }
        self.video = true;
    }

    /// The call has video in it now (the contact added theirs): the camera button and the
    /// tiles apply even while we send none.
    pub fn mark_video(&mut self) {
        self.video = true;
    }

    /// Whether we capture and encode video (it may still be turned off).
    pub fn sends_video(&self) -> bool {
        self.video_cmd.is_some()
    }

    /// Whether turning the camera off stops the stream (the contact's app renegotiates)
    /// instead of sending black.
    pub fn set_renegotiated(&self, renegotiated: bool) {
        self.shared
            .renegotiated
            .store(renegotiated, Ordering::Relaxed);
    }

    pub fn set_muted(&self, muted: bool) {
        self.shared.muted.store(muted, Ordering::Relaxed);
    }

    pub fn muted(&self) -> bool {
        self.shared.muted.load(Ordering::Relaxed)
    }

    /// Whether this is a video call (it has a camera to turn on and off).
    pub fn has_video(&self) -> bool {
        self.video
    }

    /// Turn the camera on or off. Off releases the device and sends black.
    pub fn set_camera_enabled(&self, enabled: bool) {
        self.shared.camera_off.store(!enabled, Ordering::Relaxed);
    }

    pub fn camera_enabled(&self) -> bool {
        !self.shared.camera_off.load(Ordering::Relaxed)
    }

    /// Capture from another camera (`None`: the default one).
    pub fn select_camera(&self, id: Option<String>) {
        if let Some(tx) = &self.video_cmd {
            let _ = tx.send(VideoCmd::Camera(id));
        }
    }

    pub fn select_microphone(&self, id: Option<String>) {
        let _ = self.audio_cmd.send(AudioCmd::Microphone(id));
    }

    pub fn select_speaker(&self, id: Option<String>) {
        let _ = self.audio_cmd.send(AudioCmd::Speaker(id));
    }

    /// What the devices are doing right now.
    pub fn status(&self) -> MediaStatus {
        self.shared
            .status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl Drop for CallSession {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
    }
}

fn spawn_video_sender(
    frames: &FrameSink,
    stats: &Arc<CallStats>,
    shared: &Arc<Shared>,
    self_slot: &FrameSlot,
    options: &MediaOptions,
) -> Sender<VideoCmd> {
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = VideoSender {
        frames: frames.clone(),
        stats: stats.clone(),
        shared: shared.clone(),
        self_slot: self_slot.clone(),
        synthetic: options.synthetic,
        camera_id: options.camera.clone(),
        cmds: rx,
    };
    spawn("call-video", move || worker.run());
    tx
}

/// The encoder's rate in kbit/s for the congestion controller's estimate: the video share of
/// it, never above what the picture size is encoded at on an open path.
pub fn encoder_kbps(target_bps: u32, format_kbps: u32) -> u32 {
    if target_bps == 0 {
        return format_kbps;
    }
    (parolnet_app::video_bitrate_for(target_bps) / 1000).clamp(30, format_kbps.max(30))
}

/// A frame interval in the 90 kHz RTP clock, kept between 1 ms and 2 s.
fn rtp_ticks(interval: Duration) -> u32 {
    (interval.as_micros() * 9 / 100).clamp(90, 180_000) as u32
}

fn spawn(name: &str, f: impl FnOnce() + Send + 'static) {
    if let Err(e) = std::thread::Builder::new().name(name.into()).spawn(f) {
        tracing::warn!("could not start the {name} thread: {e}");
    }
}

/// Where the video comes from.
enum VideoInput {
    /// Nothing open yet (or the camera was just turned on again): open on the next turn.
    Closed,
    Open(Box<dyn VideoSource>),
    /// The camera could not be used; black goes out until the user picks again.
    Failed,
}

struct VideoSender {
    frames: FrameSink,
    stats: Arc<CallStats>,
    shared: Arc<Shared>,
    self_slot: FrameSlot,
    synthetic: bool,
    camera_id: Option<String>,
    cmds: Receiver<VideoCmd>,
}

impl VideoSender {
    fn run(mut self) {
        let (format, kbps) = send_format();
        let mut encoder = match Vp8Encoder::new(format.width, format.height, format.fps, kbps) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("{e}");
                self.shared
                    .set_status(|s| s.camera = format!("No video: {e}"));
                return;
            }
        };
        let black = I420Frame::black(format.width, format.height);
        let mut encoder_rate = kbps;
        let mut input = VideoInput::Closed;
        let mut last_black: Option<Instant> = None;
        let mut last_sent: Option<Instant> = None;
        let mut frame_no = 0u64;
        while !self.shared.stop.load(Ordering::Relaxed) {
            loop {
                match self.cmds.try_recv() {
                    Ok(VideoCmd::Camera(id)) => {
                        self.camera_id = id;
                        // Drop the open device first: two captures of one camera fail.
                        input = VideoInput::Closed;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return,
                }
            }
            // Follow the congestion controller: the encoder never asks more of the path
            // than it carries.
            let wanted = encoder_kbps(self.shared.target_bps.load(Ordering::Relaxed), kbps);
            if wanted != encoder_rate {
                match encoder.set_bitrate(wanted) {
                    Ok(()) => encoder_rate = wanted,
                    Err(e) => tracing::debug!("{e}"),
                }
            }
            let off = self.shared.camera_off.load(Ordering::Relaxed);
            if off && self.shared.renegotiated.load(Ordering::Relaxed) {
                // The stream is stopped by renegotiation: release the device, send nothing.
                if !matches!(input, VideoInput::Closed) {
                    input = VideoInput::Closed;
                    self.shared.set_status(|s| s.camera = "Camera off".into());
                }
                last_black = None;
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            if off && !matches!(input, VideoInput::Closed) {
                // Release the device (its light goes out); turning the camera on reopens it.
                input = VideoInput::Closed;
                self.shared.set_status(|s| s.camera = "Camera off".into());
                last_black = None;
            }
            if !off && matches!(input, VideoInput::Closed) {
                input = self.open(format);
                self.shared.force_keyframe.store(true, Ordering::Relaxed);
                last_black = None;
            }
            let picture = match &mut input {
                VideoInput::Open(source) => match source.next_frame(Duration::from_millis(100)) {
                    Ok(Some(frame)) => match frame.into_i420() {
                        Ok(f) => Some(f.scaled_to(format.width, format.height)),
                        Err(e) => {
                            tracing::debug!("camera frame: {e}");
                            None
                        }
                    },
                    Ok(None) => None,
                    Err(e) => {
                        tracing::warn!("camera: {e}");
                        self.shared
                            .set_status(|s| s.camera = format!("Camera unavailable: {e}"));
                        input = VideoInput::Failed;
                        None
                    }
                },
                // Camera off or unusable: black, once a second.
                VideoInput::Closed | VideoInput::Failed => {
                    if last_black.is_none_or(|t| t.elapsed() >= BLACK_INTERVAL) {
                        self.shared
                            .force_keyframe
                            .fetch_or(last_black.is_none(), Ordering::Relaxed);
                        last_black = Some(Instant::now());
                        Some(black.clone())
                    } else {
                        std::thread::sleep(Duration::from_millis(50));
                        None
                    }
                }
            };
            let Some(picture) = picture else { continue };
            let key = self.shared.force_keyframe.swap(false, Ordering::Relaxed);
            match encoder.encode(&picture, key) {
                Ok(Some(e)) => {
                    // The RTP clock follows the real frame times (a camera in low light
                    // slows down; black frames come once a second), not a nominal 30 fps.
                    let now = Instant::now();
                    let ticks = last_sent.map_or(90_000 / format.fps, |t| rtp_ticks(now - t));
                    last_sent = Some(now);
                    if !self.frames.send(MediaKind::Video, e.data, ticks) {
                        break;
                    }
                    self.stats.video_sent.fetch_add(1, Ordering::Relaxed);
                }
                Ok(None) => {}
                Err(e) => tracing::debug!("{e}"),
            }
            // The self-view at half the rate: it is a preview, and the conversion is not free.
            frame_no += 1;
            if frame_no % 2 == 1 {
                self.self_slot.publish(
                    Presentable::from_frame(&picture, false),
                    picture.width,
                    picture.height,
                );
            }
        }
    }

    /// Open the video source: the test pattern for synthetic media or a machine without a
    /// camera, else the selected camera.
    fn open(&self, format: VideoFormat) -> VideoInput {
        // The pattern arrives as a camera's picture would (720p YUYV), so calls without a
        // camera (CI) run the same conversion and scaling as calls with one.
        let pattern = |why: &str| {
            self.shared.set_status(|s| s.camera = why.to_owned());
            let source = PatternSource::new(VideoFormat::P720).with_pixel(PatternPixel::Yuyv);
            VideoInput::Open(Box::new(source))
        };
        if self.synthetic {
            return pattern("Test pattern");
        }
        if camera::cameras().is_empty() {
            return pattern("No camera: sending a test pattern");
        }
        self.shared
            .set_status(|s| s.camera = "Opening the camera…".into());
        match camera::Camera::open(self.camera_id.as_deref(), format) {
            Ok(cam) => {
                let label = cam.label();
                self.shared.set_status(|s| s.camera = label);
                VideoInput::Open(Box::new(cam))
            }
            Err(e) => {
                tracing::warn!("camera: {e}");
                let why = match e {
                    MediaError::PermissionDenied => {
                        "Camera access was refused (allow it in the system's privacy settings)"
                            .to_owned()
                    }
                    other => format!("Camera unavailable: {other}"),
                };
                self.shared.set_status(|s| s.camera = why);
                VideoInput::Failed
            }
        }
    }
}

struct AudioWorker {
    frames: FrameSink,
    stats: Arc<CallStats>,
    shared: Arc<Shared>,
    playout: PlayoutBuffer,
    synthetic: bool,
    cmds: Receiver<AudioCmd>,
}

/// One direction's device: open, or closed with the time of the last attempt.
struct Slot<T: ?Sized> {
    device: Option<Box<T>>,
    /// The device the user picked (`None`: the default).
    wanted: Option<String>,
    /// When a failed device may be tried again; `None` when no retry is due.
    retry_at: Option<Instant>,
}

impl AudioWorker {
    fn open_microphone(&self, id: Option<&str>) -> Option<Box<dyn AudioSource>> {
        if self.synthetic {
            self.shared
                .set_status(|s| s.microphone = "Test tone".into());
            return Some(Box::new(ToneSource::new()));
        }
        match audio_io::Microphone::open(id) {
            Ok(mic) => {
                let name = mic.name().to_owned();
                self.shared.set_status(|s| s.microphone = name);
                Some(Box::new(mic))
            }
            Err(e) => {
                tracing::warn!("microphone: {e}");
                let why = match e {
                    MediaError::NoDevice => "No microphone".to_owned(),
                    MediaError::PermissionDenied => {
                        "Microphone access was refused (allow it in the system's privacy settings)"
                            .to_owned()
                    }
                    other => format!("Microphone unavailable: {other}"),
                };
                self.shared.set_status(|s| s.microphone = why);
                None
            }
        }
    }

    fn open_speaker(&self, id: Option<&str>) -> Option<Box<dyn AudioSink>> {
        if self.synthetic {
            self.shared
                .set_status(|s| s.speaker = "None (headless)".into());
            return Some(Box::new(NullSink::new(SAMPLE_RATE)));
        }
        match audio_io::Speaker::open(id) {
            Ok(speaker) => {
                let name = speaker.name().to_owned();
                self.shared.set_status(|s| s.speaker = name);
                Some(Box::new(speaker))
            }
            Err(e) => {
                tracing::warn!("speakers: {e}");
                let why = match e {
                    MediaError::NoDevice => "No speakers".to_owned(),
                    other => format!("Speakers unavailable: {other}"),
                };
                self.shared.set_status(|s| s.speaker = why);
                None
            }
        }
    }

    fn run(self, microphone: Option<String>, speaker: Option<String>) {
        let processing = match std::env::var("PAROLNET_AUDIO_PROCESSING").as_deref() {
            Ok("off") | Ok("0") => ProcessingConfig::OFF,
            _ => ProcessingConfig::CALL,
        };
        let mut duplex = AudioDuplex::new(new_processor(processing));
        tracing::info!("audio processing: {}", duplex.processor().name());
        let mut encoder = match OpusEncoder::new() {
            Ok(e) => Some(e),
            Err(e) => {
                tracing::warn!("{e}");
                None
            }
        };
        let mut mic = Slot {
            device: self.open_microphone(microphone.as_deref()),
            wanted: microphone,
            retry_at: None,
        };
        let mut out = Slot {
            device: self.open_speaker(speaker.as_deref()),
            wanted: speaker,
            retry_at: None,
        };
        let mut call_over = false;
        let mut next = Instant::now();
        while !self.shared.stop.load(Ordering::Relaxed) && !call_over {
            loop {
                match self.cmds.try_recv() {
                    Ok(AudioCmd::Microphone(id)) => {
                        // Close before opening: the same device cannot be opened twice.
                        mic.device = None;
                        mic.device = self.open_microphone(id.as_deref());
                        mic.wanted = id;
                        mic.retry_at = None;
                    }
                    Ok(AudioCmd::Speaker(id)) => {
                        out.device = None;
                        out.device = self.open_speaker(id.as_deref());
                        out.wanted = id;
                        out.retry_at = None;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return,
                }
            }
            // A device that went away: once, after a pause, try the system default.
            let now = Instant::now();
            if mic.device.is_none() && mic.retry_at.is_some_and(|t| now >= t) {
                mic.retry_at = None;
                mic.wanted = None;
                mic.device = self.open_microphone(None);
            }
            if out.device.is_none() && out.retry_at.is_some_and(|t| now >= t) {
                out.retry_at = None;
                out.wanted = None;
                out.device = self.open_speaker(None);
            }

            let muted = self.shared.muted.load(Ordering::Relaxed);
            let result = duplex.pump(
                // (`as_deref_mut` would pin the trait object's lifetime to the box's.)
                mic.device
                    .as_mut()
                    .map(|d| &mut **d as &mut dyn AudioSource),
                out.device.as_mut().map(|d| &mut **d as &mut dyn AudioSink),
                &self.playout,
                &mut |frame: &[f32]| {
                    debug_assert_eq!(frame.len(), FRAME_20MS);
                    if call_over {
                        return;
                    }
                    let Some(enc) = encoder.as_mut() else { return };
                    // Muted: silence is sent instead of the microphone (what a browser does
                    // for a disabled track), so the contact's jitter buffer sees a steady
                    // stream; the microphone still runs through the processor, which keeps
                    // the echo canceller converged.
                    let frame = if muted { &SILENCE[..] } else { frame };
                    match enc.encode(frame) {
                        Ok(packet) => {
                            if self.frames.send(
                                MediaKind::Audio,
                                packet.to_vec(),
                                FRAME_20MS as u32,
                            ) {
                                self.stats.audio_sent.fetch_add(1, Ordering::Relaxed);
                            } else {
                                call_over = true;
                            }
                        }
                        Err(e) => tracing::debug!("{e}"),
                    }
                },
            );
            match result {
                Ok(()) => {}
                Err(DuplexError::Source(e)) => {
                    tracing::warn!("microphone: {e}");
                    mic.device = None;
                    mic.retry_at = Some(now + AUDIO_RETRY);
                    self.shared
                        .set_status(|s| s.microphone = format!("Microphone lost: {e}"));
                }
                Err(DuplexError::Sink(e)) => {
                    tracing::warn!("speakers: {e}");
                    out.device = None;
                    out.retry_at = Some(now + AUDIO_RETRY);
                    self.shared
                        .set_status(|s| s.speaker = format!("Speakers lost: {e}"));
                }
            }
            next += AUDIO_TICK;
            let now = Instant::now();
            if next > now {
                std::thread::sleep(next - now);
            } else if now - next > Duration::from_millis(100) {
                // Stalled (the machine slept): do not spin to catch up.
                next = now;
            }
        }
        let stats = duplex.stats();
        tracing::debug!(?stats, "audio path");
    }
}

/// Receive: VP8 into the decoder thread and the slot, Opus into the playout buffer.
async fn receive(
    mut events: tokio::sync::mpsc::Receiver<MediaEvent>,
    frames: FrameSink,
    slot: FrameSlot,
    stats: Arc<CallStats>,
    playout: PlayoutBuffer,
    shared: Arc<Shared>,
) {
    let (sample_tx, sample_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(8);
    let (want_tx, mut want_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let decode = {
        let slot = slot.clone();
        let video = stats.video.clone();
        std::thread::Builder::new()
            .name("call-vp8-decode".into())
            .spawn(move || decode_loop(sample_rx, want_tx, slot, video, false, None))
    };
    let mut decoder = OpusDecoder::new().ok();
    let mut builder = SampleBuilder::new(256, Vp8Packet::default(), 90_000);
    let mut last_request = Instant::now() - Duration::from_secs(10);
    loop {
        tokio::select! {
            ev = events.recv() => match ev {
                Some(MediaEvent::Rtp { kind: MediaKind::Video, packet }) => {
                    stats.video.packets.fetch_add(1, Ordering::Relaxed);
                    let now = Instant::now();
                    builder.push(now, packet);
                    while let Some(sample) = builder.pop(now) {
                        stats.video.samples.fetch_add(1, Ordering::Relaxed);
                        let _ = sample_tx.try_send(sample.data.to_vec());
                    }
                }
                Some(MediaEvent::Rtp { kind: MediaKind::Audio, packet }) => {
                    stats.audio_packets.fetch_add(1, Ordering::Relaxed);
                    if let Some(d) = decoder.as_mut()
                        && let Ok(pcm) = d.decode(&packet.payload)
                    {
                        stats.audio_decoded.fetch_add(pcm.len() as u64, Ordering::Relaxed);
                        playout.push(pcm);
                    }
                }
                Some(MediaEvent::Track { kind, mime_type }) => {
                    tracing::info!(?kind, %mime_type, "remote track");
                    if kind == MediaKind::Video {
                        slot.set_status("video");
                        let _ = frames.request_keyframe();
                    }
                }
                Some(MediaEvent::KeyframeRequested) => {
                    shared.force_keyframe.store(true, Ordering::Relaxed);
                }
                Some(MediaEvent::TargetBitrate { bps }) => {
                    shared.target_bps.store(bps, Ordering::Relaxed);
                }
                Some(MediaEvent::RemoteVideo { sending }) => {
                    slot.set_status(if sending { "video" } else { "camera off" });
                    if sending {
                        let _ = frames.request_keyframe();
                    }
                }
                Some(MediaEvent::LocalVideo { sending }) => {
                    // Our stream starts (again): its first frame has to be a keyframe.
                    if sending {
                        shared.force_keyframe.store(true, Ordering::Relaxed);
                    }
                }
                None => break,
            },
            Some(()) = want_rx.recv() => {
                if last_request.elapsed() > Duration::from_secs(1) {
                    last_request = Instant::now();
                    let _ = frames.request_keyframe();
                }
            }
        }
    }
    slot.set_status("call ended");
    drop(sample_tx);
    if let Ok(t) = decode {
        let _ = t.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtp_ticks_follow_the_frame_interval() {
        assert_eq!(rtp_ticks(Duration::from_micros(33_333)), 2999);
        assert_eq!(rtp_ticks(Duration::from_secs(1)), 90_000);
        // Bounded both ways.
        assert_eq!(rtp_ticks(Duration::ZERO), 90);
        assert_eq!(rtp_ticks(Duration::from_secs(60)), 180_000);
    }

    #[test]
    fn the_encoder_follows_the_estimate_up_to_the_format_rate() {
        // No estimate yet: the format's own rate.
        assert_eq!(encoder_kbps(0, 900), 900);
        // 300 kbit/s in total leave 198 for video.
        assert_eq!(encoder_kbps(300_000, 900), 198);
        // An open path does not push the encoder past what the picture size needs.
        assert_eq!(encoder_kbps(2_500_000, 900), 900);
        assert_eq!(encoder_kbps(2_500_000, 1800), 1800);
        // The floor: a picture that is still one.
        assert_eq!(encoder_kbps(100_000, 900), 30);
    }

    #[test]
    fn the_send_format_defaults_to_360p() {
        // The variable is not set in the test environment.
        if std::env::var_os("PAROLNET_VIDEO").is_none() {
            let (format, kbps) = send_format();
            assert_eq!((format.width, format.height, format.fps), (640, 360, 30));
            assert_eq!(kbps, 900);
        }
    }
}
