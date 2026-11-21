//! A call's media on the desktop: what we send (the test pattern through the libvpx VP8
//! encoder, the microphone through the opus-rs encoder) and what we receive (VP8 into the
//! M0 decode path and the video tile, Opus decoded and played on the default output).
//!
//! Camera capture is still to come: video calls send the synthetic test pattern. A machine
//! without audio devices (CI) runs the call without sound.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use parolnet_app::{CallMedia, FrameSink, MediaEvent, MediaKind};
use parolnet_rtc::rtc::media::io::sample_builder::SampleBuilder;
use parolnet_rtc::rtc::rtp::codec::vp8::Vp8Packet;

use crate::frame::FrameSlot;
use crate::receiver::{Stats, decode_loop};
use crate::testpattern::TestPattern;
use crate::vp8enc::Vp8Encoder;

/// What we send as video.
pub const VIDEO_WIDTH: u32 = 640;
pub const VIDEO_HEIGHT: u32 = 360;
pub const VIDEO_FPS: u32 = 30;
const VIDEO_KBPS: u32 = 900;
/// Opus at 48 kHz mono, 20 ms frames.
const OPUS_FRAME: usize = 960;
/// Playback buffer cap: drop the oldest audio past 300 ms (latency over completeness).
const PLAYBACK_MAX: usize = 48_000 * 3 / 10;

/// Counters for the call view and the headless check.
#[derive(Default)]
pub struct CallStats {
    pub video: Arc<Stats>,
    pub audio_packets: AtomicU64,
    pub audio_decoded: AtomicU64,
    pub video_sent: AtomicU64,
    pub audio_sent: AtomicU64,
}

/// A running call's media. Dropping it stops capture, encoding and playback.
pub struct CallSession {
    pub slot: FrameSlot,
    pub stats: Arc<CallStats>,
    muted: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    audio_ok: bool,
}

impl CallSession {
    /// Start the media of an active (or connecting) call. `audio_devices`: open the default
    /// microphone and speakers (off for headless runs).
    pub fn start(
        media: CallMedia,
        video: bool,
        audio_devices: bool,
        runtime: &tokio::runtime::Handle,
    ) -> CallSession {
        let CallMedia { frames, events } = media;
        let slot = FrameSlot::default();
        let stats = Arc::new(CallStats::default());
        let muted = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let force_keyframe = Arc::new(AtomicBool::new(true));
        let playback = Arc::new(Mutex::new(VecDeque::<f32>::new()));

        if video {
            spawn_video_sender(
                frames.clone(),
                stats.clone(),
                stop.clone(),
                force_keyframe.clone(),
            );
        }
        let audio_ok = audio_devices
            && spawn_audio_devices(
                frames.clone(),
                stats.clone(),
                muted.clone(),
                stop.clone(),
                playback.clone(),
            );
        runtime.spawn(receive(
            events,
            frames,
            slot.clone(),
            stats.clone(),
            playback,
            force_keyframe,
        ));
        slot.set_status(if video {
            "connecting video"
        } else {
            "audio only"
        });
        CallSession {
            slot,
            stats,
            muted,
            stop,
            audio_ok,
        }
    }

    pub fn set_muted(&self, muted: bool) {
        self.muted.store(muted, Ordering::Relaxed);
    }

    pub fn muted(&self) -> bool {
        self.muted.load(Ordering::Relaxed)
    }

    /// Whether a microphone and speakers are in use.
    pub fn has_audio_devices(&self) -> bool {
        self.audio_ok
    }
}

impl Drop for CallSession {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// The test pattern at 30 fps through the VP8 encoder.
fn spawn_video_sender(
    frames: FrameSink,
    stats: Arc<CallStats>,
    stop: Arc<AtomicBool>,
    force_keyframe: Arc<AtomicBool>,
) {
    let _ = std::thread::Builder::new()
        .name("call-video".into())
        .spawn(move || {
            let mut encoder =
                match Vp8Encoder::new(VIDEO_WIDTH, VIDEO_HEIGHT, VIDEO_FPS, VIDEO_KBPS) {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::warn!("{e:#}");
                        return;
                    }
                };
            let mut pattern = TestPattern::new(VIDEO_WIDTH, VIDEO_HEIGHT);
            let period = Duration::from_secs(1) / VIDEO_FPS;
            let start = Instant::now();
            for n in 1u32.. {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let frame = pattern.next_frame();
                let key = force_keyframe.swap(false, Ordering::Relaxed);
                match encoder.encode(&frame, key) {
                    Ok(Some(e)) => {
                        if e.keyframe {
                            tracing::debug!(n, "keyframe");
                        }
                        if !frames.send(MediaKind::Video, e.data, 90_000 / VIDEO_FPS) {
                            break;
                        }
                        stats.video_sent.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(None) => {}
                    Err(e) => tracing::debug!("{e:#}"),
                }
                std::thread::sleep((start + period * n).saturating_duration_since(Instant::now()));
            }
        });
}

/// Receive: VP8 into the decoder thread and the slot, Opus into the playback buffer.
async fn receive(
    mut events: tokio::sync::mpsc::Receiver<MediaEvent>,
    frames: FrameSink,
    slot: FrameSlot,
    stats: Arc<CallStats>,
    playback: Arc<Mutex<VecDeque<f32>>>,
    force_keyframe: Arc<AtomicBool>,
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
    let mut decoder = opus_rs::OpusDecoder::new(48_000, 1).ok();
    let mut pcm = vec![0f32; 5760];
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
                        && let Ok(n) = d.decode(&packet.payload, pcm.len(), &mut pcm)
                    {
                        stats.audio_decoded.fetch_add(n as u64, Ordering::Relaxed);
                        let mut buf = playback.lock().unwrap_or_else(|e| e.into_inner());
                        buf.extend(&pcm[..n]);
                        let excess = buf.len().saturating_sub(PLAYBACK_MAX);
                        buf.drain(..excess);
                    }
                }
                Some(MediaEvent::Track { kind, mime_type }) => {
                    tracing::info!(?kind, %mime_type, "remote track");
                    if kind == MediaKind::Video {
                        slot.set_status("video");
                        let _ = frames.request_keyframe();
                    }
                }
                Some(MediaEvent::KeyframeRequested) => force_keyframe.store(true, Ordering::Relaxed),
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

/// Open the default microphone and speakers on a thread that owns the streams until `stop`.
/// Returns false when there is no device.
fn spawn_audio_devices(
    frames: FrameSink,
    stats: Arc<CallStats>,
    muted: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    playback: Arc<Mutex<VecDeque<f32>>>,
) -> bool {
    use cpal::traits::{DeviceTrait as _, HostTrait as _};
    let host = cpal::default_host();
    let (Some(input), Some(output)) = (host.default_input_device(), host.default_output_device())
    else {
        tracing::warn!("no default microphone or speakers; the call runs without sound");
        return false;
    };
    let (Ok(in_cfg), Ok(out_cfg)) = (input.default_input_config(), output.default_output_config())
    else {
        tracing::warn!("audio devices have no default configuration");
        return false;
    };
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let _ = std::thread::Builder::new()
        .name("call-audio".into())
        .spawn(move || {
            use cpal::traits::StreamTrait as _;
            // Microphone → 48 kHz mono frames → the encoder thread.
            let (pcm_tx, pcm_rx) = std::sync::mpsc::sync_channel::<Vec<f32>>(64);
            let in_rate = in_cfg.sample_rate();
            let in_channels = usize::from(in_cfg.channels()).max(1);
            let mut to_48k = Resampler::new(in_rate, 48_000);
            let input_stream = input.build_input_stream::<f32, _, _>(
                in_cfg.config(),
                move |data: &[f32], _| {
                    let mono: Vec<f32> = data
                        .chunks(in_channels)
                        .map(|c| c.iter().sum::<f32>() / c.len() as f32)
                        .collect();
                    let _ = pcm_tx.try_send(to_48k.push(&mono));
                },
                |e| tracing::warn!("microphone: {e}"),
                None,
            );
            // Playback buffer (48 kHz mono) → the device's rate and channels.
            let out_rate = out_cfg.sample_rate();
            let out_channels = usize::from(out_cfg.channels()).max(1);
            let step = 48_000.0 / out_rate as f64;
            let mut pos = 0.0f64;
            let output_stream = output.build_output_stream::<f32, _, _>(
                out_cfg.config(),
                move |data: &mut [f32], _| {
                    let mut buf = playback.lock().unwrap_or_else(|e| e.into_inner());
                    for frame in data.chunks_mut(out_channels) {
                        let v = buf.front().copied().unwrap_or(0.0);
                        pos += step;
                        while pos >= 1.0 {
                            buf.pop_front();
                            pos -= 1.0;
                        }
                        frame.fill(v);
                    }
                },
                |e| tracing::warn!("speakers: {e}"),
                None,
            );
            let (Ok(input_stream), Ok(output_stream)) = (input_stream, output_stream) else {
                tracing::warn!("could not open the audio devices");
                let _ = ready_tx.send(false);
                return;
            };
            let _ = input_stream.play();
            let _ = output_stream.play();
            let _ = ready_tx.send(true);

            let mut encoder = opus_rs::OpusEncoder::new(48_000, 1, opus_rs::Application::Voip).ok();
            let mut pending: Vec<f32> = Vec::with_capacity(OPUS_FRAME * 4);
            let mut out = vec![0u8; 1500];
            while !stop.load(Ordering::Relaxed) {
                let Ok(chunk) = pcm_rx.recv_timeout(Duration::from_millis(100)) else {
                    continue;
                };
                pending.extend(chunk);
                while pending.len() >= OPUS_FRAME {
                    let frame: Vec<f32> = pending.drain(..OPUS_FRAME).collect();
                    if muted.load(Ordering::Relaxed) {
                        continue;
                    }
                    if let Some(enc) = encoder.as_mut()
                        && let Ok(n) = enc.encode(&frame, OPUS_FRAME, &mut out)
                    {
                        if !frames.send(MediaKind::Audio, out[..n].to_vec(), OPUS_FRAME as u32) {
                            return;
                        }
                        stats.audio_sent.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            drop(input_stream);
            drop(output_stream);
        });
    ready_rx
        .recv_timeout(Duration::from_secs(3))
        .unwrap_or(false)
}

/// Linear resampling, good enough for voice (the M1 plan's AEC3 / resampler work replaces it).
struct Resampler {
    step: f64,
    pos: f64,
    last: f32,
}

impl Resampler {
    fn new(from: u32, to: u32) -> Self {
        Self {
            step: f64::from(from) / f64::from(to),
            pos: 0.0,
            last: 0.0,
        }
    }

    fn push(&mut self, input: &[f32]) -> Vec<f32> {
        if (self.step - 1.0).abs() < f64::EPSILON {
            return input.to_vec();
        }
        let mut out = Vec::with_capacity((input.len() as f64 / self.step) as usize + 1);
        // `pos` indexes into [last, input...]: 0 is `last`.
        while self.pos < input.len() as f64 {
            let i = self.pos.floor() as usize;
            let frac = (self.pos - i as f64) as f32;
            let a = if i == 0 { self.last } else { input[i - 1] };
            let b = input[i.min(input.len() - 1)];
            out.push(a + (b - a) * frac);
            self.pos += self.step;
        }
        self.pos -= input.len() as f64;
        self.last = input.last().copied().unwrap_or(self.last);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::Resampler;

    #[test]
    fn resampling_keeps_the_rate() {
        let mut r = Resampler::new(44_100, 48_000);
        let mut n = 0;
        for _ in 0..100 {
            n += r.push(&[0.5f32; 441]).len();
        }
        // 44 100 samples in, about 48 000 out.
        assert!((47_900..=48_100).contains(&n), "{n}");
        let mut same = Resampler::new(48_000, 48_000);
        assert_eq!(same.push(&[0.1, 0.2]).len(), 2);
    }
}
