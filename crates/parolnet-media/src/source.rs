//! The capture and playback traits, and the synthetic implementations CI and the bot use (a
//! test pattern for a camera, a tone for a microphone, a sink that plays into nothing).
//!
//! Devices are pull-based from the call's own threads: nothing here calls back into the call,
//! and nothing blocks longer than the timeout it is given. A device that fails returns an
//! error (it never panics); the call then closes it and carries on without it.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::frame::VideoFrame;
use crate::pattern::TestPattern;
use crate::{MediaError, SAMPLE_RATE};

/// A capture or playback device, for the device menus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    /// What to pass back to open this device (stable while the device stays plugged in).
    pub id: String,
    /// The name to show.
    pub name: String,
}

/// A picture size and rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VideoFormat {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
}

impl VideoFormat {
    /// 640x360 at 30 fps: the default send size.
    pub const P360: Self = Self {
        width: 640,
        height: 360,
        fps: 30,
    };
    /// 1280x720 at 30 fps.
    pub const P720: Self = Self {
        width: 1280,
        height: 720,
        fps: 30,
    };

    /// The time between two frames.
    pub fn frame_interval(&self) -> Duration {
        Duration::from_secs(1) / self.fps.max(1)
    }
}

/// A camera (or something that stands in for one).
pub trait VideoSource: Send {
    /// What the source delivers (after the format negotiation with the device).
    fn format(&self) -> VideoFormat;

    /// The newest picture: waits up to `timeout` for one that was not returned before, and
    /// returns `Ok(None)` when none came. Pictures the caller was too slow for are dropped,
    /// never queued.
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<VideoFrame>, MediaError>;

    /// The source's name, for the UI and logs.
    fn label(&self) -> String;
}

/// A microphone (or something that stands in for one): mono samples at the device's rate.
pub trait AudioSource: Send {
    /// The rate of the samples [`AudioSource::read`] returns.
    fn sample_rate(&self) -> u32;

    /// Append the samples captured since the last call. Never blocks.
    fn read(&mut self, out: &mut Vec<f32>) -> Result<(), MediaError>;

    /// The time from the microphone to [`AudioSource::read`], as far as the device reports it.
    fn latency(&self) -> Duration {
        Duration::ZERO
    }
}

/// Speakers (or something that stands in for them): mono samples at the device's rate.
pub trait AudioSink: Send {
    /// The rate [`AudioSink::write`] takes.
    fn sample_rate(&self) -> u32;

    /// Samples written and not played yet.
    fn queued(&self) -> usize;

    /// How many samples the sink wants queued to play without gaps (the writer tops it up to
    /// this level and no further, which keeps the latency down).
    fn target_queue(&self) -> usize {
        self.sample_rate() as usize * 30 / 1000
    }

    /// Queue samples for playback. Never blocks; what does not fit is dropped.
    fn write(&mut self, samples: &[f32]) -> Result<(), MediaError>;

    /// The time from the queue's end to the loudspeaker, as far as the device reports it.
    fn latency(&self) -> Duration {
        Duration::ZERO
    }
}

/// A latest-value slot between a producer thread and a consumer: the producer overwrites,
/// the consumer takes, a value nobody took in time is dropped.
pub struct LatestSlot<T> {
    inner: Mutex<SlotState<T>>,
    ready: Condvar,
}

struct SlotState<T> {
    value: Option<T>,
    closed: Option<String>,
    dropped: u64,
}

impl<T> Default for LatestSlot<T> {
    fn default() -> Self {
        Self {
            inner: Mutex::new(SlotState {
                value: None,
                closed: None,
                dropped: 0,
            }),
            ready: Condvar::new(),
        }
    }
}

impl<T> LatestSlot<T> {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SlotState<T>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Replace the value (the previous one, if nobody took it, is dropped and counted).
    pub fn put(&self, value: T) {
        let mut s = self.lock();
        if s.value.replace(value).is_some() {
            s.dropped += 1;
        }
        drop(s);
        self.ready.notify_one();
    }

    /// The producer is gone: takers get `reason` as an error once the slot is empty.
    pub fn close(&self, reason: impl Into<String>) {
        self.lock().closed = Some(reason.into());
        self.ready.notify_all();
    }

    /// Take the value, waiting up to `timeout` for one. `Err` once the producer closed the
    /// slot and nothing is left.
    pub fn take(&self, timeout: Duration) -> Result<Option<T>, String> {
        let deadline = Instant::now() + timeout;
        let mut s = self.lock();
        loop {
            if let Some(v) = s.value.take() {
                return Ok(Some(v));
            }
            if let Some(reason) = &s.closed {
                return Err(reason.clone());
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            s = self
                .ready
                .wait_timeout(s, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// Values replaced before anyone took them.
    pub fn dropped(&self) -> u64 {
        self.lock().dropped
    }
}

/// The test pattern as a camera: colour bars, a moving box and a frame counter at a steady
/// frame rate.
pub struct PatternSource {
    pattern: TestPattern,
    format: VideoFormat,
    pixel: PatternPixel,
    started: Instant,
    produced: u64,
}

/// The pixel format a [`PatternSource`] delivers: I420, or one of the formats real cameras
/// deliver, so that a call without a camera still runs the conversion a camera needs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PatternPixel {
    #[default]
    I420,
    Nv12,
    Yuyv,
}

impl PatternSource {
    /// `format`'s width and height must be even (the VP8 encoder's requirement).
    pub fn new(format: VideoFormat) -> Self {
        Self {
            pattern: TestPattern::new(format.width, format.height),
            format,
            pixel: PatternPixel::I420,
            started: Instant::now(),
            produced: 0,
        }
    }

    /// Deliver the pattern in `pixel` format instead of I420.
    pub fn with_pixel(mut self, pixel: PatternPixel) -> Self {
        self.pixel = pixel;
        self
    }
}

impl VideoSource for PatternSource {
    fn format(&self) -> VideoFormat {
        self.format
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<VideoFrame>, MediaError> {
        let interval = self.format.frame_interval();
        let due = self.started + interval.mul_f64(self.produced as f64);
        let now = Instant::now();
        if due > now {
            let wait = due - now;
            if wait > timeout {
                std::thread::sleep(timeout);
                return Ok(None);
            }
            std::thread::sleep(wait);
        } else if now - due > interval * 4 {
            // The caller fell behind (a slow encoder): skip the frames it missed rather than
            // deliver a burst.
            let behind = (now - due).as_secs_f64() / interval.as_secs_f64();
            self.produced += behind as u64;
        }
        self.produced += 1;
        let frame = self.pattern.next_frame();
        Ok(Some(match self.pixel {
            PatternPixel::I420 => VideoFrame::I420(frame),
            PatternPixel::Nv12 => frame.to_nv12(),
            PatternPixel::Yuyv => frame.to_yuyv(),
        }))
    }

    fn label(&self) -> String {
        "Test pattern".to_owned()
    }
}

/// A sine generator: phase-continuous over any number of calls.
#[derive(Clone, Debug)]
pub struct Tone {
    step: f64,
    phase: f64,
    amplitude: f32,
}

impl Tone {
    pub fn new(sample_rate: u32, hz: f64, amplitude: f32) -> Self {
        Self {
            step: std::f64::consts::TAU * hz / f64::from(sample_rate.max(1)),
            phase: 0.0,
            amplitude,
        }
    }

    /// Append `n` samples.
    pub fn generate(&mut self, n: usize, out: &mut Vec<f32>) {
        out.reserve(n);
        for _ in 0..n {
            out.push(self.phase.sin() as f32 * self.amplitude);
            self.phase += self.step;
            if self.phase >= std::f64::consts::TAU {
                self.phase -= std::f64::consts::TAU;
            }
        }
    }
}

/// A tone as a microphone, paced by the wall clock (what `--call-check` and the bot send).
pub struct ToneSource {
    tone: Tone,
    rate: u32,
    started: Instant,
    produced: u64,
}

impl ToneSource {
    /// A 440 Hz tone at -20 dBFS, 48 kHz.
    pub fn new() -> Self {
        Self::with(SAMPLE_RATE, 440.0, 0.1)
    }

    pub fn with(sample_rate: u32, hz: f64, amplitude: f32) -> Self {
        Self {
            tone: Tone::new(sample_rate, hz, amplitude),
            rate: sample_rate.max(1),
            started: Instant::now(),
            produced: 0,
        }
    }
}

impl Default for ToneSource {
    fn default() -> Self {
        Self::new()
    }
}

impl AudioSource for ToneSource {
    fn sample_rate(&self) -> u32 {
        self.rate
    }

    fn read(&mut self, out: &mut Vec<f32>) -> Result<(), MediaError> {
        let due = (self.started.elapsed().as_secs_f64() * f64::from(self.rate)) as u64;
        // After a stall, do not flood: at most 200 ms at once.
        let max = u64::from(self.rate) / 5;
        if due > self.produced + max {
            self.produced = due - max;
        }
        let n = due.saturating_sub(self.produced) as usize;
        self.tone.generate(n, out);
        self.produced = due;
        Ok(())
    }
}

/// Speakers that play into nothing, paced by the wall clock: a call without an output device
/// (CI, a headless check) still runs its playout path against it.
pub struct NullSink {
    rate: u32,
    started: Instant,
    written: u64,
}

impl NullSink {
    pub fn new(sample_rate: u32) -> Self {
        Self {
            rate: sample_rate.max(1),
            started: Instant::now(),
            written: 0,
        }
    }

    fn played(&self) -> u64 {
        (self.started.elapsed().as_secs_f64() * f64::from(self.rate)) as u64
    }
}

impl AudioSink for NullSink {
    fn sample_rate(&self) -> u32 {
        self.rate
    }

    fn queued(&self) -> usize {
        self.written.saturating_sub(self.played()) as usize
    }

    fn write(&mut self, samples: &[f32]) -> Result<(), MediaError> {
        // An underrun does not carry over: playback restarts from now.
        self.written = self.written.max(self.played()) + samples.len() as u64;
        Ok(())
    }
}

/// A simulated room for tests and the media check: a loudspeaker, a microphone that hears
/// it (delayed and attenuated: the echo path) plus whatever is said in the room, and a clock
/// the test advances by hand. [`SimRoom::sink`] and [`SimRoom::source`] are its two devices.
#[derive(Clone)]
pub struct SimRoom(Arc<Mutex<RoomState>>);

struct RoomState {
    rate: u32,
    /// Written by the sink, not played yet.
    speaker: std::collections::VecDeque<f32>,
    /// What the loudspeaker played, newest last (the echo path reads back into it).
    played: std::collections::VecDeque<f32>,
    /// Captured, not read yet.
    mic: Vec<f32>,
    /// Echo path: (delay in samples, gain) per reflection.
    echo: Vec<(usize, f32)>,
    underruns: u64,
}

impl SimRoom {
    /// A room whose devices run at `sample_rate`, with one echo path per `(delay, gain)`.
    pub fn new(sample_rate: u32, echo: &[(Duration, f32)]) -> Self {
        let rate = sample_rate.max(1);
        let echo = echo
            .iter()
            .map(|(d, g)| ((d.as_secs_f64() * f64::from(rate)) as usize, *g))
            .collect();
        SimRoom(Arc::new(Mutex::new(RoomState {
            rate,
            speaker: Default::default(),
            played: Default::default(),
            mic: Vec::new(),
            echo,
            underruns: 0,
        })))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RoomState> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Let `near_end.len()` sample times pass: the loudspeaker plays that much of what was
    /// written (silence where nothing was), and the microphone records the echo plus
    /// `near_end` (what is said in the room).
    pub fn advance(&self, near_end: &[f32]) {
        let mut s = self.lock();
        let longest = s.echo.iter().map(|(d, _)| *d).max().unwrap_or(0);
        for &near in near_end {
            let out = match s.speaker.pop_front() {
                Some(v) => v,
                None => {
                    s.underruns += 1;
                    0.0
                }
            };
            s.played.push_back(out);
            let n = s.played.len();
            let mut heard = near;
            for &(delay, gain) in &s.echo {
                if n > delay {
                    heard += s.played[n - 1 - delay] * gain;
                }
            }
            s.mic.push(heard);
            if s.played.len() > longest + 1 {
                s.played.pop_front();
            }
        }
    }

    /// Sample times the loudspeaker had nothing to play.
    pub fn underruns(&self) -> u64 {
        self.lock().underruns
    }

    /// The room's loudspeaker.
    pub fn sink(&self) -> impl AudioSink + use<> {
        RoomSink(self.clone())
    }

    /// The room's microphone.
    pub fn source(&self) -> impl AudioSource + use<> {
        RoomSource(self.clone())
    }
}

struct RoomSink(SimRoom);
struct RoomSource(SimRoom);

impl AudioSink for RoomSink {
    fn sample_rate(&self) -> u32 {
        self.0.lock().rate
    }
    fn queued(&self) -> usize {
        self.0.lock().speaker.len()
    }
    fn write(&mut self, samples: &[f32]) -> Result<(), MediaError> {
        self.0.lock().speaker.extend(samples);
        Ok(())
    }
}

impl AudioSource for RoomSource {
    fn sample_rate(&self) -> u32 {
        self.0.lock().rate
    }
    fn read(&mut self, out: &mut Vec<f32>) -> Result<(), MediaError> {
        out.append(&mut self.0.lock().mic);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_slot_keeps_only_the_newest_value() {
        let slot = LatestSlot::new();
        assert_eq!(slot.take(Duration::ZERO), Ok(None));
        for n in 0..3 {
            slot.put(n);
        }
        assert_eq!(slot.dropped(), 2);
        assert_eq!(slot.take(Duration::ZERO), Ok(Some(2)));
        assert_eq!(slot.take(Duration::from_millis(5)), Ok(None));
        slot.put(7);
        slot.close("unplugged");
        // What was captured before the close is still delivered, then the error.
        assert_eq!(slot.take(Duration::ZERO), Ok(Some(7)));
        assert_eq!(
            slot.take(Duration::from_secs(5)),
            Err("unplugged".to_owned())
        );
    }

    #[test]
    fn the_slot_wakes_a_waiting_taker() {
        let slot = LatestSlot::new();
        let producer = slot.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            producer.put(1u8);
        });
        assert_eq!(slot.take(Duration::from_secs(5)), Ok(Some(1)));
        t.join().unwrap();
    }

    #[test]
    fn the_pattern_source_paces_itself() {
        let mut src = PatternSource::new(VideoFormat {
            width: 64,
            height: 36,
            fps: 100,
        });
        let start = Instant::now();
        let mut frames = 0;
        while frames < 10 {
            if let Some(f) = src.next_frame(Duration::from_millis(50)).unwrap() {
                assert_eq!(f.size(), (64, 36));
                frames += 1;
            }
        }
        // Ten frames at 100 fps: the tenth is due after 90 ms.
        assert!(start.elapsed() >= Duration::from_millis(85));
        assert_eq!(src.label(), "Test pattern");
        let mut yuyv = PatternSource::new(VideoFormat::P360).with_pixel(PatternPixel::Yuyv);
        let frame = yuyv.next_frame(Duration::from_secs(1)).unwrap().unwrap();
        assert_eq!((frame.format_name(), frame.size()), ("YUYV", (640, 360)));
        // A short timeout returns without a frame.
        let mut slow = PatternSource::new(VideoFormat {
            width: 64,
            height: 36,
            fps: 1,
        });
        assert!(slow.next_frame(Duration::ZERO).unwrap().is_some());
        assert!(slow.next_frame(Duration::from_millis(1)).unwrap().is_none());
    }

    #[test]
    fn the_tone_source_follows_the_clock() {
        let mut src = ToneSource::new();
        let mut out = Vec::new();
        std::thread::sleep(Duration::from_millis(50));
        src.read(&mut out).unwrap();
        // 50 ms at 48 kHz is 2400 samples (more if the test thread was slow to wake).
        assert!((2300..=9600).contains(&out.len()), "{}", out.len());
        let peak = out.iter().fold(0f32, |m, v| m.max(v.abs()));
        assert!((0.09..=0.1001).contains(&peak), "{peak}");
    }

    #[test]
    fn the_null_sink_drains_in_real_time() {
        let mut sink = NullSink::new(48_000);
        sink.write(&[0.0; 4800]).unwrap();
        let before = sink.queued();
        assert!(before > 3000, "{before}");
        std::thread::sleep(Duration::from_millis(30));
        assert!(sink.queued() < before);
        assert_eq!(sink.target_queue(), 1440);
    }

    #[test]
    fn the_room_echoes_what_the_speaker_played() {
        let room = SimRoom::new(1000, &[(Duration::from_millis(3), 0.5)]);
        let (mut sink, mut source) = (room.sink(), room.source());
        sink.write(&[1.0, 0.0, 0.0, 0.0, 0.0]).unwrap();
        assert_eq!(sink.queued(), 5);
        room.advance(&[0.25; 6]);
        let mut heard = Vec::new();
        source.read(&mut heard).unwrap();
        // The impulse comes back three samples later at half the level, on top of the room.
        assert_eq!(heard, [0.25, 0.25, 0.25, 0.75, 0.25, 0.25]);
        assert_eq!(room.underruns(), 1);
        assert_eq!(sink.queued(), 0);
    }
}
