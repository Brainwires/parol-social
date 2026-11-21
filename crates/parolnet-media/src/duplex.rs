//! The audio path of a call, between the devices and the codec.
//!
//! ```text
//! microphone ─ resample to 48 kHz ─ 10 ms frames ─ process_capture ─ 20 ms frames ─▶ encoder
//!                                                       ▲ echo reference
//! decoder ─▶ PlayoutBuffer ─ 10 ms frames ─ process_render ─ resample to device ─ speakers
//! ```
//!
//! One thread owns an [`AudioDuplex`] and calls [`AudioDuplex::pump`] every few milliseconds.
//! Device callbacks never run this code: they only move samples through lock-free queues
//! (see `audio_io`), so nothing here has to be real-time safe, and the audio processor needs
//! no lock.
//!
//! The render side is pulled by the sink: each pump tops the sink's queue up to its target and
//! no further, so every frame goes through `process_render` just before it is played, and the
//! time from there to the microphone (sink queue + device latencies + capture queue) is what
//! the processor is told as its stream delay.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::processing::AudioProcessor;
use crate::resample::Resampler;
use crate::source::{AudioSink, AudioSource};
use crate::{FRAME_10MS, FRAME_20MS, MediaError, SAMPLE_RATE};

/// Decoded audio from the contact (48 kHz mono), waiting to be played: a small jitter
/// buffer. The receive path pushes decoded packets; the audio thread pops 10 ms frames.
///
/// After running empty it holds playback back until [`PlayoutBuffer::PREBUFFER`] is there
/// again (a late packet then costs one gap instead of a stutter), and it never holds more
/// than [`PlayoutBuffer::MAX`]: the oldest audio is dropped first (latency over completeness).
#[derive(Clone, Default)]
pub struct PlayoutBuffer(Arc<Mutex<PlayoutState>>);

#[derive(Default)]
struct PlayoutState {
    samples: VecDeque<f32>,
    /// Waiting for the prebuffer before playing again.
    buffering: bool,
    started: bool,
    underruns: u64,
    dropped: u64,
}

impl PlayoutBuffer {
    /// What must be buffered before playback (re)starts: 40 ms.
    pub const PREBUFFER: usize = SAMPLE_RATE as usize * 40 / 1000;
    /// The most that is kept: 300 ms.
    pub const MAX: usize = SAMPLE_RATE as usize * 300 / 1000;

    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PlayoutState> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Queue decoded samples (48 kHz mono).
    pub fn push(&self, samples: &[f32]) {
        let mut s = self.lock();
        s.samples.extend(samples);
        let excess = s.samples.len().saturating_sub(Self::MAX);
        if excess > 0 {
            s.samples.drain(..excess);
            s.dropped += excess as u64;
        }
    }

    /// Fill `frame` with the next samples to play. Returns false (and silence) when there is
    /// nothing to play: before the first audio, or while refilling after running empty.
    pub fn pop(&self, frame: &mut [f32]) -> bool {
        let mut s = self.lock();
        if !s.started || s.buffering {
            if s.samples.len() < Self::PREBUFFER.max(frame.len()) {
                frame.fill(0.0);
                return false;
            }
            s.started = true;
            s.buffering = false;
        }
        if s.samples.len() < frame.len() {
            s.buffering = true;
            s.underruns += 1;
            frame.fill(0.0);
            return false;
        }
        let n = frame.len();
        for (out, v) in frame.iter_mut().zip(s.samples.drain(..n)) {
            *out = v;
        }
        true
    }

    /// Samples waiting.
    pub fn len(&self) -> usize {
        self.lock().samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// (times it ran empty, samples dropped because it was full)
    pub fn stats(&self) -> (u64, u64) {
        let s = self.lock();
        (s.underruns, s.dropped)
    }
}

/// Counters of an [`AudioDuplex`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DuplexStats {
    /// 10 ms frames through `process_capture`.
    pub capture_frames: u64,
    /// 10 ms frames through `process_render`.
    pub render_frames: u64,
    /// Render frames that were silence because the playout buffer had nothing.
    pub render_silence: u64,
    /// Capture samples dropped because the caller pumped too rarely.
    pub capture_dropped: u64,
    /// The stream delay last told to the processor, in milliseconds.
    pub stream_delay_ms: u32,
}

/// The audio path of one call. See the module documentation.
pub struct AudioDuplex {
    processor: Box<dyn AudioProcessor>,
    capture_resampler: Option<Resampler>,
    render_resampler: Option<Resampler>,
    /// Microphone samples at the device rate (scratch).
    device_in: Vec<f32>,
    /// Microphone samples at 48 kHz, not yet a whole frame.
    capture: Vec<f32>,
    /// Processed capture, not yet a whole 20 ms frame.
    out: Vec<f32>,
    /// Render samples at the device rate (scratch).
    device_out: Vec<f32>,
    stats: DuplexStats,
}

/// At most this much capture audio waits for processing (a stalled thread drops the rest).
const MAX_CAPTURE_BACKLOG: usize = SAMPLE_RATE as usize / 5;

impl AudioDuplex {
    pub fn new(processor: Box<dyn AudioProcessor>) -> Self {
        Self {
            processor,
            capture_resampler: None,
            render_resampler: None,
            device_in: Vec::with_capacity(4096),
            capture: Vec::with_capacity(MAX_CAPTURE_BACKLOG * 2),
            out: Vec::with_capacity(FRAME_20MS * 2),
            device_out: Vec::with_capacity(4096),
            stats: DuplexStats::default(),
        }
    }

    pub fn stats(&self) -> DuplexStats {
        self.stats
    }

    pub fn processor(&self) -> &dyn AudioProcessor {
        self.processor.as_ref()
    }

    /// Run the path once: play what is due, process what was captured.
    ///
    /// `sink`: the speakers, topped up from `playout` (each frame through the processor's
    /// reverse stream first). `source`: the microphone; every processed 20 ms frame (960
    /// samples, 48 kHz mono) goes to `on_frame`. Either may be absent (no device, or it
    /// failed): the other direction keeps running.
    ///
    /// A device error is returned after the rest of the pump ran; the caller drops that
    /// device (and may open another).
    pub fn pump(
        &mut self,
        source: Option<&mut dyn AudioSource>,
        sink: Option<&mut dyn AudioSink>,
        playout: &PlayoutBuffer,
        on_frame: &mut dyn FnMut(&[f32]),
    ) -> Result<(), DuplexError> {
        let mut error = None;

        // Render first: what is played from now on must be known to the processor before the
        // microphone hears it.
        let mut render_delay = Duration::ZERO;
        if let Some(sink) = sink {
            let rate = sink.sample_rate().max(1);
            if self.render_resampler.as_ref().map(Resampler::to_rate) != Some(rate) {
                self.render_resampler = Some(Resampler::new(SAMPLE_RATE, rate));
            }
            let target = sink.target_queue();
            // Bounded: at most half a second per pump, whatever the sink claims.
            for _ in 0..50 {
                if sink.queued() >= target {
                    break;
                }
                let mut frame = [0f32; FRAME_10MS];
                if !playout.pop(&mut frame) {
                    self.stats.render_silence += 1;
                }
                self.processor.process_render(&frame);
                self.stats.render_frames += 1;
                self.device_out.clear();
                if let Some(r) = self.render_resampler.as_mut() {
                    r.process(&frame, &mut self.device_out);
                }
                if let Err(e) = sink.write(&self.device_out) {
                    error = Some(DuplexError::Sink(e));
                    break;
                }
            }
            render_delay =
                Duration::from_secs_f64(sink.queued() as f64 / f64::from(rate)) + sink.latency();
        }

        let mut capture_delay = Duration::ZERO;
        if let Some(source) = source {
            let rate = source.sample_rate().max(1);
            if self.capture_resampler.as_ref().map(Resampler::from_rate) != Some(rate) {
                self.capture_resampler = Some(Resampler::new(rate, SAMPLE_RATE));
            }
            self.device_in.clear();
            if let Err(e) = source.read(&mut self.device_in) {
                error = Some(DuplexError::Source(e));
            }
            if let Some(r) = self.capture_resampler.as_mut() {
                r.process(&self.device_in, &mut self.capture);
            }
            let excess = self.capture.len().saturating_sub(MAX_CAPTURE_BACKLOG);
            if excess > 0 {
                self.capture.drain(..excess);
                self.stats.capture_dropped += excess as u64;
            }
            capture_delay = source.latency()
                + Duration::from_secs_f64(self.capture.len() as f64 / f64::from(SAMPLE_RATE));
        }

        let delay = render_delay + capture_delay;
        self.stats.stream_delay_ms = delay.as_millis().min(u128::from(u32::MAX)) as u32;
        self.processor.set_stream_delay(delay);

        let mut start = 0;
        while self.capture.len() - start >= FRAME_10MS {
            let frame = &mut self.capture[start..start + FRAME_10MS];
            self.processor.process_capture(frame);
            self.stats.capture_frames += 1;
            self.out.extend_from_slice(frame);
            start += FRAME_10MS;
            if self.out.len() >= FRAME_20MS {
                on_frame(&self.out[..FRAME_20MS]);
                self.out.drain(..FRAME_20MS);
            }
        }
        self.capture.drain(..start);

        match error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// Which device failed in [`AudioDuplex::pump`].
#[derive(Debug, thiserror::Error)]
pub enum DuplexError {
    #[error("microphone: {0}")]
    Source(MediaError),
    #[error("speakers: {0}")]
    Sink(MediaError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::processing::Passthrough;
    use crate::source::{SimRoom, Tone};

    #[test]
    fn the_playout_buffer_prebuffers_and_caps() {
        let buf = PlayoutBuffer::new();
        let mut frame = [1f32; FRAME_10MS];
        assert!(!buf.pop(&mut frame));
        assert!(frame.iter().all(|v| *v == 0.0), "silence before any audio");
        // 20 ms is below the prebuffer: still silence.
        buf.push(&[0.5; FRAME_20MS]);
        assert!(!buf.pop(&mut frame));
        buf.push(&[0.5; FRAME_20MS]);
        for _ in 0..4 {
            assert!(buf.pop(&mut frame));
            assert!(frame.iter().all(|v| *v == 0.5));
        }
        // Ran empty: one underrun, then it waits for the prebuffer again.
        assert!(!buf.pop(&mut frame));
        buf.push(&[0.5; FRAME_10MS]);
        assert!(!buf.pop(&mut frame));
        assert_eq!(buf.stats().0, 1);
        // Never more than the cap; the oldest goes first.
        buf.push(&vec![0.1; PlayoutBuffer::MAX]);
        buf.push(&[0.9; FRAME_10MS]);
        assert_eq!(buf.len(), PlayoutBuffer::MAX);
        assert!(buf.stats().1 > 0);
        assert!(!buf.is_empty());
    }

    /// Run a duplex against a simulated room for `ms` milliseconds in 5 ms steps.
    fn run(
        duplex: &mut AudioDuplex,
        room: &SimRoom,
        playout: &PlayoutBuffer,
        ms: usize,
        mut far_end: impl FnMut(&mut Vec<f32>),
        rate: u32,
    ) -> Vec<f32> {
        let (mut sink, mut source) = (room.sink(), room.source());
        let mut sent = Vec::new();
        let mut far = Vec::new();
        let mut owed = 0.0f64;
        for step in 0..ms / 5 {
            if step % 4 == 0 {
                far.clear();
                far_end(&mut far);
                playout.push(&far);
            }
            duplex
                .pump(Some(&mut source), Some(&mut sink), playout, &mut |f| {
                    sent.extend_from_slice(f)
                })
                .unwrap();
            // 5 ms of device time (a fractional sample count at 44.1 kHz).
            owed += f64::from(rate) * 0.005;
            let n = owed as usize;
            owed -= n as f64;
            room.advance(&vec![0.0; n]);
        }
        sent
    }

    #[test]
    fn a_passthrough_duplex_carries_both_directions_at_any_device_rate() {
        for rate in [48_000u32, 44_100, 16_000] {
            let room = SimRoom::new(rate, &[(Duration::from_millis(10), 0.5)]);
            let playout = PlayoutBuffer::new();
            let mut duplex = AudioDuplex::new(Box::new(Passthrough));
            let mut tone = Tone::new(SAMPLE_RATE, 1000.0, 0.5);
            let sent = run(
                &mut duplex,
                &room,
                &playout,
                2000,
                |far| tone.generate(FRAME_20MS, far),
                rate,
            );
            // Two seconds of device time give (nearly) two seconds of 20 ms frames.
            assert_eq!(sent.len() % FRAME_20MS, 0);
            assert!(
                (1900 * 48..=2000 * 48).contains(&sent.len()),
                "{rate}: {}",
                sent.len()
            );
            // What the far end said came back through the room at half the level: the tone
            // at amplitude 0.25 has mean-square power 1/32.
            let tail = &sent[sent.len() - 48_000 / 2..];
            let power = tail.iter().map(|v| f64::from(*v).powi(2)).sum::<f64>() / tail.len() as f64;
            assert!((power - 1.0 / 32.0).abs() < 0.004, "{rate}: {power}");
            let stats = duplex.stats();
            assert!(
                stats.capture_frames >= 190 && stats.render_frames >= 190,
                "{stats:?}"
            );
            assert_eq!(stats.capture_dropped, 0);
            // The sink is kept near its target (30 ms), so the delay told to the processor
            // stays in the tens of milliseconds.
            assert!((10..=80).contains(&stats.stream_delay_ms), "{stats:?}");
            // Steady playback: the loudspeaker ran dry only before the first audio arrived.
            assert!(
                room.underruns() < u64::from(rate) / 10,
                "{}",
                room.underruns()
            );
        }
    }

    #[test]
    fn a_missing_device_leaves_the_other_direction_running() {
        let room = SimRoom::new(48_000, &[]);
        let playout = PlayoutBuffer::new();
        let mut duplex = AudioDuplex::new(Box::new(Passthrough));
        let mut source = room.source();
        let mut frames = 0;
        for _ in 0..20 {
            room.advance(&[0.1; 240]);
            duplex
                .pump(Some(&mut source), None, &playout, &mut |f| {
                    assert_eq!(f.len(), FRAME_20MS);
                    frames += 1;
                })
                .unwrap();
        }
        assert_eq!(frames, 5);
        assert_eq!(duplex.stats().render_frames, 0);
        // No microphone: playback still runs.
        let mut sink = room.sink();
        playout.push(&vec![0.2; 4800]);
        duplex
            .pump(None, Some(&mut sink), &playout, &mut |_| {
                panic!("nothing was captured")
            })
            .unwrap();
        assert!(sink.queued() >= sink.target_queue());
    }

    struct Broken;
    impl AudioSource for Broken {
        fn sample_rate(&self) -> u32 {
            48_000
        }
        fn read(&mut self, _: &mut Vec<f32>) -> Result<(), MediaError> {
            Err(MediaError::Device("unplugged".into()))
        }
    }
    impl AudioSink for Broken {
        fn sample_rate(&self) -> u32 {
            48_000
        }
        fn queued(&self) -> usize {
            0
        }
        fn write(&mut self, _: &[f32]) -> Result<(), MediaError> {
            Err(MediaError::Device("unplugged".into()))
        }
    }

    #[test]
    fn device_errors_are_reported_not_fatal() {
        let playout = PlayoutBuffer::new();
        let mut duplex = AudioDuplex::new(Box::new(Passthrough));
        let err = duplex
            .pump(Some(&mut Broken), None, &playout, &mut |_| {})
            .unwrap_err();
        assert!(matches!(err, DuplexError::Source(_)), "{err}");
        let err = duplex
            .pump(None, Some(&mut Broken), &playout, &mut |_| {})
            .unwrap_err();
        assert!(matches!(err, DuplexError::Sink(_)), "{err}");
    }
}
