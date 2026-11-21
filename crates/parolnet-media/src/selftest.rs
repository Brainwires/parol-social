//! "Echo cancellation works on speakers", measured instead of listened to.
//!
//! A known far-end signal (speech-shaped noise) is played into the processor's reverse
//! stream; the simulated microphone hears it back through an echo path (three reflections,
//! 42 to 71 ms late, the strongest 6 dB down), later together with a near-end tone. The
//! measurement is the echo return loss enhancement (ERLE): how many dB less of the far-end
//! signal is in the processor's output than in the microphone signal, once the canceller has
//! converged, and whether the near-end tone comes through.
//!
//! Everything is deterministic (no devices, no clock, a fixed noise seed), so the numbers are
//! the same on every run and platform up to floating-point differences. The crate's tests
//! assert on them and `parolnet-desktop --media-check` prints them.

use std::time::Duration;

use crate::duplex::{AudioDuplex, PlayoutBuffer};
use crate::processing::{AudioProcessor, Passthrough};
use crate::source::{AudioSink as _, AudioSource as _, SimRoom, Tone};
use crate::{FRAME_10MS, FRAME_20MS, SAMPLE_RATE};

/// The echo path: (delay, gain) per reflection.
pub const ECHO_PATH: [(Duration, f32); 3] = [
    (Duration::from_millis(42), 0.5),
    (Duration::from_millis(55), 0.2),
    (Duration::from_millis(71), -0.1),
];
/// The near-end tone.
pub const NEAR_END_HZ: f64 = 1000.0;
const NEAR_END_AMPLITUDE: f32 = 0.1;

/// The schedule, in seconds: the canceller converges on the far-end signal alone, the ERLE
/// is measured, then the near-end tone joins (double talk) and is measured after a second.
const CONVERGE_S: usize = 6;
const MEASURE_S: usize = 3;
const SETTLE_S: usize = 1;
const TOTAL_S: usize = CONVERGE_S + MEASURE_S + SETTLE_S + MEASURE_S;

/// What the measurement found.
#[derive(Clone, Debug, PartialEq)]
pub struct EchoReport {
    /// The processor that was measured.
    pub backend: &'static str,
    /// Far end alone: echo power at the microphone over echo power in the output, in dB.
    pub erle_db: f64,
    /// Double talk: the same for everything in the output that is not the near-end tone.
    pub double_talk_erle_db: f64,
    /// Double talk: the near-end tone's level in the output relative to the microphone, in
    /// dB (0 is untouched, negative is attenuated).
    pub near_end_db: f64,
}

impl EchoReport {
    /// The thresholds the tests and the media check hold an echo canceller to:
    ///
    /// - far end alone: at least 30 dB less echo (AEC3 measures 53 dB in WebRTC's C++ and
    ///   67 dB in the Rust port on this signal; a canceller that has not converged, or one
    ///   fed the wrong reference, stays under 10);
    /// - double talk: at least 5 dB less of everything that is not the near-end tone. AEC3
    ///   holds its suppressor back while someone talks at the near end, so only the linear
    ///   filter's share is left: 7 to 9 dB here, in both implementations;
    /// - the near-end tone within 4 dB of its level (measured: -1.7 to -2.2 dB).
    pub fn passes(&self) -> bool {
        self.erle_db >= 30.0 && self.double_talk_erle_db >= 5.0 && self.near_end_db.abs() <= 4.0
    }
}

impl std::fmt::Display for EchoReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "backend={:?} erle_db={:.1} double_talk_erle_db={:.1} near_end_db={:.1}",
            self.backend, self.erle_db, self.double_talk_erle_db, self.near_end_db
        )
    }
}

/// Speech-shaped noise: white noise from a fixed-seed generator, band-limited to roughly the
/// voice band, with a syllable-rate envelope and pauses.
pub struct SpeechNoise {
    state: u64,
    low: f32,
    high: f32,
    n: u64,
    rate: f64,
}

impl SpeechNoise {
    pub fn new(sample_rate: u32) -> Self {
        Self {
            state: 0x5eed_cafe_f00d_0001,
            low: 0.0,
            high: 0.0,
            n: 0,
            rate: f64::from(sample_rate.max(1)),
        }
    }

    /// Append `n` samples.
    pub fn generate(&mut self, n: usize, out: &mut Vec<f32>) {
        // One-pole filters: low-pass near 3.4 kHz, high-pass near 300 Hz.
        let lp = (1.0 - (-std::f64::consts::TAU * 3400.0 / self.rate).exp()) as f32;
        let hp = (1.0 - (-std::f64::consts::TAU * 300.0 / self.rate).exp()) as f32;
        out.reserve(n);
        for _ in 0..n {
            self.state = self
                .state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let white = ((self.state >> 40) as f32 / (1u64 << 23) as f32) - 1.0;
            self.low += lp * (white - self.low);
            self.high += hp * (self.low - self.high);
            let band = self.low - self.high;
            let t = self.n as f64 / self.rate;
            // Syllables at 3 Hz, a pause of 0.4 s in every 2 s.
            let syllable = 0.55 + 0.45 * (std::f64::consts::TAU * 3.0 * t).sin();
            let talking = if t % 2.0 < 1.6 { 1.0 } else { 0.0 };
            out.push(band * (syllable * talking) as f32 * 0.6);
            self.n += 1;
        }
    }
}

fn power(x: &[f32]) -> f64 {
    x.iter().map(|&v| f64::from(v).powi(2)).sum::<f64>() / x.len().max(1) as f64
}

/// Mean-square power of the `hz` component of `x` (Goertzel).
fn tone_power(x: &[f32], hz: f64) -> f64 {
    let n = x.len().max(1) as f64;
    let coeff = 2.0 * (std::f64::consts::TAU * hz / f64::from(SAMPLE_RATE)).cos();
    let (mut s1, mut s2) = (0.0f64, 0.0f64);
    for &v in x {
        let s0 = f64::from(v) + coeff * s1 - s2;
        s2 = s1;
        s1 = s0;
    }
    2.0 * (s1 * s1 + s2 * s2 - coeff * s1 * s2) / (n * n)
}

fn db(ratio: f64) -> f64 {
    10.0 * ratio.max(1e-12).log10()
}

/// Compare the unprocessed microphone signal with the processed one over the two windows.
fn report(backend: &'static str, mic: &[f32], out: &[f32]) -> EchoReport {
    let rate = SAMPLE_RATE as usize;
    let n = mic.len().min(out.len());
    let single = (CONVERGE_S * rate).min(n)..((CONVERGE_S + MEASURE_S) * rate).min(n);
    let double = ((CONVERGE_S + MEASURE_S + SETTLE_S) * rate).min(n)..(TOTAL_S * rate).min(n);
    let (mic_tone, out_tone) = (
        tone_power(&mic[double.clone()], NEAR_END_HZ),
        tone_power(&out[double.clone()], NEAR_END_HZ),
    );
    let mic_rest = (power(&mic[double.clone()]) - mic_tone).max(1e-12);
    let out_rest = (power(&out[double]) - out_tone).max(1e-12);
    EchoReport {
        backend,
        erle_db: db(power(&mic[single.clone()]) / power(&out[single]).max(1e-12)),
        double_talk_erle_db: db(mic_rest / out_rest),
        near_end_db: db(out_tone / mic_tone.max(1e-12)),
    }
}

/// Measure `processor` directly: 10 ms frames at 48 kHz, the render frame handed over just
/// before the capture frame that carries its echo (as the call's audio thread does).
pub fn echo_test(processor: &mut dyn AudioProcessor) -> EchoReport {
    let rate = SAMPLE_RATE as usize;
    let mut far = SpeechNoise::new(SAMPLE_RATE);
    let mut near = Tone::new(SAMPLE_RATE, NEAR_END_HZ, NEAR_END_AMPLITUDE);
    let taps: Vec<(usize, f32)> = ECHO_PATH
        .iter()
        .map(|(d, g)| ((d.as_secs_f64() * rate as f64) as usize, *g))
        .collect();
    let mut played: Vec<f32> = Vec::with_capacity(TOTAL_S * rate);
    let (mut mic, mut out) = (
        Vec::with_capacity(TOTAL_S * rate),
        Vec::with_capacity(TOTAL_S * rate),
    );
    let mut frame = Vec::with_capacity(FRAME_10MS);
    let mut tone = Vec::with_capacity(FRAME_10MS);
    let double_from = (CONVERGE_S + MEASURE_S) * rate;
    // The first reflection is 42 ms late; the processor is told 40.
    processor.set_stream_delay(Duration::from_millis(40));
    for i in 0..TOTAL_S * 100 {
        frame.clear();
        far.generate(FRAME_10MS, &mut frame);
        processor.process_render(&frame);
        played.extend_from_slice(&frame);

        tone.clear();
        if i * FRAME_10MS >= double_from {
            near.generate(FRAME_10MS, &mut tone);
        } else {
            tone.resize(FRAME_10MS, 0.0);
        }
        let base = i * FRAME_10MS;
        let mut capture = [0f32; FRAME_10MS];
        for (j, c) in capture.iter_mut().enumerate() {
            let t = base + j;
            *c = tone[j];
            for &(delay, gain) in &taps {
                if t >= delay {
                    *c += played[t - delay] * gain;
                }
            }
        }
        mic.extend_from_slice(&capture);
        processor.process_capture(&mut capture);
        out.extend_from_slice(&capture);
    }
    report(processor.name(), &mic, &out)
}

/// One run of the whole audio path against a simulated room whose devices run at
/// `device_rate`: returns what the call would send.
fn duplex_run(processor: Box<dyn AudioProcessor>, device_rate: u32) -> Vec<f32> {
    let room = SimRoom::new(device_rate, &ECHO_PATH);
    let (mut sink, mut source) = (room.sink(), room.source());
    let playout = PlayoutBuffer::new();
    let mut duplex = AudioDuplex::new(processor);
    let mut far = SpeechNoise::new(SAMPLE_RATE);
    let mut near = Tone::new(device_rate, NEAR_END_HZ, NEAR_END_AMPLITUDE);
    let mut sent = Vec::with_capacity(TOTAL_S * SAMPLE_RATE as usize);
    let (mut packet, mut room_audio) = (Vec::new(), Vec::new());
    let mut owed = 0.0f64;
    let double_from_step = (CONVERGE_S + MEASURE_S) * 200;
    // 5 ms steps: the audio thread's cadence. The contact's audio arrives every 20 ms.
    for step in 0..TOTAL_S * 200 {
        if step % 4 == 0 {
            packet.clear();
            far.generate(FRAME_20MS, &mut packet);
            playout.push(&packet);
        }
        // The simulated devices cannot fail.
        let _ = duplex.pump(Some(&mut source), Some(&mut sink), &playout, &mut |f| {
            sent.extend_from_slice(f)
        });
        owed += f64::from(device_rate) * 0.005;
        let n = owed as usize;
        owed -= n as f64;
        room_audio.clear();
        if step >= double_from_step {
            near.generate(n, &mut room_audio);
        } else {
            room_audio.resize(n, 0.0);
        }
        room.advance(&room_audio);
    }
    // Keep the borrow checker's view simple: the devices go before the room.
    let _ = (sink.queued(), source.sample_rate());
    sent
}

/// Measure a processor inside the whole audio path ([`AudioDuplex`]) with devices at
/// `device_rate`: resampling both ways, the playout buffer, 5 ms pumping. The reference is
/// the same run with a passthrough processor, so the path's own delay and filtering cancel
/// out of the comparison.
pub fn duplex_echo_test(processor: Box<dyn AudioProcessor>, device_rate: u32) -> EchoReport {
    let backend = processor.name();
    let reference = duplex_run(Box::new(Passthrough), device_rate);
    let processed = duplex_run(processor, device_rate);
    report(backend, &reference, &processed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "aec3")]
    use crate::processing::{ProcessingConfig, new_processor};

    #[test]
    fn the_far_end_signal_is_speech_shaped_and_deterministic() {
        let (mut a, mut b) = (Vec::new(), Vec::new());
        SpeechNoise::new(SAMPLE_RATE).generate(96_000, &mut a);
        SpeechNoise::new(SAMPLE_RATE).generate(96_000, &mut b);
        assert_eq!(a, b);
        let level = db(power(&a));
        assert!((-35.0..=-15.0).contains(&level), "{level:.1} dBFS");
        // The pause at 1.6..2.0 s is silent.
        assert!(power(&a[80_000..95_000]) < 1e-9);
    }

    #[test]
    fn a_passthrough_cancels_nothing() {
        let r = echo_test(&mut Passthrough);
        assert!(r.erle_db.abs() < 0.01 && r.near_end_db.abs() < 0.01, "{r}");
        assert!(!r.passes());
        let r = duplex_echo_test(Box::new(Passthrough), 48_000);
        assert!(r.erle_db.abs() < 0.01, "{r}");
    }

    /// The M1 criterion "echo cancellation works on speakers", in CI form.
    #[cfg(feature = "aec3")]
    #[test]
    fn aec3_removes_the_echo_and_keeps_the_near_end() {
        let mut p = new_processor(ProcessingConfig::ECHO_ONLY);
        let r = echo_test(p.as_mut());
        println!("echo-test {r}");
        assert!(r.passes(), "{r}");
    }

    /// The same through the whole audio path, with devices at 44.1 kHz (resampling both
    /// ways) and at 48 kHz.
    #[cfg(feature = "aec3")]
    #[test]
    fn aec3_works_through_the_duplex_path_at_device_rates() {
        for rate in [44_100u32, 48_000] {
            let r = duplex_echo_test(new_processor(ProcessingConfig::ECHO_ONLY), rate);
            println!("duplex-echo-test rate={rate} {r}");
            assert!(r.passes(), "{rate}: {r}");
        }
    }

    /// The call's configuration (noise suppression and gain control on as well) still removes
    /// the echo. The near-end tone is not asserted here: noise suppression treats a steady
    /// tone as noise, by design.
    #[cfg(feature = "aec3")]
    #[test]
    fn the_call_configuration_removes_the_echo() {
        let mut p = new_processor(ProcessingConfig::CALL);
        let r = echo_test(p.as_mut());
        println!("echo-test call {r}");
        assert!(r.erle_db >= 30.0, "{r}");
    }
}
