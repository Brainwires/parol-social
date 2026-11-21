//! Sample-rate conversion for mono audio: a polyphase windowed-sinc filter (Kaiser window),
//! streaming, for the device rates sound cards run at (44.1, 48, 96 kHz, 16 kHz headsets) to
//! and from the call's 48 kHz.
//!
//! Linear interpolation (what the first call slice used) folds everything above the lower
//! Nyquist frequency back into the voice band; the echo canceller then sees content in the
//! microphone signal that was never in its reference. This filter keeps images and aliases
//! about 70 dB down.

/// Zero crossings of the sinc on each side of the centre, at the lower of the two rates.
const HALF_WIDTH: usize = 16;
/// Kaiser window shape (about 70 dB of stop-band attenuation).
const KAISER_BETA: f64 = 7.0;
/// Phases of the filter bank when the ratio's exact phase count would be larger.
const MAX_PHASES: usize = 1024;
/// Pass band, as a share of the lower Nyquist frequency.
const CUTOFF: f64 = 0.94;

/// A streaming resampler for one channel.
pub struct Resampler {
    from: u32,
    to: u32,
    /// `phases` filters of `taps` coefficients each, back to back.
    bank: Vec<f32>,
    taps: usize,
    phases: usize,
    /// Input history: the last `taps` samples carried over, then the new input.
    history: Vec<f32>,
    /// Position of the next output sample in input samples, as a whole part (an index into
    /// `history`, where the filter window starts) and a fraction in units of
    /// `1 / frac_den`.
    pos: usize,
    frac: u64,
    /// Advance per output sample: `step_whole` + `step_frac / frac_den` input samples.
    step_whole: usize,
    step_frac: u64,
    frac_den: u64,
}

fn gcd(a: u32, b: u32) -> u32 {
    if b == 0 { a } else { gcd(b, a % b) }
}

/// The zeroth-order modified Bessel function of the first kind (for the Kaiser window).
fn bessel_i0(x: f64) -> f64 {
    let (mut sum, mut term, mut k) = (1.0f64, 1.0f64, 1.0f64);
    while term > sum * 1e-12 {
        term *= (x / (2.0 * k)).powi(2);
        sum += term;
        k += 1.0;
    }
    sum
}

impl Resampler {
    /// A resampler from `from` Hz to `to` Hz (both non-zero; equal rates pass through).
    pub fn new(from: u32, to: u32) -> Self {
        let (from, to) = (from.max(1), to.max(1));
        let g = gcd(from, to);
        let (up, down) = ((to / g) as usize, (from / g) as usize);
        let phases = if from == to { 1 } else { up.min(MAX_PHASES) };
        // When downsampling the filter cuts at the output's Nyquist, so it is longer.
        let stretch = (f64::from(from) / f64::from(to)).max(1.0);
        let half = ((HALF_WIDTH as f64) * stretch).ceil() as usize;
        let taps = if from == to { 1 } else { (2 * half).min(512) };
        let cutoff = CUTOFF / stretch;
        let mut bank = vec![0f32; phases * taps];
        if from == to {
            bank[0] = 1.0;
        } else {
            let i0_beta = bessel_i0(KAISER_BETA);
            for phase in 0..phases {
                // The output sample sits `phase / phases` of an input sample after the
                // tap at index `taps / 2 - 1`.
                let offset = phase as f64 / phases as f64;
                let centre = (taps / 2 - 1) as f64 + offset;
                let row = &mut bank[phase * taps..(phase + 1) * taps];
                let mut sum = 0.0f64;
                let mut coeffs = vec![0f64; taps];
                for (i, c) in coeffs.iter_mut().enumerate() {
                    let t = i as f64 - centre;
                    let x = std::f64::consts::PI * t * cutoff;
                    let sinc = if x.abs() < 1e-9 { 1.0 } else { x.sin() / x };
                    let r = t / (taps as f64 / 2.0);
                    let window = if r.abs() >= 1.0 {
                        0.0
                    } else {
                        bessel_i0(KAISER_BETA * (1.0 - r * r).sqrt()) / i0_beta
                    };
                    *c = cutoff * sinc * window;
                    sum += *c;
                }
                // Unity gain at DC for every phase, so a steady level has no ripple.
                for (out, c) in row.iter_mut().zip(&coeffs) {
                    *out = (*c / sum) as f32;
                }
            }
        }
        Self {
            from,
            to,
            bank,
            taps,
            phases,
            // Start as if `taps - 1` zeroes came before the first sample.
            history: vec![0.0; taps - 1],
            pos: 0,
            frac: 0,
            step_whole: down / up,
            step_frac: (down % up) as u64,
            frac_den: up as u64,
        }
    }

    pub fn from_rate(&self) -> u32 {
        self.from
    }

    pub fn to_rate(&self) -> u32 {
        self.to
    }

    /// The filter's delay, in input samples.
    pub fn delay(&self) -> usize {
        self.taps / 2
    }

    /// Resample `input`, appending to `out`. Allocates only when `out` or the history has to
    /// grow (not in the steady state of equal-sized calls).
    pub fn process(&mut self, input: &[f32], out: &mut Vec<f32>) {
        if self.from == self.to {
            out.extend_from_slice(input);
            return;
        }
        self.history.extend_from_slice(input);
        let taps = self.taps;
        while self.pos + taps <= self.history.len() {
            // Nearest phase of the bank (exact when the bank has `frac_den` phases).
            let phase = if self.phases as u64 == self.frac_den {
                self.frac as usize
            } else {
                ((self.frac * self.phases as u64 + self.frac_den / 2) / self.frac_den) as usize
            };
            // Rounding up to the next whole sample is phase 0 one sample later.
            let (window, phase) = if phase >= self.phases {
                (self.pos + 1, 0)
            } else {
                (self.pos, phase)
            };
            if window + taps > self.history.len() {
                break;
            }
            let coeffs = &self.bank[phase * taps..(phase + 1) * taps];
            let acc: f32 = self.history[window..window + taps]
                .iter()
                .zip(coeffs)
                .map(|(s, c)| s * c)
                .sum();
            out.push(acc);
            self.pos += self.step_whole;
            self.frac += self.step_frac;
            if self.frac >= self.frac_den {
                self.frac -= self.frac_den;
                self.pos += 1;
            }
        }
        // Keep what the next window still needs.
        let consumed = self.pos.min(self.history.len());
        self.history.drain(..consumed);
        self.pos -= consumed;
    }

    /// Forget the history (after a gap in the input).
    pub fn reset(&mut self) {
        self.history.clear();
        self.history.resize(self.taps.saturating_sub(1), 0.0);
        self.pos = 0;
        self.frac = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tone(rate: u32, hz: f64, n: usize) -> Vec<f32> {
        (0..n)
            .map(|i| (2.0 * std::f64::consts::PI * hz * i as f64 / f64::from(rate)).sin() as f32)
            .collect()
    }

    /// Mean-square power of `hz` in `x` (Goertzel) and the total mean-square power.
    fn tone_power(x: &[f32], rate: u32, hz: f64) -> (f64, f64) {
        let n = x.len() as f64;
        let coeff = 2.0 * (2.0 * std::f64::consts::PI * hz / f64::from(rate)).cos();
        let (mut s1, mut s2) = (0.0f64, 0.0f64);
        for &v in x {
            let s0 = f64::from(v) + coeff * s1 - s2;
            s2 = s1;
            s1 = s0;
        }
        let power = 2.0 * (s1 * s1 + s2 * s2 - coeff * s1 * s2) / (n * n);
        let total = x.iter().map(|&v| f64::from(v).powi(2)).sum::<f64>() / n;
        (power, total)
    }

    #[test]
    fn keeps_the_rate_in_any_chunking() {
        for (from, to) in [
            (44_100u32, 48_000u32),
            (48_000, 44_100),
            (16_000, 48_000),
            (48_000, 16_000),
            (96_000, 48_000),
            (22_050, 48_000),
            (48_000, 11_025),
        ] {
            let mut r = Resampler::new(from, to);
            let input = vec![0.25f32; from as usize];
            let mut out = Vec::new();
            // One second, in uneven chunks.
            let mut rest = &input[..];
            let mut chunk = 1;
            while !rest.is_empty() {
                let n = chunk.min(rest.len());
                r.process(&rest[..n], &mut out);
                rest = &rest[n..];
                chunk = chunk * 3 % 997 + 1;
            }
            let want = to as i64;
            assert!(
                (out.len() as i64 - want).abs() <= 2,
                "{from} -> {to}: {} samples",
                out.len()
            );
            // A steady level comes out steady once the filter has filled.
            let settled = &out[out.len() / 2..];
            assert!(
                settled.iter().all(|v| (v - 0.25).abs() < 1e-3),
                "{from} -> {to}"
            );
        }
    }

    #[test]
    fn equal_rates_pass_through() {
        let mut r = Resampler::new(48_000, 48_000);
        let mut out = Vec::new();
        r.process(&[0.1, 0.2, -0.3], &mut out);
        assert_eq!(out, [0.1, 0.2, -0.3]);
    }

    #[test]
    fn a_tone_survives_and_nothing_else_appears() {
        for (from, to) in [(44_100u32, 48_000u32), (48_000, 44_100), (16_000, 48_000)] {
            let mut r = Resampler::new(from, to);
            let mut out = Vec::new();
            r.process(&tone(from, 1000.0, from as usize), &mut out);
            let settled = &out[to as usize / 10..];
            let (power, total) = tone_power(settled, to, 1000.0);
            // A unit sine has mean-square power 0.5.
            assert!((power - 0.5).abs() < 0.01, "{from} -> {to}: {power}");
            // Everything that is not the tone is at least 55 dB down.
            let rest = (total - power).max(1e-12);
            let snr = 10.0 * (power / rest).log10();
            assert!(snr > 55.0, "{from} -> {to}: {snr:.1} dB");
        }
    }

    #[test]
    fn downsampling_removes_what_would_alias() {
        // 20 kHz at 48 kHz would fold to 4 kHz at 24 kHz... use 48 -> 16 kHz: 10 kHz folds to
        // 6 kHz without a filter.
        let mut r = Resampler::new(48_000, 16_000);
        let mut out = Vec::new();
        r.process(&tone(48_000, 10_000.0, 48_000), &mut out);
        let settled = &out[1600..];
        let total =
            settled.iter().map(|&v| f64::from(v).powi(2)).sum::<f64>() / settled.len() as f64;
        let db = 10.0 * (total / 0.5).log10();
        assert!(db < -55.0, "alias at {db:.1} dB");
    }

    #[test]
    fn reset_starts_over() {
        let mut r = Resampler::new(44_100, 48_000);
        let mut out = Vec::new();
        r.process(&[1.0; 441], &mut out);
        r.reset();
        out.clear();
        r.process(&[0.0; 441], &mut out);
        assert!(out.iter().all(|v| *v == 0.0));
    }
}
