//! Echo cancellation, noise suppression and gain control behind one trait.
//!
//! The processor works on 10 ms frames of 48 kHz mono audio ([`crate::FRAME_10MS`] samples).
//! Two streams go through it, and their order is what makes echo cancellation work:
//!
//! - the **render** (far-end, reverse) stream: every frame that is about to be played on the
//!   speakers goes to [`AudioProcessor::process_render`] first;
//! - the **capture** (near-end) stream: every microphone frame goes through
//!   [`AudioProcessor::process_capture`], which removes what the microphone picked up of the
//!   render stream.
//!
//! [`AudioProcessor::set_stream_delay`] tells it how long a render frame takes to come back
//! as echo (playout buffer + output latency + input latency + capture buffer). AEC3 estimates
//! the delay itself; the hint shortens its search.
//!
//! With the `aec3` feature, [`new_processor`] returns WebRTC's audio processing module (AEC3,
//! noise suppression, AGC2, high-pass filter) in its pure-Rust port, `sonora`. Without it, or
//! with everything turned off in [`ProcessingConfig`], it returns [`Passthrough`].

use std::time::Duration;

/// What the processor does to the capture stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessingConfig {
    /// Remove the echo of the render stream (AEC3).
    pub echo_cancellation: bool,
    /// Suppress steady background noise.
    pub noise_suppression: bool,
    /// Bring speech to a steady level (AGC2's adaptive digital gain and limiter).
    pub gain_control: bool,
    /// Remove DC and rumble below the voice band.
    pub high_pass: bool,
}

impl ProcessingConfig {
    /// Everything on: what a call uses.
    pub const CALL: Self = Self {
        echo_cancellation: true,
        noise_suppression: true,
        gain_control: true,
        high_pass: true,
    };

    /// Echo cancellation alone (what the echo measurement uses, so that noise suppression
    /// and gain do not move the levels it compares).
    pub const ECHO_ONLY: Self = Self {
        echo_cancellation: true,
        noise_suppression: false,
        gain_control: false,
        high_pass: false,
    };

    /// Nothing: a passthrough.
    pub const OFF: Self = Self {
        echo_cancellation: false,
        noise_suppression: false,
        gain_control: false,
        high_pass: false,
    };

    fn is_off(&self) -> bool {
        *self == Self::OFF
    }
}

impl Default for ProcessingConfig {
    fn default() -> Self {
        Self::CALL
    }
}

/// Audio processing on 10 ms frames of 48 kHz mono audio. Owned by the call's audio thread.
pub trait AudioProcessor: Send {
    /// One frame ([`crate::FRAME_10MS`] samples) that is about to be played: the reverse stream.
    /// Frames of another length are ignored.
    fn process_render(&mut self, frame: &[f32]);

    /// One microphone frame ([`crate::FRAME_10MS`] samples), processed in place against the render
    /// stream. Frames of another length are left as they are.
    fn process_capture(&mut self, frame: &mut [f32]);

    /// How long a render frame takes from [`AudioProcessor::process_render`] until its echo
    /// reaches [`AudioProcessor::process_capture`].
    fn set_stream_delay(&mut self, delay: Duration);

    /// The backend's name, for logs and the media check.
    fn name(&self) -> &'static str;

    /// The echo return loss enhancement the processor measures itself, in dB, if it does.
    fn reported_erle_db(&self) -> Option<f64> {
        None
    }
}

/// Leaves both streams alone.
#[derive(Clone, Copy, Debug, Default)]
pub struct Passthrough;

impl AudioProcessor for Passthrough {
    fn process_render(&mut self, _frame: &[f32]) {}
    fn process_capture(&mut self, _frame: &mut [f32]) {}
    fn set_stream_delay(&mut self, _delay: Duration) {}
    fn name(&self) -> &'static str {
        "passthrough"
    }
}

/// The processor for `config`: AEC3 with the `aec3` feature, else (or with everything off) a
/// passthrough.
pub fn new_processor(config: ProcessingConfig) -> Box<dyn AudioProcessor> {
    if config.is_off() {
        return Box::new(Passthrough);
    }
    #[cfg(feature = "aec3")]
    {
        Box::new(aec3::Aec3::new(config))
    }
    #[cfg(not(feature = "aec3"))]
    {
        Box::new(Passthrough)
    }
}

/// Whether [`new_processor`] can cancel echo in this build.
pub const fn echo_cancellation_available() -> bool {
    cfg!(feature = "aec3")
}

#[cfg(feature = "aec3")]
pub use aec3::Aec3;

#[cfg(feature = "aec3")]
mod aec3 {
    use std::time::Duration;

    use sonora::config::{
        AdaptiveDigital, EchoCanceller, GainController2, HighPassFilter, MaxProcessingRate,
        NoiseSuppression, NoiseSuppressionLevel, Pipeline,
    };
    use sonora::{AudioProcessing, Config, StreamConfig};

    use super::{AudioProcessor, ProcessingConfig};
    use crate::{FRAME_10MS, SAMPLE_RATE};

    /// WebRTC's audio processing module (AEC3, noise suppression, AGC2) at 48 kHz mono.
    pub struct Aec3 {
        apm: AudioProcessing,
        /// Scratch output frame (the module does not process in place).
        out: [f32; FRAME_10MS],
        render_out: [f32; FRAME_10MS],
    }

    impl Aec3 {
        pub fn new(config: ProcessingConfig) -> Self {
            let apm_config = Config {
                pipeline: Pipeline {
                    // Full band: the call's audio is 48 kHz Opus.
                    maximum_internal_processing_rate: MaxProcessingRate::Rate48kHz,
                    multi_channel_render: false,
                    multi_channel_capture: false,
                    ..Default::default()
                },
                high_pass_filter: config.high_pass.then(HighPassFilter::default),
                echo_canceller: config.echo_cancellation.then(EchoCanceller::default),
                noise_suppression: config.noise_suppression.then(|| NoiseSuppression {
                    level: NoiseSuppressionLevel::Moderate,
                    ..Default::default()
                }),
                gain_controller2: config.gain_control.then(|| GainController2 {
                    adaptive_digital: Some(AdaptiveDigital::default()),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let stream = StreamConfig::new(SAMPLE_RATE, 1);
            let apm = AudioProcessing::builder()
                .config(apm_config)
                .capture_config(stream)
                .render_config(stream)
                .build();
            Self {
                apm,
                out: [0.0; FRAME_10MS],
                render_out: [0.0; FRAME_10MS],
            }
        }
    }

    impl AudioProcessor for Aec3 {
        fn process_render(&mut self, frame: &[f32]) {
            if frame.len() != FRAME_10MS {
                return;
            }
            if let Err(e) = self
                .apm
                .process_render_f32(&[frame], &mut [&mut self.render_out[..]])
            {
                tracing::debug!("audio processing (render): {e}");
            }
        }

        fn process_capture(&mut self, frame: &mut [f32]) {
            if frame.len() != FRAME_10MS {
                return;
            }
            match self
                .apm
                .process_capture_f32(&[&*frame], &mut [&mut self.out[..]])
            {
                Ok(()) => frame.copy_from_slice(&self.out),
                // Leave the frame unprocessed rather than drop audio.
                Err(e) => tracing::debug!("audio processing (capture): {e}"),
            }
        }

        fn set_stream_delay(&mut self, delay: Duration) {
            // The module clamps to 0..=500 ms itself and says so; that is not an error here.
            let _ = self
                .apm
                .set_stream_delay_ms(delay.as_millis().min(500) as i32);
        }

        fn name(&self) -> &'static str {
            "aec3 (sonora)"
        }

        fn reported_erle_db(&self) -> Option<f64> {
            self.apm.statistics().echo_return_loss_enhancement
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FRAME_10MS;

    #[test]
    fn passthrough_changes_nothing() {
        let mut p = new_processor(ProcessingConfig::OFF);
        assert_eq!(p.name(), "passthrough");
        let mut frame = [0.25f32; FRAME_10MS];
        p.process_render(&frame);
        p.process_capture(&mut frame);
        p.set_stream_delay(Duration::from_millis(40));
        assert!(frame.iter().all(|v| *v == 0.25));
        assert!(p.reported_erle_db().is_none());
    }

    #[cfg(feature = "aec3")]
    #[test]
    fn wrong_frame_sizes_are_left_alone() {
        let mut p = new_processor(ProcessingConfig::CALL);
        assert_eq!(p.name(), "aec3 (sonora)");
        let mut short = [0.5f32; 100];
        p.process_render(&short);
        p.process_capture(&mut short);
        assert!(short.iter().all(|v| *v == 0.5));
        // An absurd delay is clamped, not refused.
        p.set_stream_delay(Duration::from_secs(10));
        let mut frame = [0.0f32; FRAME_10MS];
        p.process_capture(&mut frame);
        assert!(frame.iter().all(|v| v.is_finite()));
    }
}
