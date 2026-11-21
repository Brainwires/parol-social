//! Device-independent call media for ParolNet's native clients.
//!
//! `parolnet-app`'s core does no capture and no codec work: a client feeds it encoded frames
//! and receives RTP. This crate is the client's side of that line, with every backend behind a
//! cargo feature:
//!
//! | Module | Feature | What |
//! | --- | --- | --- |
//! | [`frame`] | - (`convert` for pixel-format conversion) | [`AudioFrame`], [`VideoFrame`], [`I420Frame`], scaling |
//! | [`source`] | - | the capture traits ([`VideoSource`], [`AudioSource`], [`AudioSink`]) and the synthetic sources (test pattern, tone, a simulated room) |
//! | [`resample`] | - | sample-rate conversion between device rates and 48 kHz |
//! | [`processing`] | `aec3` for the real one | [`AudioProcessor`]: echo cancellation, noise suppression, gain; a passthrough otherwise |
//! | [`duplex`] | - | the audio path of a call: capture → processor → 20 ms frames, playout → processor's reverse stream → device |
//! | [`selftest`] | - | the echo-cancellation measurement (ERLE) the tests and `--media-check` run |
//! | [`opus`] | `opus` | Opus encode / decode (opus-rs) |
//! | [`vp8`] | `vpx` | VP8 encode / decode (system libvpx) |
//! | [`audio_io`] | `audio-io` | microphone and speakers (cpal) |
//! | [`camera`] | `camera` | camera capture (nokhwa) |
//!
//! The default features are pure Rust; `vpx`, `audio-io` and `camera` need system libraries or
//! devices and are turned on by the desktop app.

#[cfg(feature = "audio-io")]
pub mod audio_io;
#[cfg(feature = "camera")]
pub mod camera;
pub mod duplex;
mod error;
pub mod frame;
#[cfg(feature = "opus")]
pub mod opus;
pub mod pattern;
pub mod processing;
pub mod resample;
pub mod selftest;
pub mod source;
#[cfg(feature = "vpx")]
pub mod vp8;

pub use error::MediaError;
pub use frame::{AudioFrame, I420Frame, VideoFrame};
pub use processing::{AudioProcessor, Passthrough, ProcessingConfig};
pub use source::{AudioSink, AudioSource, DeviceInfo, VideoFormat, VideoSource};

/// The rate the call's audio runs at (Opus's, and the audio processor's).
pub const SAMPLE_RATE: u32 = 48_000;
/// Samples in the 10 ms frames the audio processor takes.
pub const FRAME_10MS: usize = 480;
/// Samples in the 20 ms frames Opus takes.
pub const FRAME_20MS: usize = 960;
