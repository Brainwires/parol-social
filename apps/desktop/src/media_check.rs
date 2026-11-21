//! `parolnet-desktop --media-check`: the call media's device-independent checks, without a
//! window, a network or a device. For CI on every desktop target.
//!
//! 1. **Echo cancellation.** The echo return loss enhancement of the call's audio processor
//!    (`parolnet_media::selftest`): directly on 10 ms frames, and through the whole audio path
//!    with simulated devices at 44.1 and 48 kHz. Fails below the thresholds in
//!    [`parolnet_media::selftest::EchoReport::passes`].
//! 2. **A synthetic camera.** The test pattern delivered the way cameras deliver pictures
//!    (720p YUYV, NV12, I420), converted to I420, scaled to the send size, encoded with
//!    libvpx and decoded again; the decoded pictures must be the pattern, not a flat fill.
//!
//! Prints `media-check ...` lines and exits 0 when everything passed.

use std::time::Duration;

use anyhow::{Context as _, bail};
use parolnet_media::processing::{ProcessingConfig, echo_cancellation_available, new_processor};
use parolnet_media::selftest::{duplex_echo_test, echo_test};
use parolnet_media::source::{PatternPixel, PatternSource};
use parolnet_media::vp8::{Vp8Decoder, Vp8Encoder, libvpx_version};
use parolnet_media::{VideoFormat, VideoSource as _};

use crate::call::send_format;

pub fn main() -> anyhow::Result<()> {
    echo()?;
    camera()?;
    println!("media-check ok");
    Ok(())
}

fn echo() -> anyhow::Result<()> {
    if !echo_cancellation_available() {
        bail!("this build has no echo canceller (parolnet-media without `aec3`)");
    }
    let mut processor = new_processor(ProcessingConfig::ECHO_ONLY);
    let report = echo_test(processor.as_mut());
    println!("media-check echo path=direct {report}");
    if !report.passes() {
        bail!("echo cancellation is below the thresholds: {report}");
    }
    for rate in [44_100u32, 48_000] {
        let report = duplex_echo_test(new_processor(ProcessingConfig::ECHO_ONLY), rate);
        println!("media-check echo path=duplex device_rate={rate} {report}");
        if !report.passes() {
            bail!("echo cancellation through the audio path at {rate} Hz: {report}");
        }
    }
    // The call's own configuration (noise suppression and gain control as well).
    let mut call = new_processor(ProcessingConfig::CALL);
    let report = echo_test(call.as_mut());
    println!("media-check echo path=direct config=call {report}");
    if report.erle_db < 30.0 {
        bail!("echo cancellation in the call configuration: {report}");
    }
    Ok(())
}

fn camera() -> anyhow::Result<()> {
    let (send, kbps) = send_format();
    println!("media-check libvpx {}", libvpx_version());
    let cases = [
        (PatternPixel::Yuyv, VideoFormat::P720),
        (PatternPixel::Nv12, VideoFormat::P720),
        // A 4:3 camera: cropped to 16:9.
        (
            PatternPixel::Yuyv,
            VideoFormat {
                width: 640,
                height: 480,
                fps: 30,
            },
        ),
        (PatternPixel::I420, send),
    ];
    for (pixel, capture) in cases {
        // 120 fps so that the check does not wait on the pattern's pacing.
        let mut source = PatternSource::new(VideoFormat {
            fps: 120,
            ..capture
        })
        .with_pixel(pixel);
        let mut encoder = Vp8Encoder::new(send.width, send.height, send.fps, kbps)?;
        let mut decoder = Vp8Decoder::new(1)?;
        let (mut frames, mut decoded, mut spread) = (0u32, 0u32, 0.0f64);
        while frames < 30 {
            let Some(frame) = source.next_frame(Duration::from_millis(100))? else {
                continue;
            };
            frames += 1;
            let picture = frame
                .into_i420()
                .context("converting the camera's picture")?
                .scaled_to(send.width, send.height);
            let Some(encoded) = encoder.encode(&picture, false)? else {
                continue;
            };
            for out in decoder.decode(&encoded.data)? {
                if (out.width, out.height) != (send.width, send.height) {
                    bail!("decoded {}x{}", out.width, out.height);
                }
                decoded += 1;
                spread = out.luma_stats().1;
            }
        }
        println!(
            "media-check camera format={pixel:?} capture={}x{} send={}x{} frames={frames} \
             decoded={decoded} luma_sd={spread:.1}",
            capture.width, capture.height, send.width, send.height
        );
        if decoded < 25 {
            bail!("only {decoded} of {frames} frames came through the encoder and decoder");
        }
        if spread < 20.0 {
            bail!("the decoded picture is a flat fill (luma sd {spread:.1}), not the pattern");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// The same checks as `--media-check`, in `cargo test`.
    #[test]
    fn the_synthetic_camera_path_encodes_and_decodes() {
        super::camera().unwrap();
    }

    #[test]
    fn echo_cancellation_passes() {
        super::echo().unwrap();
    }
}
