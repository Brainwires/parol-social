//! VP8 through the system's libvpx (BSD-3-Clause): a hand-written binding of the decoder and
//! a small C shim (`vp8enc.c`, built by `build.rs`) around the encoder.

mod dec;
mod enc;

pub use dec::{Vp8Decoder, libvpx_version};
pub use enc::{EncodedFrame, Vp8Encoder};

/// VP8 key frames have bit 0 of the first byte clear (RFC 6386 section 9.1).
pub fn is_keyframe(frame: &[u8]) -> bool {
    frame.first().is_some_and(|b| b & 1 == 0)
}
