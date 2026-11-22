//! VP8 encoding through the libvpx shim in `vp8enc.c` (built by `build.rs`).

use std::ffi::{CStr, c_char, c_int, c_uint, c_void};

use crate::MediaError;
use crate::frame::I420Frame;

unsafe extern "C" {
    fn pn_vp8enc_new(
        w: c_uint,
        h: c_uint,
        fps: c_uint,
        kbps: c_uint,
        err: *mut c_char,
        err_len: usize,
    ) -> *mut c_void;
    fn pn_vp8enc_encode(
        e: *mut c_void,
        i420: *const u8,
        pts: i64,
        force_keyframe: c_int,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
        is_keyframe: *mut c_int,
    ) -> c_int;
    fn pn_vp8enc_set_bitrate(e: *mut c_void, kbps: c_uint) -> c_int;
    fn pn_vp8enc_free(e: *mut c_void);
}

/// One encoded frame.
pub struct EncodedFrame {
    pub data: Vec<u8>,
    pub keyframe: bool,
}

/// A real-time VP8 encoder for one fixed picture size.
pub struct Vp8Encoder {
    raw: *mut c_void,
    width: u32,
    height: u32,
    pts: i64,
    out: Vec<u8>,
}

// The libvpx context is used from one thread at a time (`&mut self`).
unsafe impl Send for Vp8Encoder {}

impl Vp8Encoder {
    /// `width` and `height` must be even.
    pub fn new(width: u32, height: u32, fps: u32, kbps: u32) -> Result<Self, MediaError> {
        let mut err = [0 as c_char; 256];
        // SAFETY: plain values and a writable error buffer of the given size.
        let raw = unsafe { pn_vp8enc_new(width, height, fps, kbps, err.as_mut_ptr(), err.len()) };
        if raw.is_null() {
            // SAFETY: the shim NUL-terminates the buffer it wrote.
            let msg = unsafe { CStr::from_ptr(err.as_ptr()) }.to_string_lossy();
            return Err(MediaError::Codec(format!("VP8 encoder: {msg}")));
        }
        Ok(Self {
            raw,
            width,
            height,
            pts: 0,
            out: vec![0; (width * height * 3) as usize + 4096],
        })
    }

    /// Change the target bitrate (kbit/s) from the next frame on, without a keyframe: what a
    /// call does when the congestion controller's estimate moves.
    pub fn set_bitrate(&mut self, kbps: u32) -> Result<(), MediaError> {
        // SAFETY: the context is ours; the shim validates the value.
        let rc = unsafe { pn_vp8enc_set_bitrate(self.raw, kbps) };
        if rc != 0 {
            return Err(MediaError::Codec(format!(
                "VP8 encoder: cannot set the bitrate to {kbps} kbit/s"
            )));
        }
        Ok(())
    }

    /// Encode the next frame; `None` when the rate control dropped it.
    pub fn encode(
        &mut self,
        frame: &I420Frame,
        force_keyframe: bool,
    ) -> Result<Option<EncodedFrame>, MediaError> {
        if frame.width != self.width || frame.height != self.height {
            return Err(MediaError::Format(format!(
                "frame is {}x{}, the encoder {}x{}",
                frame.width, frame.height, self.width, self.height
            )));
        }
        let (mut len, mut key) = (0usize, 0 as c_int);
        // SAFETY: `frame.data()` holds a full I420 picture of the encoder's size; `out` is
        // writable for `out.len()` bytes; the context is ours.
        let rc = unsafe {
            pn_vp8enc_encode(
                self.raw,
                frame.data().as_ptr(),
                self.pts,
                c_int::from(force_keyframe),
                self.out.as_mut_ptr(),
                self.out.len(),
                &mut len,
                &mut key,
            )
        };
        self.pts += 1;
        if rc != 0 {
            return Err(MediaError::Codec(format!("VP8 encode failed ({rc})")));
        }
        Ok((len > 0).then(|| EncodedFrame {
            data: self.out[..len].to_vec(),
            keyframe: key != 0,
        }))
    }
}

impl Drop for Vp8Encoder {
    fn drop(&mut self) {
        // SAFETY: created by pn_vp8enc_new, freed once.
        unsafe { pn_vp8enc_free(self.raw) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An IVF file (the container libvpx's tools and `rtc::media::io::ivf_reader` read).
    pub fn ivf(width: u16, height: u16, fps: u32, frames: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"DKIF");
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(b"VP80");
        out.extend_from_slice(&width.to_le_bytes());
        out.extend_from_slice(&height.to_le_bytes());
        out.extend_from_slice(&fps.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(frames.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        for (i, f) in frames.iter().enumerate() {
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(&(i as u64).to_le_bytes());
            out.extend_from_slice(f);
        }
        out
    }

    use crate::pattern::TestPattern;
    use crate::vp8::Vp8Decoder;

    #[test]
    fn encodes_a_test_pattern_the_decoder_reads_back() {
        let mut pattern = TestPattern::new(320, 240);
        let mut enc = Vp8Encoder::new(320, 240, 30, 500).unwrap();
        let mut dec = Vp8Decoder::new(1).unwrap();
        let mut decoded = 0;
        for i in 0..30 {
            let frame = pattern.next_frame();
            if let Some(e) = enc.encode(&frame, false).unwrap() {
                if i == 0 {
                    assert!(e.keyframe, "the first frame is a keyframe");
                }
                decoded += dec.decode(&e.data).unwrap().len();
            }
        }
        assert!(decoded >= 25, "decoded {decoded} of 30");
        let forced = enc.encode(&pattern.next_frame(), true).unwrap().unwrap();
        assert!(forced.keyframe);
    }

    /// The rate follows `set_bitrate` mid-stream, without a keyframe.
    #[test]
    fn the_bitrate_can_be_changed_while_encoding() {
        // A picture with enough moving detail that the rate control has to work for either
        // target: two drifting wave patterns and a little noise.
        let (mut seed, mut t) = (1u32, 0f32);
        let mut noisy = |frame: &mut I420Frame| {
            t += 1.0;
            for (i, value) in frame.plane_mut(0).iter_mut().enumerate() {
                let (x, y) = ((i % 320) as f32, (i / 320) as f32);
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let noise = (seed >> 28) as f32 - 8.0;
                let v = 128.0
                    + 60.0 * ((x + 3.0 * t) / 7.0).sin()
                    + 40.0 * ((y * 1.3 - 2.0 * t) / 5.0).sin()
                    + noise;
                *value = v.clamp(0.0, 255.0) as u8;
            }
        };
        let mut enc = Vp8Encoder::new(320, 240, 30, 1000).unwrap();
        let mut frame = I420Frame::new(320, 240);
        let mut bytes = |enc: &mut Vp8Encoder, frames: usize| -> (usize, usize) {
            let (mut total, mut keys) = (0, 0);
            for _ in 0..frames {
                noisy(&mut frame);
                if let Some(e) = enc.encode(&frame, false).unwrap() {
                    total += e.data.len();
                    keys += usize::from(e.keyframe);
                }
            }
            (total, keys)
        };
        let _ = bytes(&mut enc, 30); // the first second, with its keyframe
        let (high, _) = bytes(&mut enc, 60);
        enc.set_bitrate(100).unwrap();
        let _ = bytes(&mut enc, 30); // the rate control's buffer settling
        let (low, keys) = bytes(&mut enc, 60);
        assert_eq!(keys, 0, "no keyframe was forced by the change");
        // Two seconds each: about 250 kB at 1000 kbit/s, 25 kB at 100 kbit/s.
        assert!(high > 120_000, "{high} bytes at 1000 kbit/s");
        assert!(low < high / 3, "{low} bytes at 100 kbit/s after {high}");
        enc.set_bitrate(100).unwrap();
        assert!(enc.set_bitrate(0).is_err());
    }

    /// Writes the bot's test pattern (crates/parolnet-app/examples/testpattern.ivf):
    /// `cargo test -p parolnet-media --features vpx write_bot_ivf -- --ignored`.
    #[test]
    #[ignore]
    fn write_bot_ivf() {
        let (w, h, fps) = (160u32, 120u32, 30u32);
        let mut pattern = TestPattern::new(w, h);
        let mut enc = Vp8Encoder::new(w, h, fps, 150).unwrap();
        let mut frames = Vec::new();
        for i in 0..60 {
            let e = enc.encode(&pattern.next_frame(), i == 0).unwrap().unwrap();
            frames.push(e.data);
        }
        let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/parolnet-app/examples/testpattern.ivf");
        std::fs::write(&out, ivf(w as u16, h as u16, fps, &frames)).unwrap();
    }
}
