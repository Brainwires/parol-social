//! VP8 encoding through the libvpx shim in `vp8enc.c` (built by `build.rs`).

use std::ffi::{CStr, c_char, c_int, c_uint, c_void};

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
    pub fn new(width: u32, height: u32, fps: u32, kbps: u32) -> anyhow::Result<Self> {
        let mut err = [0 as c_char; 256];
        // SAFETY: plain values and a writable error buffer of the given size.
        let raw = unsafe { pn_vp8enc_new(width, height, fps, kbps, err.as_mut_ptr(), err.len()) };
        if raw.is_null() {
            // SAFETY: the shim NUL-terminates the buffer it wrote.
            let msg = unsafe { CStr::from_ptr(err.as_ptr()) }.to_string_lossy();
            anyhow::bail!("VP8 encoder: {msg}");
        }
        Ok(Self {
            raw,
            width,
            height,
            pts: 0,
            out: vec![0; (width * height * 3) as usize + 4096],
        })
    }

    /// Encode the next frame; `None` when the rate control dropped it.
    pub fn encode(
        &mut self,
        frame: &I420Frame,
        force_keyframe: bool,
    ) -> anyhow::Result<Option<EncodedFrame>> {
        anyhow::ensure!(
            frame.width == self.width && frame.height == self.height,
            "frame is {}x{}, the encoder {}x{}",
            frame.width,
            frame.height,
            self.width,
            self.height
        );
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
        anyhow::ensure!(rc == 0, "VP8 encode failed ({rc})");
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

    use crate::testpattern::TestPattern;
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

    /// Writes the bot's test pattern (crates/parolnet-app/examples/testpattern.ivf):
    /// `PAROLNET_WRITE_IVF=1 cargo test --features runtime-shaders write_bot_ivf -- --ignored`.
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
