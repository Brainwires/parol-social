//! Decoded pictures and the latest-frame slot between the media thread and the UI.

use std::sync::{Arc, Mutex};

use yuv::{YuvPlanarImage, YuvRange, YuvStandardMatrix};

/// One decoded picture, I420 (planar Y, U, V; chroma halved both ways), tightly packed.
#[derive(Clone)]
pub struct I420Frame {
    pub width: u32,
    pub height: u32,
    data: Vec<u8>,
}

impl I420Frame {
    pub fn new(width: u32, height: u32) -> Self {
        let (w, h) = (width as usize, height as usize);
        let chroma = w.div_ceil(2) * h.div_ceil(2);
        Self {
            width,
            height,
            data: vec![0; w * h + 2 * chroma],
        }
    }

    fn chroma_dims(&self) -> (usize, usize) {
        (
            (self.width as usize).div_ceil(2),
            (self.height as usize).div_ceil(2),
        )
    }

    fn plane_range(&self, plane: usize) -> std::ops::Range<usize> {
        let luma = self.width as usize * self.height as usize;
        let (cw, ch) = self.chroma_dims();
        let chroma = cw * ch;
        match plane {
            0 => 0..luma,
            1 => luma..luma + chroma,
            _ => luma + chroma..luma + 2 * chroma,
        }
    }

    pub fn plane(&self, plane: usize) -> &[u8] {
        &self.data[self.plane_range(plane)]
    }

    pub fn plane_mut(&mut self, plane: usize) -> &mut [u8] {
        let range = self.plane_range(plane);
        &mut self.data[range]
    }

    fn planar(&self) -> YuvPlanarImage<'_, u8> {
        let (cw, _) = self.chroma_dims();
        YuvPlanarImage {
            y_plane: self.plane(0),
            y_stride: self.width,
            u_plane: self.plane(1),
            u_stride: cw as u32,
            v_plane: self.plane(2),
            v_stride: cw as u32,
            width: self.width,
            height: self.height,
        }
    }

    /// BGRA, 4 bytes per pixel, BT.601 limited range (what browsers' VP8 encoders send).
    pub fn to_bgra(&self) -> Vec<u8> {
        let mut out = vec![0; self.width as usize * self.height as usize * 4];
        yuv::yuv420_to_bgra(
            &self.planar(),
            &mut out,
            self.width * 4,
            YuvRange::Limited,
            YuvStandardMatrix::Bt601,
        )
        .expect("buffer sizes match the frame");
        out
    }

    /// RGBA, for writing PNGs.
    pub fn to_rgba(&self) -> Vec<u8> {
        let mut out = vec![0; self.width as usize * self.height as usize * 4];
        yuv::yuv420_to_rgba(
            &self.planar(),
            &mut out,
            self.width * 4,
            YuvRange::Limited,
            YuvStandardMatrix::Bt601,
        )
        .expect("buffer sizes match the frame");
        out
    }

    /// The luma plane's mean and spread: a cheap "this is a picture, not a flat fill" check.
    pub fn luma_stats(&self) -> (f64, f64) {
        let y = self.plane(0);
        let n = y.len().max(1) as f64;
        let mean = y.iter().map(|&v| v as f64).sum::<f64>() / n;
        let var = y.iter().map(|&v| (v as f64 - mean).powi(2)).sum::<f64>() / n;
        (mean, var.sqrt())
    }
}

/// What the UI shows: the newest picture, already in the form the platform draws.
pub enum Presentable {
    /// macOS: an IOSurface-backed NV12 pixel buffer for `gpui::surface()`.
    #[cfg(target_os = "macos")]
    Surface(crate::macos::PixelBuffer),
    /// Elsewhere: BGRA pixels for a `RenderImage`.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Bgra {
        width: u32,
        height: u32,
        pixels: Vec<u8>,
    },
}

impl Presentable {
    /// Converts on the media thread, so the UI thread only uploads.
    pub fn from_frame(frame: &I420Frame, force_bgra: bool) -> Self {
        #[cfg(target_os = "macos")]
        if !force_bgra && let Some(buffer) = crate::macos::PixelBuffer::from_i420(frame) {
            return Presentable::Surface(buffer);
        }
        let _ = force_bgra;
        Presentable::Bgra {
            width: frame.width,
            height: frame.height,
            pixels: frame.to_bgra(),
        }
    }
}

#[derive(Default)]
struct SlotInner {
    latest: Option<Presentable>,
    sequence: u64,
    status: String,
    width: u32,
    height: u32,
}

/// The latest-frame slot: the media thread overwrites, the UI takes. A late frame is simply
/// replaced, never queued.
#[derive(Clone, Default)]
pub struct FrameSlot(Arc<Mutex<SlotInner>>);

impl FrameSlot {
    pub fn publish(&self, frame: Presentable, width: u32, height: u32) {
        let mut inner = self.0.lock().unwrap();
        inner.latest = Some(frame);
        inner.sequence += 1;
        inner.width = width;
        inner.height = height;
    }

    pub fn set_status(&self, status: impl Into<String>) {
        self.0.lock().unwrap().status = status.into();
    }

    /// (frames published so far, status line, last size)
    pub fn info(&self) -> (u64, String, u32, u32) {
        let inner = self.0.lock().unwrap();
        (
            inner.sequence,
            inner.status.clone(),
            inner.width,
            inner.height,
        )
    }

    pub fn take(&self) -> Option<Presentable> {
        self.0.lock().unwrap().latest.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn odd_sizes_round_chroma_up() {
        let frame = I420Frame::new(5, 3);
        assert_eq!(frame.plane(0).len(), 15);
        assert_eq!(frame.plane(1).len(), 6);
        assert_eq!(frame.plane(2).len(), 6);
    }

    #[test]
    fn limited_range_white_and_black_convert_to_bgra() {
        let mut frame = I420Frame::new(2, 2);
        frame.plane_mut(0).copy_from_slice(&[235, 235, 16, 16]);
        frame.plane_mut(1).fill(128);
        frame.plane_mut(2).fill(128);
        let bgra = frame.to_bgra();
        assert!(
            bgra[..3].iter().all(|&c| c >= 250),
            "white: {:?}",
            &bgra[..4]
        );
        assert!(
            bgra[8..11].iter().all(|&c| c <= 5),
            "black: {:?}",
            &bgra[8..12]
        );
        assert_eq!(bgra[3], 255);
        let (_, spread) = frame.luma_stats();
        assert!(spread > 100.0);
    }

    #[test]
    fn the_slot_keeps_only_the_newest_picture() {
        let slot = FrameSlot::default();
        for n in 0..3u8 {
            slot.publish(
                Presentable::Bgra {
                    width: 1,
                    height: 1,
                    pixels: vec![n, 0, 0, 255],
                },
                1,
                1,
            );
        }
        let (sequence, ..) = slot.info();
        assert_eq!(sequence, 3);
        match slot.take() {
            Some(Presentable::Bgra { pixels, .. }) => assert_eq!(pixels[0], 2),
            _ => panic!("expected the last picture"),
        }
        assert!(slot.take().is_none());
    }
}
