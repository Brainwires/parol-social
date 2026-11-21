//! Pictures in the form the platform draws, and the latest-frame slot between the media
//! threads and the UI. The frames themselves ([`I420Frame`]) live in `parolnet-media`.

use std::sync::{Arc, Mutex};

pub use parolnet_media::I420Frame;

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
