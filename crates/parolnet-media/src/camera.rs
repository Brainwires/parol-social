//! Camera capture through `nokhwa` (AVFoundation on macOS, Media Foundation on Windows,
//! V4L2 on Linux).
//!
//! A [`Camera`] owns a capture thread: it opens the device, negotiates a mode close to the
//! wanted size and rate ([`choose_mode`]), and puts every picture the device delivers into a
//! latest-frame slot, in the pixel format the device produced. The consumer (the call's
//! encoder thread) takes the newest one through [`VideoSource::next_frame`] and converts it
//! ([`VideoFrame::into_i420`], [`crate::I420Frame::scaled_to`]); a consumer that is slower
//! than the camera simply skips pictures. Nothing here runs on a UI thread.
//!
//! Device errors (unplugged, the stream stalls, a buffer of the wrong size) end the capture
//! thread and surface as an error from `next_frame`; they never panic.
//!
//! macOS notes. Opening a camera asks the user for access the first time, and the app needs
//! `NSCameraUsageDescription` in its `Info.plist` (macOS ends a process that asks without
//! one). `nokhwa`'s AVFoundation backend asks AVFoundation for packed 4:2:2 (`yuvs`) for
//! every 4:2:0 native format and reports those as YUYV, which is the path used here; its
//! NV12 request would ask for 10-bit bi-planar buffers and read them wrongly, so NV12 modes
//! are not chosen on macOS.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use nokhwa::utils::{
    ApiBackend, CameraFormat, CameraIndex, FrameFormat, RequestedFormat, RequestedFormatType,
    Resolution,
};

use crate::MediaError;
use crate::frame::{I420Frame, VideoFrame};
use crate::source::{DeviceInfo, LatestSlot, VideoFormat, VideoSource};

/// Every format `nokhwa` may deliver; all of them are converted here.
const ALL_FORMATS: &[FrameFormat] = &[
    FrameFormat::NV12,
    FrameFormat::YUYV,
    FrameFormat::MJPEG,
    FrameFormat::RAWRGB,
    FrameFormat::RAWBGR,
    FrameFormat::GRAY,
];

/// How long the user may take to answer the operating system's camera prompt.
const ACCESS_TIMEOUT: Duration = Duration::from_secs(120);
/// How long opening the device may take once access is granted.
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
/// A camera that delivers nothing for this long is treated as gone.
const STALL: Duration = Duration::from_secs(3);

/// The pixel formats a camera mode can have, cheapest to convert first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PixelKind {
    Nv12,
    Yuyv,
    Mjpeg,
    Rgb,
    Gray,
}

/// One mode a camera offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CameraMode {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub pixel: PixelKind,
}

/// Pick the mode to capture in for a wanted picture size and rate.
///
/// In order: a size that covers the wanted one with the least excess (the exact size first;
/// another aspect ratio, which is cropped, counts as half a wanted picture of excess), else
/// the largest smaller one; then a rate at or above the wanted one, the closest first, else
/// the highest; then the cheapest pixel format. USB cameras often offer the wanted size as
/// raw YUYV at 10 fps and as MJPEG at 30: the rate decides before the format does.
pub fn choose_mode(modes: &[CameraMode], want: VideoFormat) -> Option<CameraMode> {
    let (ww, wh) = (u64::from(want.width), u64::from(want.height));
    modes
        .iter()
        .filter(|m| m.width > 0 && m.height > 0 && m.fps > 0)
        .min_by_key(|m| {
            let (w, h) = (u64::from(m.width), u64::from(m.height));
            let size = if w >= ww && h >= wh {
                let crop_cost = if w * wh == h * ww { 0 } else { ww * wh / 2 };
                (0u8, w * h - ww * wh + crop_cost)
            } else {
                // Too small: the larger the better.
                (1, u64::MAX - w * h)
            };
            let rate = if m.fps >= want.fps {
                (0u8, m.fps - want.fps)
            } else {
                (1, want.fps - m.fps)
            };
            (size, rate, m.pixel)
        })
        .copied()
}

fn pixel_kind(format: FrameFormat) -> PixelKind {
    match format {
        FrameFormat::NV12 => PixelKind::Nv12,
        FrameFormat::YUYV => PixelKind::Yuyv,
        FrameFormat::MJPEG => PixelKind::Mjpeg,
        FrameFormat::RAWRGB | FrameFormat::RAWBGR => PixelKind::Rgb,
        FrameFormat::GRAY => PixelKind::Gray,
    }
}

fn device_error(e: nokhwa::NokhwaError) -> MediaError {
    MediaError::Device(e.to_string())
}

/// The cameras the system has. Listing them does not ask for access.
pub fn cameras() -> Vec<DeviceInfo> {
    match nokhwa::query(ApiBackend::Auto) {
        Ok(list) => list
            .into_iter()
            .map(|info| DeviceInfo {
                id: info.index().as_string(),
                name: info.human_name(),
            })
            .collect(),
        Err(e) => {
            tracing::debug!("listing cameras: {e}");
            Vec::new()
        }
    }
}

/// Whether the operating system already lets this process use cameras (always true where
/// there is no such permission).
pub fn access_granted() -> bool {
    nokhwa::nokhwa_check()
}

/// Ask the operating system for camera access if it was not decided yet, and wait for the
/// user's answer. Blocks: call it off the UI thread.
pub fn request_access() -> bool {
    if nokhwa::nokhwa_check() {
        return true;
    }
    let (tx, rx) = std::sync::mpsc::sync_channel::<bool>(1);
    nokhwa::nokhwa_initialize(move |granted| {
        let _ = tx.try_send(granted);
    });
    rx.recv_timeout(ACCESS_TIMEOUT).unwrap_or(false)
}

/// Turn one of `nokhwa`'s buffers into a [`VideoFrame`], checking its size (a device that
/// pads its rows is unpadded; one whose buffer makes no sense is an error).
pub fn frame_from_buffer(
    format: FrameFormat,
    width: u32,
    height: u32,
    data: &[u8],
) -> Result<VideoFrame, MediaError> {
    let (w, h) = (width as usize, height as usize);
    if w == 0 || h == 0 {
        return Err(MediaError::Format("camera frame without a size".into()));
    }
    let short = |want: usize| {
        MediaError::Format(format!(
            "{format:?} {width}x{height}: {} bytes, expected {want}",
            data.len()
        ))
    };
    // Rows of `row` bytes, possibly padded to a longer stride.
    let packed = |row: usize| -> Result<Vec<u8>, MediaError> {
        let want = row * h;
        if data.len() == want {
            return Ok(data.to_vec());
        }
        let stride = data.len() / h;
        if data.len().is_multiple_of(h) && stride > row {
            let mut out = Vec::with_capacity(want);
            for line in data.chunks_exact(stride) {
                out.extend_from_slice(&line[..row]);
            }
            return Ok(out);
        }
        if data.len() > want {
            // Trailing bytes after a tight picture.
            return Ok(data[..want].to_vec());
        }
        Err(short(want))
    };
    match format {
        FrameFormat::YUYV => Ok(VideoFrame::Yuyv {
            width,
            height,
            data: packed(w.div_ceil(2) * 4)?,
        }),
        FrameFormat::NV12 => {
            let want = w * h + 2 * w.div_ceil(2) * h.div_ceil(2);
            if data.len() < want {
                return Err(short(want));
            }
            Ok(VideoFrame::Nv12 {
                width,
                height,
                data: data[..want].to_vec(),
            })
        }
        FrameFormat::MJPEG => {
            if data.len() < 4 || data[..2] != [0xff, 0xd8] {
                return Err(MediaError::Format("camera frame is not a JPEG".into()));
            }
            Ok(VideoFrame::Mjpeg {
                width,
                height,
                data: data.to_vec(),
            })
        }
        FrameFormat::RAWRGB => Ok(VideoFrame::Rgb24 {
            width,
            height,
            data: packed(w * 3)?,
        }),
        FrameFormat::RAWBGR => Ok(VideoFrame::Bgr24 {
            width,
            height,
            data: packed(w * 3)?,
        }),
        FrameFormat::GRAY => {
            let luma = packed(w)?;
            let mut frame = I420Frame::black(width, height);
            frame.plane_mut(0).copy_from_slice(&luma);
            Ok(VideoFrame::I420(frame))
        }
    }
}

/// A camera, capturing on its own thread.
pub struct Camera {
    slot: Arc<LatestSlot<VideoFrame>>,
    format: VideoFormat,
    label: String,
    stop: Arc<AtomicBool>,
    idle: Duration,
    /// Disconnects when the capture thread has closed the device.
    closed: std::sync::mpsc::Receiver<()>,
}

impl Camera {
    /// Open the camera with `id` (as [`DeviceInfo::id`]), or the first one, in the mode
    /// closest to `want`. Asks for camera access if the system has not decided yet, and
    /// blocks until the device delivers or fails: call it off the UI thread.
    pub fn open(id: Option<&str>, want: VideoFormat) -> Result<Self, MediaError> {
        let index = match id {
            Some(id) => match id.parse::<u32>() {
                Ok(n) => CameraIndex::Index(n),
                Err(_) => CameraIndex::String(id.to_owned()),
            },
            None => CameraIndex::Index(0),
        };
        let slot = LatestSlot::new();
        let stop = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) =
            std::sync::mpsc::sync_channel::<Result<(VideoFormat, String), MediaError>>(1);
        let (closed_tx, closed) = std::sync::mpsc::channel::<()>();
        {
            let (slot, stop) = (slot.clone(), stop.clone());
            std::thread::Builder::new()
                .name("camera".into())
                .spawn(move || {
                    capture(index, want, slot, stop, ready_tx);
                    drop(closed_tx);
                })
                .map_err(|e| MediaError::Device(format!("camera thread: {e}")))?;
        }
        match ready_rx.recv_timeout(ACCESS_TIMEOUT + OPEN_TIMEOUT) {
            Ok(Ok((format, label))) => Ok(Self {
                slot,
                format,
                label,
                stop,
                idle: Duration::ZERO,
                closed,
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                stop.store(true, Ordering::Relaxed);
                Err(MediaError::Device("the camera did not open in time".into()))
            }
        }
    }

    /// Pictures the consumer was too slow for.
    pub fn dropped(&self) -> u64 {
        self.slot.dropped()
    }
}

/// The capture thread.
fn capture(
    index: CameraIndex,
    want: VideoFormat,
    slot: Arc<LatestSlot<VideoFrame>>,
    stop: Arc<AtomicBool>,
    ready: std::sync::mpsc::SyncSender<Result<(VideoFormat, String), MediaError>>,
) {
    let opened = (|| {
        if !request_access() {
            return Err(MediaError::PermissionDenied);
        }
        let mut camera = nokhwa::Camera::new(
            index,
            RequestedFormat::with_formats(RequestedFormatType::None, ALL_FORMATS),
        )
        .map_err(device_error)?;
        let offered = camera.compatible_camera_formats().map_err(device_error)?;
        let modes: Vec<(CameraMode, CameraFormat)> = offered
            .into_iter()
            // See the module notes: NV12 is not usable through this backend on macOS.
            .filter(|f| !(cfg!(target_os = "macos") && f.format() == FrameFormat::NV12))
            .map(|f| {
                (
                    CameraMode {
                        width: f.width(),
                        height: f.height(),
                        fps: f.frame_rate(),
                        pixel: pixel_kind(f.format()),
                    },
                    f,
                )
            })
            .collect();
        let only_modes: Vec<CameraMode> = modes.iter().map(|(m, _)| *m).collect();
        if let Some(chosen) = choose_mode(&only_modes, want)
            && let Some((_, format)) = modes.iter().find(|(m, f)| {
                *m == chosen && f.resolution() == Resolution::new(chosen.width, chosen.height)
            })
        {
            // If the device refuses the mode it listed, the one it opened with stays.
            if let Err(e) = camera.set_camera_requset(RequestedFormat::with_formats(
                RequestedFormatType::Exact(*format),
                ALL_FORMATS,
            )) {
                tracing::debug!("camera mode {chosen:?}: {e}");
            }
        }
        camera.open_stream().map_err(device_error)?;
        let active = camera.camera_format();
        let format = VideoFormat {
            width: active.width(),
            height: active.height(),
            fps: active.frame_rate().max(1),
        };
        tracing::info!(
            "camera {:?}: {}x{} @{} {:?}",
            camera.info().human_name(),
            format.width,
            format.height,
            format.fps,
            active.format()
        );
        let label = camera.info().human_name();
        Ok((camera, format, label))
    })();
    let mut camera = match opened {
        Ok((camera, format, label)) => {
            if ready.send(Ok((format, label))).is_err() {
                return;
            }
            camera
        }
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };
    let mut bad = 0u32;
    while !stop.load(Ordering::Relaxed) {
        let buffer = match camera.frame() {
            Ok(b) => b,
            Err(e) => {
                slot.close(format!("camera: {e}"));
                break;
            }
        };
        let res = buffer.resolution();
        match frame_from_buffer(
            buffer.source_frame_format(),
            res.width(),
            res.height(),
            buffer.buffer(),
        ) {
            Ok(frame) => {
                bad = 0;
                slot.put(frame);
            }
            Err(e) => {
                bad += 1;
                // One odd buffer is skipped; a camera that only sends those is unusable.
                if bad >= 30 {
                    slot.close(format!("camera: {e}"));
                    break;
                }
            }
        }
    }
    let _ = camera.stop_stream();
}

impl VideoSource for Camera {
    fn format(&self) -> VideoFormat {
        self.format
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<VideoFrame>, MediaError> {
        match self.slot.take(timeout) {
            Ok(Some(frame)) => {
                self.idle = Duration::ZERO;
                Ok(Some(frame))
            }
            Ok(None) => {
                self.idle += timeout;
                if self.idle >= STALL {
                    return Err(MediaError::Device(format!(
                        "{} stopped delivering pictures",
                        self.label
                    )));
                }
                Ok(None)
            }
            Err(reason) => Err(MediaError::Device(reason)),
        }
    }

    fn label(&self) -> String {
        self.label.clone()
    }
}

impl Drop for Camera {
    fn drop(&mut self) {
        // The capture thread stops after the picture it is waiting for and closes the
        // device (the camera's light goes out). Wait for that, briefly, so the same camera
        // can be opened again right away; a thread stuck on a device that went away is
        // left behind rather than waited for.
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.closed.recv_timeout(Duration::from_millis(500));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(width: u32, height: u32, fps: u32, pixel: PixelKind) -> CameraMode {
        CameraMode {
            width,
            height,
            fps,
            pixel,
        }
    }

    #[test]
    fn the_exact_size_at_30_fps_wins() {
        let modes = [
            mode(1920, 1080, 30, PixelKind::Mjpeg),
            mode(1280, 720, 30, PixelKind::Yuyv),
            mode(640, 480, 30, PixelKind::Yuyv),
            mode(640, 360, 30, PixelKind::Yuyv),
            mode(640, 360, 60, PixelKind::Yuyv),
            mode(320, 180, 30, PixelKind::Yuyv),
        ];
        assert_eq!(
            choose_mode(&modes, VideoFormat::P360),
            Some(mode(640, 360, 30, PixelKind::Yuyv))
        );
        assert_eq!(
            choose_mode(&modes, VideoFormat::P720),
            Some(mode(1280, 720, 30, PixelKind::Yuyv))
        );
    }

    #[test]
    fn the_frame_rate_decides_before_the_pixel_format() {
        // A typical USB camera: raw 720p only at 10 fps, MJPEG at 30.
        let modes = [
            mode(1280, 720, 10, PixelKind::Yuyv),
            mode(1280, 720, 30, PixelKind::Mjpeg),
            mode(640, 480, 30, PixelKind::Yuyv),
        ];
        assert_eq!(
            choose_mode(&modes, VideoFormat::P720),
            Some(mode(1280, 720, 30, PixelKind::Mjpeg))
        );
        // Same size and rate in two formats: the cheaper conversion.
        let modes = [
            mode(640, 360, 30, PixelKind::Mjpeg),
            mode(640, 360, 30, PixelKind::Nv12),
            mode(640, 360, 30, PixelKind::Yuyv),
        ];
        assert_eq!(
            choose_mode(&modes, VideoFormat::P360).map(|m| m.pixel),
            Some(PixelKind::Nv12)
        );
    }

    #[test]
    fn without_the_exact_size_the_nearest_covering_one_is_scaled_down() {
        // No 640x360: 640x480 cropped is cheaper than 1280x720 scaled.
        let modes = [
            mode(1920, 1080, 30, PixelKind::Yuyv),
            mode(1280, 720, 30, PixelKind::Yuyv),
            mode(640, 480, 30, PixelKind::Yuyv),
            mode(320, 240, 30, PixelKind::Yuyv),
        ];
        assert_eq!(
            choose_mode(&modes, VideoFormat::P360),
            Some(mode(640, 480, 30, PixelKind::Yuyv))
        );
        // The same shape wins when the excess is comparable.
        let modes = [
            mode(800, 600, 30, PixelKind::Yuyv),
            mode(960, 540, 30, PixelKind::Yuyv),
        ];
        assert_eq!(
            choose_mode(&modes, VideoFormat::P360),
            Some(mode(960, 540, 30, PixelKind::Yuyv))
        );
        // Nothing covers: the largest there is, at the best rate below the wanted one.
        let modes = [
            mode(320, 240, 15, PixelKind::Yuyv),
            mode(320, 240, 25, PixelKind::Yuyv),
            mode(160, 120, 30, PixelKind::Yuyv),
        ];
        assert_eq!(
            choose_mode(&modes, VideoFormat::P720),
            Some(mode(320, 240, 25, PixelKind::Yuyv))
        );
        assert_eq!(choose_mode(&[], VideoFormat::P360), None);
        assert_eq!(
            choose_mode(&[mode(0, 0, 30, PixelKind::Yuyv)], VideoFormat::P360),
            None
        );
    }

    #[test]
    fn buffers_are_checked_and_unpadded() {
        // Tight YUYV.
        let f = frame_from_buffer(FrameFormat::YUYV, 4, 2, &[1; 16]).unwrap();
        assert!(matches!(f, VideoFrame::Yuyv { ref data, .. } if data.len() == 16));
        // Rows padded to 12 bytes.
        let mut padded = Vec::new();
        for row in 0..2u8 {
            padded.extend_from_slice(&[row + 1; 8]);
            padded.extend_from_slice(&[0xee; 4]);
        }
        match frame_from_buffer(FrameFormat::YUYV, 4, 2, &padded).unwrap() {
            VideoFrame::Yuyv { data, .. } => {
                assert_eq!(data.len(), 16);
                assert!(data[..8].iter().all(|b| *b == 1) && data[8..].iter().all(|b| *b == 2));
            }
            other => panic!("{other:?}"),
        }
        // Too short, of every kind.
        for format in [
            FrameFormat::YUYV,
            FrameFormat::NV12,
            FrameFormat::RAWRGB,
            FrameFormat::RAWBGR,
            FrameFormat::GRAY,
            FrameFormat::MJPEG,
        ] {
            assert!(
                frame_from_buffer(format, 640, 360, &[0; 3]).is_err(),
                "{format:?}"
            );
            assert!(
                frame_from_buffer(format, 0, 0, &[0; 64]).is_err(),
                "{format:?}"
            );
        }
        let f = frame_from_buffer(FrameFormat::NV12, 4, 2, &[7; 12]).unwrap();
        assert_eq!(f.into_i420().unwrap().plane(1), [7, 7]);
        let f = frame_from_buffer(FrameFormat::GRAY, 2, 2, &[9; 4]).unwrap();
        let gray = f.into_i420().unwrap();
        assert_eq!(gray.plane(0), [9; 4]);
        assert_eq!(gray.plane(1), [128]);
        assert!(frame_from_buffer(FrameFormat::MJPEG, 2, 2, &[0xff, 0xd8, 0xff, 0xe0]).is_ok());
        assert!(frame_from_buffer(FrameFormat::RAWRGB, 2, 2, &[5; 12]).is_ok());
    }
}
