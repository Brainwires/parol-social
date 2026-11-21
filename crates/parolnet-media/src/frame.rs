//! Raw media frames: audio as interleaved `f32`, video in the pixel formats cameras and
//! decoders deliver, and I420 (what the VP8 encoder takes and its decoder returns).

use crate::MediaError;

/// A block of PCM audio: interleaved `f32` samples in -1.0..=1.0.
#[derive(Clone, Debug, PartialEq)]
pub struct AudioFrame {
    pub sample_rate: u32,
    pub channels: u16,
    /// `channels` samples per sample time, interleaved.
    pub samples: Vec<f32>,
}

impl AudioFrame {
    /// A mono frame.
    pub fn mono(sample_rate: u32, samples: Vec<f32>) -> Self {
        Self {
            sample_rate,
            channels: 1,
            samples,
        }
    }

    /// Sample times in the frame (samples per channel).
    pub fn frames(&self) -> usize {
        self.samples.len() / usize::from(self.channels.max(1))
    }

    /// The frame's length in time.
    pub fn duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs_f64(
            self.frames() as f64 / f64::from(self.sample_rate.max(1)),
        )
    }

    /// Mix the channels down to one (their mean), appending to `out`.
    pub fn downmix_into(&self, out: &mut Vec<f32>) {
        downmix(&self.samples, usize::from(self.channels), out);
    }
}

/// Mix interleaved `channels`-channel audio down to mono (the channels' mean), appending.
pub fn downmix(interleaved: &[f32], channels: usize, out: &mut Vec<f32>) {
    match channels {
        0 | 1 => out.extend_from_slice(interleaved),
        n => out.extend(
            interleaved
                .chunks_exact(n)
                .map(|c| c.iter().sum::<f32>() / n as f32),
        ),
    }
}

/// One picture, I420 (planar Y, U, V; chroma halved both ways), tightly packed.
#[derive(Clone, PartialEq, Eq)]
pub struct I420Frame {
    pub width: u32,
    pub height: u32,
    data: Vec<u8>,
}

impl std::fmt::Debug for I420Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "I420Frame({}x{})", self.width, self.height)
    }
}

impl I420Frame {
    /// A frame of zeroes (dark green; see [`I420Frame::black`]).
    pub fn new(width: u32, height: u32) -> Self {
        let (w, h) = (width as usize, height as usize);
        let chroma = w.div_ceil(2) * h.div_ceil(2);
        Self {
            width,
            height,
            data: vec![0; w * h + 2 * chroma],
        }
    }

    /// A black picture (limited range: Y 16, chroma 128): what a muted camera sends.
    pub fn black(width: u32, height: u32) -> Self {
        let mut f = Self::new(width, height);
        f.plane_mut(0).fill(16);
        f.plane_mut(1).fill(128);
        f.plane_mut(2).fill(128);
        f
    }

    /// Width and height of the chroma planes.
    pub fn chroma_dims(&self) -> (usize, usize) {
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

    /// Y, U and V planes back to back (what the VP8 encoder takes).
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Plane 0 is Y, 1 is U, 2 is V.
    pub fn plane(&self, plane: usize) -> &[u8] {
        &self.data[self.plane_range(plane)]
    }

    pub fn plane_mut(&mut self, plane: usize) -> &mut [u8] {
        let range = self.plane_range(plane);
        &mut self.data[range]
    }

    /// The three planes, mutable at once.
    pub fn planes_mut(&mut self) -> (&mut [u8], &mut [u8], &mut [u8]) {
        let (u, v) = (self.plane_range(1), self.plane_range(2));
        let (y, chroma) = self.data.split_at_mut(u.start);
        let (u_plane, v_plane) = chroma.split_at_mut(v.start - u.start);
        (y, u_plane, v_plane)
    }

    /// The luma plane's mean and spread: a cheap "this is a picture, not a flat fill" check.
    pub fn luma_stats(&self) -> (f64, f64) {
        let y = self.plane(0);
        let n = y.len().max(1) as f64;
        let mean = y.iter().map(|&v| v as f64).sum::<f64>() / n;
        let var = y.iter().map(|&v| (v as f64 - mean).powi(2)).sum::<f64>() / n;
        (mean, var.sqrt())
    }

    /// The same picture as NV12 (what many cameras deliver).
    pub fn to_nv12(&self) -> VideoFrame {
        let mut data = Vec::with_capacity(self.data.len());
        data.extend_from_slice(self.plane(0));
        for (u, v) in self.plane(1).iter().zip(self.plane(2)) {
            data.push(*u);
            data.push(*v);
        }
        VideoFrame::Nv12 {
            width: self.width,
            height: self.height,
            data,
        }
    }

    /// The same picture as packed 4:2:2 YUYV (what most USB cameras deliver); each chroma
    /// row is used for two picture rows.
    pub fn to_yuyv(&self) -> VideoFrame {
        let (w, h) = (self.width as usize, self.height as usize);
        let (cw, _) = self.chroma_dims();
        let (y, u, v) = (self.plane(0), self.plane(1), self.plane(2));
        let mut data = Vec::with_capacity(cw * 4 * h);
        for row in 0..h {
            let chroma = (row / 2) * cw;
            for pair in 0..cw {
                let x = pair * 2;
                data.push(y[row * w + x]);
                data.push(u[chroma + pair]);
                // An odd width repeats its last pixel.
                data.push(y[row * w + (x + 1).min(w - 1)]);
                data.push(v[chroma + pair]);
            }
        }
        VideoFrame::Yuyv {
            width: self.width,
            height: self.height,
            data,
        }
    }

    /// This picture at `width` x `height`: cropped around its centre to the target's aspect
    /// ratio, then scaled (a 2x2 mean for an exact halving, bilinear otherwise). Returns a
    /// clone when the size already matches.
    pub fn scaled_to(&self, width: u32, height: u32) -> I420Frame {
        if (self.width, self.height) == (width, height) || self.width == 0 || self.height == 0 {
            return self.clone();
        }
        let mut out = I420Frame::new(width, height);
        if width == 0 || height == 0 {
            return out;
        }
        // The crop, in luma pixels, kept even so the chroma crop is exact.
        let (sw, sh) = (u64::from(self.width), u64::from(self.height));
        let (tw, th) = (u64::from(width), u64::from(height));
        let (crop_w, crop_h) = if sw * th > sh * tw {
            (((sh * tw / th) & !1).clamp(2.min(sw), sw), sh)
        } else {
            (sw, ((sw * th / tw) & !1).clamp(2.min(sh), sh))
        };
        let x0 = (((sw - crop_w) / 2) & !1) as usize;
        let y0 = (((sh - crop_h) / 2) & !1) as usize;
        let (crop_w, crop_h) = (crop_w as usize, crop_h as usize);

        let (src_cw, _) = self.chroma_dims();
        let (dst_cw, dst_ch) = out.chroma_dims();
        let src_w = self.width as usize;
        let (dw, dh) = (width as usize, height as usize);
        let crop_cw = crop_w.div_ceil(2);
        let crop_ch = crop_h.div_ceil(2);
        let (y, u, v) = out.planes_mut();
        scale_plane(self.plane(0), src_w, (x0, y0, crop_w, crop_h), y, (dw, dh));
        for (plane, dst) in [(1, u), (2, v)] {
            scale_plane(
                self.plane(plane),
                src_cw,
                (x0 / 2, y0 / 2, crop_cw, crop_ch),
                dst,
                (dst_cw, dst_ch),
            );
        }
        out
    }
}

/// Scale the `(x, y, w, h)` region of a plane (`stride` bytes per row) into `dst` (`dw` x `dh`,
/// tightly packed).
fn scale_plane(
    src: &[u8],
    stride: usize,
    (x0, y0, w, h): (usize, usize, usize, usize),
    dst: &mut [u8],
    (dw, dh): (usize, usize),
) {
    if w == 0 || h == 0 || dw == 0 || dh == 0 {
        return;
    }
    if w == dw && h == dh {
        for row in 0..dh {
            let s = (y0 + row) * stride + x0;
            dst[row * dw..(row + 1) * dw].copy_from_slice(&src[s..s + dw]);
        }
        return;
    }
    if w == dw * 2 && h == dh * 2 {
        for row in 0..dh {
            let a = (y0 + row * 2) * stride + x0;
            let b = a + stride;
            let out = &mut dst[row * dw..(row + 1) * dw];
            for (col, o) in out.iter_mut().enumerate() {
                let i = col * 2;
                let sum = u16::from(src[a + i])
                    + u16::from(src[a + i + 1])
                    + u16::from(src[b + i])
                    + u16::from(src[b + i + 1]);
                *o = ((sum + 2) / 4) as u8;
            }
        }
        return;
    }
    // Bilinear, 16.16 fixed point, sampling at pixel centres.
    let x_step = ((w as u64) << 16) / dw as u64;
    let y_step = ((h as u64) << 16) / dh as u64;
    for row in 0..dh {
        let sy = ((row as u64 * y_step + y_step / 2).saturating_sub(1 << 15))
            .min(((h - 1) as u64) << 16);
        let (iy, fy) = ((sy >> 16) as usize, (sy & 0xffff) as u32);
        let iy1 = (iy + 1).min(h - 1);
        let top = (y0 + iy) * stride + x0;
        let bottom = (y0 + iy1) * stride + x0;
        let out = &mut dst[row * dw..(row + 1) * dw];
        for (col, o) in out.iter_mut().enumerate() {
            let sx = ((col as u64 * x_step + x_step / 2).saturating_sub(1 << 15))
                .min(((w - 1) as u64) << 16);
            let (ix, fx) = ((sx >> 16) as usize, (sx & 0xffff) as u32);
            let ix1 = (ix + 1).min(w - 1);
            let lerp = |a: u8, b: u8, f: u32| (u32::from(a) * (65_536 - f) + u32::from(b) * f) >> 8;
            let t = lerp(src[top + ix], src[top + ix1], fx);
            let b = lerp(src[bottom + ix], src[bottom + ix1], fx);
            // t and b carry 8 fractional bits.
            let value =
                (u64::from(t) * u64::from(65_536 - fy) + u64::from(b) * u64::from(fy) + (1 << 23))
                    >> 24;
            *o = value.min(255) as u8;
        }
    }
}

/// One picture as a camera or a decoder delivers it. Every variant is tightly packed (no row
/// padding) at `width` x `height`.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum VideoFrame {
    /// Planar 4:2:0.
    I420(I420Frame),
    /// The Y plane, then one plane of interleaved U and V at half size both ways.
    Nv12 {
        width: u32,
        height: u32,
        data: Vec<u8>,
    },
    /// Packed 4:2:2, `Y0 U Y1 V` per two pixels (YUY2).
    Yuyv {
        width: u32,
        height: u32,
        data: Vec<u8>,
    },
    /// Three bytes per pixel, red first.
    Rgb24 {
        width: u32,
        height: u32,
        data: Vec<u8>,
    },
    /// Three bytes per pixel, blue first.
    Bgr24 {
        width: u32,
        height: u32,
        data: Vec<u8>,
    },
    /// One JPEG image (motion JPEG from a USB camera).
    Mjpeg {
        width: u32,
        height: u32,
        data: Vec<u8>,
    },
}

impl VideoFrame {
    /// The picture's size (for MJPEG: what the camera announced).
    pub fn size(&self) -> (u32, u32) {
        match self {
            VideoFrame::I420(f) => (f.width, f.height),
            VideoFrame::Nv12 { width, height, .. }
            | VideoFrame::Yuyv { width, height, .. }
            | VideoFrame::Rgb24 { width, height, .. }
            | VideoFrame::Bgr24 { width, height, .. }
            | VideoFrame::Mjpeg { width, height, .. } => (*width, *height),
        }
    }

    /// The format's name, for logs.
    pub fn format_name(&self) -> &'static str {
        match self {
            VideoFrame::I420(_) => "I420",
            VideoFrame::Nv12 { .. } => "NV12",
            VideoFrame::Yuyv { .. } => "YUYV",
            VideoFrame::Rgb24 { .. } => "RGB24",
            VideoFrame::Bgr24 { .. } => "BGR24",
            VideoFrame::Mjpeg { .. } => "MJPEG",
        }
    }

    /// Convert to I420 (BT.601 limited range for the RGB formats; YUV formats keep their
    /// levels). I420 and NV12 need no feature; the others need `convert`.
    pub fn into_i420(self) -> Result<I420Frame, MediaError> {
        match self {
            VideoFrame::I420(f) => Ok(f),
            VideoFrame::Nv12 {
                width,
                height,
                data,
            } => nv12_to_i420(width, height, &data),
            #[cfg(feature = "convert")]
            other => convert::to_i420(other),
            #[cfg(not(feature = "convert"))]
            other => Err(MediaError::Format(format!(
                "{} needs the `convert` feature",
                other.format_name()
            ))),
        }
    }
}

fn short_buffer(what: &str, width: u32, height: u32, got: usize, want: usize) -> MediaError {
    MediaError::Format(format!(
        "{what} {width}x{height}: {got} bytes, expected {want}"
    ))
}

fn nv12_to_i420(width: u32, height: u32, data: &[u8]) -> Result<I420Frame, MediaError> {
    let mut out = I420Frame::new(width, height);
    let luma = width as usize * height as usize;
    let (cw, ch) = out.chroma_dims();
    let want = luma + 2 * cw * ch;
    if data.len() < want {
        return Err(short_buffer("NV12", width, height, data.len(), want));
    }
    let (y, u, v) = out.planes_mut();
    y.copy_from_slice(&data[..luma]);
    for ((pair, u), v) in data[luma..want]
        .chunks_exact(2)
        .zip(u.iter_mut())
        .zip(v.iter_mut())
    {
        *u = pair[0];
        *v = pair[1];
    }
    Ok(out)
}

#[cfg(feature = "convert")]
mod convert {
    use yuv::{
        BufferStoreMut, YuvConversionMode, YuvPackedImage, YuvPlanarImage, YuvPlanarImageMut,
        YuvRange, YuvStandardMatrix,
    };

    use super::{I420Frame, VideoFrame, short_buffer};
    use crate::MediaError;

    fn err(e: impl std::fmt::Display) -> MediaError {
        MediaError::Format(e.to_string())
    }

    fn planar_mut(frame: &mut I420Frame) -> YuvPlanarImageMut<'_, u8> {
        let (width, height) = (frame.width, frame.height);
        let cw = frame.chroma_dims().0 as u32;
        let (y, u, v) = frame.planes_mut();
        YuvPlanarImageMut {
            y_plane: BufferStoreMut::Borrowed(y),
            y_stride: width,
            u_plane: BufferStoreMut::Borrowed(u),
            u_stride: cw,
            v_plane: BufferStoreMut::Borrowed(v),
            v_stride: cw,
            width,
            height,
        }
    }

    fn planar(frame: &I420Frame) -> YuvPlanarImage<'_, u8> {
        let cw = frame.chroma_dims().0 as u32;
        YuvPlanarImage {
            y_plane: frame.plane(0),
            y_stride: frame.width,
            u_plane: frame.plane(1),
            u_stride: cw,
            v_plane: frame.plane(2),
            v_stride: cw,
            width: frame.width,
            height: frame.height,
        }
    }

    fn rgb_to_i420(
        width: u32,
        height: u32,
        data: &[u8],
        bgr: bool,
    ) -> Result<I420Frame, MediaError> {
        let want = width as usize * height as usize * 3;
        if data.len() < want {
            let what = if bgr { "BGR24" } else { "RGB24" };
            return Err(short_buffer(what, width, height, data.len(), want));
        }
        let mut out = I420Frame::new(width, height);
        let convert = if bgr {
            yuv::bgr_to_yuv420
        } else {
            yuv::rgb_to_yuv420
        };
        convert(
            &mut planar_mut(&mut out),
            &data[..want],
            width * 3,
            YuvRange::Limited,
            YuvStandardMatrix::Bt601,
            YuvConversionMode::Balanced,
        )
        .map_err(err)?;
        Ok(out)
    }

    pub(super) fn to_i420(frame: VideoFrame) -> Result<I420Frame, MediaError> {
        match frame {
            VideoFrame::Yuyv {
                width,
                height,
                data,
            } => {
                // 4:2:2 pairs: an odd width still carries a whole last pair.
                let stride = (width as usize).div_ceil(2) * 4;
                let want = stride * height as usize;
                if data.len() < want {
                    return Err(short_buffer("YUYV", width, height, data.len(), want));
                }
                let mut out = I420Frame::new(width, height);
                yuv::yuyv422_to_yuv420(
                    &mut planar_mut(&mut out),
                    &YuvPackedImage {
                        yuy: &data[..want],
                        yuy_stride: stride as u32,
                        width,
                        height,
                    },
                )
                .map_err(err)?;
                Ok(out)
            }
            VideoFrame::Rgb24 {
                width,
                height,
                data,
            } => rgb_to_i420(width, height, &data, false),
            VideoFrame::Bgr24 {
                width,
                height,
                data,
            } => rgb_to_i420(width, height, &data, true),
            VideoFrame::Mjpeg { data, .. } => {
                let mut decoder = zune_jpeg::JpegDecoder::new(
                    zune_jpeg::zune_core::bytestream::ZCursor::new(&data),
                );
                let pixels = decoder.decode().map_err(err)?;
                let info = decoder
                    .info()
                    .ok_or_else(|| MediaError::Format("JPEG without a header".into()))?;
                if decoder.output_colorspace()
                    != Some(zune_jpeg::zune_core::colorspace::ColorSpace::RGB)
                {
                    return Err(MediaError::Format("JPEG did not decode to RGB".into()));
                }
                rgb_to_i420(
                    u32::from(info.width),
                    u32::from(info.height),
                    &pixels,
                    false,
                )
            }
            VideoFrame::I420(f) => Ok(f),
            VideoFrame::Nv12 {
                width,
                height,
                data,
            } => super::nv12_to_i420(width, height, &data),
        }
    }

    impl I420Frame {
        /// BGRA, 4 bytes per pixel, BT.601 limited range (what browsers' VP8 encoders send).
        pub fn to_bgra(&self) -> Vec<u8> {
            let mut out = vec![0; self.width as usize * self.height as usize * 4];
            // The buffer sizes match the frame, so the conversion cannot fail; a failure
            // would leave the picture black rather than panic.
            let _ = yuv::yuv420_to_bgra(
                &planar(self),
                &mut out,
                self.width * 4,
                YuvRange::Limited,
                YuvStandardMatrix::Bt601,
            );
            out
        }

        /// RGBA, for writing PNGs.
        pub fn to_rgba(&self) -> Vec<u8> {
            let mut out = vec![0; self.width as usize * self.height as usize * 4];
            let _ = yuv::yuv420_to_rgba(
                &planar(self),
                &mut out,
                self.width * 4,
                YuvRange::Limited,
                YuvStandardMatrix::Bt601,
            );
            out
        }
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
    fn downmix_averages_the_channels() {
        let frame = AudioFrame {
            sample_rate: 48_000,
            channels: 2,
            samples: vec![1.0, 0.0, 0.5, 0.5],
        };
        let mut mono = Vec::new();
        frame.downmix_into(&mut mono);
        assert_eq!(mono, [0.5, 0.5]);
        assert_eq!(frame.frames(), 2);
    }

    #[test]
    fn nv12_deinterleaves_chroma() {
        let data = vec![1, 2, 3, 4, /* uv */ 50, 60];
        let f = VideoFrame::Nv12 {
            width: 2,
            height: 2,
            data,
        }
        .into_i420()
        .unwrap();
        assert_eq!(f.plane(0), [1, 2, 3, 4]);
        assert_eq!(f.plane(1), [50]);
        assert_eq!(f.plane(2), [60]);
        let short = VideoFrame::Nv12 {
            width: 2,
            height: 2,
            data: vec![0; 5],
        };
        assert!(short.into_i420().is_err());
    }

    /// A gradient picture: Y rises left to right, U top to bottom, V constant.
    fn gradient(w: u32, h: u32) -> I420Frame {
        let mut f = I420Frame::new(w, h);
        let (cw, ch) = f.chroma_dims();
        let (y, u, v) = f.planes_mut();
        for (i, p) in y.iter_mut().enumerate() {
            *p = ((i % w as usize) * 255 / (w as usize - 1)) as u8;
        }
        for (i, p) in u.iter_mut().enumerate() {
            *p = ((i / cw) * 255 / (ch - 1)) as u8;
        }
        v.fill(90);
        f
    }

    #[test]
    fn halving_and_bilinear_scaling_keep_the_picture() {
        let src = gradient(1280, 720);
        for (w, h) in [(640u32, 360u32), (320, 180), (854, 480)] {
            let out = src.scaled_to(w, h);
            assert_eq!((out.width, out.height), (w, h));
            let y = out.plane(0);
            let (w, h) = (w as usize, h as usize);
            // Left edge dark, right edge bright, monotonic in between.
            let row = &y[(h / 2) * w..(h / 2 + 1) * w];
            assert!(row[0] < 4 && row[w - 1] > 251, "{} {}", row[0], row[w - 1]);
            assert!(row.windows(2).all(|p| p[0] <= p[1]));
            let (cw, ch) = out.chroma_dims();
            let u = out.plane(1);
            assert!(u[0] < 4 && u[(ch - 1) * cw] > 251);
            assert!(out.plane(2).iter().all(|&p| p == 90));
        }
    }

    #[test]
    fn scaling_crops_to_the_target_aspect() {
        // 4:3 into 16:9: rows are cropped top and bottom, the full width is kept.
        let src = gradient(640, 480);
        let out = src.scaled_to(640, 360);
        assert_eq!(out.plane(0)[0], 0);
        assert_eq!(out.plane(0)[639], 255);
        // U runs top to bottom: the crop starts 60 rows down.
        let first_u = out.plane(1)[0];
        assert!((28..=36).contains(&first_u), "{first_u}");
        // A degenerate target does not panic.
        assert_eq!(src.scaled_to(0, 0).data().len(), 0);
        assert_eq!(I420Frame::new(1, 1).scaled_to(64, 36).width, 64);
    }

    #[test]
    fn nv12_round_trips() {
        let src = gradient(64, 36);
        assert_eq!(src.to_nv12().into_i420().unwrap(), src);
    }

    #[test]
    fn black_is_limited_range_black() {
        let f = I420Frame::black(4, 2);
        assert!(f.plane(0).iter().all(|&p| p == 16));
        assert!(f.plane(1).iter().chain(f.plane(2)).all(|&p| p == 128));
    }

    #[cfg(feature = "convert")]
    mod convert {
        use super::super::*;

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
        fn yuyv_and_rgb_convert_to_i420() {
            // Two rows of two pixels: Y 100, 110 / 120, 130, U 80, V 160.
            let yuyv = VideoFrame::Yuyv {
                width: 2,
                height: 2,
                data: vec![100, 80, 110, 160, 120, 80, 130, 160],
            }
            .into_i420()
            .unwrap();
            assert_eq!(yuyv.plane(0), [100, 110, 120, 130]);
            assert_eq!(yuyv.plane(1), [80]);
            assert_eq!(yuyv.plane(2), [160]);

            // Pure red, 4x2, both byte orders.
            let rgb: Vec<u8> = [255u8, 0, 0].repeat(8);
            let bgr: Vec<u8> = [0u8, 0, 255].repeat(8);
            for frame in [
                VideoFrame::Rgb24 {
                    width: 4,
                    height: 2,
                    data: rgb,
                },
                VideoFrame::Bgr24 {
                    width: 4,
                    height: 2,
                    data: bgr,
                },
            ] {
                let f = frame.into_i420().unwrap();
                // BT.601 limited-range red is about (81, 90, 240).
                assert!(f.plane(0).iter().all(|&y| (79..=83).contains(&y)));
                assert!(f.plane(1).iter().all(|&u| (88..=92).contains(&u)));
                assert!(f.plane(2).iter().all(|&v| (238..=241).contains(&v)));
            }
            let short = VideoFrame::Yuyv {
                width: 4,
                height: 4,
                data: vec![0; 8],
            };
            assert!(short.into_i420().is_err());
            let junk = VideoFrame::Mjpeg {
                width: 4,
                height: 4,
                data: vec![1, 2, 3],
            };
            assert!(junk.into_i420().is_err());
        }

        #[test]
        fn yuyv_round_trips() {
            let mut src = I420Frame::new(8, 4);
            for (i, p) in src.plane_mut(0).iter_mut().enumerate() {
                *p = 16 + i as u8 * 3;
            }
            src.plane_mut(1)
                .copy_from_slice(&[60, 70, 80, 90, 100, 110, 120, 130]);
            src.plane_mut(2)
                .copy_from_slice(&[200, 190, 180, 170, 160, 150, 140, 130]);
            let yuyv = src.to_yuyv();
            assert_eq!(yuyv.format_name(), "YUYV");
            // Both picture rows of a pair carry the same chroma, so 4:2:0 gets it back.
            assert_eq!(yuyv.into_i420().unwrap(), src);
        }

        #[test]
        fn mjpeg_decodes_to_i420() {
            // 16x8, the left half red, the right half blue.
            let jpeg = include_bytes!("../testdata/red_blue_16x8.jpg");
            let f = VideoFrame::Mjpeg {
                // The size comes from the JPEG, not from what the camera announced.
                width: 0,
                height: 0,
                data: jpeg.to_vec(),
            }
            .into_i420()
            .unwrap();
            assert_eq!((f.width, f.height), (16, 8));
            // BT.601 limited range: red is about (81, 90, 240), blue about (41, 240, 110).
            let (y, u, v) = (f.plane(0), f.plane(1), f.plane(2));
            assert!((70..=92).contains(&y[16 * 4 + 2]), "{}", y[16 * 4 + 2]);
            assert!((30..=52).contains(&y[16 * 4 + 13]), "{}", y[16 * 4 + 13]);
            assert!(
                v[8 * 2 + 1] > 215 && u[8 * 2 + 6] > 215,
                "{} {}",
                v[17],
                u[22]
            );
        }
    }
}
