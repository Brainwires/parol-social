//! macOS: copy an I420 picture into an IOSurface-backed NV12 `CVPixelBuffer`, which
//! `gpui::surface()` samples on the GPU. One copy (planar U/V interleaved into the CbCr
//! plane); libvpx has no zero-copy output. VideoToolbox decode (H.264 / HEVC / VP9, M4) hands
//! over its own pixel buffers instead. M1: draw them from a `CVPixelBufferPool`.

use std::ptr::{self, NonNull};

use objc2_core_foundation::{CFDictionary, CFRetained, CFString};
use objc2_core_video::{
    CVPixelBuffer, CVPixelBufferCreate, CVPixelBufferGetBaseAddressOfPlane,
    CVPixelBufferGetBytesPerRowOfPlane, CVPixelBufferLockBaseAddress, CVPixelBufferLockFlags,
    CVPixelBufferUnlockBaseAddress, kCVPixelBufferIOSurfacePropertiesKey,
    kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, kCVReturnSuccess,
};

use crate::frame::I420Frame;

/// A retained pixel buffer that may cross to the UI thread.
pub struct PixelBuffer(pub CFRetained<CVPixelBuffer>);

// SAFETY: CoreVideo pixel buffers are reference counted with atomic retain / release and
// are documented as safe to hand between threads; we never write after publishing.
unsafe impl Send for PixelBuffer {}

impl PixelBuffer {
    pub fn from_i420(frame: &I420Frame) -> Option<Self> {
        let (w, h) = (frame.width as usize, frame.height as usize);
        let empty: CFRetained<CFDictionary<CFString, CFString>> =
            CFDictionary::from_slices(&[], &[]);
        // SAFETY: the key is a CoreVideo constant.
        let key: &CFString = unsafe { kCVPixelBufferIOSurfacePropertiesKey };
        let attrs = CFDictionary::<CFString, CFDictionary<CFString, CFString>>::from_slices(
            &[key],
            &[&*empty],
        );
        let mut out: *mut CVPixelBuffer = ptr::null_mut();
        // SAFETY: out is a valid out-pointer; attrs lives across the call.
        let rc = unsafe {
            CVPixelBufferCreate(
                None,
                w,
                h,
                kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                Some(attrs.as_opaque()),
                NonNull::from(&mut out),
            )
        };
        if rc != kCVReturnSuccess || out.is_null() {
            return None;
        }
        // SAFETY: CVPixelBufferCreate returned +1.
        let buffer = unsafe { CFRetained::from_raw(NonNull::new(out)?) };

        // SAFETY: locked for writing; the base addresses and strides are valid while locked.
        unsafe {
            if CVPixelBufferLockBaseAddress(&buffer, CVPixelBufferLockFlags(0)) != kCVReturnSuccess
            {
                return None;
            }
            let y_dst = CVPixelBufferGetBaseAddressOfPlane(&buffer, 0) as *mut u8;
            let y_stride = CVPixelBufferGetBytesPerRowOfPlane(&buffer, 0);
            let c_dst = CVPixelBufferGetBaseAddressOfPlane(&buffer, 1) as *mut u8;
            let c_stride = CVPixelBufferGetBytesPerRowOfPlane(&buffer, 1);
            let y = frame.plane(0);
            for row in 0..h {
                ptr::copy_nonoverlapping(y[row * w..].as_ptr(), y_dst.add(row * y_stride), w);
            }
            let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
            let (u, v) = (frame.plane(1), frame.plane(2));
            for row in 0..ch {
                let dst = std::slice::from_raw_parts_mut(c_dst.add(row * c_stride), cw * 2);
                for col in 0..cw {
                    dst[col * 2] = u[row * cw + col];
                    dst[col * 2 + 1] = v[row * cw + col];
                }
            }
            CVPixelBufferUnlockBaseAddress(&buffer, CVPixelBufferLockFlags(0));
        }
        Some(PixelBuffer(buffer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use objc2_core_video::{
        CVPixelBufferGetHeight, CVPixelBufferGetPixelFormatType, CVPixelBufferGetWidth,
    };

    #[test]
    fn i420_becomes_an_nv12_pixel_buffer() {
        let mut frame = I420Frame::new(6, 4);
        frame
            .plane_mut(0)
            .iter_mut()
            .enumerate()
            .for_each(|(i, v)| *v = i as u8);
        frame.plane_mut(1).fill(100);
        frame.plane_mut(2).fill(200);
        let buffer = PixelBuffer::from_i420(&frame).expect("pixel buffer").0;
        assert_eq!(CVPixelBufferGetWidth(&buffer), 6);
        assert_eq!(CVPixelBufferGetHeight(&buffer), 4);
        assert_eq!(
            CVPixelBufferGetPixelFormatType(&buffer),
            kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange
        );
        // SAFETY: read-only lock; plane pointers valid while locked.
        unsafe {
            assert_eq!(
                CVPixelBufferLockBaseAddress(&buffer, CVPixelBufferLockFlags::ReadOnly),
                kCVReturnSuccess
            );
            let y = CVPixelBufferGetBaseAddressOfPlane(&buffer, 0) as *const u8;
            let y_stride = CVPixelBufferGetBytesPerRowOfPlane(&buffer, 0);
            assert_eq!(*y.add(y_stride + 1), 7);
            let c = CVPixelBufferGetBaseAddressOfPlane(&buffer, 1) as *const u8;
            assert_eq!(
                std::slice::from_raw_parts(c, 6),
                &[100, 200, 100, 200, 100, 200]
            );
            CVPixelBufferUnlockBaseAddress(&buffer, CVPixelBufferLockFlags::ReadOnly);
        }
    }
}
