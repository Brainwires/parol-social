//! A minimal libvpx VP8 decoder binding (hand-written: six functions and two structs, so no
//! bindgen and no MPL-licensed `-sys` crate). Moves to `parolnet-media` in M1.
//!
//! The layouts below follow libvpx's public headers (`vpx_codec.h`, `vpx_decoder.h`,
//! `vpx_image.h`), stable since ABI version 5 of `vpx_image_t` (libvpx 1.8 and later).

use std::ffi::{CStr, c_char, c_int, c_long, c_uint, c_void};
use std::ptr;

use crate::frame::I420Frame;

/// `VPX_DECODER_ABI_VERSION` = 3 + `VPX_CODEC_ABI_VERSION` (4 + `VPX_IMAGE_ABI_VERSION` (5)).
const VPX_DECODER_ABI_VERSION: c_int = 12;
const VPX_IMG_FMT_PLANAR: c_int = 0x100;
const VPX_IMG_FMT_I420: c_int = VPX_IMG_FMT_PLANAR | 2;

#[repr(C)]
struct VpxCodecCtx {
    name: *const c_char,
    iface: *const c_void,
    err: c_int,
    err_detail: *const c_char,
    init_flags: c_long,
    config: *const c_void,
    priv_: *mut c_void,
}

#[repr(C)]
struct VpxCodecDecCfg {
    threads: c_uint,
    w: c_uint,
    h: c_uint,
}

#[repr(C)]
struct VpxImage {
    fmt: c_int,
    cs: c_int,
    range: c_int,
    w: c_uint,
    h: c_uint,
    bit_depth: c_uint,
    d_w: c_uint,
    d_h: c_uint,
    r_w: c_uint,
    r_h: c_uint,
    x_chroma_shift: c_uint,
    y_chroma_shift: c_uint,
    planes: [*mut u8; 4],
    stride: [c_int; 4],
    bps: c_int,
    user_priv: *mut c_void,
    img_data: *mut u8,
    img_data_owner: c_int,
    self_allocd: c_int,
    fb_priv: *mut c_void,
}

unsafe extern "C" {
    fn vpx_codec_vp8_dx() -> *const c_void;
    fn vpx_codec_dec_init_ver(
        ctx: *mut VpxCodecCtx,
        iface: *const c_void,
        cfg: *const VpxCodecDecCfg,
        flags: c_long,
        ver: c_int,
    ) -> c_int;
    fn vpx_codec_decode(
        ctx: *mut VpxCodecCtx,
        data: *const u8,
        data_sz: c_uint,
        user_priv: *mut c_void,
        deadline: c_long,
    ) -> c_int;
    fn vpx_codec_get_frame(ctx: *mut VpxCodecCtx, iter: *mut *const c_void) -> *const VpxImage;
    fn vpx_codec_destroy(ctx: *mut VpxCodecCtx) -> c_int;
    fn vpx_codec_error(ctx: *const VpxCodecCtx) -> *const c_char;
    fn vpx_codec_version_str() -> *const c_char;
}

/// The linked libvpx's version string.
pub fn libvpx_version() -> String {
    // SAFETY: returns a static NUL-terminated string.
    unsafe { CStr::from_ptr(vpx_codec_version_str()) }
        .to_string_lossy()
        .into_owned()
}

/// A VP8 decoder context.
pub struct Vp8Decoder {
    ctx: Box<VpxCodecCtx>,
}

// SAFETY: the context is used from one thread at a time (it moves with the decoder).
unsafe impl Send for Vp8Decoder {}

impl Vp8Decoder {
    pub fn new(threads: u32) -> anyhow::Result<Self> {
        let mut ctx = Box::new(VpxCodecCtx {
            name: ptr::null(),
            iface: ptr::null(),
            err: 0,
            err_detail: ptr::null(),
            init_flags: 0,
            config: ptr::null(),
            priv_: ptr::null_mut(),
        });
        let cfg = VpxCodecDecCfg {
            threads,
            w: 0,
            h: 0,
        };
        // SAFETY: ctx and cfg are valid for the call; libvpx copies cfg.
        let rc = unsafe {
            vpx_codec_dec_init_ver(
                &mut *ctx,
                vpx_codec_vp8_dx(),
                &cfg,
                0,
                VPX_DECODER_ABI_VERSION,
            )
        };
        if rc != 0 {
            anyhow::bail!(
                "vpx_codec_dec_init failed ({rc}); libvpx {}",
                libvpx_version()
            );
        }
        Ok(Self { ctx })
    }

    fn last_error(&self) -> String {
        // SAFETY: ctx is initialised; vpx_codec_error returns a static string.
        unsafe { CStr::from_ptr(vpx_codec_error(&*self.ctx)) }
            .to_string_lossy()
            .into_owned()
    }

    /// Decodes one VP8 frame (a whole RTP-reassembled sample) and returns the pictures it
    /// produced (zero or one for VP8).
    pub fn decode(&mut self, data: &[u8]) -> anyhow::Result<Vec<I420Frame>> {
        // SAFETY: data outlives the call. Deadline 1 is VPX_DL_REALTIME.
        let rc = unsafe {
            vpx_codec_decode(
                &mut *self.ctx,
                data.as_ptr(),
                data.len() as c_uint,
                ptr::null_mut(),
                1,
            )
        };
        if rc != 0 {
            anyhow::bail!("vpx_codec_decode: {}", self.last_error());
        }
        let mut frames = Vec::new();
        let mut iter: *const c_void = ptr::null();
        loop {
            // SAFETY: iter starts null and is advanced by libvpx.
            let img = unsafe { vpx_codec_get_frame(&mut *self.ctx, &mut iter) };
            if img.is_null() {
                break;
            }
            // SAFETY: libvpx returns a valid image until the next decode call.
            let img = unsafe { &*img };
            if img.fmt != VPX_IMG_FMT_I420 {
                anyhow::bail!("unexpected libvpx image format {:#x}", img.fmt);
            }
            frames.push(copy_i420(img));
        }
        Ok(frames)
    }
}

fn copy_i420(img: &VpxImage) -> I420Frame {
    let width = img.d_w as usize;
    let height = img.d_h as usize;
    let chroma_w = width.div_ceil(2);
    let chroma_h = height.div_ceil(2);
    let mut frame = I420Frame::new(width as u32, height as u32);
    let planes = [
        (0usize, width, height),
        (1, chroma_w, chroma_h),
        (2, chroma_w, chroma_h),
    ];
    for (plane, w, h) in planes {
        let stride = img.stride[plane] as usize;
        let dst = frame.plane_mut(plane);
        for row in 0..h {
            // SAFETY: libvpx guarantees `h` rows of `stride` bytes per plane, `w` <= stride.
            let src = unsafe { std::slice::from_raw_parts(img.planes[plane].add(row * stride), w) };
            dst[row * w..row * w + w].copy_from_slice(src);
        }
    }
    frame
}

impl Drop for Vp8Decoder {
    fn drop(&mut self) {
        // SAFETY: the context was initialised in `new`.
        unsafe {
            vpx_codec_destroy(&mut *self.ctx);
        }
    }
}
