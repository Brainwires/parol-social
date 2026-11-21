// A small VP8 encoder shim over libvpx (BSD-3-Clause), compiled against the system headers so
// the encoder configuration struct and its ABI version always match the library (the decoder
// side is a hand-written binding in vp8.rs; the encoder's config struct is too large and
// version-dependent for that).

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_encoder.h>

typedef struct pn_vp8enc {
    vpx_codec_ctx_t ctx;
    vpx_image_t img;
    unsigned w, h;
} pn_vp8enc;

static void set_err(char *err, size_t len, const char *msg) {
    if (err && len) {
        strncpy(err, msg ? msg : "unknown error", len - 1);
        err[len - 1] = 0;
    }
}

pn_vp8enc *pn_vp8enc_new(unsigned w, unsigned h, unsigned fps, unsigned kbps, char *err,
                         size_t err_len) {
    vpx_codec_enc_cfg_t cfg;
    if (w == 0 || h == 0 || (w & 1) || (h & 1) || fps == 0) {
        set_err(err, err_len, "width and height must be even and non-zero");
        return NULL;
    }
    if (vpx_codec_enc_config_default(vpx_codec_vp8_cx(), &cfg, 0) != VPX_CODEC_OK) {
        set_err(err, err_len, "vpx_codec_enc_config_default failed");
        return NULL;
    }
    cfg.g_w = w;
    cfg.g_h = h;
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = (int)fps;
    cfg.g_threads = 2;
    cfg.g_lag_in_frames = 0;
    cfg.g_error_resilient = VPX_ERROR_RESILIENT_DEFAULT;
    cfg.rc_end_usage = VPX_CBR;
    cfg.rc_target_bitrate = kbps;
    cfg.rc_min_quantizer = 4;
    cfg.rc_max_quantizer = 56;
    cfg.rc_undershoot_pct = 100;
    cfg.rc_overshoot_pct = 15;
    cfg.rc_buf_sz = 1000;
    cfg.rc_buf_initial_sz = 500;
    cfg.rc_buf_optimal_sz = 600;
    cfg.kf_mode = VPX_KF_AUTO;
    cfg.kf_max_dist = fps * 3;

    pn_vp8enc *e = calloc(1, sizeof *e);
    if (!e) {
        set_err(err, err_len, "out of memory");
        return NULL;
    }
    if (vpx_codec_enc_init(&e->ctx, vpx_codec_vp8_cx(), &cfg, 0) != VPX_CODEC_OK) {
        set_err(err, err_len, vpx_codec_error_detail(&e->ctx) ? vpx_codec_error_detail(&e->ctx)
                                                               : vpx_codec_error(&e->ctx));
        free(e);
        return NULL;
    }
    // Real-time speed (VP8: -16..16; higher is faster).
    vpx_codec_control(&e->ctx, VP8E_SET_CPUUSED, 8);
    vpx_codec_control(&e->ctx, VP8E_SET_STATIC_THRESHOLD, 1);
    vpx_codec_control(&e->ctx, VP8E_SET_MAX_INTRA_BITRATE_PCT, 300);
    e->w = w;
    e->h = h;
    return e;
}

// Encode one I420 frame (`i420` holds Y, then U, then V, tightly packed). The encoded frame
// (one per call with these settings) is copied into `out`; `*out_len` is 0 when the encoder
// dropped the frame. Returns 0, or -1 on an encoder error, -2 when `out` is too small.
int pn_vp8enc_encode(pn_vp8enc *e, const uint8_t *i420, int64_t pts, int force_keyframe,
                     uint8_t *out, size_t out_cap, size_t *out_len, int *is_keyframe) {
    *out_len = 0;
    *is_keyframe = 0;
    if (!vpx_img_wrap(&e->img, VPX_IMG_FMT_I420, e->w, e->h, 1, (unsigned char *)i420)) {
        return -1;
    }
    vpx_enc_frame_flags_t flags = force_keyframe ? VPX_EFLAG_FORCE_KF : 0;
    if (vpx_codec_encode(&e->ctx, &e->img, pts, 1, flags, VPX_DL_REALTIME) != VPX_CODEC_OK) {
        return -1;
    }
    vpx_codec_iter_t iter = NULL;
    const vpx_codec_cx_pkt_t *pkt;
    while ((pkt = vpx_codec_get_cx_data(&e->ctx, &iter)) != NULL) {
        if (pkt->kind != VPX_CODEC_CX_FRAME_PKT) {
            continue;
        }
        if (*out_len + pkt->data.frame.sz > out_cap) {
            return -2;
        }
        memcpy(out + *out_len, pkt->data.frame.buf, pkt->data.frame.sz);
        *out_len += pkt->data.frame.sz;
        if (pkt->data.frame.flags & VPX_FRAME_IS_KEY) {
            *is_keyframe = 1;
        }
    }
    return 0;
}

void pn_vp8enc_free(pn_vp8enc *e) {
    if (e) {
        vpx_codec_destroy(&e->ctx);
        free(e);
    }
}
