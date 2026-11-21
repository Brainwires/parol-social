# M0: GPUI + webrtc-rs-rtc spike, findings and go / no-go

Date: 2026-11-20. Branch `m0/gpui-spike`. Plan: `parolnet-gpui.md`, milestone M0.

**Verdict: GO for M1**, on the pins below, with three conditions: the dispatched
`desktop-spike.yml` run must show the window on all five targets (it has run on macOS arm64
headless only so far), `webrtc-audio-processing` must build on all five pools early in M1, and
`opus-rs` must pass the encode direction (opus-rs to browser) before it carries calls.
(M1 slice 3: `webrtc-audio-processing` has no Windows build path; echo cancellation is `sonora`,
the pure-Rust port, see section 4.)

## 1. What the spike proves

`apps/desktop` receives a VP8 + Opus stream from headless Chromium through `webrtc-rs-rtc`
(driven by the new `parolnet-rtc` crate), decodes VP8 with libvpx and shows it in a GPUI window.
Signaling is a loopback WHIP-style endpoint, test scaffolding only (in the product, SDP travels
in E2EE call signals). The sender (`apps/desktop/spike/send.mjs`) draws colour bars, a moving
box and a frame counter on a canvas, plus a 1000 Hz tone, so checks assert on real pictures and
sound rather than "it looked fine".

Result on the Mac mini (macOS arm64, Chrome stable, libvpx 1.17.0), `--headless`:

```
spike-result decoded=151 packets=344 samples=151 decode_errors=0 size=640x360 luma_mean=110.8 luma_sd=63.3
spike-audio packets=293 decode_errors=0 samples=96000 peak_hz=1000 peak_share=1.00
```

ICE + DTLS + SRTP to `connected` took about 0.2 s on loopback; the first keyframe arrived after
one PLI; no decode errors, no NACKs. The decoded frame matches the canvas (bars, box, counter).

| Path | Where | State |
| --- | --- | --- |
| Engine receive (ICE, DTLS-SRTP, VP8 + Opus depacketizing, PLI) | all | verified on macOS arm64 |
| libvpx VP8 decode (hand-written FFI, six functions) | all | verified on macOS arm64 |
| I420 → full-range NV12 (`420f`, levels expanded from VP8's limited range in the copy) IOSurface `CVPixelBuffer` → `gpui::surface()` | macOS | buffer path unit-tested; on-screen in CI. GPUI's Metal surface pass accepts only `420f`: the first CI run's video-range (`420v`) buffers were refused frame by frame while the app still counted them presented, so `ci-run.sh` now fails on renderer errors |
| I420 → BGRA (`yuv` crate, SIMD) → `RenderImage` → `img()`, previous image dropped each frame | Windows, Linux (and macOS with `--bgra`) | conversion unit-tested; on-screen in CI |
| Window, latest-frame slot, ~120 Hz poll, status line (`gpui-component` `Root` + `Label`; macOS text needs `gpui-platform`'s `font-kit` feature, else GPUI draws none; Linux needs its `x11` / `wayland` features, else GPUI runs headless and the window never draws) | all | builds clean (clippy `-D warnings`) on macOS arm64; runs in CI |

No window was opened on a developer machine. `desktop-spike.yml` (dispatch, or label a PR
`desktop-spike`) builds on linux-x64, macos-arm64, macos-x64, windows-x64 and windows-arm64, runs
the unit tests and the headless check, then opens the window under Xvfb / the runner's desktop,
streams into it, screenshots the screen and uploads `spike-<target>` (frame PNG, screenshot,
logs). The jobs use GitHub's images for now; moving them to our pools (pick-runners) is M1 train
work.

Not measured yet (needs the CI run or a runner): CPU per 720p30 stream on the BGRA path, the
plan's "video cost off macOS" risk. The headless check is at 640x360.

## 2. GPUI pin

The plan said `gpui = "=0.2.2"` and `gpui-component = "=0.10.0"`. **They do not go together**:
`gpui-component` moved off the official `gpui` crate after 0.5.0; 0.6 and later depend on
`gpui-pre`, and 0.10.0 pins `gpui-pre = "=0.3.12"`. Using both would link two GPUIs with two
incompatible `App` types.

| Crate | Latest | Publisher | Notes |
| --- | --- | --- | --- |
| `gpui` | 0.2.2 (2025-10-22) | Zed team | Official, but a year old; `gpui-component` 0.4 / 0.5 are the last on it |
| `gpui-pre` | 0.3.13 (weekly) | Jason Lee (`gpui-component` / Longbridge) | Snapshot of `zed@main` (0.3.12 = zed `d2a4fb6`); platform split into `gpui-pre-platform`, `-macos`, `-linux`, `-windows`, `-wgpu` |
| `gpui-ce` | 0.3.0 | community fork | Rust 1.95+, small user base, no `gpui-component` |

**Chosen: `gpui-pre = "=0.3.12"`, `gpui-pre-platform = "=0.3.12"`, `gpui-component = "=0.10.0"`,
`Cargo.lock` committed** (`apps/desktop/Cargo.toml`). Why: it is the only pair `gpui-component`
supports, it is current Zed code (fixes since 0.2.2 included), and it builds the same three
platform backends `gpui-component`'s own CI ships. 0.3.12 rather than 0.3.13 because
`gpui-component` 0.10.0 pins it exactly.

Consequences:
- **Toolchain.** `gpui-pre` uses `cfg_select!` and needs Rust 1.95+. The desktop app is therefore
  its own workspace (`apps/desktop`, root `exclude`) with `rust-toolchain.toml` at 1.99.1; the
  root workspace keeps 1.92 / MSRV 1.91 and does not see GPUI's system dependencies.
- **Supply chain.** `gpui-pre` is republished from Zed by one maintainer, not by Zed. Exact pins,
  the lockfile and reviewing each upgrade's diff against the named Zed commit contain that; the
  fallback stays the plan's: one exact git `rev` of `zed-industries/zed` (plus a matching
  `gpui-component` rev).
- **Linux renders through wgpu now** (`gpui-pre-wgpu`; Blade is gone upstream). Plan 3.1's "gpui
  renders through Metal, Blade and DirectX, not wgpu" is out of date: on Linux a custom YUV
  element could be a wgpu shader, and `gpui-pre-wgpu` already has a surfaces pipeline. Worth
  re-checking before the M4 GPU element item.
- **macOS builds need Xcode's Metal compiler** (Xcode 26: the separately installed Metal
  toolchain), or the app's `runtime-shaders` feature, which compiles the shaders at launch.
- **Licences.** GPUI brings three MPL-2.0 crates: `cbindgen` (build tool only), `dwrote`
  (Windows fonts) and `option-ext`. MPL is file-level copyleft and fine to link; they are named
  exceptions in `apps/desktop/deny.toml`, and nothing else may use MPL.

## 3. Engine pin

`rtc` from `Brainwires/webrtc-rs-rtc`, tag `v0.22.0+brainwires.1`, as a git dependency in the root
`Cargo.toml` (and through `parolnet-rtc` in the desktop lock). It resolves cleanly; it raised
`bytes` to 1.12, `log` to 0.4.35, `libc` and `rcgen` in the root lock. Its DTLS / SRTP provider is
ring (default `crypto-ring`), which CLAUDE.md invariant 6 now scopes away from the E2EE layer.

**Where `brainwires.2` matters** (merged as PR #12, not tagged yet: codec-less send encodings,
`sendEncodings` RTX, rejected remote sections):
- **Sending video (M1).** RTX on send encodings is how a sender repairs loss for a browser
  receiver; the desktop's camera send path needs it.
- **Rejected m-sections.** A browser offer with media the answerer does not want (a data-only
  connection receiving an audio + video offer, or audio declined) depends on correct rejected
  sections; the spike sidesteps it by accepting both.
- **Simulcast send (E3, M2)** builds on the send-encoding changes.
Bump the tag in one place (root `Cargo.toml`, then `cargo update -p rtc` in both workspaces) when
`v0.22.0+brainwires.2` exists. (Done: M1 pins `v0.22.0+brainwires.3`.) E1 (renegotiation rebinding, camera on / off mid-call) looks to start on the
fork's `fix/set-direction-renegotiation` branch and is the next engine item M1 waits on.

Engine log noise seen in the spike (not errors): `discard success message ... no such remote`
before the remote candidate is known (peer-reflexive learning), and DTLS's `server_name` default
warning.

## 4. Component go / no-go

| Component | Licence | Verdict | Evidence | Fallback |
| --- | --- | --- | --- | --- |
| **opus-rs** 0.1.42 (pure Rust) | BSD-3-Clause | **GO for decode; encode to be proven in M1** | Decodes Chromium's libopus stream with 0 errors; the decoded 1000 Hz tone carries all the energy (Goertzel, 20 Hz bins) | `audiopus` (libopus, BSD; ISC bindings) |
| **webrtc-audio-processing** 2.1.0 (AEC3, C++) | BSD-3-Clause + Google patent grant; bundled third-party parts permissive (pffft, Ooura, Olesen FFT, Dijkstra sqrt); abseil Apache-2.0 when bundled. **No GPL / LGPL anywhere** (checked the crate sources) | **NO-GO (M1, slice 3): replaced by `sonora`.** The build condition failed on paper for Windows | Licence fine (cargo-deny passes it with the desktop's config, warning only about the missing SPDX field). `bundled` builds on macOS arm64 (38 s, Homebrew meson / ninja / abseil). Its `build.rs` shells out to `meson`, `ninja`, `cp -a`, `nm --defined-only --format=posix` and `rust-objcopy`, looks for `lib*.a`, passes `-std=c++17`, and runs bindgen: no MSVC path, and its README lists none, so Windows x64 / arm64 would need our own build of the C++ library | - |
| **sonora** 0.3.0 (AEC3, noise suppression, AGC2, high-pass: WebRTC's audio processing module ported to Rust) | BSD-3-Clause | **GO** | Pure Rust, MSRV 1.91, no build script beyond cargo, maintained (0.1.0 2026-02, 0.3.0 2026-11). On our echo test it measures 67.5 dB ERLE (far end alone), 8.6 dB in double talk and -1.9 dB on the near-end tone; the C++ module on the same signal: 53.2 / 7.7 / -1.7 dB (docs/m1-desktop.md, "Echo cancellation, measured") | The C++ module built by us per target; speexdsp-style cancellers are clearly weaker and not considered |
| **nokhwa** 0.10.11 | Apache-2.0 | **GO, conditional; macOS is the weak target** | Licence fine; maintained (2026-05). Used with `default-features = false` (its MJPEG decoder is mozjpeg, C; we decode with `zune-jpeg`). Builds on macOS arm64; Linux needs libclang (bindgen for the V4L2 binding). Reading its AVFoundation backend: it copies `CVPixelBufferGetBaseAddress` for `CVPixelBufferGetDataSize` bytes without plane or stride handling, reports 4:2:0 native formats as YUYV and asks AVFoundation for packed `yuvs` (which works), and its NV12 request asks for 10-bit bi-planar (which would not): `parolnet-media` uses the YUYV path only on macOS, checks every buffer's size, and does its own mode selection (`Closest` returns nothing when the exact size is missing). Its `frame()` blocks forever when a camera is unplugged on macOS; a stalled camera is reported after 3 s and its thread left behind. It pulls `block` 0.1.6, which a future Rust will reject. Camera capture can't run on CI runners or the dev machine: synthetic sources in tests, plus the manual checklist | Per-OS capture: AVFoundation (`objc2-av-foundation`), Media Foundation (`windows`), V4L2 / PipeWire. Likely for macOS first |
| **scap** (`zed-scap` 0.0.8-zed) | MIT | **GO (M3)** | It is what `gpui-pre`'s own `screen-capture` feature uses on Linux and Windows; macOS uses ScreenCaptureKit inside `gpui-pre-macos` | `gpui-pre`'s screen-capture API directly |
| **gpui-component** 0.10.0 | Apache-2.0 | **GO** | Builds with `default-features = false`; `Root`, `Label` used in the spike; the heavy parts (tree-sitter, code editor, speech) are opt-in features | Plain GPUI elements (we own the views either way) |
| **libvpx** (system) | BSD-3-Clause | **GO** | Decode verified. Linked from the system: Homebrew, `libvpx-dev`, vcpkg `*-windows-static-md`. Hand-written FFI (no bindgen, no MPL `env-libvpx-sys`) | `vp8-decoder` (pure Rust, new and unvetted) only if linking becomes a problem |

Codec2 (`codec2` crate) is **LGPL-2.1**, which the licence gate refuses. It is now behind the
opt-in `codec2` feature of `parolnet-core` (off by default) and leaves with PNP-011 in M1.

## 5. What builds where (as of this commit)

| Target | Root workspace | `apps/desktop` |
| --- | --- | --- |
| macOS arm64 (Mac mini) | `cargo check --workspace --all-targets`; `parolnet-rtc` tests; `parolnet-core` `core_tests` with and without `codec2`; MSRV 1.91 check of `parolnet-rtc` + `parolnet-core`; clippy | build, clippy `-D warnings`, unit tests (incl. the CVPixelBuffer path), headless Chromium end to end |
| Linux x64, macOS x64, Windows x64 / arm64 | CI (`ci.yml`, ubuntu) | `desktop-spike.yml`, not run yet. A local cross-check for Linux was not possible (ring needs a target C toolchain) |

## 6. Repositioning done in M0

README rewritten, CLAUDE.md updated (overview, invariants 3 and 6, licence and pinning policy),
IMPLEMENTATION_STATUS.md updated, THREAT_MODEL.md 1.0 (outline: adversaries, non-goals, the
metadata statement, `hardened` in an appendix), ROADMAP.md / STRATEGIES.md / threat model 0.2
archived under `docs/archive/`, the `cargo-deny` licence gate in CI, and a `mesh` feature on
`parolnet-core`.

**Not done: the `hardened` feature.** The relay's `relay_node`, `handshake` and `pool` modules are
built on `onion`, so gating onion circuits, bridges and traffic shaping is a restructuring of
`parolnet-relay` and the relay server, with the conformance suite's PNP-004 / PNP-006 clauses
following it. It needs its own design pass; scheduled for M1.
