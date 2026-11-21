# ParolNet desktop

The GPUI desktop client. By default it is the M1 client (UI v0 over `parolnet-app`): contacts,
pairing by QR code or code (compatible with the PWA), safety numbers, 1:1 end-to-end encrypted
chat over a direct data channel per contact (bound to the session by both DTLS fingerprints),
the direct-path state, and 1:1 voice / video calls: camera capture (a test pattern without a
camera), echo cancellation (AEC3), camera / microphone / speaker menus, camera off, a self-view,
and files (PNP-010): attach or drop a file onto a conversation, accept / decline / cancel, progress
in the timeline; files travel only over the direct connection and received ones go to
`Downloads/ParolNet`. The media code is `crates/parolnet-media`. Status and limits:
[docs/m1-desktop.md](../../docs/m1-desktop.md).

With `--spike` (or any spike flag) it is the M0 spike: a window that shows a VP8 stream received
through `webrtc-rs-rtc` (via `parolnet-rtc`) and decoded with libvpx. Findings:
[docs/m0-spike.md](../../docs/m0-spike.md).

This directory is its own Cargo workspace: it pins a newer toolchain (`rust-toolchain.toml`) and
needs system libraries the root workspace does not.

## Build

| OS | Needs |
| --- | --- |
| macOS | Xcode (its Metal compiler; on Xcode 26 install the Metal toolchain component) or build with `--features runtime-shaders`; `brew install libvpx pkgconf` |
| Linux | `libvpx-dev libasound2-dev clang libclang-dev pkg-config libxkbcommon-dev libxkbcommon-x11-dev libwayland-dev libx11-xcb-dev libfontconfig-dev libvulkan1` and a Vulkan driver; `perl` and `make` (the store's SQLCipher links an OpenSSL libcrypto built from source) |
| Windows | `vcpkg install libvpx:x64-windows-static-md` (or `arm64-windows-static-md`) with `VCPKG_ROOT` set; Strawberry Perl for the OpenSSL build (from Git Bash set `OPENSSL_SRC_PERL=C:/Strawberry/perl/bin/perl.exe`, its own perl cannot run OpenSSL's Configure) |

`VPX_LIB_DIR` (and `VPX_STATIC=1`, `VPX_INCLUDE_DIR` for the encoder shim
`crates/parolnet-media/src/vp8/vp8enc.c`) points the build at a libvpx of your own. A C compiler
is needed for that shim. Echo cancellation, Opus and pixel conversion are pure Rust.

On macOS the executable carries `macos/Info.plist` (camera and microphone usage strings) in its
`__TEXT,__info_plist` section; an app bundle's `Info.plist` must carry the same two keys.

```sh
cargo build --release
cargo test
```

## Run

```sh
# the chat client (data in the platform's per-user data directory, encrypted; the key is in the
# OS keychain, or with --key-storage file in a key file beside the data: weaker, for machines
# without a keychain service; a data directory keeps the kind it was created with)
cargo run --release -- [--relay wss://parol.social/ws] [--data-dir DIR] [--key-storage keychain|file]

# the call media without a window: pair with a code, video-call, report what decoded
cargo run --release -- --call-check --relay ws://HOST/ws --code CODE [--video] [--seconds 8]

# the media checks that need no network and no device: echo cancellation (ERLE) and a
# synthetic camera through conversion, scaling, libvpx encode and decode
cargo run --release -- --media-check
```

Environment: `PAROLNET_SYNTHETIC_MEDIA=1` makes the window's calls use the test pattern, a tone
and no devices (as `--call-check` always does); `PAROLNET_VIDEO=720p` sends 1280x720 instead of
640x360; `PAROLNET_AUDIO_PROCESSING=off` bypasses echo cancellation, noise suppression and gain.

`node apps/desktop/interop/desktop-call.mjs target/release/parolnet-desktop` (from the repository
root, with the relay and the bot built in the root workspace) runs `--call-check` against the
headless bot.

The spike:

```sh
# terminal 1: the window (or --headless to decode without one)
cargo run --release -- --spike --signal 127.0.0.1:8189
# terminal 2, from the repository root (npm ci once): headless Chromium sends to it
node apps/desktop/spike/send.mjs http://127.0.0.1:8189/whip 30
```

Flags: `--headless` (no window; `--frames N`, `--timeout SECS`, `--out frame.png`,
`--expect-tone HZ`), `--exit-after SECS` (quit that long after the first picture), `--bgra`
(use the `RenderImage` path on macOS too), `--bind ADDR` (the UDP socket, loopback by default).

The signaling endpoint is test scaffolding only. In ParolNet, offers and answers travel as call
signals inside the end-to-end encrypted session.

## CI

`.github/workflows/desktop-spike.yml` runs on the five desktop targets when dispatched, or on a
pull request labelled `desktop-spike`, driven by `spike/ci-run.sh` (which opens a window and
screenshots the screen: CI only).
