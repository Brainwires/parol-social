# ParolNet desktop

The GPUI desktop client. By default it is the M1 chat client (UI v0 over `parolnet-app`):
contacts, pairing by QR code or code (compatible with the PWA), 1:1 end-to-end encrypted chat over
a direct data channel per contact, and the direct-path state. Status and limits:
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
| Linux | `libvpx-dev pkg-config libxkbcommon-dev libxkbcommon-x11-dev libwayland-dev libx11-xcb-dev libfontconfig-dev libvulkan1` and a Vulkan driver |
| Windows | `vcpkg install libvpx:x64-windows-static-md` (or `arm64-windows-static-md`) with `VCPKG_ROOT` set |

`VPX_LIB_DIR` (and `VPX_STATIC=1`) points the build at a libvpx of your own.

```sh
cargo build --release
cargo test
```

## Run

```sh
# the chat client (data in the platform's per-user data directory)
cargo run --release -- [--relay wss://parol.social/ws] [--data-dir DIR]
```

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
