#!/usr/bin/env bash
# CI driver for the M0 spike (desktop-spike.yml). Never run it on a developer's machine: the
# window mode opens a real window and takes a screenshot of the whole screen.
#
#   apps/desktop/spike/ci-run.sh headless <binary> <out-dir>
#   apps/desktop/spike/ci-run.sh window   <binary> <out-dir>
#
# headless: decodes 150 VP8 frames and a 1000 Hz Opus tone from headless Chromium, writes the
#           last picture to <out-dir>/frame.png and fails unless both are real.
# window:   opens the GPUI window, streams into it, screenshots the screen to
#           <out-dir>/window.png once a picture is up, and fails unless frames were presented.
set -euo pipefail

mode=$1 bin=$2 out=$3
mkdir -p "$out"
here=$(cd "$(dirname "$0")" && pwd)

wait_for() { # file pattern tries
  for _ in $(seq 1 "$3"); do
    grep -q "$2" "$1" 2>/dev/null && return 0
    sleep 0.5
  done
  echo "timed out waiting for '$2' in $1" >&2
  cat "$1" >&2 || true
  return 1
}

screenshot() {
  case "$(uname -s)" in
    Darwin) screencapture -x "$1" ;;
    Linux) import -window root "$1" ;;
    MINGW* | MSYS* | CYGWIN*)
      powershell -NoProfile -Command "
        Add-Type -AssemblyName System.Windows.Forms, System.Drawing
        \$b = [System.Windows.Forms.SystemInformation]::VirtualScreen
        \$bmp = New-Object System.Drawing.Bitmap \$b.Width, \$b.Height
        \$g = [System.Drawing.Graphics]::FromImage(\$bmp)
        \$g.CopyFromScreen(\$b.Left, \$b.Top, 0, 0, \$bmp.Size)
        \$bmp.Save('$(cygpath -w "$1")', [System.Drawing.Imaging.ImageFormat]::Png)"
      ;;
  esac
}

case "$mode" in
  headless)
    port=18189
    "$bin" --headless --signal "127.0.0.1:$port" --frames 150 --timeout 90 \
      --expect-tone 1000 --out "$out/frame.png" >"$out/receiver.log" 2>&1 &
    receiver=$!
    wait_for "$out/receiver.log" whip-endpoint 60
    node "$here/send.mjs" "http://127.0.0.1:$port/whip" 15 >"$out/sender.log" 2>&1 || true
    status=0
    wait "$receiver" || status=$?
    cat "$out/sender.log"
    grep -E "spike-(result|audio)" "$out/receiver.log"
    exit "$status"
    ;;
  window)
    port=18190
    "$bin" --signal "127.0.0.1:$port" --exit-after 8 >"$out/window.log" 2>&1 &
    app=$!
    wait_for "$out/window.log" whip-endpoint 120
    node "$here/send.mjs" "http://127.0.0.1:$port/whip" 20 >"$out/sender-window.log" 2>&1 &
    sender=$!
    wait_for "$out/window.log" "spike-window first-frame" 120
    sleep 3
    screenshot "$out/window.png"
    status=0
    wait "$app" || status=$?
    wait "$sender" || true
    cat "$out/window.log"
    grep -q "spike-window presented=[1-9]" "$out/window.log"
    exit "$status"
    ;;
  *)
    echo "usage: $0 headless|window <binary> <out-dir>" >&2
    exit 2
    ;;
esac
