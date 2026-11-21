# WebKit on Linux: a track that ends while an element plays it can freeze the page

`pc-close.html` shows it without any app code. Two `RTCPeerConnection`s in one page call each other
with the mock camera and microphone; each remote stream plays in a `<video>`, each capture in a
muted `<video>`. Then the call is torn down in the order the query string names, with a line logged
before and after every browser call.

## What happens

In WebKit's GStreamer ports (WPE and WebKitGTK; seen here in the WPE build that Playwright 1.65.1
ships, `webkit-2388`, in `mcr.microsoft.com/playwright:v1.65.1-noble`), when a `MediaStreamTrack`
ends while a media element is still playing its stream, the call that ended it sometimes never
returns:

- `RTCPeerConnection.close()` (the remote tracks end, the remote `<video>` is playing them), or
- `MediaStreamTrack.stop()` (the capture ends, the self-view `<video>` is playing it).

The main thread is blocked for good: the page answers nothing (`page.evaluate` does not return), no
timer runs, and the last line logged is the one before that call.

The web process's main thread, from `gdb` on a frozen page (`?order=stop-first`, frozen in
`track.stop()`):

```
#1  pthread_mutex_lock ()                  libc
#3  gst_pad_set_active ()                  libgstreamer-1.0
#4-6  ??                                   gstreamer-1.0/libgstplayback.so
#8  gst_bus_post ()                        libgstreamer-1.0
#11 gst_element_post_message ()            libgstreamer-1.0
        (twice more up the bins)
#21 gst_element_post_message ()            libgstreamer-1.0
#22-28  ??                                 libWPEWebKit-2.0  (called from script)
```

and a streaming thread of the same element's pipeline, holding the pad's stream lock:

```
"vqueue:src"
#1  g_cond_wait ()
#2  gst_base_sink_wait_preroll ()          libgstbase-1.0
#3  gst_base_sink_do_preroll ()
... gst_pad_push () ...
```

WebKit's media-stream source element posts a message on the element's playback pipeline from the
main thread; the playback bin handles it synchronously and deactivates a pad, which needs the stream
lock of a streaming thread that is itself waiting in a sink. Neither lets go.

## What avoids it

Take the stream away from every element first (`pause()`, `srcObject = null`), and only then stop
tracks and close the connection. Measured in the container (arm64, `--cpus 4`, the machine otherwise
busy), three pages at a time, three calls per page, with a second microphone capture held by the
page (`hold=1`) as the flows do:

| `order`        | what it does                                                                                                   | pages frozen            |
| -------------- | -------------------------------------------------------------------------------------------------------------- | ----------------------- |
| `close-first`  | `pc.close()`, `track.stop()`, then `srcObject = null` (what the app did)                                       | 11 of 30                |
| `stop-first`   | `track.stop()`, `pc.close()`, then `srcObject = null`                                                          | 6 of 30                 |
| `detach-first` | `pause()` + `srcObject = null`, then `pc.close()`, `track.stop()`                                              | 0 of 30                 |
| `deferred`     | `pause()` + `srcObject = null`; a task later `track.stop()`; a task later `pc.close()` (what the app does now) | 0 of 30                 |
| `camera-only`  | no connection at all: a camera playing in an element, `track.stop()` while it plays                            | 1 of 30 (5 rounds each) |

The app's order is `deferred`: `src/engine/calls.ts` publishes the end of the call first, the store
detaches every element in the same turn (`src/platform/playback.ts`), and the engine stops the
capture and closes the connection in later tasks.

## Running it

In the Playwright container (WebKit runs on Linux only there), from `web/`:

```sh
docker run --rm --ipc=host -v "$PWD":/work -w /work/tests/e2e \
  mcr.microsoft.com/playwright:v1.65.1-noble \
  node repro/run.mjs close-first 30 3 3
```

`run.mjs <order> <pages> <rounds per page> <pages at a time>` prints, for each frozen page, whether
it still answers and its last lines, then a summary; it exits with 1 if any page froze. A busy
machine freezes more often. `REPRO_ON_FREEZE` names a shell command to run when a page freezes (for
example `gdb -p <pid> -batch -ex "thread apply all bt"` on the `WPEWebProcess` processes, in an
image that has `gdb` and with `--cap-add SYS_PTRACE`).

## What is not known

Safari on macOS and iOS does not use GStreamer; its media elements and WebRTC run on AVFoundation
and libwebrtc, so this deadlock, which is inside GStreamer's playback bins, is not expected there.
That has not been tested: no run of this page, or of the app's flows, has been made in a real
Safari.
