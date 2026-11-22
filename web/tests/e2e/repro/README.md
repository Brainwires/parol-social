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

Take the stream away from every element first (`srcObject = null`), and only then stop tracks and
close the connection. Measured in the container (arm64, `--cpus 4`, the machine otherwise busy),
three pages at a time, three calls per page, with a second microphone capture held by the page
(`hold=1`) as the flows do:

| `order`        | what it does                                                                                                   | pages frozen            |
| -------------- | -------------------------------------------------------------------------------------------------------------- | ----------------------- |
| `close-first`  | `pc.close()`, `track.stop()`, then `srcObject = null` (what the app did)                                       | 11 of 30                |
| `stop-first`   | `track.stop()`, `pc.close()`, then `srcObject = null`                                                          | 6 of 30                 |
| `detach-first` | `pause()` + `srcObject = null`, then `pc.close()`, `track.stop()`                                              | 0 of 30                 |
| `deferred`     | `pause()` + `srcObject = null`; a task later `track.stop()`; a task later `pc.close()` (what the app does now) | 0 of 30                 |
| `camera-only`  | no connection at all: a camera playing in an element, `track.stop()` while it plays                            | 1 of 30 (5 rounds each) |

`pause()` before `srcObject = null` is not what helps: `deferred` with `REPRO_PAUSE=0` (no
`pause()`) also froze 0 of 30, and that is what the app does.

The app's order is `deferred` without the pause: `src/engine/calls.ts` publishes the end of the call
first, the store detaches every element in the same turn (`src/platform/playback.ts`), and the
engine stops the capture and closes the connection in later tasks.

## A second freeze: detaching a stream around a camera switch

`camera-off` ends no track at all: the camera is switched off (`enabled = false`), its element is
detached, and the same stream is attached again 300 ms later. The page sometimes stops for good
while the stream is attached again (once, in `srcObject = null`). The main thread is inside a state
change of the element's pipeline, waiting on a condition inside WebKit, while a streaming thread of
the capture (an `appsink` handing a sample to WebKit) is in an object's destruction, also waiting on
a condition inside WebKit.

| `order`         | what it does                                                                       | pages frozen                             |
| --------------- | ---------------------------------------------------------------------------------- | ---------------------------------------- |
| `camera-off`    | `enabled = false`, `srcObject = null`, attach again; 5 rounds a page               | 1 of 40 (6 of 40 with `pause()` first)   |
| `camera-off`    | the same, 30 rounds a page                                                         | 16 of 20 (the same with `pause()` first) |
| `camera-toggle` | `enabled = false`, then `true`; the element keeps the stream; 10 rounds a page     | 0 of 37                                  |
| `camera-end`    | off and on with the element attached, `srcObject = null` 200 ms later; once a page | 0 of 150 (0 of 146 hidden meanwhile)     |

(The two five-round `camera-off` runs were made one after the other on a machine whose load kept
changing, so "more often with `pause()`" is a hint and no more. Pages that never got their capture
while other containers were being stopped answered and are not counted.)

This is the app's "Turn camera off": the self view goes away, and comes back with "Turn camera on".
In the call flow the page of the person who pressed the button froze there in 2 of 45 runs, later in
3 of 156, on a busy machine. Leaving the self view attached and hidden (`camera-toggle`) was tried
in the app first: the button no longer froze the page (0 of 43 runs), but the same person's page
then froze once in those 43 runs at the end of the call, in the detaching of the elements, which it
had not done in 260 runs before. One freeze for another, so that was dropped.

### What avoids it: let the stream go first, then switch the camera off

Two more orders, each 20 pages of 30 rounds, three pages at a time, in the same session as a new
baseline (container, arm64, `--cpus 4`, `hold=1`, no `pause()`, the machine busy with other work):

| `order`                         | what it does                                                                                                                 | pages frozen |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------ |
| `camera-off`                    | `enabled = false`, a task, `srcObject = null` (what the app did)                                                             | 15 of 20     |
| `camera-off-detach-first`       | `srcObject = null`, then `enabled = false`; `enabled = true` before the stream is attached again (what the app does now)     | 0 of 20      |
| `camera-off-detach-first&gap=1` | the same with a task between the two                                                                                         | 0 of 20      |
| `camera-off-clone`              | the element plays a clone of the camera track; off: disable the camera, detach, a task later stop the clone; on: a new clone | 0 of 20      |
| `camera-off-clone-keep`         | one clone for the whole page, only detached and attached                                                                     | 1 of 20      |

So the element must not be holding the stream at the moment its track is disabled: detached before,
nothing freezes; detached after, most pages do within 30 rounds. A clone also works when it is
stopped the safe way after each use, at the price of a second capture and of its own
stop-while-playing hazard; kept alive and merely detached and re-attached, it froze one page.

The app takes the simple one. The store detaches the self view (`StoreEnv.keepPlaying` with only the
remote stream) in the same turn in which it then tells the engine to switch the camera off, and
allows the local stream again before it tells the engine to switch it on
(`src/state/engine-store.ts`, `setCameraOff`). Measured with the app's call flow in the same
container, `--cpus 4`, three at a time, the machine busy:

| build                            | runs | froze at "Turn camera off" | other                                                                                                            |
| -------------------------------- | ---- | -------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| before (detach after disabling)  | 60   | 1                          |                                                                                                                  |
| after (detach first), two series | 120  | 0                          | 1 run failed before the button was pressed: one page's remote video showed no frame in 30 s; both pages answered |
| after, the final code, no skip   | 120  | 0                          | 1 run failed the same way, before the button was pressed; both pages answered                                    |

Together with the earlier series, "before" is 6 freezes in 261 runs; "after" is 0 in 240. The flow
no longer treats a freeze at that step as an expected failure (`KNOWN_WEBKIT_FREEZE` is gone from
`real.flows.ts`): a frozen page fails the test.

The two runs that failed "after" are another matter, seen with the machine at a load of 12 to 19:
one page's `<video>` for the other person's stream stayed at 0 by 0 for 30 seconds after the call
connected, with both pages answering and both connections up. It happens before any camera button is
pressed, and it is not a freeze. It was not seen in the 216 "before" runs of this session and the
last one; whether that is chance (2 of 240 against 0 of 216) is not known.

## Running it

In the Playwright container (WebKit runs on Linux only there), from `web/`:

```sh
docker run --rm --ipc=host -v "$PWD":/work -w /work/tests/e2e \
  mcr.microsoft.com/playwright:v1.65.1-noble \
  node repro/run.mjs close-first 30 3 3
```

`run.mjs <order> <pages> <rounds per page> <pages at a time>` prints, for each frozen page, whether
it still answers and its last lines, then a summary; it exits with 1 if any page froze. A busy
machine freezes more often. `REPRO_PAUSE=0` detaches without `pause()`. `REPRO_ON_FREEZE` names a
shell command to run when a page freezes (for example
`gdb -p <pid> -batch -ex "thread apply all bt"` on the `WPEWebProcess` processes, in an image that
has `gdb` and with `--cap-add SYS_PTRACE`).

## What is not known

Safari on macOS and iOS does not use GStreamer; its media elements and WebRTC run on AVFoundation
and libwebrtc, so this deadlock, which is inside GStreamer's playback bins, is not expected there.
That has not been tested: no run of this page, or of the app's flows, has been made in a real
Safari.
