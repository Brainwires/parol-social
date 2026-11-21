// The media elements that play a call's streams, so they can all be let go at once, in the
// same turn in which the call ends.
//
// Why at once: in WebKit on Linux (GStreamer) a track that ends while an element is still
// playing its stream can block the page for good, inside `RTCPeerConnection.close()` or
// `MediaStreamTrack.stop()` (tests/e2e/repro has the page that shows it without the app).
// The engine publishes "ended" before it releases any media (src/engine/calls.ts); the store
// answers by detaching every element here, synchronously, and only then does the engine stop
// tracks and close the connection. Waiting for the call screen to render again would be too
// late and would depend on when rendering happens.

const playing = new Set<HTMLMediaElement>();
/** The streams the call has, once the store has said so (`keepOnly`); null before that. */
let current: readonly (MediaStream | null)[] | null = null;

/**
 * Play `stream` in `element` (null: stop playing). A stream the call no longer has is not
 * played: an effect of a render from before the call ended may ask for it afterwards.
 */
export function play(
  element: HTMLMediaElement,
  stream: MediaStream | null,
): void {
  if (!stream || (current !== null && !current.includes(stream))) {
    detach(element);
    return;
  }
  playing.add(element);
  if (element.srcObject !== stream) element.srcObject = stream;
  void element.play().catch(() => {});
}

/** Let go of the stream `element` plays. */
export function detach(element: HTMLMediaElement): void {
  playing.delete(element);
  try {
    // Not paused first: on the browser this is for, a paused pipeline made the freeze that
    // comes with attaching the stream again more likely, and made this one no rarer
    // (tests/e2e/repro).
    if (element.srcObject !== null) element.srcObject = null;
  } catch {
    // An element the browser already tore down.
  }
}

/**
 * The call's streams are now `streams` (none: the call is over). Every element playing
 * anything else is detached before this returns.
 */
export function keepOnly(streams: readonly (MediaStream | null)[]): void {
  current = streams;
  for (const element of [...playing]) {
    if (!streams.includes(element.srcObject as MediaStream | null)) {
      detach(element);
    }
  }
}
