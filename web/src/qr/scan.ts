// Reads QR codes from the camera. The browser's own BarcodeDetector where it exists and
// reads QR codes; otherwise jsQR (public/vendor/jsqr.js), loaded the first time it is needed.
// Nothing leaves the page: frames go from the <video> to a canvas to the decoder.
import { assetUrl } from "../platform/base.ts";
import { encodeQr } from "./encode.ts";

type Decode = (frame: HTMLCanvasElement) => Promise<string | null>;

type JsQr = (
  data: Uint8ClampedArray,
  width: number,
  height: number,
  options?: { inversionAttempts?: string },
) => { data: string } | null;

interface Detector {
  detect(source: CanvasImageSource): Promise<Array<{ rawValue: string }>>;
}
interface DetectorClass {
  new (options: { formats: string[] }): Detector;
  getSupportedFormats(): Promise<string[]>;
}

/** Frames are scaled down to this before decoding: enough for a code held to the camera. */
const MAX_SIDE = 720;
const INTERVAL_MS = 120;

let jsQrLoading: Promise<JsQr> | null = null;

function loadJsQr(): Promise<JsQr> {
  // A URL only known at run time: the bundler leaves this import alone. The file is a UMD
  // bundle; loaded as a module it defines `globalThis.jsQR`.
  jsQrLoading ??= import(assetUrl("vendor/jsqr.js")).then(() => {
    const decode = (globalThis as unknown as { jsQR?: JsQr }).jsQR;
    if (typeof decode !== "function") throw new Error("the QR decoder did not load");
    return decode;
  });
  jsQrLoading.catch(() => (jsQrLoading = null));
  return jsQrLoading;
}

function withJsQr(): Decode {
  return async (frame) => {
    const decode = await loadJsQr();
    const context = frame.getContext("2d", { willReadFrequently: true });
    if (!context) return null;
    const image = context.getImageData(0, 0, frame.width, frame.height);
    return decode(image.data, image.width, image.height, { inversionAttempts: "dontInvert" })
      ?.data || null;
  };
}

const PROBE = "parolnet";

/** A QR code of our own on a canvas: what a decoder that works must be able to read. */
function probeFrame(): HTMLCanvasElement {
  const matrix = encodeQr(new TextEncoder().encode(PROBE));
  const scale = 6;
  const quiet = 4;
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = (matrix.size + 2 * quiet) * scale;
  const context = canvas.getContext("2d");
  if (!context) return canvas;
  context.fillStyle = "#ffffff";
  context.fillRect(0, 0, canvas.width, canvas.height);
  context.fillStyle = "#000000";
  matrix.modules.forEach((row, y) =>
    row.forEach((dark, x) => {
      if (dark) context.fillRect((x + quiet) * scale, (y + quiet) * scale, scale, scale);
    })
  );
  return canvas;
}

/** How long a BarcodeDetector gets to prove itself before the bundled decoder is used. */
const PROBE_TIMEOUT_MS = 1500;

async function nativeDecoder(Native: DetectorClass): Promise<Decode | null> {
  if (!(await Native.getSupportedFormats()).includes("qr_code")) return null;
  const detector = new Native({ formats: ["qr_code"] });
  if ((await detector.detect(probeFrame()))[0]?.rawValue !== PROBE) return null;
  return async (frame) => (await detector.detect(frame))[0]?.rawValue || null;
}

/**
 * Which decoder this browser gets. A BarcodeDetector that says it reads QR codes is only
 * believed once it has read one, and promptly: on some platforms it exists and finds
 * nothing, or never answers.
 */
export async function chooseDecoder(): Promise<{ kind: "native" | "jsqr"; decode: Decode }> {
  const Native = (globalThis as unknown as { BarcodeDetector?: DetectorClass }).BarcodeDetector;
  if (Native) {
    const decode = await Promise.race([
      nativeDecoder(Native).catch(() => null),
      new Promise<null>((resolve) => setTimeout(() => resolve(null), PROBE_TIMEOUT_MS)),
    ]);
    if (decode) return { kind: "native", decode };
  }
  return { kind: "jsqr", decode: withJsQr() };
}

export type ScanFailure = "denied" | "no-camera" | "failed";

export interface Scanner {
  /** Stop reading and release the camera. Safe to call more than once. */
  stop(): void;
}

function failureOf(error: unknown): ScanFailure {
  const name = (error as { name?: string })?.name;
  if (name === "NotAllowedError" || name === "SecurityError") return "denied";
  if (name === "NotFoundError" || name === "OverconstrainedError") return "no-camera";
  return "failed";
}

/**
 * Show the camera in `video` and call `onText` with what each QR code says, until `stop()`.
 * Rejects with a `ScanFailure` when the camera cannot be used.
 */
export async function startScanner(
  video: HTMLVideoElement,
  onText: (text: string) => void,
): Promise<Scanner> {
  const media = navigator.mediaDevices;
  if (!media?.getUserMedia) throw "no-camera" satisfies ScanFailure;
  let stream: MediaStream;
  try {
    stream = await media.getUserMedia({
      audio: false,
      video: { facingMode: { ideal: "environment" } },
    });
  } catch (error) {
    throw failureOf(error);
  }

  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const stop = () => {
    if (stopped) return;
    stopped = true;
    clearTimeout(timer);
    // Let the element go before its tracks end: ending a track that a <video> still plays can
    // block the page in WebKit's GStreamer ports (web/tests/e2e/repro).
    video.srcObject = null;
    for (const track of stream.getTracks()) track.stop();
  };

  try {
    video.srcObject = stream;
    await video.play();
  } catch (error) {
    stop();
    throw failureOf(error);
  }

  const { decode } = await chooseDecoder();
  const frame = document.createElement("canvas");
  const tick = async () => {
    if (stopped) return;
    try {
      const { videoWidth: width, videoHeight: height } = video;
      if (video.readyState >= 2 && width > 0 && height > 0) {
        const scale = Math.min(1, MAX_SIDE / Math.max(width, height));
        frame.width = Math.round(width * scale);
        frame.height = Math.round(height * scale);
        frame.getContext("2d", { willReadFrequently: true })?.drawImage(
          video,
          0,
          0,
          frame.width,
          frame.height,
        );
        const text = await decode(frame);
        if (text && !stopped) onText(text);
      }
    } catch {
      // A frame that could not be read: try the next one.
    }
    if (!stopped) timer = setTimeout(() => void tick(), INTERVAL_MS);
  };
  void tick();
  return { stop };
}
