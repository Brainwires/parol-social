// Handing a received file to the person. Where the browser has a save dialog
// (`showSaveFilePicker`) the file is streamed into what they choose; otherwise it is a download
// through a link to an object URL, revoked afterwards. The file's content is never opened or
// shown by the app, and its type is whatever the engine's Blob says.

/** What the save dialog returns that we use. */
export interface SaveHandle {
  createWritable(): Promise<WritableStream<Uint8Array>>;
}

/** What saving needs from the page, so it can be tested with fakes. */
export interface SaveDeps {
  /** The browser's save dialog, where there is one. */
  showSaveFilePicker?: (options: { suggestedName: string }) => Promise<SaveHandle>;
  createObjectURL(blob: Blob): string;
  revokeObjectURL(url: string): void;
  /** Start a download of `url` under `name` (a link with `download`, clicked). */
  download(url: string, name: string): void;
  setTimeout(fn: () => void, ms: number): unknown;
}

/** How long an object URL lives after its download started (some browsers read it late). */
export const REVOKE_AFTER_MS = 30_000;

export type SaveOutcome =
  /** Written, or handed to the browser's downloads. */
  | "saved"
  /** The person closed the save dialog. */
  | "cancelled"
  /** There was no file to save (it is no longer on this device). */
  | "missing";

function isAbort(error: unknown): boolean {
  return typeof error === "object" && error !== null &&
    (error as { name?: unknown }).name === "AbortError";
}

/**
 * Save the file `getBlob` returns under `name`. The dialog is opened before the file is read,
 * so it still counts as the person's click.
 */
export async function saveFile(
  name: string,
  getBlob: () => Promise<Blob | null>,
  deps: SaveDeps = browserSaveDeps(),
): Promise<SaveOutcome> {
  const picker = deps.showSaveFilePicker;
  if (picker) {
    let handle: SaveHandle;
    try {
      handle = await picker({ suggestedName: name });
    } catch (error) {
      if (isAbort(error)) return "cancelled";
      throw error;
    }
    const blob = await getBlob();
    if (!blob) return "missing";
    const writable = await handle.createWritable();
    // pipeTo closes the file when the stream ends, and aborts it if reading fails.
    await blob.stream().pipeTo(writable);
    return "saved";
  }
  const blob = await getBlob();
  if (!blob) return "missing";
  const url = deps.createObjectURL(blob);
  try {
    deps.download(url, name);
  } catch (error) {
    deps.revokeObjectURL(url);
    throw error;
  }
  deps.setTimeout(() => deps.revokeObjectURL(url), REVOKE_AFTER_MS);
  return "saved";
}

/** The page's own: the save dialog where it exists, else a download link. */
export function browserSaveDeps(): SaveDeps {
  const page = globalThis as unknown as {
    showSaveFilePicker?: (options: { suggestedName: string }) => Promise<SaveHandle>;
  };
  const picker = typeof page.showSaveFilePicker === "function"
    ? page.showSaveFilePicker.bind(globalThis)
    : undefined;
  return {
    showSaveFilePicker: picker,
    createObjectURL: (blob) => URL.createObjectURL(blob),
    revokeObjectURL: (url) => URL.revokeObjectURL(url),
    download(url, name) {
      const link = document.createElement("a");
      link.href = url;
      link.download = name;
      link.rel = "noopener";
      link.hidden = true;
      document.body.append(link);
      link.click();
      link.remove();
    },
    setTimeout: (fn, ms) => setTimeout(fn, ms),
  };
}
