// Where received files are kept while they arrive (PNP-010): two implementations of
// `FileStore`. A file is stored as a sequence of segments, each written once from front to
// back, so nothing ever rewrites or copies what is already there and the finished file is a
// `Blob` over the segments, not a buffer in memory.
//
// - `OpfsFileStore`: the origin private file system. Segments survive a reload, so a
//   transfer continues where it stopped. Needs `FileSystemFileHandle.createWritable`.
// - `MemoryFileStore`: `Blob`s (the browser may spill large ones to disk). Lost on reload:
//   the transfer then starts again from the first record.
//
// Neither sees a file's plaintext: the engine seals every segment before it is written
// (./sealed-files.ts; docs/web-port/at-rest.md, "Received files"), and what `readSegment`
// and `blob` return is that ciphertext. What is stored is removed when the transfer is
// removed, when its contact is removed, by "delete all data" and by a restore from a backup.
import type { FileStore, SegmentWriter } from "./platform.ts";

/** In-memory store (tests, and browsers without a writable OPFS). */
export class MemoryFileStore implements FileStore {
  readonly persistent = false;
  private readonly files = new Map<string, Blob[]>();
  /** Test hook: make the next `write` fail (a full disk). */
  failNextWrite = false;

  segments(id: string): Promise<number> {
    return Promise.resolve(this.files.get(id)?.length ?? 0);
  }

  async readSegment(id: string, index: number): Promise<Uint8Array> {
    const blob = this.files.get(id)?.[index];
    if (!blob) throw new Error("no such segment");
    return new Uint8Array(await blob.arrayBuffer());
  }

  writer(id: string, index: number): Promise<SegmentWriter> {
    let list = this.files.get(id);
    if (!list) this.files.set(id, list = []);
    list.length = Math.min(list.length, index);
    if (list.length !== index) return Promise.reject(new Error("segments must be contiguous"));
    const parts: Uint8Array<ArrayBuffer>[] = [];
    const segments = list;
    return Promise.resolve({
      write: (chunk: Uint8Array): Promise<void> => {
        if (this.failNextWrite) {
          this.failNextWrite = false;
          return Promise.reject(new Error("no space"));
        }
        // The chunk is a view of wasm memory or of a message: keep a copy.
        parts.push(new Uint8Array(chunk));
        return Promise.resolve();
      },
      close: (): Promise<void> => {
        segments[index] = new Blob(parts);
        parts.length = 0;
        return Promise.resolve();
      },
      abort: (): Promise<void> => {
        parts.length = 0;
        return Promise.resolve();
      },
    });
  }

  blob(id: string, count: number, type: string): Promise<Blob> {
    const list = this.files.get(id) ?? [];
    if (list.length < count) return Promise.reject(new Error("segments are missing"));
    return Promise.resolve(new Blob(list.slice(0, count), { type }));
  }

  remove(id: string): Promise<void> {
    this.files.delete(id);
    return Promise.resolve();
  }

  clear(): Promise<void> {
    this.files.clear();
    return Promise.resolve();
  }
}

// The parts of the File System API used here (lib.dom lacks some of them in Deno's types).
interface OpfsWritable {
  write(data: Uint8Array<ArrayBuffer>): Promise<void>;
  close(): Promise<void>;
  abort(): Promise<void>;
}
interface OpfsFile {
  getFile(): Promise<Blob>;
  createWritable?(): Promise<OpfsWritable>;
}
interface OpfsDir {
  getDirectoryHandle(name: string, options?: { create?: boolean }): Promise<OpfsDir>;
  getFileHandle(name: string, options?: { create?: boolean }): Promise<OpfsFile>;
  removeEntry(name: string, options?: { recursive?: boolean }): Promise<void>;
}

/** The directory inside the origin private file system that holds every transfer's parts. */
const ROOT = "parolnet-transfers";

type OpfsRoot = { getDirectory?(): Promise<unknown> } | undefined;

const pageStorage = (): OpfsRoot =>
  (globalThis as { navigator?: { storage?: OpfsRoot } }).navigator?.storage;

/**
 * Remove everything the transfers keep in the origin private file system, without a store
 * and without the engine: for "delete all data" on a locked device, and after a restore
 * from a backup (the rows that held the files' keys are gone then). Never rejects.
 */
export async function clearStoredFiles(storage: OpfsRoot = pageStorage()): Promise<void> {
  try {
    if (typeof storage?.getDirectory !== "function") return;
    const top = await storage.getDirectory() as OpfsDir;
    await top.removeEntry(ROOT, { recursive: true });
  } catch { /* nothing stored, or no OPFS here */ }
}

/** Segments in OPFS: `parolnet-transfers/<transfer id>/<index>`. */
export class OpfsFileStore implements FileStore {
  readonly persistent = true;

  private constructor(private readonly root: OpfsDir) {}

  /**
   * The store, or null where the browser cannot write OPFS files from a page (no
   * `navigator.storage.getDirectory`, no `createWritable`, or a context that refuses it).
   */
  static async open(storage: OpfsRoot = pageStorage()): Promise<OpfsFileStore | null> {
    try {
      if (typeof storage?.getDirectory !== "function") return null;
      const top = await storage.getDirectory() as OpfsDir;
      const root = await top.getDirectoryHandle(ROOT, { create: true });
      // Probe: some engines expose the directory but not writable streams.
      const probe = await root.getFileHandle(".probe", { create: true });
      if (typeof probe.createWritable !== "function") return null;
      const w = await probe.createWritable();
      await w.close();
      await root.removeEntry(".probe");
      return new OpfsFileStore(root);
    } catch {
      return null;
    }
  }

  private async dir(id: string, create: boolean): Promise<OpfsDir | null> {
    if (!/^[0-9a-f]{32}$/.test(id)) throw new Error("bad transfer id");
    try {
      return await this.root.getDirectoryHandle(id, { create });
    } catch {
      return null;
    }
  }

  async segments(id: string): Promise<number> {
    const dir = await this.dir(id, false);
    if (!dir) return 0;
    let n = 0;
    for (;; n++) {
      try {
        await dir.getFileHandle(String(n));
      } catch {
        return n;
      }
    }
  }

  async readSegment(id: string, index: number): Promise<Uint8Array> {
    const dir = await this.dir(id, false);
    if (!dir) throw new Error("no such segment");
    const file = await (await dir.getFileHandle(String(index))).getFile();
    return new Uint8Array(await file.arrayBuffer());
  }

  async writer(id: string, index: number): Promise<SegmentWriter> {
    const dir = await this.dir(id, true);
    if (!dir) throw new Error("cannot create the transfer's directory");
    // Anything from `index` on is from an attempt that did not finish its segment.
    for (let n = index;; n++) {
      try {
        await dir.removeEntry(String(n));
      } catch {
        break;
      }
    }
    const handle = await dir.getFileHandle(String(index), { create: true });
    if (!handle.createWritable) throw new Error("no writable streams");
    const w = await handle.createWritable();
    return {
      // A copy: the chunk is a view the caller may reuse, and the stream takes its time.
      write: (chunk: Uint8Array) => w.write(new Uint8Array(chunk)),
      close: () => w.close(),
      abort: async () => {
        try {
          await w.abort();
        } catch { /* already closed */ }
        try {
          await dir.removeEntry(String(index));
        } catch { /* nothing there */ }
      },
    };
  }

  async blob(id: string, count: number, type: string): Promise<Blob> {
    const dir = await this.dir(id, false);
    if (!dir) throw new Error("segments are missing");
    const parts: Blob[] = [];
    for (let n = 0; n < count; n++) {
      parts.push(await (await dir.getFileHandle(String(n))).getFile());
    }
    return new Blob(parts, { type });
  }

  async remove(id: string): Promise<void> {
    try {
      await this.root.removeEntry(id, { recursive: true });
    } catch { /* nothing stored */ }
  }

  clear(): Promise<void> {
    return clearStoredFiles();
  }
}
