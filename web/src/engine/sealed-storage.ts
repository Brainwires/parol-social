// The engine's `Storage`, encrypted at rest: every row is sealed on its way into
// `RawStorage` and opened on its way out (./vault.ts; docs/web-port/at-rest.md).
//
// One operation runs at a time. WebCrypto is asynchronous and an IndexedDB transaction
// cannot wait for it, so a write seals its rows first and then applies them in one
// transaction; the queue keeps a change of keys (which reads and rewrites everything) from
// running between the two.
import type { Storage, StoreName, WriteOp } from "./platform.ts";
import { DATA_STORES, KEY_PATHS, type RawStorage, type RawWriteOp } from "./storage.ts";
import { type Vault, VaultError } from "./vault.ts";

type Key = string | number;

function compareKeys(a: Key, b: Key): number {
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a) < String(b) ? -1 : String(a) > String(b) ? 1 : 0;
}

/** Every row of every store of the engine, opened. */
export type Rows = Record<StoreName, unknown[]>;

export class SealedStorage implements Storage {
  private tail: Promise<unknown> = Promise.resolve();
  private frozen = false;

  constructor(private readonly vault: Vault) {
    vault.exclusive = (fn) => this.run(fn);
  }

  private get raw(): RawStorage {
    return this.vault.raw;
  }

  /** Run `fn` after everything queued before it. */
  private run<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.tail.then(fn, fn);
    this.tail = next.catch(() => {});
    return next;
  }

  /** In the order of the rows' own keys, as `Storage.getAll` promises. */
  private async openAll<T>(store: StoreName, sealed: unknown[]): Promise<T[]> {
    const sealer = this.vault.sealer;
    const rows = await Promise.all(sealed.map((row) => sealer.open<T>(store, row)));
    const column = KEY_PATHS[store];
    return rows.sort((a, b) =>
      compareKeys((a as Record<string, Key>)[column], (b as Record<string, Key>)[column])
    );
  }

  get<T>(store: StoreName, key: Key): Promise<T | undefined> {
    return this.run(async () => {
      const sealer = this.vault.sealer;
      const sealed = await this.raw.get(store, await sealer.storedKey(store, key));
      return sealed === undefined ? undefined : await sealer.open<T>(store, sealed);
    });
  }

  getAll<T>(store: StoreName): Promise<T[]> {
    return this.run(async () => this.openAll<T>(store, await this.raw.getAll(store)));
  }

  getAllByPeer<T>(store: "messages" | "outbox", peerId: string): Promise<T[]> {
    return this.run(async () => {
      const tag = await this.vault.sealer.storedKey(store, peerId);
      return this.openAll<T>(store, await this.raw.getAllByPeer(store, tag as string));
    });
  }

  maxKey(store: "messages" | "outbox"): Promise<number> {
    return this.run(() => this.raw.maxKey(store));
  }

  write(ops: readonly WriteOp[]): Promise<void> {
    return this.run(async () => {
      if (this.frozen) throw new VaultError("State", "this database was replaced");
      const sealer = this.vault.sealer;
      const sealed: RawWriteOp[] = [];
      for (const op of ops) {
        sealed.push(
          op.op === "put"
            ? { op: "put", store: op.store, value: await sealer.seal(op.store, op.value) }
            : { op: "delete", store: op.store, key: await sealer.storedKey(op.store, op.key) },
        );
      }
      await this.raw.write(sealed);
    });
  }

  /** Every row of the engine, as of one moment (one transaction). */
  snapshot(): Promise<Rows> {
    return this.run(async () => {
      const kept = await this.raw.dump(DATA_STORES);
      const out = {} as Rows;
      for (const store of DATA_STORES) {
        out[store] = await this.openAll(store, kept.get(store) ?? []);
      }
      return out;
    });
  }

  /**
   * Replace everything the engine keeps by `rows`, in one transaction, and refuse every
   * write after it: an engine still running on the old rows must not write over the new
   * ones. The caller reloads the page.
   */
  replaceAll(rows: Partial<Rows>): Promise<void> {
    return this.run(async () => {
      const sealer = this.vault.sealer;
      const kept = await this.raw.dump(DATA_STORES);
      const ops: RawWriteOp[] = [];
      for (const store of DATA_STORES) {
        const column = KEY_PATHS[store];
        for (const old of kept.get(store) ?? []) {
          ops.push({ op: "delete", store, key: (old as Record<string, Key>)[column] });
        }
      }
      for (const store of DATA_STORES) {
        for (const row of rows[store] ?? []) {
          ops.push({ op: "put", store, value: await sealer.seal(store, row) });
        }
      }
      await this.raw.write(ops);
      this.frozen = true;
    });
  }

  close(): void {
    this.raw.close();
  }

  destroy(): Promise<void> {
    return this.vault.destroy();
  }
}
