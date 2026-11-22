// The storage schema (docs/web-port/storage.md §8.7, adjusted: see docs/web-port/engine.md)
// and the two places rows are kept: IndexedDB for the browser and memory for tests. Both
// are `RawStorage`: they keep rows exactly as given. In the app the engine never sees them
// directly; `SealedStorage` (./sealed-storage.ts) sits in between and encrypts every row
// (docs/web-port/at-rest.md). Version 2 added the `vault` store, which holds the keys;
// there is no migration from the old PWA.
import type { Storage, StoreName } from "./platform.ts";
import type { DeliveryState, Direction, Verification } from "./types.ts";

export const DB_NAME = "parolnet-web";
export const DB_VERSION = 2;

/** The store that holds the storage keys (./vault.ts). Never sealed, never the engine's. */
export const VAULT_STORE = "vault";
export type RawStoreName = StoreName | typeof VAULT_STORE;

export type RawWriteOp =
  | { op: "put"; store: RawStoreName; value: unknown }
  | { op: "delete"; store: RawStoreName; key: string | number };

/** `RawStorage.write` found the row its `unlessExists` names. Nothing was written. */
export class PreconditionFailed extends Error {
  constructor() {
    super("the row already exists");
    this.name = "PreconditionFailed";
  }
}

/**
 * Rows as they are kept: `Storage` plus the `vault` store, a read of several stores in one
 * transaction, and a conditional write.
 */
export interface RawStorage extends Storage {
  get<T>(store: RawStoreName, key: string | number): Promise<T | undefined>;
  getAll<T>(store: RawStoreName): Promise<T[]>;
  /** Every row of each named store, all read in one transaction. */
  dump(stores: readonly RawStoreName[]): Promise<Map<RawStoreName, unknown[]>>;
  /**
   * Apply every operation or none. With `unlessExists`, nothing is applied and the promise
   * rejects with `PreconditionFailed` when that row exists (checked in the same transaction).
   */
  write(
    ops: readonly RawWriteOp[],
    options?: { unlessExists?: { store: RawStoreName; key: string | number } },
  ): Promise<void>;
}

/** store `identity`, key `"self"`. */
export interface IdentityRow {
  id: "self";
  /** The Ed25519 secret, hex. Never logged. */
  secretHex: string;
}

/**
 * store `identity`, key `"pairing"`: the pairing code on screen, so it survives a reload within
 * its lifetime. `pendingHex` is the wasm `export_pending_bootstrap()` blob: secret key material,
 * kept like the identity secret and deleted once the code is used, expires or is cancelled.
 */
export interface PendingPairingRow {
  id: "pairing";
  code: string;
  expiresAtMs: number;
  /** Never logged. */
  pendingHex: string;
}

/** store `sessions`, key `"blob"`: the wasm `export_sessions()` JSON, one row. */
export interface SessionsRow {
  id: "blob";
  json: string;
}

/** store `contacts`, key `peerId`. Never overwritten by incoming traffic. */
export interface ContactRow {
  peerId: string;
  name: string;
  identityKey: string | null;
  addedMs: number;
  verified: Verification;
  verifiedMs: number | null;
  /**
   * Set when this contact came out of a backup (./backup.ts): its session may be older than
   * the one the contact's device has. Removed once a connection to it has passed its check.
   */
  restoredMs?: number;
}

/** store `messages`, key `id` (allocated by the engine, increasing), index `peerId`. */
export interface MessageRow {
  id: number;
  peerId: string;
  direction: Direction;
  text: string;
  timestampMs: number;
  state: DeliveryState;
  editedMs?: number;
}

/**
 * store `outbox`, key `id` (increasing: FIFO per peer), index `peerId`.
 *
 * A `text` entry holds the message as plaintext and is encrypted when it is flushed, so a
 * queued message can be edited or taken back without touching the ratchet. A `bootstrap`
 * entry is the scanner's bootstrap-completing envelope, already encrypted at pairing.
 */
export type OutboxRow =
  | {
    id: number;
    peerId: string;
    kind: "text";
    messageId: number;
    text: string;
    createdMs: number;
  }
  | {
    id: number;
    peerId: string;
    kind: "bootstrap";
    envelopeHex: string;
    createdMs: number;
  };

/** store `contactState`, key `peerId`. */
export interface ContactStateRow {
  peerId: string;
  lastActivityMs: number;
  unread: number;
}

/** store `settings`, key `key`. */
export interface SettingRow {
  key: string;
  value: unknown;
}

export const KEY_PATHS: Record<RawStoreName, string> = {
  identity: "id",
  sessions: "id",
  contacts: "peerId",
  messages: "id",
  outbox: "id",
  contactState: "peerId",
  settings: "key",
  vault: "id",
};

/** Every store of the engine: all of them but `vault`. */
export const DATA_STORES = (Object.keys(KEY_PATHS) as RawStoreName[]).filter(
  (name): name is StoreName => name !== VAULT_STORE,
);

/** Stores with the `peerId` index. */
export const PEER_INDEXED: readonly StoreName[] = ["messages", "outbox"];

type Key = string | number;

function compareKeys(a: Key, b: Key): number {
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a) < String(b) ? -1 : String(a) > String(b) ? 1 : 0;
}

/** A copy as IndexedDB would make it. A `CryptoKey` (the vault's rows) is kept as it is. */
function cloneRow<T>(value: T): T {
  try {
    return structuredClone(value);
  } catch {
    // This runtime cannot clone a `CryptoKey`: copy the row, share the key.
    const copy = { ...(value as Record<string, unknown>) };
    for (const [k, v] of Object.entries(copy)) {
      if (v instanceof Uint8Array) copy[k] = v.slice();
    }
    return copy as T;
  }
}

/** In-memory storage for tests. Values are structured-cloned in and out, like IndexedDB. */
export class MemoryStorage implements RawStorage {
  private stores = new Map<RawStoreName, Map<Key, unknown>>();
  /** Test hook: make the next `write` fail. */
  failNextWrite = false;
  /** Test hook: how many writes were applied. */
  writes = 0;
  destroyed = false;

  private store(name: RawStoreName): Map<Key, unknown> {
    let s = this.stores.get(name);
    if (!s) this.stores.set(name, s = new Map());
    return s;
  }

  private sorted(name: RawStoreName): unknown[] {
    return [...this.store(name).entries()].sort((a, b) => compareKeys(a[0], b[0])).map((e) =>
      cloneRow(e[1])
    );
  }

  get<T>(store: RawStoreName, key: Key): Promise<T | undefined> {
    const v = this.store(store).get(key);
    return Promise.resolve(
      v === undefined ? undefined : cloneRow(v) as T,
    );
  }

  getAll<T>(store: RawStoreName): Promise<T[]> {
    return Promise.resolve(this.sorted(store) as T[]);
  }

  dump(stores: readonly RawStoreName[]): Promise<Map<RawStoreName, unknown[]>> {
    return Promise.resolve(new Map(stores.map((name) => [name, this.sorted(name)])));
  }

  getAllByPeer<T>(store: "messages" | "outbox", peerId: string): Promise<T[]> {
    const rows = this.sorted(store) as { peerId: string }[];
    return Promise.resolve(rows.filter((r) => r.peerId === peerId) as T[]);
  }

  maxKey(store: "messages" | "outbox"): Promise<number> {
    let max = 0;
    for (const k of this.store(store).keys()) {
      if (typeof k === "number" && k > max) max = k;
    }
    return Promise.resolve(max);
  }

  write(
    ops: readonly RawWriteOp[],
    options?: { unlessExists?: { store: RawStoreName; key: Key } },
  ): Promise<void> {
    if (this.failNextWrite) {
      this.failNextWrite = false;
      return Promise.reject(new Error("write failed"));
    }
    const unless = options?.unlessExists;
    if (unless && this.store(unless.store).has(unless.key)) {
      return Promise.reject(new PreconditionFailed());
    }
    for (const op of ops) {
      if (op.op === "put") {
        const key = (op.value as Record<string, Key>)[KEY_PATHS[op.store]];
        this.store(op.store).set(key, cloneRow(op.value));
      } else {
        this.store(op.store).delete(op.key);
      }
    }
    this.writes += 1;
    return Promise.resolve();
  }

  close(): void {}

  destroy(): Promise<void> {
    this.stores.clear();
    this.destroyed = true;
    return Promise.resolve();
  }
}

// ── IndexedDB ────────────────────────────────────────────────────

/** The few IndexedDB types used, so the module type-checks without the DOM library. */
interface IdbRequest<T> {
  result: T;
  error: unknown;
  onsuccess: (() => void) | null;
  onerror: (() => void) | null;
}
interface IdbObjectStore {
  get(key: Key): IdbRequest<unknown>;
  getAll(): IdbRequest<unknown[]>;
  put(value: unknown): IdbRequest<unknown>;
  delete(key: Key): IdbRequest<unknown>;
  index(name: string): { getAll(key: Key): IdbRequest<unknown[]> };
  openKeyCursor(
    range: null,
    direction: "prev",
  ): IdbRequest<{ key: Key } | null>;
  createIndex(name: string, keyPath: string): unknown;
}
interface IdbTransaction {
  objectStore(name: string): IdbObjectStore;
  oncomplete: (() => void) | null;
  onerror: (() => void) | null;
  onabort: (() => void) | null;
  error: unknown;
  abort(): void;
}
interface IdbDatabase {
  transaction(stores: string[], mode: "readonly" | "readwrite"): IdbTransaction;
  createObjectStore(name: string, options: { keyPath: string }): IdbObjectStore;
  objectStoreNames: { contains(name: string): boolean };
  close(): void;
  onversionchange: (() => void) | null;
}
interface IdbOpenRequest extends IdbRequest<IdbDatabase> {
  onupgradeneeded: (() => void) | null;
  onblocked: (() => void) | null;
}
export interface IdbFactory {
  open(name: string, version: number): IdbOpenRequest;
  deleteDatabase(
    name: string,
  ): IdbRequest<unknown> & { onblocked: (() => void) | null };
}

function request<T>(req: IdbRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(new Error("database request failed"));
  });
}

/** Rows in IndexedDB. Pass `indexedDB`; nothing is read from globals here. */
export class IdbStorage implements RawStorage {
  private constructor(
    private readonly factory: IdbFactory,
    private readonly name: string,
    private db: IdbDatabase | null,
  ) {}

  static async open(
    factory: IdbFactory,
    name: string = DB_NAME,
  ): Promise<IdbStorage> {
    const req = factory.open(name, DB_VERSION);
    req.onupgradeneeded = () => {
      // A new database, or one of an earlier version: make the stores it does not have.
      // Rows are left as they are (`Vault.open` seals a version 1 database's rows).
      const db = req.result;
      for (const store of Object.keys(KEY_PATHS) as RawStoreName[]) {
        if (db.objectStoreNames.contains(store)) continue;
        const os = db.createObjectStore(store, { keyPath: KEY_PATHS[store] });
        if ((PEER_INDEXED as readonly string[]).includes(store)) os.createIndex("peerId", "peerId");
      }
    };
    const db = await request(req);
    const storage = new IdbStorage(factory, name, db);
    // Another context deletes or upgrades the database: let go at once.
    db.onversionchange = () => storage.close();
    return storage;
  }

  private tx(
    stores: RawStoreName[],
    mode: "readonly" | "readwrite",
  ): IdbTransaction {
    if (!this.db) throw new Error("database closed");
    return this.db.transaction(stores, mode);
  }

  async get<T>(store: RawStoreName, key: Key): Promise<T | undefined> {
    const v = await request(
      this.tx([store], "readonly").objectStore(store).get(key),
    );
    return v === undefined ? undefined : v as T;
  }

  async getAll<T>(store: RawStoreName): Promise<T[]> {
    return await request(
      this.tx([store], "readonly").objectStore(store).getAll(),
    ) as T[];
  }

  async dump(stores: readonly RawStoreName[]): Promise<Map<RawStoreName, unknown[]>> {
    const tx = this.tx([...stores], "readonly");
    // Every request is made before any is awaited, so all of them are in this transaction.
    const reads = stores.map((name) => request(tx.objectStore(name).getAll()));
    const rows = await Promise.all(reads);
    return new Map(stores.map((name, i) => [name, rows[i]]));
  }

  async getAllByPeer<T>(
    store: "messages" | "outbox",
    peerId: string,
  ): Promise<T[]> {
    const os = this.tx([store], "readonly").objectStore(store);
    // An index returns its matches in primary-key order.
    return await request(os.index("peerId").getAll(peerId)) as T[];
  }

  async maxKey(store: "messages" | "outbox"): Promise<number> {
    const os = this.tx([store], "readonly").objectStore(store);
    const cursor = await request(os.openKeyCursor(null, "prev"));
    return cursor && typeof cursor.key === "number" ? cursor.key : 0;
  }

  write(
    ops: readonly RawWriteOp[],
    options?: { unlessExists?: { store: RawStoreName; key: Key } },
  ): Promise<void> {
    if (ops.length === 0) return Promise.resolve();
    const unless = options?.unlessExists;
    const stores = [...new Set([...ops.map((o) => o.store), ...(unless ? [unless.store] : [])])];
    return new Promise((resolve, reject) => {
      let tx: IdbTransaction;
      try {
        tx = this.tx(stores, "readwrite");
      } catch {
        reject(new Error("database closed"));
        return;
      }
      let refused = false;
      const fail = () =>
        reject(refused ? new PreconditionFailed() : new Error("database write failed"));
      const abort = () => {
        try {
          tx.abort();
        } catch { /* already aborted */ }
        fail();
      };
      tx.oncomplete = () => resolve();
      tx.onerror = tx.onabort = fail;
      const apply = () => {
        try {
          for (const op of ops) {
            const os = tx.objectStore(op.store);
            if (op.op === "put") os.put(op.value);
            else os.delete(op.key);
          }
        } catch {
          abort();
        }
      };
      try {
        if (!unless) {
          apply();
          return;
        }
        // The check and the writes are one transaction: no other tab gets in between.
        const check = tx.objectStore(unless.store).get(unless.key);
        check.onsuccess = () => {
          if (check.result === undefined) {
            apply();
          } else {
            refused = true;
            abort();
          }
        };
      } catch {
        abort();
      }
    });
  }

  close(): void {
    this.db?.close();
    this.db = null;
  }

  async destroy(): Promise<void> {
    this.close();
    const req = this.factory.deleteDatabase(this.name);
    // Blocked by another open connection: it goes through once that one closes (ours asks
    // them to with `versionchange`).
    req.onblocked = () => {};
    await request(req);
  }
}
