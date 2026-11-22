// The browser's implementations of the engine's platform interfaces. This is the only
// module of the engine that touches browser globals, and it reads each one at call time.
import type {
  Clock,
  Fetch,
  InstanceLock,
  Logger,
  MediaDevices,
  PeerConfig,
  PeerConnection,
  PeerConnectionFactory,
  Platform,
  Random,
  Sha256,
  Socket,
  SocketFactory,
  Storage,
  WasmApi,
} from "./platform.ts";
import { OpfsFileStore } from "./files.ts";
import { SealedStorage } from "./sealed-storage.ts";
import { DB_NAME, type IdbFactory, IdbStorage } from "./storage.ts";
import { EngineError } from "./types.ts";
import { Vault, type VaultCrypto } from "./vault.ts";

// deno-lint-ignore no-explicit-any
const g = globalThis as any;

/**
 * `RTCPeerConnection` is looked up on `globalThis` at every call, never captured: test
 * drivers wrap the constructor to observe connections.
 */
export const browserPeerConnections: PeerConnectionFactory = (
  config: PeerConfig,
) => new g.RTCPeerConnection(config) as unknown as PeerConnection;

export const browserSockets: SocketFactory = (url: string) =>
  new g.WebSocket(url) as unknown as Socket;

export const browserClock: Clock = {
  now: () => Date.now(),
  setTimeout: (fn, ms) => g.setTimeout(fn, ms),
  clearTimeout: (handle) => g.clearTimeout(handle),
};

export const browserRandom: Random = {
  next: () => Math.random(),
  bytes: (n) => g.crypto.getRandomValues(new Uint8Array(n)),
};

/** No credentials, no referrer, never cached: the request carries nothing but its URL. */
export const browserFetch: Fetch = (url, init) =>
  g.fetch(url, {
    signal: init?.signal,
    credentials: "omit",
    referrerPolicy: "no-referrer",
    cache: "no-store",
  });

export const browserSha256: Sha256 = async (data) =>
  new Uint8Array(await g.crypto.subtle.digest("SHA-256", data));

export const consoleLogger: Logger = {
  debug: () => {},
  info: (...args) => g.console.log(...args),
  warn: (...args) => g.console.warn(...args),
};

/** Capture through `navigator.mediaDevices`, with small video (the old PWA's 320×240). */
export const browserMedia: MediaDevices = {
  getUserMedia: (constraints) =>
    g.navigator.mediaDevices.getUserMedia({
      audio: constraints.audio,
      video: constraints.video === true ? { width: 320, height: 240 } : constraints.video,
    }),
};

/**
 * One engine per database, across tabs, through the Web Locks API. Without that API the
 * lock is always granted.
 */
export function browserLock(name = `${DB_NAME}-engine`): InstanceLock {
  let release: (() => void) | null = null;
  return {
    acquire() {
      const locks = g.navigator?.locks;
      if (!locks) return Promise.resolve(true);
      return new Promise<boolean>((resolve) => {
        locks.request(name, { ifAvailable: true }, (lock: unknown) => {
          if (lock === null) {
            resolve(false);
            return undefined;
          }
          resolve(true);
          return new Promise<void>((done) => (release = done));
        }).catch(() => resolve(true));
      });
    },
    release() {
      release?.();
      release = null;
    },
  };
}

const WASM_EXPORTS: readonly (keyof WasmApi)[] = [
  "initialize",
  "initialize_from_key",
  "export_secret_key",
  "get_peer_id",
  "get_public_key",
  "sign_bytes",
  "envelope_encode",
  "envelope_decode",
  "trial_decrypt",
  "has_session",
  "export_sessions",
  "import_sessions",
  "channel_binding_body",
  "channel_binding_verify",
  "generate_qr_payload",
  "process_scanned_qr",
  "safety_number",
  "version",
  "pnp010_new_offer",
  "pnp010_encode_offer",
  "pnp010_encode_control",
  "pnp010_decode_control",
  "pnp010_on_control",
  "pnp010_admit_channel",
  "pnp010_label_id",
  "pnp010_label",
  "pnp010_admit_offer",
  "pnp010_sanitize_file_name",
  "pnp010_numbered_file_name",
  "pnp010_limits",
  "TransferOfferLimiter",
  "TransferHasher",
  "TransferSender",
  "TransferReceiver",
  "argon2id",
];

/**
 * Check an initialised parolnet-wasm module (the wasm-bindgen glue, after its `default`
 * init resolved) and type it. Throws when an export the engine needs is missing.
 */
export function wasmApi(module: Record<string, unknown>): WasmApi {
  for (const name of WASM_EXPORTS) {
    if (typeof module[name] !== "function") {
      throw new Error(`parolnet-wasm has no export ${name}`);
    }
  }
  return module as unknown as WasmApi;
}

/** `wss://<this origin>/ws`: the relay that serves the app. */
export function sameOriginRelayUrl(
  location: { protocol: string; host: string } = g.location,
): string {
  return `${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}/ws`;
}

export interface BrowserPlatformOptions {
  /** An initialised parolnet-wasm module (see `wasmApi`). */
  wasm: WasmApi;
  /** Database name; the default is the app's. */
  dbName?: string;
  /**
   * The storage to run on. The default opens the database's vault (`openBrowserVault`) and
   * uses its sealed storage; that fails when the vault is locked with a passphrase, so an
   * app that offers the lock opens the vault itself and passes the storage in.
   */
  storage?: Storage;
  /** Media capture for calls (default: `navigator.mediaDevices`). */
  media?: MediaDevices;
  log?: Logger;
}

/** WebCrypto, randomness and the clock of this browser, and Argon2id from the wasm core. */
export function browserVaultCrypto(wasm: WasmApi): VaultCrypto {
  return {
    subtle: g.crypto.subtle,
    random: (n) => g.crypto.getRandomValues(new Uint8Array(n)),
    argon2id: (passphrase, salt, memoryKiB, passes, lanes, len) =>
      wasm.argon2id(passphrase, salt, memoryKiB, passes, lanes, len),
    now: () => Date.now(),
  };
}

/**
 * Open (or create) the database and its vault. A database that is not sealed yet is sealed
 * here. The vault may be locked: `vault.locked` says so, and `vault.unlock` opens it.
 */
export async function openBrowserVault(wasm: WasmApi, dbName: string = DB_NAME): Promise<Vault> {
  const raw = await IdbStorage.open(g.indexedDB as IdbFactory, dbName);
  try {
    return await Vault.open(raw, browserVaultCrypto(wasm));
  } catch (error) {
    raw.close();
    throw error;
  }
}

/** Everything the engine needs, from this browser. Opens (or creates) the database. */
export async function browserPlatform(
  options: BrowserPlatformOptions,
): Promise<Platform> {
  const dbName = options.dbName ?? DB_NAME;
  let storage = options.storage;
  if (!storage) {
    const vault = await openBrowserVault(options.wasm, dbName);
    if (vault.locked) {
      vault.raw.close();
      throw new EngineError("Storage", "this device's storage is locked with a passphrase");
    }
    storage = new SealedStorage(vault);
  }
  return {
    wasm: options.wasm,
    storage,
    sockets: browserSockets,
    peerConnections: browserPeerConnections,
    clock: browserClock,
    random: browserRandom,
    fetch: browserFetch,
    sha256: browserSha256,
    log: options.log ?? consoleLogger,
    media: options.media ??
      (g.navigator?.mediaDevices ? browserMedia : undefined),
    lock: browserLock(`${dbName}-engine`),
    // Received files: OPFS where this browser can write it from a page (a part then
    // survives a reload); otherwise the engine keeps them in memory.
    files: (await OpfsFileStore.open()) ?? undefined,
  };
}

/**
 * Ask the browser not to evict the database under storage pressure. Firefox answers with a
 * permission prompt (and only then resolves), so the engine never calls this itself: the UI
 * does, on a user action. Resolves to whether storage is now persistent.
 */
export async function requestPersistentStorage(): Promise<boolean> {
  try {
    return (await g.navigator?.storage?.persist?.()) === true;
  } catch {
    return false;
  }
}

/**
 * Reconnect to the relay as soon as the network is back or the page is shown again.
 * Returns the function that removes the listeners.
 */
export function attachLifecycle(
  engine: { networkChanged(): void },
): () => void {
  const nudge = () => engine.networkChanged();
  const visible = () => {
    if (g.document?.visibilityState === "visible") nudge();
  };
  g.addEventListener?.("online", nudge);
  g.document?.addEventListener?.("visibilitychange", visible);
  return () => {
    g.removeEventListener?.("online", nudge);
    g.document?.removeEventListener?.("visibilitychange", visible);
  };
}
