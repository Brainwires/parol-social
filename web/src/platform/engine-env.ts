// The page's side of the store (src/state/engine-store.ts): loads the wasm core, opens the
// engine's storage, starts the engine, and lets tabs of the app talk to each other.
import {
  attachLifecycle,
  browserPlatform,
  browserVaultCrypto,
  consoleLogger,
  openBrowserVault,
  wasmApi,
} from "../engine/browser.ts";
import { Engine } from "../engine/engine.ts";
import { clearStoredFiles } from "../engine/files.ts";
import type { WasmApi } from "../engine/platform.ts";
import { SealedStorage } from "../engine/sealed-storage.ts";
import type { Vault } from "../engine/vault.ts";
import {
  type EnginePort,
  StartError,
  type StoreEnv,
  type Unlocked,
} from "../state/engine-store.ts";
import { deviceVault } from "./device-vault.ts";
import { callMedia } from "./devices.ts";
import { keepOnly } from "./playback.ts";
import { clearPrefs } from "./prefs.ts";
import { relayUrl } from "./relay-url.ts";
import { loadWasm } from "./wasm.ts";

const TABS_CHANNEL = "parolnet-web-tabs";
const TAKEOVER_KEY = "parolnet.takeover";

export interface EnvOptions {
  onEngine?(engine: Engine | null): void;
  onEvent?: StoreEnv["onEvent"];
}

export function browserEnv(options: EnvOptions): StoreEnv {
  const channel = typeof BroadcastChannel === "undefined"
    ? null
    : new BroadcastChannel(TABS_CHANNEL);
  let detachLifecycle: (() => void) | null = null;

  return {
    async prepare() {
      let wasm: WasmApi;
      try {
        wasm = wasmApi(await loadWasm() as unknown as Record<string, unknown>);
      } catch {
        throw new StartError("core");
      }
      // The database, sealed (a plaintext one of the earlier version is sealed here). With
      // a passphrase set, nothing in it can be read until the person has typed it.
      let vault: Vault;
      try {
        vault = await openBrowserVault(wasm);
      } catch {
        throw new StartError("storage");
      }
      const unlocked = async (): Promise<Unlocked> => {
        const storage = new SealedStorage(vault);
        try {
          const platform = await browserPlatform({
            wasm,
            storage,
            media: callMedia,
            log: consoleLogger,
          });
          return {
            hasIdentity: (await storage.get("identity", "self")) !== undefined,
            device: deviceVault(vault, storage, browserVaultCrypto(wasm), clearStoredFiles),
            start: (): Promise<EnginePort> =>
              Engine.start(platform, {
                relayUrl: relayUrl(),
                // No name until the person gives one: the screens say "New contact" until
                // then, and ask for a name (src/state/names.ts).
                defaultContactName: "",
              }),
          };
        } catch {
          throw new StartError("storage");
        }
      };
      if (!vault.locked) return await unlocked();
      return {
        locked: {
          retryAtMs: () => vault.retryAtMs(),
          async unlock(passphrase) {
            await vault.unlock(passphrase);
            return await unlocked();
          },
          // The database and its keys, then the received files those keys could open.
          async destroy() {
            await vault.destroy();
            await clearStoredFiles();
          },
        },
      };
    },

    tabs: channel && {
      askToTakeOver: () => channel.postMessage({ type: "takeover" }),
      onAskedToHandOver(handler) {
        channel.addEventListener("message", (event) => {
          if ((event.data as { type?: string })?.type === "takeover") handler();
        });
      },
    },

    takeoverOnStart: {
      set() {
        try {
          sessionStorage.setItem(TAKEOVER_KEY, "1");
        } catch { /* the person presses the button again after the reload */ }
      },
      take() {
        try {
          const wanted = sessionStorage.getItem(TAKEOVER_KEY) === "1";
          sessionStorage.removeItem(TAKEOVER_KEY);
          return wanted;
        } catch {
          return false;
        }
      },
    },

    keepPlaying: keepOnly,

    reload: () => location.reload(),
    clearPreferences: clearPrefs,
    setTimeout: (fn, ms) => setTimeout(fn, ms),
    clearTimeout: (handle) => clearTimeout(handle as number | undefined),

    onEngine(engine) {
      detachLifecycle?.();
      detachLifecycle = engine ? attachLifecycle(engine as Engine) : null;
      options.onEngine?.(engine as Engine | null);
    },
    onEvent: options.onEvent,
  };
}
