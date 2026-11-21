// The page's side of the store (src/state/engine-store.ts): loads the wasm core, opens the
// engine's storage, starts the engine, and lets tabs of the app talk to each other.
import { attachLifecycle, browserPlatform, consoleLogger, wasmApi } from "../engine/browser.ts";
import { Engine } from "../engine/engine.ts";
import type { Platform, WasmApi } from "../engine/platform.ts";
import { type EnginePort, StartError, type StoreEnv } from "../state/engine-store.ts";
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
      let platform: Platform;
      let hasIdentity: boolean;
      try {
        platform = await browserPlatform({ wasm, media: callMedia, log: consoleLogger });
        hasIdentity = (await platform.storage.get("identity", "self")) !== undefined;
      } catch {
        throw new StartError("storage");
      }
      return {
        hasIdentity,
        start: (): Promise<EnginePort> =>
          Engine.start(platform, {
            relayUrl: relayUrl(),
            // No name until the person gives one: the screens say "New contact" until
            // then, and ask for a name (src/state/names.ts).
            defaultContactName: "",
          }),
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
