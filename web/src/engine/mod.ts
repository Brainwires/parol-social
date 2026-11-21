// The ParolNet web engine: a headless client core with the same shape as the native one
// (crates/parolnet-app). Commands in, events and immutable snapshots out; no DOM and no
// framework. See docs/web-port/engine.md.
//
// `test-hooks.ts` is deliberately not re-exported: import it only in test builds.
export { Engine, type EngineConfig } from "./engine.ts";
export * from "./types.ts";
export type * from "./platform.ts";
export { DEFAULT_RECONNECT, type ReconnectConfig } from "./reconnect.ts";
export { DB_NAME, DB_VERSION, IdbStorage, MemoryStorage } from "./storage.ts";
export {
  attachLifecycle,
  browserMedia,
  browserPlatform,
  type BrowserPlatformOptions,
  sameOriginRelayUrl,
  wasmApi,
} from "./browser.ts";
