// The page of the engine's end-to-end test: no UI, just the engine over the real browser
// platform (WebSocket, RTCPeerConnection, IndexedDB) with the test hooks installed.
import {
  attachLifecycle,
  browserPlatform,
  sameOriginRelayUrl,
  wasmApi,
} from "../../../../src/engine/browser.ts";
import { Engine } from "../../../../src/engine/engine.ts";
import { installTestHooks } from "../../../../src/engine/test-hooks.ts";
import type { AppEvent } from "../../../../src/engine/types.ts";

interface HarnessWindow {
  __engine?: Engine;
  __events: AppEvent[];
  __harness: { state: "starting" | "ready" | "failed"; error?: string };
}

const w = globalThis as unknown as HarnessWindow;
w.__events = [];
w.__harness = { state: "starting" };

async function main(): Promise<void> {
  // Loaded at run time, next to the page: the bundle does not contain the wasm glue.
  const glue = new URL("./pkg/parolnet_wasm.js", location.href).href;
  const module = await import(glue);
  await module.default({ module_or_path: new URL("./pkg/parolnet_wasm_bg.wasm", location.href) });
  const platform = await browserPlatform({ wasm: wasmApi(module) });
  const engine = await Engine.start(platform, { relayUrl: sameOriginRelayUrl() });
  engine.subscribe((ev) => w.__events.push(ev));
  attachLifecycle(engine);
  installTestHooks(engine);
  w.__engine = engine;
  w.__harness = { state: "ready" };
  document.getElementById("status")!.textContent = `ready ${engine.peerId}`;
}

main().catch((e) => {
  w.__harness = { state: "failed", error: String(e?.code ?? e?.message ?? e) };
  document.getElementById("status")!.textContent = "failed";
});
