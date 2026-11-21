// Starts the app: the router, the language, the store over the engine, the first render, the
// service worker. Both entries call it: src/main.tsx (production) and src/main.dev.tsx
// (development and test builds, which add the state lab and the test hooks).
import type { ReactNode } from "denext";
import { createRoot } from "denext/client";
import "./design/tokens.css";
import "./design/base.css";
import "./components/components.css";
import "./screens/screens.css";
import { App } from "./app.tsx";
import type { Engine } from "./engine/engine.ts";
import type { AppEvent } from "./engine/types.ts";
import { preferredLocale, setLocale, t } from "./i18n/index.ts";
import { browserEnv } from "./platform/engine-env.ts";
import { watchInstall } from "./platform/install.ts";
import { announce, notify } from "./platform/notify.ts";
import { registerServiceWorker } from "./platform/service-worker.ts";
import { loadWasm } from "./platform/wasm.ts";
import { isLabHash, route, startRouter } from "./router.ts";
import { createEngineStore } from "./state/engine-store.ts";
import { type AppStore, nameOf } from "./state/store.ts";

export interface StartOptions {
  /** Development and test builds: the state lab, on its own made-up store. */
  lab?: { store: AppStore; page: ReactNode };
  /** Test builds: the engine started (or stopped: null). */
  onEngine?(engine: Engine | null): void;
}

/** A message or a call arrived: say so to assistive technology, and to a hidden tab. */
function tell(event: AppEvent, store: AppStore): void {
  if (event.kind === "Message" && event.message.direction === "Received") {
    const peerId = event.message.peerId;
    const name = nameOf(store, peerId);
    const current = route.value;
    const reading = current.name === "conversation" && current.peerId === peerId &&
      document.visibilityState === "visible";
    // In the open conversation the message itself is read out; elsewhere, only who wrote.
    announce(reading ? `${name}: ${event.message.text}` : t("notify.message", { name }));
    notify("ParolNet", t("notify.message", { name }), `message-${peerId}`);
  } else if (event.kind === "Call" && event.call.state.kind === "Incoming") {
    const name = nameOf(store, event.call.peerId);
    announce(t("notify.call", { name }));
    notify("ParolNet", t("notify.call", { name }), "call");
  }
}

export async function startApp(options: StartOptions = {}): Promise<void> {
  // Everything under #/lab runs on the lab's store, with no engine. Crossing between the lab
  // and the real app reloads the page, so the two never share a session.
  const inLab = options.lab !== undefined && isLabHash(location.hash);
  startRouter({
    lab: inLab,
    onBoundary: options.lab ? () => location.reload() : undefined,
  });
  watchInstall();
  // The language before the first render, so the first screen is not shown twice.
  await setLocale(preferredLocale(navigator.languages ?? [])).catch(() => {});

  const real = inLab ? null : createEngineStore(browserEnv({
    onEngine: options.onEngine,
    onEvent: tell,
  }));
  const store = real ?? options.lab!.store;
  const root = document.getElementById("root");
  if (root) createRoot(root).render(<App store={store} lab={options.lab?.page} />);

  if (real) void real.start();
  // The lab shows the wasm core at work without an engine.
  else void loadWasm().catch(() => {});
  void registerServiceWorker();
}
