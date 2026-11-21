// Registers public/sw.js and surfaces its update flow: a new build installs in the
// background and waits; `updateReady` turns true; `applyUpdate()` lets it take over and
// reloads the page onto it.
import { type ReadonlySignal, signal } from "denext/signals";
import { assetUrl } from "./base.ts";

const ready = signal(false);

/** True when a newer build is installed and waiting for the person to reload. */
export const updateReady: ReadonlySignal<boolean> = ready;

let registration: ServiceWorkerRegistration | null = null;
let reloadOnTakeover = false;

function watch(reg: ServiceWorkerRegistration): void {
  const check = () => {
    // A waiting worker next to a controller is an update; without a controller it is the
    // first install, which activates by itself.
    ready.value = reg.waiting !== null && navigator.serviceWorker.controller !== null;
  };
  check();
  reg.addEventListener("updatefound", () => {
    const installing = reg.installing;
    installing?.addEventListener("statechange", check);
  });
}

export async function registerServiceWorker(): Promise<void> {
  if (!("serviceWorker" in navigator)) return;
  navigator.serviceWorker.addEventListener("controllerchange", () => {
    if (reloadOnTakeover) location.reload();
  });
  try {
    registration = await navigator.serviceWorker.register(assetUrl("sw.js"), {
      scope: assetUrl("./"),
      updateViaCache: "none",
    });
  } catch (error) {
    // The app works without it (no offline start); nothing for the person to do.
    console.warn("service worker registration failed", error);
    return;
  }
  watch(registration);
  // Look for a new build when the app comes back to the foreground, and hourly.
  const update = () => registration?.update().catch(() => {});
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") update();
  });
  setInterval(update, 60 * 60 * 1000);
}

/** The person chose to reload: let the waiting worker take over, then reload onto it. */
export function applyUpdate(): void {
  const waiting = registration?.waiting;
  if (!waiting) {
    location.reload();
    return;
  }
  reloadOnTakeover = true;
  waiting.postMessage({ type: "SKIP_WAITING" });
}
