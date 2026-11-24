// Registers public/sw.js and surfaces its update flow: a new build installs in the
// background and waits; `updateReady` turns true; `applyUpdate()` lets it take over and
// reloads the page onto it.
import { type ReadonlySignal, signal } from "denext/signals";
import { assetUrl } from "./base.ts";

const ready = signal(false);

/** True when a newer build is installed and waiting for the person to reload. */
export const updateReady: ReadonlySignal<boolean> = ready;

let registration: ServiceWorkerRegistration | null = null;
/** The new build's worker, installed and waiting for the person to reload. */
let waiting: ServiceWorker | null = null;
let reloadOnTakeover = false;

function watch(reg: ServiceWorkerRegistration): void {
  const offer = (worker: ServiceWorker | null) => {
    // A waiting worker next to a controller that is another worker is an update. Without a
    // controller it is the first install, which activates by itself; and the controller can
    // already be that first install: it claims the page when it activates, and WebKit may
    // apply the claim before it delivers the worker's "installed" state change (CI run
    // 45388216463: "A new version is ready" on a first visit). A worker object is the same
    // object wherever this page meets it, so identity tells the two apart.
    waiting = worker;
    const controller = navigator.serviceWorker.controller;
    ready.value = worker !== null && controller !== null && controller !== worker;
  };
  offer(reg.waiting);
  reg.addEventListener("updatefound", () => {
    const installing = reg.installing;
    if (!installing) return;
    // Judged by the worker's own state, not by `reg.waiting`: the browser reports the two
    // separately and may deliver the state change first (seen in Chromium under load), and
    // nothing would ask again afterwards.
    installing.addEventListener("statechange", () => {
      if (installing.state === "installed") offer(installing);
      else if (installing.state === "redundant" && waiting === installing) offer(reg.waiting);
    });
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
  const next = waiting ?? registration?.waiting;
  if (!next) {
    location.reload();
    return;
  }
  reloadOnTakeover = true;
  next.postMessage({ type: "SKIP_WAITING" });
}
