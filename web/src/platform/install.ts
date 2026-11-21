// Installing the app (where the browser offers it): an installed app keeps its storage more
// reliably, which matters because this device's identity lives only there.
import { type ReadonlySignal, signal } from "denext/signals";
import { readPref, writePref } from "./prefs.ts";

interface InstallPromptEvent extends Event {
  prompt(): Promise<void>;
  userChoice: Promise<{ outcome: "accepted" | "dismissed" }>;
}

let pending: InstallPromptEvent | null = null;
const available = signal(false);

/** The browser can install the app now and the person has not waved the hint away. */
export const installAvailable: ReadonlySignal<boolean> = available;

export function watchInstall(): void {
  addEventListener("beforeinstallprompt", (event) => {
    // Keep the browser's own banner away; the app offers it in its own time.
    event.preventDefault();
    pending = event as InstallPromptEvent;
    available.value = readPref("installDismissed") !== "yes";
  });
  addEventListener("appinstalled", () => {
    pending = null;
    available.value = false;
  });
}

export async function install(): Promise<void> {
  const event = pending;
  if (!event) return;
  pending = null;
  available.value = false;
  await event.prompt();
  await event.userChoice.catch(() => {});
}

export function dismissInstall(): void {
  available.value = false;
  writePref("installDismissed", "yes");
}

/**
 * Ask the browser to keep this device's storage (the identity lives only there). Firefox
 * answers with a prompt, so this runs once, on a user action, after the first contact.
 */
export async function keepStorage(request: () => Promise<boolean>): Promise<void> {
  if (readPref("persistAsked") === "yes") return;
  writePref("persistAsked", "yes");
  await request();
}
