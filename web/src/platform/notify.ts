// What the app says on its own while the person is elsewhere: a line for screen readers
// (always), and a system notification while the tab is in the background (only when the
// person turned "Notify me while ParolNet is open" on). There is no push: nothing arrives
// while the app is closed. A notification never carries what a message says.
import { type ReadonlySignal, signal } from "denext/signals";
import { assetUrl } from "./base.ts";
import { readPref, writePref } from "./prefs.ts";

const spoken = signal<{ id: number; text: string } | null>(null);
let nextId = 0;

/** The latest announcement; `Announcer` renders it in a polite live region. */
export const announcement: ReadonlySignal<{ id: number; text: string } | null> = spoken;

/** Say something to assistive technology without moving focus. */
export function announce(text: string): void {
  spoken.value = { id: ++nextId, text };
}

const enabled = signal(typeof localStorage !== "undefined" && readPref("notify") === "on");

/** The person asked for notifications and the browser allows them. */
export const notifyEnabled: ReadonlySignal<boolean> = enabled;

export function notificationsSupported(): boolean {
  return typeof Notification !== "undefined";
}

/** Turn notifications on (asks the browser's permission, on this user action) or off. */
export async function setNotify(on: boolean): Promise<boolean> {
  if (!on) {
    enabled.value = false;
    writePref("notify", null);
    return false;
  }
  if (!notificationsSupported()) return false;
  let permission = Notification.permission;
  if (permission === "default") {
    try {
      permission = await Notification.requestPermission();
    } catch {
      permission = "denied";
    }
  }
  enabled.value = permission === "granted";
  writePref("notify", enabled.value ? "on" : null);
  return enabled.value;
}

/** A system notification, only while the tab is hidden. Clicking it brings the tab back. */
export function notify(title: string, body: string, tag: string): void {
  if (!enabled.value || !notificationsSupported() || Notification.permission !== "granted") return;
  if (typeof document === "undefined" || document.visibilityState === "visible") return;
  try {
    const notification = new Notification(title, {
      body,
      tag,
      icon: assetUrl("icons/icon-192.png"),
    });
    notification.onclick = () => {
      globalThis.focus();
      notification.close();
    };
  } catch {
    // Some browsers only allow notifications from a service worker; nothing to do here.
  }
}
