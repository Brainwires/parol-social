// Where the app's relay is. By default the server the app came from (`wss://<host>/ws`); a
// person can name another one under Settings, Advanced.
import { sameOriginRelayUrl } from "../engine/browser.ts";
import { readPref, writePref } from "./prefs.ts";

/** A relay address the engine accepts: ws:// or wss:// with a host. */
export function isRelayUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (url.protocol === "wss:" || url.protocol === "ws:") && url.host !== "";
  } catch {
    return false;
  }
}

export function defaultRelayUrl(): string {
  return sameOriginRelayUrl();
}

/** The saved address when there is a usable one, otherwise null (the default applies). */
export function savedRelayUrl(): string | null {
  const saved = readPref("relayUrl");
  return saved && isRelayUrl(saved) ? saved : null;
}

export function relayUrl(): string {
  return savedRelayUrl() ?? defaultRelayUrl();
}

/** Takes effect at the next start. `null` goes back to the default. */
export function saveRelayUrl(value: string | null): void {
  writePref("relayUrl", value);
}
