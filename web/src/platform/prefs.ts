// What the app remembers outside the engine's database: preferences only, never anything
// secret. Everything lives in localStorage under "parolnet.", so "Delete all data on this
// device" can remove it in one sweep.
const PREFIX = "parolnet.";

export type PrefKey =
  | "theme"
  | "locale"
  | "relayUrl"
  | "devices"
  | "notify"
  | "persistAsked"
  | "installDismissed"
  | "backupHintDismissed";

export function readPref(key: PrefKey): string | null {
  try {
    return localStorage.getItem(PREFIX + key);
  } catch {
    return null;
  }
}

export function writePref(key: PrefKey, value: string | null): void {
  try {
    if (value === null) localStorage.removeItem(PREFIX + key);
    else localStorage.setItem(PREFIX + key, value);
  } catch {
    // Storage is unavailable: the choice lasts for this visit.
  }
}

/** Remove every preference (part of "Delete all data on this device"). */
export function clearPrefs(): void {
  try {
    const keys: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key?.startsWith(PREFIX)) keys.push(key);
    }
    for (const key of keys) localStorage.removeItem(key);
    sessionStorage.clear();
  } catch {
    // Nothing was stored, then.
  }
}
