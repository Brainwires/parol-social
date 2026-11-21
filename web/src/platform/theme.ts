// Theme: follow the system by default, with an override kept on this device.
// public/theme-boot.js applies the saved value before first paint; this module owns it after.
import { type ReadonlySignal, signal } from "denext/signals";

export type ThemeChoice = "system" | "light" | "dark";

export const THEME_STORAGE_KEY = "parolnet.theme";

function read(): ThemeChoice {
  try {
    const saved = localStorage.getItem(THEME_STORAGE_KEY);
    return saved === "light" || saved === "dark" ? saved : "system";
  } catch {
    return "system";
  }
}

const choice = signal<ThemeChoice>(typeof localStorage === "undefined" ? "system" : read());

export const themeChoice: ReadonlySignal<ThemeChoice> = choice;

export function setTheme(next: ThemeChoice): void {
  choice.value = next;
  const root = document.documentElement;
  if (next === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", next);
  try {
    if (next === "system") localStorage.removeItem(THEME_STORAGE_KEY);
    else localStorage.setItem(THEME_STORAGE_KEY, next);
  } catch {
    // Storage is unavailable: the choice lasts for this visit.
  }
}
