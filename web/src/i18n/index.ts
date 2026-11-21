// The message catalogue. English is bundled; every other locale is a JSON file loaded the
// first time it is chosen (its own chunk). `t()` reads the locale signal, so a component that
// calls it re-renders when the locale changes.
import { computed, type ReadonlySignal, signal } from "denext/signals";
import { assetUrl } from "../platform/base.ts";
import { formatMessage, type MessageParams } from "./format.ts";
import en from "./locales/en.json" with { type: "json" };

export type MessageKey = keyof typeof en;
type Catalogue = Partial<Record<MessageKey, string>>;

/** Locales with a catalogue. The other eight of the old PWA come with the protocol port. */
const LOADERS: Record<string, () => Promise<{ default: Catalogue }>> = {
  ar: () => import("./locales/ar.json", { with: { type: "json" } }),
};

export const LOCALES = ["en", ...Object.keys(LOADERS)] as const;

const RTL = new Set(["ar", "fa", "he", "ur"]);
/** Locales whose script needs Vazirmatn; its stylesheet is linked only for them. */
const ARABIC_SCRIPT = new Set(["ar", "fa"]);

const catalogues = new Map<string, Catalogue>([["en", en]]);
const current = signal("en");
const directionOverride = signal<"ltr" | "rtl" | null>(null);

export const locale: ReadonlySignal<string> = current;

/** Text direction: the locale's, unless the state lab overrides it. */
export const direction: ReadonlySignal<"ltr" | "rtl"> = computed(() =>
  directionOverride.value ?? (RTL.has(current.value) ? "rtl" : "ltr")
);

function applyToDocument(): void {
  if (typeof document === "undefined") return;
  document.documentElement.lang = current.value;
  document.documentElement.dir = direction.value;
}

function linkArabicFont(): void {
  const id = "font-vazirmatn";
  if (typeof document === "undefined" || document.getElementById(id)) return;
  const link = document.createElement("link");
  link.id = id;
  link.rel = "stylesheet";
  link.href = assetUrl("fonts/vazirmatn.css");
  document.head.append(link);
}

export async function setLocale(code: string): Promise<void> {
  if (!catalogues.has(code)) {
    const loader = LOADERS[code];
    if (!loader) throw new Error(`no catalogue for locale "${code}"`);
    catalogues.set(code, (await loader()).default);
  }
  if (ARABIC_SCRIPT.has(code)) linkArabicFont();
  current.value = code;
  applyToDocument();
}

/** State lab only: force a direction regardless of the locale (null follows the locale). */
export function setDirectionOverride(dir: "ltr" | "rtl" | null): void {
  directionOverride.value = dir;
  applyToDocument();
}

/** The message for `key` in the current locale (English when the locale lacks it). */
export function t(key: MessageKey, params: MessageParams = {}): string {
  const code = current.value;
  const message = catalogues.get(code)?.[key] ?? en[key];
  return formatMessage(message, params, code);
}
