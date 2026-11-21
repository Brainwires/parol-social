import { assertEquals } from "@std/assert";
import { formatMessage } from "../../src/i18n/format.ts";
import { LANGUAGES, preferredLocale, setLocale, t } from "../../src/i18n/index.ts";
import ar from "../../src/i18n/locales/ar.json" with { type: "json" };
import de from "../../src/i18n/locales/de.json" with { type: "json" };
import en from "../../src/i18n/locales/en.json" with { type: "json" };
import es from "../../src/i18n/locales/es.json" with { type: "json" };
import fa from "../../src/i18n/locales/fa.json" with { type: "json" };
import fr from "../../src/i18n/locales/fr.json" with { type: "json" };
import it from "../../src/i18n/locales/it.json" with { type: "json" };
import ja from "../../src/i18n/locales/ja.json" with { type: "json" };
import ko from "../../src/i18n/locales/ko.json" with { type: "json" };

Deno.test("format: named arguments", () => {
  assertEquals(formatMessage("Message {name}", { name: "Mira" }, "en"), "Message Mira");
  assertEquals(formatMessage("{a} and {b}", { a: "1", b: 2 }, "en"), "1 and 2");
});

Deno.test("format: a missing argument stays visible", () => {
  assertEquals(formatMessage("Message {name}", {}, "en"), "Message {name}");
});

Deno.test("format: plural picks the locale's category and formats #", () => {
  const message = "{n, plural, =0 {none} one {# message} other {# messages}}";
  assertEquals(formatMessage(message, { n: 0 }, "en"), "none");
  assertEquals(formatMessage(message, { n: 1 }, "en"), "1 message");
  assertEquals(formatMessage(message, { n: 1200 }, "en"), "1,200 messages");
});

Deno.test("format: Arabic plural categories", () => {
  const message = ar["list.waiting"];
  assertEquals(formatMessage(message, { n: 1 }, "ar"), "رسالة واحدة في الانتظار");
  assertEquals(formatMessage(message, { n: 2 }, "ar"), "رسالتان في الانتظار");
  // The digits are whatever this ICU build uses for Arabic.
  const three = new Intl.NumberFormat("ar").format(3);
  assertEquals(formatMessage(message, { n: 3 }, "ar"), `${three} رسائل في الانتظار`);
});

Deno.test("format: arguments inside a plural branch", () => {
  const message = "{n, plural, one {# note for {name}} other {# notes for {name}}}";
  assertEquals(formatMessage(message, { n: 2, name: "Jun" }, "en"), "2 notes for Jun");
});

/** The argument names a message uses. */
function argumentsOf(message: string): string[] {
  const names = new Set<string>();
  for (const match of message.matchAll(/\{(\w+)(?=[,}])/g)) names.add(match[1]);
  return [...names].sort();
}

const LOCALES = { ar, de, es, fa, fr, it, ja, ko } as Record<string, Record<string, string>>;

Deno.test("catalogue: a locale only has keys English has, with the same arguments", () => {
  // A locale may lack keys (each falls back to English), but never invents or misuses one.
  for (const [code, catalogue] of Object.entries(LOCALES)) {
    for (const [key, message] of Object.entries(catalogue)) {
      assertEquals(key in en, true, `${code}: unknown key ${key}`);
      assertEquals(
        argumentsOf(message),
        argumentsOf(en[key as keyof typeof en]),
        `${code}: ${key}`,
      );
    }
  }
});

Deno.test("catalogue: every language the settings offer has a catalogue, and the reverse", () => {
  assertEquals(
    LANGUAGES.map((language) => language.code).sort(),
    ["en", ...Object.keys(LOCALES)].sort(),
  );
});

Deno.test("catalogue: a missing key falls back to English, key by key", async () => {
  await setLocale("de");
  // Ported from the old PWA.
  assertEquals(t("composer.send"), de["composer.send" as keyof typeof de]);
  // Not translated yet.
  assertEquals("firstRun.start" in de, false);
  assertEquals(t("firstRun.start"), "Start");
  await setLocale("en");
});

Deno.test("catalogue: an English fallback in a right-to-left locale is isolated", async () => {
  await setLocale("ar");
  assertEquals("firstRun.start" in ar, false);
  // LRI … PDI: the sentence keeps its own direction (and its full stop at its own end).
  assertEquals(t("firstRun.start"), "\u2066Start\u2069");
  assertEquals(t("composer.send"), ar["composer.send" as keyof typeof ar]);
  await setLocale("en");
});

Deno.test("catalogue: the language to start in", () => {
  assertEquals(preferredLocale(["fr-CA", "en"]), "fr");
  assertEquals(preferredLocale(["pt-BR", "ko"]), "ko");
  assertEquals(preferredLocale(["zz"]), "en");
  assertEquals(preferredLocale([]), "en");
});

Deno.test("catalogue: plain words in the primary interface", () => {
  // Rule 5 of docs/ux/web-app.md. The settings may name things: "relay server" where a
  // person sets up their own, "TURN" in that setting's title.
  const banned = /\b(peer|bootstrap|ICE|STUN|TURN|NAT|SDP|WebRTC)\b/;
  const mayNameRelay = /^(action\.useOwnRelay|settings\.|notice\.turn\.|toast\.turn)/;
  for (const [key, message] of Object.entries(en)) {
    if (key !== "settings.turn.title") {
      assertEquals(banned.test(message), false, `${key}: ${message}`);
    }
    if (/relay/i.test(message)) assertEquals(mayNameRelay.test(key), true, key);
  }
});

Deno.test("catalogue: sentence case, no all-caps labels", () => {
  const acronyms = new Set(["IP", "TURN"]);
  for (const [key, message] of Object.entries(en)) {
    const words = message.replace(/\{[^}]*\}/g, "").split(/[^A-Za-z]+/).filter((w) =>
      w.length >= 2 && !acronyms.has(w)
    );
    const shouting = words.filter((w) => w === w.toUpperCase());
    assertEquals(shouting, [], key);
  }
});

Deno.test("catalogue: how a call ended has words for every case", () => {
  for (const words of ["youEnded", "theyEnded", "theyDeclined", "noAnswer", "missed", "failed"]) {
    assertEquals(`call.ended.${words}` in en, true, words);
  }
});
