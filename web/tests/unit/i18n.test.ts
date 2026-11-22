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
import { coverage, META_PREFIX, problems } from "./catalogue.ts";

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

const LOCALES = { ar, de, es, fa, fr, it, ja, ko } as Record<string, Record<string, string>>;

Deno.test("catalogue: every locale has every key, with the same arguments used the same way", () => {
  // Also: no key English lacks, no empty message, balanced braces, and for a plural a
  // branch for every category the language has (tests/unit/catalogue.ts).
  for (const [code, catalogue] of Object.entries(LOCALES)) {
    assertEquals(problems(code, catalogue, en), [], code);
    assertEquals(coverage(catalogue, en), Object.keys(en).length, code);
  }
});

Deno.test("catalogue: the checker notices what can go wrong in a translation", () => {
  const english = { a: "Hello {name}", b: "{n, plural, one {# day} other {# days}}", c: "Plain" };
  const found = (catalogue: Record<string, string>, code = "de") =>
    problems(code, catalogue, english).map((line) => line.replace(/^\w+: /, ""));
  const good = { a: "Hallo {name}", b: "{n, plural, one {# Tag} other {# Tage}}", c: "Schlicht" };
  assertEquals(found(good), []);
  assertEquals(found({ ...good, [`${META_PREFIX}translation`]: "machine" }), []);
  assertEquals(found({ a: good.a, b: good.b }), ["c is missing"]);
  assertEquals(found({ ...good, d: "x" }), ["d is not a key of the English catalogue"]);
  assertEquals(found({ ...good, c: " " }), ["c is empty"]);
  assertEquals(found({ ...good, a: "Hallo {nom}" }), ["a has arguments [nom], English has [name]"]);
  assertEquals(found({ ...good, a: "Hallo" }), ["a has arguments [], English has [name]"]);
  assertEquals(found({ ...good, a: "Hallo {name" }), ["a: a brace is never closed"]);
  assertEquals(found({ ...good, b: "{n} Tage" }), ["b has arguments [n], English has [n:plural]"]);
  assertEquals(found({ ...good, b: "{n, plural, one {# Tag}}" }), [
    'b has a plural without "other"',
    'b lacks the plural branch "other"',
  ]);
  assertEquals(found({ ...good, b: "{n, plural, other {# Tage}}" }), [
    'b lacks the plural branch "one"',
  ]);
  assertEquals(found({ ...good, b: "{n, plural, one {# Tag} few {# Tage} other {# Tage}}" }), [
    'b has a plural branch "few" the language does not use',
  ]);
  // Japanese has one category; an exact case is always allowed.
  assertEquals(found({ ...good, b: "{n, plural, =0 {なし} other {#日}}" }, "ja"), []);
});

Deno.test("catalogue: every translated catalogue says how it was translated", () => {
  // Machine-translated until a native speaker has reviewed it (docs/web-port/app.md).
  for (const [code, catalogue] of Object.entries(LOCALES)) {
    assertEquals(
      ["machine", "reviewed"].includes(catalogue[`${META_PREFIX}translation`]),
      true,
      code,
    );
  }
});

Deno.test("catalogue: every language the settings offer has a catalogue, and the reverse", () => {
  assertEquals(
    LANGUAGES.map((language) => language.code).sort(),
    ["en", ...Object.keys(LOCALES)].sort(),
  );
});

/** Run `fn` with `key` taken out of a catalogue (the one the app itself has loaded). */
async function without(
  catalogue: Record<string, string>,
  key: string,
  fn: () => void | Promise<void>,
): Promise<void> {
  const kept = catalogue[key];
  delete catalogue[key];
  try {
    await fn();
  } finally {
    catalogue[key] = kept;
  }
}

Deno.test("catalogue: a missing key falls back to English, key by key", async () => {
  // Every catalogue is complete; a key added to English before it is translated is not.
  await setLocale("de");
  assertEquals(t("composer.send"), LOCALES.de["composer.send"]);
  await without(LOCALES.de, "firstRun.start", () => {
    assertEquals(t("firstRun.start"), "Start");
    assertEquals(t("composer.send"), LOCALES.de["composer.send"]);
  });
  assertEquals(t("firstRun.start"), LOCALES.de["firstRun.start"]);
  await setLocale("en");
});

Deno.test("catalogue: an English fallback in a right-to-left locale is isolated", async () => {
  await setLocale("ar");
  await without(LOCALES.ar, "firstRun.start", () => {
    // LRI … PDI: the sentence keeps its own direction (and its full stop at its own end).
    assertEquals(t("firstRun.start"), "\u2066Start\u2069");
  });
  assertEquals(t("composer.send"), LOCALES.ar["composer.send"]);
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
