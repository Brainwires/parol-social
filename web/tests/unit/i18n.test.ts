import { assertEquals } from "@std/assert";
import { formatMessage } from "../../src/i18n/format.ts";
import ar from "../../src/i18n/locales/ar.json" with { type: "json" };
import en from "../../src/i18n/locales/en.json" with { type: "json" };

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

Deno.test("catalogue: ar has exactly en's keys and the same arguments", () => {
  assertEquals(Object.keys(ar).sort(), Object.keys(en).sort());
  for (const key of Object.keys(en) as Array<keyof typeof en>) {
    assertEquals(argumentsOf(ar[key]), argumentsOf(en[key]), key);
  }
});

Deno.test("catalogue: plain words in the primary interface", () => {
  // Rule 5 of docs/ux/web-app.md. "relay" appears only where the person chooses a relay
  // server of their own.
  const banned = /\b(peer|bootstrap|ICE|STUN|TURN|NAT|SDP)\b/;
  for (const [key, message] of Object.entries(en)) {
    assertEquals(banned.test(message), false, `${key}: ${message}`);
    if (/relay/i.test(message)) {
      assertEquals(/^(action\.useOwnRelay|sheet\.relay\.)/.test(key), true, key);
    }
  }
});

Deno.test("catalogue: sentence case, no all-caps labels", () => {
  for (const [key, message] of Object.entries(en)) {
    const words = message.replace(/\{[^}]*\}/g, "").split(/\s+/).filter((w) =>
      /[A-Za-z]{2,}/.test(w)
    );
    const shouting = words.filter((w) => w === w.toUpperCase());
    assertEquals(shouting, [], key);
  }
});
