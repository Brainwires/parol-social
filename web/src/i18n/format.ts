// A small ICU MessageFormat subset, enough for the app's catalogue:
//   "Message {name}"                                         a named argument
//   "{n, plural, one {# waiting} other {# waiting}}"         plural, with "=0"-style exact cases
// "#" inside a plural branch is the number, formatted for the locale. Braces nest.
// An unknown argument is left as written, so a missing value is visible instead of silent.

export type MessageParams = Record<string, string | number>;

/** Index of the "}" that closes the "{" at `open`. */
function closing(text: string, open: number): number {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === "{") depth++;
    else if (text[i] === "}" && --depth === 0) return i;
  }
  return -1;
}

function pluralBranches(body: string): Map<string, string> {
  const branches = new Map<string, string>();
  let i = 0;
  while (i < body.length) {
    const open = body.indexOf("{", i);
    if (open < 0) break;
    const close = closing(body, open);
    if (close < 0) break;
    branches.set(body.slice(i, open).trim(), body.slice(open + 1, close));
    i = close + 1;
  }
  return branches;
}

export function formatMessage(message: string, params: MessageParams, locale: string): string {
  let out = "";
  let i = 0;
  while (i < message.length) {
    const open = message.indexOf("{", i);
    if (open < 0) break;
    const close = closing(message, open);
    if (close < 0) break;
    out += message.slice(i, open);
    const inner = message.slice(open + 1, close);
    const comma = inner.indexOf(",");
    const name = (comma < 0 ? inner : inner.slice(0, comma)).trim();
    const value = params[name];
    if (value === undefined) {
      out += message.slice(open, close + 1);
    } else if (comma < 0) {
      out += String(value);
    } else {
      const rest = inner.slice(comma + 1).trim();
      if (rest.startsWith("plural,") && typeof value === "number") {
        const branches = pluralBranches(rest.slice("plural,".length));
        const category = new Intl.PluralRules(locale).select(value);
        const branch = branches.get(`=${value}`) ?? branches.get(category) ??
          branches.get("other") ?? "";
        const number = new Intl.NumberFormat(locale).format(value);
        out += formatMessage(branch.replaceAll("#", number), params, locale);
      } else {
        out += String(value);
      }
    }
    i = close + 1;
  }
  return out + message.slice(i);
}
