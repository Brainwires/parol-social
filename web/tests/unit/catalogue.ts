// What a translated catalogue must have in common with the English one: the same keys, and
// for every key the same arguments, used the same way (plain or plural). The unit tests and
// `scripts/i18n-check.ts` both use it.

/** Keys that describe the file, not a message (for example how it was translated). */
export const META_PREFIX = "@meta.";

export interface Argument {
  name: string;
  /** "" for a plain argument, otherwise its ICU type ("plural"). */
  type: string;
  /** For a plural: the branch selectors, sorted ("one", "other", "=0", ...). */
  branches: string[];
}

function closing(text: string, open: number): number {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === "{") depth++;
    else if (text[i] === "}" && --depth === 0) return i;
  }
  return -1;
}

/** Every argument of a message, at any depth, in the order written. Throws on bad braces. */
export function argumentsOf(message: string): Argument[] {
  const found: Argument[] = [];
  let i = 0;
  while (i < message.length) {
    const open = message.indexOf("{", i);
    if (open < 0) break;
    const close = closing(message, open);
    if (close < 0) throw new Error("a brace is never closed");
    const inner = message.slice(open + 1, close);
    const comma = inner.indexOf(",");
    if (comma < 0) {
      if (!/^\w+$/.test(inner.trim())) throw new Error(`not an argument: {${inner}}`);
      found.push({ name: inner.trim(), type: "", branches: [] });
    } else {
      const name = inner.slice(0, comma).trim();
      const rest = inner.slice(comma + 1).trim();
      const second = rest.indexOf(",");
      if (second < 0) throw new Error(`argument ${name} has a type but no body`);
      const type = rest.slice(0, second).trim();
      const body = rest.slice(second + 1);
      const branches: string[] = [];
      let j = 0;
      while (j < body.length) {
        const branchOpen = body.indexOf("{", j);
        if (branchOpen < 0) break;
        const branchClose = closing(body, branchOpen);
        if (branchClose < 0) throw new Error(`a branch of ${name} is never closed`);
        branches.push(body.slice(j, branchOpen).trim());
        found.push(...argumentsOf(body.slice(branchOpen + 1, branchClose)));
        j = branchClose + 1;
      }
      found.push({ name, type, branches: branches.sort() });
    }
    i = close + 1;
  }
  if (message.replace(/\{/g, "").length - message.replace(/\}/g, "").length !== 0) {
    throw new Error("unbalanced braces");
  }
  return found;
}

/** `name` or `name:type`, each once, sorted: what two translations of a key must share. */
export function signature(message: string): string[] {
  return [...new Set(argumentsOf(message).map((a) => (a.type ? `${a.name}:${a.type}` : a.name)))]
    .sort();
}

/** Everything wrong with `catalogue` (locale `code`) measured against English; empty: fine. */
export function problems(
  code: string,
  catalogue: Record<string, string>,
  english: Record<string, string>,
): string[] {
  const out: string[] = [];
  const keys = Object.keys(catalogue).filter((key) => !key.startsWith(META_PREFIX));
  for (const key of Object.keys(english)) {
    if (!(key in catalogue)) out.push(`${code}: ${key} is missing`);
  }
  const categories = new Set(new Intl.PluralRules(code).resolvedOptions().pluralCategories);
  for (const key of keys) {
    const message = catalogue[key];
    if (!(key in english)) {
      out.push(`${code}: ${key} is not a key of the English catalogue`);
      continue;
    }
    if (typeof message !== "string" || message.trim() === "") {
      out.push(`${code}: ${key} is empty`);
      continue;
    }
    try {
      const own = signature(message);
      const theirs = signature(english[key]);
      if (own.join(" ") !== theirs.join(" ")) {
        out.push(`${code}: ${key} has arguments [${own}], English has [${theirs}]`);
      }
      for (const argument of argumentsOf(message)) {
        if (argument.type !== "plural") continue;
        if (!argument.branches.includes("other")) {
          out.push(`${code}: ${key} has a plural without "other"`);
        }
        for (const branch of argument.branches) {
          if (!/^=\d+$/.test(branch) && !categories.has(branch as Intl.LDMLPluralRule)) {
            out.push(`${code}: ${key} has a plural branch "${branch}" the language does not use`);
          }
        }
        for (const category of categories) {
          if (!argument.branches.includes(category)) {
            out.push(`${code}: ${key} lacks the plural branch "${category}"`);
          }
        }
      }
    } catch (error) {
      out.push(`${code}: ${key}: ${(error as Error).message}`);
    }
  }
  return out;
}

/** How many of English's keys `catalogue` has. */
export function coverage(
  catalogue: Record<string, string>,
  english: Record<string, string>,
): number {
  return Object.keys(english).filter((key) => key in catalogue).length;
}
