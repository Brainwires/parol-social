// Checks the translated catalogues against the English one and prints the coverage table of
// docs/web-port/app.md.
//
//   denext deno run --allow-read=. scripts/i18n-check.ts [locale ...]
//
// Exits with 1 when a named locale (default: all of them) lacks a key, has one English does
// not, or uses a message's arguments differently.
import { fromFileUrl, join } from "@std/path";
import { coverage, META_PREFIX, problems } from "../tests/unit/catalogue.ts";

const dir = join(fromFileUrl(new URL("..", import.meta.url)), "src", "i18n", "locales");
const read = async (code: string) =>
  JSON.parse(await Deno.readTextFile(join(dir, `${code}.json`))) as Record<string, string>;

const english = await read("en");
const total = Object.keys(english).length;
const codes = Deno.args.length > 0 ? Deno.args : [];
if (codes.length === 0) {
  for await (const entry of Deno.readDir(dir)) {
    const code = entry.name.replace(/\.json$/, "");
    if (code !== "en") codes.push(code);
  }
  codes.sort();
}

let failed = false;
console.log(`| Locale | Keys | Coverage | Translation |\n|---|---|---|---|`);
console.log(`| \`en\` | ${total} / ${total} | 100% | source |`);
const found: string[] = [];
for (const code of codes) {
  const catalogue = await read(code);
  const have = coverage(catalogue, english);
  const how = catalogue[`${META_PREFIX}translation`] ?? "not stated";
  console.log(
    `| \`${code}\` | ${have} / ${total} | ${Math.floor((have / total) * 100)}% | ${how} |`,
  );
  found.push(...problems(code, catalogue, english));
}
for (const problem of found) {
  console.error(problem);
  failed = true;
}
if (failed) Deno.exit(1);
