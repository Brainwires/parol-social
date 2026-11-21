// Runs after `denext export` (see the `build` task). It makes out/ a self-contained static app
// that can be hosted under any path (the live site serves it at /pwa/):
//
//   1. gives the entry script and the stylesheet content-hashed names (Denext leaves them as
//      index.js / index.css) and makes their URLs in index.html relative (Denext writes
//      "/assets/…", which only works at the origin's root);
//   2. writes the service worker's precache list into out/sw.js from the files really exported;
//   3. measures the first-load JavaScript and fails over the budget.
import { encodeHex } from "@std/encoding/hex";
import { walk } from "@std/fs/walk";
import { fromFileUrl, join, relative, SEPARATOR } from "@std/path";

/** First-load JavaScript budget, gzip, wasm excluded. */
export const FIRST_LOAD_BUDGET_BYTES = 150 * 1024;

export interface PrecacheFile {
  url: string;
  revision: string;
  immutable: boolean;
}

export interface Precache {
  version: string;
  files: PrecacheFile[];
}

/** Files whose name carries a content hash or a version: safe to cache forever. */
export function isImmutable(path: string): boolean {
  return /^assets\/.+-[A-Z0-9]{8}\.[a-z0-9]+$/.test(path) || // Denext's hashed chunks
    /^wasm\/.+-[0-9a-f]{8}\.(js|wasm)$/.test(path) || // scripts/build-wasm.ts
    /^fonts\/.+-\d+\.\d+\.\d+\.woff2$/.test(path); // versioned font files
}

/** Files the worker must not precache. */
export function isPrecached(path: string): boolean {
  return path !== "sw.js" && !path.endsWith(".gz") && !path.endsWith(".map") &&
    !path.startsWith("_denext/") && !path.endsWith(".txt");
}

async function sha256(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  return encodeHex(await crypto.subtle.digest("SHA-256", bytes));
}

/** Denext-style hash: 8 characters of A-Z0-9. */
function hash8(hex: string): string {
  return BigInt("0x" + hex.slice(0, 16)).toString(36).toUpperCase().padStart(8, "0").slice(0, 8);
}

async function gzipSize(bytes: Uint8Array<ArrayBuffer>): Promise<number> {
  const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream("gzip"));
  return (await new Response(stream).arrayBuffer()).byteLength;
}

/** The entry and every chunk it imports statically (`from"./x.js"`), transitively. */
export function staticImports(source: string): string[] {
  const found = new Set<string>();
  for (const m of source.matchAll(/(?:from|import)\s*"(\.\/[^"]+\.js)"/g)) found.add(m[1]);
  return [...found];
}

async function hashEntry(outDir: string, html: string, name: string): Promise<string> {
  const [stem, ext] = name.split(".");
  const path = join(outDir, "assets", name);
  const hashed = `${stem}-${hash8(await sha256(await Deno.readFile(path)))}.${ext}`;
  const absolute = `"/assets/${name}"`;
  if (!html.includes(absolute)) throw new Error(`postexport: index.html does not name ${absolute}`);
  await Deno.rename(path, join(outDir, "assets", hashed));
  return html.replace(absolute, `"./assets/${hashed}"`);
}

export async function postexport(outDir: string): Promise<void> {
  const indexPath = join(outDir, "index.html");
  let html = await Deno.readTextFile(indexPath);

  // Nothing else may import the entry by its old name once it is renamed.
  for await (const entry of walk(join(outDir, "assets"), { exts: [".js"] })) {
    if (entry.name === "index.js") continue;
    if ((await Deno.readTextFile(entry.path)).includes('"./index.js"')) {
      throw new Error(`postexport: ${entry.name} imports the entry; cannot rename it`);
    }
  }
  html = await hashEntry(outDir, html, "index.js");
  html = await hashEntry(outDir, html, "index.css");
  if (/(?:src|href)="\/(?!\/)/.test(html)) {
    throw new Error("postexport: index.html still has a root-absolute URL");
  }
  await Deno.writeTextFile(indexPath, html);

  // The precache list: every exported file, with a revision for the unhashed ones.
  const files: PrecacheFile[] = [];
  for await (const entry of walk(outDir, { includeDirs: false })) {
    const path = relative(outDir, entry.path).split(SEPARATOR).join("/");
    if (!isPrecached(path)) continue;
    const revision = (await sha256(await Deno.readFile(entry.path))).slice(0, 16);
    files.push({ url: path, revision, immutable: isImmutable(path) });
  }
  files.sort((a, b) => a.url.localeCompare(b.url));
  const digest = await sha256(new TextEncoder().encode(JSON.stringify(files)));
  const precache: Precache = { version: digest.slice(0, 16), files };

  const swPath = join(outDir, "sw.js");
  const sw = await Deno.readTextFile(swPath);
  const marker = /\/\*__PRECACHE__\*\/[\s\S]*?\/\*__END_PRECACHE__\*\//;
  if (!marker.test(sw)) throw new Error("postexport: sw.js has no precache marker");
  await Deno.writeTextFile(swPath, sw.replace(marker, JSON.stringify(precache)));

  // First-load JavaScript: the entry and its static imports.
  const entryName = /src="\.\/assets\/(index-[A-Z0-9]{8}\.js)"/.exec(html)?.[1];
  if (!entryName) throw new Error("postexport: no entry script in index.html");
  const seen = new Set<string>();
  const queue = [entryName];
  let raw = 0;
  let gzip = 0;
  while (queue.length > 0) {
    const name = queue.pop()!;
    if (seen.has(name)) continue;
    seen.add(name);
    const bytes = await Deno.readFile(join(outDir, "assets", name));
    raw += bytes.length;
    gzip += await gzipSize(bytes);
    for (const spec of staticImports(new TextDecoder().decode(bytes))) queue.push(spec.slice(2));
  }
  const css = await Deno.readFile(
    join(outDir, "assets", /href="\.\/assets\/(index-[A-Z0-9]{8}\.css)"/.exec(html)![1]),
  );
  const kb = (n: number) => (n / 1024).toFixed(1) + " KB";
  console.log(`  version ${precache.version}, ${files.length} files precached`);
  console.log(`  first-load JS: ${kb(raw)} raw, ${kb(gzip)} gzip (${seen.size} files)`);
  console.log(`  stylesheet:    ${kb(css.length)} raw, ${kb(await gzipSize(css))} gzip`);
  if (gzip > FIRST_LOAD_BUDGET_BYTES) {
    throw new Error(`postexport: first-load JS ${kb(gzip)} is over ${kb(FIRST_LOAD_BUDGET_BYTES)}`);
  }
}

if (import.meta.main) {
  await postexport(fromFileUrl(new URL("../out", import.meta.url)));
}
