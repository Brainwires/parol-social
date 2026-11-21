// Fetches the self-hosted font files in public/fonts/ (already committed; run this only to
// change the version). The files are Fontsource's builds of the Google Fonts subsets:
// variable weight, Latin and Latin Extended (and Arabic for Vazirmatn), woff2.
// Run: denext deno run --allow-net=registry.npmjs.org --allow-write=public/fonts scripts/fetch-fonts.ts
import { UntarStream } from "@std/tar/untar-stream";

const VERSION = "5.3.0";
const FONTS: Array<{ pkg: string; license: string; files: Record<string, string> }> = [
  {
    pkg: "atkinson-hyperlegible-next",
    license: "OFL-AtkinsonHyperlegibleNext.txt",
    files: {
      "atkinson-hyperlegible-next-latin-wght-normal.woff2": "atkinson-hyperlegible-next-latin",
      "atkinson-hyperlegible-next-latin-ext-wght-normal.woff2":
        "atkinson-hyperlegible-next-latin-ext",
    },
  },
  {
    pkg: "atkinson-hyperlegible-mono",
    license: "OFL-AtkinsonHyperlegibleMono.txt",
    files: {
      "atkinson-hyperlegible-mono-latin-wght-normal.woff2": "atkinson-hyperlegible-mono-latin",
      "atkinson-hyperlegible-mono-latin-ext-wght-normal.woff2":
        "atkinson-hyperlegible-mono-latin-ext",
    },
  },
  {
    pkg: "vazirmatn",
    license: "OFL-Vazirmatn.txt",
    files: { "vazirmatn-arabic-wght-normal.woff2": "vazirmatn-arabic" },
  },
];

const out = new URL("../public/fonts/", import.meta.url);
for (const font of FONTS) {
  const url =
    `https://registry.npmjs.org/@fontsource-variable/${font.pkg}/-/${font.pkg}-${VERSION}.tgz`;
  const response = await fetch(url);
  if (!response.ok || !response.body) throw new Error(`${url}: HTTP ${response.status}`);
  const entries = response.body.pipeThrough(new DecompressionStream("gzip")).pipeThrough(
    new UntarStream(),
  );
  for await (const entry of entries) {
    const name = entry.path.split("/").pop() ?? "";
    const target = name === "LICENSE"
      ? font.license
      : font.files[name] && `${font.files[name]}-${VERSION}.woff2`;
    if (target && entry.readable) {
      await Deno.writeFile(new URL(target, out), entry.readable);
      console.log(`wrote public/fonts/${target}`);
    } else {
      await entry.readable?.cancel();
    }
  }
}
