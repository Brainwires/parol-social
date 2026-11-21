// Builds crates/parolnet-wasm for the browser and puts it where the app loads it from:
//
//   public/wasm/parolnet_wasm-<hash>.js        the wasm-bindgen glue, minified
//   public/wasm/parolnet_wasm_bg-<hash>.wasm   the module
//   public/wasm/manifest.json                  { glue, wasm, wasmBytes }: the two names above
//                                              and the module's size (for load progress)
//
// Both files live in public/ and are named by content hash, so a static host can cache them
// forever; the app reads manifest.json (src/platform/wasm.ts) to find them. Denext's native
// SPA bundler neither emits `.wasm` imports nor rewrites `new URL("x.wasm", import.meta.url)`,
// which is why nothing here goes through the bundler's module graph.
//
// Run: `denext task build-wasm` (needs cargo, the wasm32-unknown-unknown target and wasm-pack).
// AUTHORITY_PUBKEYS / AUTHORITY_THRESHOLD are passed through to the crate's build script, as
// pwa/build.sh does.
import { encodeHex } from "@std/encoding/hex";
import { emptyDir } from "@std/fs/empty-dir";
import { fromFileUrl, join } from "@std/path";

const webDir = fromFileUrl(new URL("..", import.meta.url));
const repoDir = join(webDir, "..");
const pkgDir = join(webDir, ".wasm-pkg");
const outDir = join(webDir, "public", "wasm");

async function run(cmd: string, args: string[], cwd: string): Promise<void> {
  console.log(`$ ${cmd} ${args.join(" ")}`);
  const { success, code } = await new Deno.Command(cmd, { args, cwd }).spawn().status;
  if (!success) {
    console.error(`${cmd} exited with ${code}`);
    Deno.exit(code || 1);
  }
}

async function hash8(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  return encodeHex(await crypto.subtle.digest("SHA-256", bytes)).slice(0, 8);
}

await run("wasm-pack", [
  "build",
  "crates/parolnet-wasm",
  "--target",
  "web",
  "--release",
  "--out-dir",
  pkgDir,
], repoDir);

// Minify the glue with the runtime's bundler (one module in, one out: nothing to resolve).
const minified = join(pkgDir, "parolnet_wasm.min.js");
await run(Deno.execPath(), [
  "bundle",
  "--minify",
  "--platform",
  "browser",
  "--format",
  "esm",
  "-o",
  minified,
  join(pkgDir, "parolnet_wasm.js"),
], webDir);

const glue = await Deno.readFile(minified);
const wasm = await Deno.readFile(join(pkgDir, "parolnet_wasm_bg.wasm"));
const manifest = {
  glue: `parolnet_wasm-${await hash8(glue)}.js`,
  wasm: `parolnet_wasm_bg-${await hash8(wasm)}.wasm`,
  wasmBytes: wasm.length,
};

await emptyDir(outDir);
await Deno.writeFile(join(outDir, manifest.glue), glue);
await Deno.writeFile(join(outDir, manifest.wasm), wasm);
await Deno.writeTextFile(join(outDir, "manifest.json"), JSON.stringify(manifest) + "\n");
console.log(
  `public/wasm: ${manifest.glue} (${glue.length} B), ${manifest.wasm} (${wasm.length} B)`,
);
