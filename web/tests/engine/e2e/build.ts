// Builds the end-to-end harness into e2e/dist: the bundled page script, its HTML and the
// parolnet-wasm package (web/.wasm-pkg, see `denext task build-wasm`, or PAROLNET_WASM_PKG).
const here = new URL(".", import.meta.url).pathname;
const dist = `${here}dist`;
const pkg = Deno.env.get("PAROLNET_WASM_PKG") ?? `${here}../../../.wasm-pkg`;

await Deno.remove(dist, { recursive: true }).catch(() => {});
await Deno.mkdir(`${dist}/pkg`, { recursive: true });

const bundle = await new Deno.Command(Deno.execPath(), {
  args: [
    "bundle",
    "--platform",
    "browser",
    "--format",
    "esm",
    "-o",
    `${dist}/app.js`,
    `${here}harness/main.ts`,
  ],
  cwd: `${here}..`,
  stdout: "inherit",
  stderr: "inherit",
}).output();
if (!bundle.success) Deno.exit(bundle.code || 1);

await Deno.copyFile(`${here}harness/index.html`, `${dist}/index.html`);
for (const name of ["parolnet_wasm.js", "parolnet_wasm_bg.wasm"]) {
  try {
    await Deno.copyFile(`${pkg}/${name}`, `${dist}/pkg/${name}`);
  } catch {
    console.error(`parolnet-wasm is not built: run \`denext task build-wasm\` (looked in ${pkg})`);
    Deno.exit(1);
  }
}
console.log(`built ${dist}`);
