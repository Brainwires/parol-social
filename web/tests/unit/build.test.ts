import { assertEquals } from "@std/assert";
import { isImmutable, isPrecached, staticImports } from "../../scripts/postexport.ts";

Deno.test("postexport: which files are cached forever", () => {
  assertEquals(isImmutable("assets/index-I2UQPTMK.js"), true);
  assertEquals(isImmutable("assets/chunk-V2ZSXF7R.js"), true);
  assertEquals(isImmutable("wasm/parolnet_wasm_bg-b7b5d83b.wasm"), true);
  assertEquals(isImmutable("fonts/atkinson-hyperlegible-next-latin-5.3.0.woff2"), true);
  // Names that can change content without changing name are revalidated.
  assertEquals(isImmutable("index.html"), false);
  assertEquals(isImmutable("wasm/manifest.json"), false);
  assertEquals(isImmutable("manifest.webmanifest"), false);
  assertEquals(isImmutable("fonts/vazirmatn.css"), false);
  assertEquals(isImmutable("assets/index.js"), false);
});

Deno.test("postexport: the worker never precaches itself", () => {
  assertEquals(isPrecached("sw.js"), false);
  assertEquals(isPrecached("assets/index-I2UQPTMK.js.gz"), false);
  assertEquals(isPrecached("index.html"), true);
});

Deno.test("postexport: static imports of a chunk", () => {
  const source = 'import{a}from"./chunk-AAAA1111.js";import"./chunk-BBBB2222.js";' +
    'const x=()=>import("./lazy-CCCC3333.js");export{b}from"./chunk-AAAA1111.js";';
  assertEquals(staticImports(source).sort(), ["./chunk-AAAA1111.js", "./chunk-BBBB2222.js"]);
});
