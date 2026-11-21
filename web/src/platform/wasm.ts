// Loads the wasm-bindgen module built from crates/parolnet-wasm (scripts/build-wasm.ts puts
// it in public/wasm/). The glue and the module are static files named by content hash;
// wasm/manifest.json names them, so nothing here goes through the bundler.
import { type ReadonlySignal, signal } from "denext/signals";
import { assetUrl } from "./base.ts";

/** The exports the app uses so far. The protocol port extends this (see the crate's lib.rs). */
export interface ParolnetWasm {
  version(): string;
  /** A fresh identity's PeerId (hex). Does not touch the module's own identity. */
  generate_identity(): string;
  /** The 60-digit safety number of two PeerIds (hex), the same in either order. */
  safety_number(peerA: string, peerB: string): string;
}

interface WasmGlue extends ParolnetWasm {
  default(input: { module_or_path: Response | Promise<Response> }): Promise<unknown>;
}

interface WasmManifest {
  glue: string;
  wasm: string;
  /** Size of the module, uncompressed: the total the progress counts toward. */
  wasmBytes: number;
}

export type WasmStatus =
  | { state: "idle" }
  | { state: "loading"; loaded: number; total: number }
  | { state: "ready"; api: ParolnetWasm; version: string }
  | { state: "failed"; reason: string };

const status = signal<WasmStatus>({ state: "idle" });

/** Where loading stands; components read it to show progress. */
export const wasmStatus: ReadonlySignal<WasmStatus> = status;

/** Counts the bytes of a response body as they arrive. */
function withProgress(response: Response, total: number): Response {
  if (!response.body) return response;
  let loaded = 0;
  const counter = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      loaded += chunk.byteLength;
      status.value = { state: "loading", loaded: Math.min(loaded, total), total };
      controller.enqueue(chunk);
    },
  });
  // instantiateStreaming needs the wasm media type; keep the original headers.
  return new Response(response.body.pipeThrough(counter), {
    status: response.status,
    headers: response.headers,
  });
}

let pending: Promise<ParolnetWasm> | null = null;

async function load(): Promise<ParolnetWasm> {
  const manifestResponse = await fetch(assetUrl("wasm/manifest.json"));
  if (!manifestResponse.ok) throw new Error(`wasm manifest: HTTP ${manifestResponse.status}`);
  const manifest = await manifestResponse.json() as WasmManifest;
  status.value = { state: "loading", loaded: 0, total: manifest.wasmBytes };

  // A URL only known at run time: the bundler leaves this import alone.
  const glueUrl = assetUrl(`wasm/${manifest.glue}`);
  const [glue, response] = await Promise.all([
    import(glueUrl) as Promise<WasmGlue>,
    fetch(assetUrl(`wasm/${manifest.wasm}`)),
  ]);
  if (!response.ok) throw new Error(`wasm module: HTTP ${response.status}`);
  await glue.default({ module_or_path: withProgress(response, manifest.wasmBytes) });
  return glue;
}

/** Loads the module once; later calls return the same promise. A failure can be retried. */
export function loadWasm(): Promise<ParolnetWasm> {
  pending ??= load().then(
    (api) => {
      status.value = { state: "ready", api, version: api.version() };
      return api;
    },
    (error: unknown) => {
      pending = null;
      status.value = {
        state: "failed",
        reason: error instanceof Error ? error.message : String(error),
      };
      throw error;
    },
  );
  return pending;
}
