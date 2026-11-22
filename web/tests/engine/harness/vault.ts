// What the vault and backup tests share: the real WebCrypto and the real Argon2id of the
// wasm core, at a cost that keeps the tests fast.
import type { KdfParams, VaultCrypto } from "../../../src/engine/vault.ts";
import { newWasm } from "./world.ts";

/** Cheap settings: the tests are about the logic, not about the cost. */
export const FAST_KDF: KdfParams = {
  alg: "argon2id",
  version: 19,
  memoryKiB: 64,
  passes: 1,
  lanes: 1,
};

export async function testCrypto(clock: { now(): number } = Date): Promise<VaultCrypto> {
  const wasm = await newWasm();
  return {
    subtle: crypto.subtle,
    random: (n) => crypto.getRandomValues(new Uint8Array(n)),
    argon2id: (...args) => wasm.argon2id(...args),
    now: () => clock.now(),
  };
}
