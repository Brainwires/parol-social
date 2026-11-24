// Starts the relay binary for a test on a port it chooses itself, the way the Rust harnesses do
// (crates/parolnet-app/tests/support, crates/parolnet-conformance/tests/common): RELAY_PORT=0,
// then wait for the one line the relay prints on stdout once it serves,
// `PAROLNET_RELAY_LISTENING=<addr>`. Picking a free port first (bind port 0, read it, close,
// hand the number over) let two relays started together get the same port, and a readiness
// probe reach another test's relay. Node built-ins only: the web app's browser tests, the
// engine e2e harness and the desktop interop scripts all import it.
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const LISTENING = "PAROLNET_RELAY_LISTENING=";

/**
 * Spawns `bin` with `env` plus `RELAY_PORT=0` and resolves with the child and the port it
 * reported. Rejects, and kills the child, if it exits or fails to start before reporting, or
 * does not report within `timeoutMs`. The relay's stdout keeps being read for as long as it
 * runs (written to this process's stdout when `echo`), so it never blocks on a full pipe.
 *
 * @param {string} bin
 * @param {{ env?: Record<string, string | undefined>, stderr?: "ignore" | "inherit" | "pipe",
 *   echo?: boolean, timeoutMs?: number }} [options]
 * @returns {Promise<{ child: import("node:child_process").ChildProcess, port: number, addr: string }>}
 */
export function spawnRelay(
  bin,
  { env = {}, stderr = "ignore", echo = false, timeoutMs = 20_000 } = {},
) {
  const child = spawn(bin, [], {
    env: { ...env, RELAY_PORT: "0" },
    stdio: ["ignore", "pipe", stderr],
  });
  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (message) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.kill();
      reject(new Error(`relay ${bin}: ${message}`));
    };
    const timer = setTimeout(
      () =>
        fail(
          `did not report its address (${LISTENING}<addr>) within ${timeoutMs} ms`,
        ),
      timeoutMs,
    );
    child.on("error", (err) => fail(`could not start: ${err.message}`));
    child.on(
      "exit",
      (code, signal) =>
        fail(
          `exited (${signal ?? `status ${code}`}) before it reported its address`,
        ),
    );
    createInterface({ input: child.stdout }).on("line", (line) => {
      if (echo) process.stdout.write(`${line}\n`);
      if (settled || !line.startsWith(LISTENING)) return;
      const addr = line.slice(LISTENING.length).trim();
      const port = Number(addr.slice(addr.lastIndexOf(":") + 1));
      if (!Number.isInteger(port) || port <= 0 || port > 65535) {
        fail(`reported an address without a port: ${addr}`);
        return;
      }
      settled = true;
      clearTimeout(timer);
      resolve({ child, port, addr });
    });
  });
}
