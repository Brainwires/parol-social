// What every browser test shares: a server per test (so one test can stop it or swap the
// build without touching another), a recorder of everything the page must not do, and, for
// the tests of real flows, a relay per test.
import { expect, type Page, test as base } from "@playwright/test";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { connect, createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startServer } from "./static-server.mjs";

/** The production export (`denext task build`). */
export const OUT_DIR = fileURLToPath(new URL("../../out", import.meta.url));
/** The development and test build (`denext task build:test`): adds the state lab. */
export const TEST_OUT_DIR = fileURLToPath(new URL("../../out-test", import.meta.url));
export const ARTIFACTS_DIR = fileURLToPath(new URL("./artifacts", import.meta.url));

const REPO_DIR = fileURLToPath(new URL("../../..", import.meta.url));
/** The relay binary: PAROLNET_RELAY_BIN, or cargo's debug build of this repository. */
export const RELAY_BIN = process.env.PAROLNET_RELAY_BIN ??
  join(
    process.env.CARGO_TARGET_DIR ?? join(REPO_DIR, "target"),
    "debug",
    process.platform === "win32" ? "parolnet-relay.exe" : "parolnet-relay",
  );

export interface Server {
  origin: string;
  url: string;
  setRoot(root: string): void;
  close(): Promise<void>;
}

export interface Problems {
  /** Console errors, uncaught exceptions and failed same-origin requests. */
  errors: string[];
  /** URLs requested from anywhere but the test server (WebSockets included). */
  external: string[];
  /** Reports of the `securitypolicyviolation` event. */
  csp(): Promise<string[]>;
}

/**
 * Firefox reports a WebSocket that a reload or a closed tab cut off as a console error
 * ("… was interrupted while the page was loading", and "can't establish a connection" for
 * one that was still connecting). That is the browser describing the unload, not the app
 * failing; whether the relay is reachable is asserted by what the tests then do with it.
 */
const UNLOAD_NOISE =
  /(The connection to wss?:\/\/\S+ was interrupted while the page was loading|Firefox can’t establish a connection to the server at wss?:\/\/)/;

/** Records console errors, page errors, CSP violations and requests that leave localhost. */
export async function watch(page: Page, server: Server): Promise<Problems> {
  const errors: string[] = [];
  const external: string[] = [];
  const origins = [server.origin + "/", server.origin.replace(/^http/, "ws") + "/"];
  const note = (url: string) => {
    if (url.startsWith("data:") || url.startsWith("blob:")) return;
    if (!origins.some((origin) => url.startsWith(origin))) external.push(url);
  };
  page.on("console", (message) => {
    if (message.type() !== "error" || UNLOAD_NOISE.test(message.text())) return;
    errors.push(`console: ${message.text()}`);
  });
  page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
  page.on("request", (request) => note(request.url()));
  page.on("websocket", (socket) => note(socket.url()));
  await page.addInitScript(() => {
    const seen: string[] = [];
    (window as unknown as { __csp: string[] }).__csp = seen;
    document.addEventListener("securitypolicyviolation", (event) => {
      seen.push(
        `${event.violatedDirective} blocked ${event.blockedURI} (${event.sourceFile}:${event.lineNumber})`,
      );
    });
  });
  return {
    errors,
    external,
    csp: () => page.evaluate(() => (window as unknown as { __csp: string[] }).__csp ?? []),
  };
}

export async function expectClean(problems: Problems): Promise<void> {
  expect(await problems.csp(), "CSP violations").toEqual([]);
  expect(problems.errors, "console and page errors").toEqual([]);
  expect(problems.external, "requests that left localhost").toEqual([]);
}

/** Resolves once a service worker controls the page. */
export async function controlled(page: Page): Promise<void> {
  await page.waitForFunction(async () => {
    await navigator.serviceWorker.ready;
    return navigator.serviceWorker.controller !== null;
  });
}

/**
 * The build version the controlling worker serves. Waits for a controller first: between
 * `controlled` and this call the page can be one that has none for a moment (the worker that
 * claimed it is replaced, or the document is a newer one than the one `controlled` saw).
 */
export async function workerVersion(page: Page): Promise<string> {
  await controlled(page);
  return await page.evaluate(async () => {
    await navigator.serviceWorker.ready;
    const controller = navigator.serviceWorker.controller ??
      await new Promise<ServiceWorker>((resolve) =>
        navigator.serviceWorker.addEventListener(
          "controllerchange",
          () => resolve(navigator.serviceWorker.controller!),
          { once: true },
        )
      );
    return await new Promise<string>((resolve) => {
      const channel = new MessageChannel();
      channel.port1.onmessage = (event) => resolve(event.data.version);
      controller.postMessage({ type: "GET_VERSION" }, [channel.port2]);
    });
  });
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address() as { port: number };
      probe.close(() => resolve(port));
    });
    probe.on("error", reject);
  });
}

/** A relay in its default (signaling-only) profile, with its own state directory. */
async function startRelay(): Promise<{ port: number; stop(): void }> {
  if (!existsSync(RELAY_BIN)) {
    throw new Error(
      `relay binary not found: ${RELAY_BIN} (cargo build -p parolnet-relay-server --bin parolnet-relay, or set PAROLNET_RELAY_BIN)`,
    );
  }
  const port = await freePort();
  const dir = mkdtempSync(join(tmpdir(), "parolnet-web-relay-"));
  const child = spawn(RELAY_BIN, [], {
    env: {
      PATH: process.env.PATH,
      RELAY_PORT: String(port),
      RELAY_KEY_FILE: join(dir, "relay.key"),
      RELAY_AUTHORITY_KEY_FILE: join(dir, "relay-authority.cbor"),
      RUST_LOG: "warn",
      // Every page shares one address here.
      RELAY_CONN_PER_MINUTE: "1000",
      RELAY_MAX_PEERS_PER_IP: "16",
      RELAY_MAX_CONNS_PER_IP: "32",
    },
    stdio: ["ignore", "ignore", "inherit"],
  });
  const deadline = Date.now() + 20_000;
  for (;;) {
    const up = await new Promise<boolean>((resolve) => {
      const socket = connect(port, "127.0.0.1", () => {
        socket.end();
        resolve(true);
      });
      socket.on("error", () => resolve(false));
    });
    if (up) break;
    if (Date.now() > deadline) throw new Error("the relay did not start listening");
    await new Promise((done) => setTimeout(done, 100));
  }
  return {
    port,
    stop() {
      child.kill();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

export interface Fixtures {
  /** Which export `server` hosts: the production one, or the test build with the lab. */
  build: "production" | "test";
  /** The export under /pwa/ with the production CSP. No relay behind it. */
  server: Server;
  /** The production export with a relay behind it at the same origin, as deployed. */
  live: Server;
}

export const test = base.extend<Fixtures>({
  build: ["production", { option: true }],
  server: async ({ build }, use) => {
    const server = await startServer({ root: build === "test" ? TEST_OUT_DIR : OUT_DIR });
    await use(server);
    await server.close();
  },
  // deno-lint-ignore no-empty-pattern
  live: async ({}, use) => {
    const relay = await startRelay();
    const server = await startServer({ root: OUT_DIR, relayPort: relay.port });
    await use(server);
    await server.close();
    relay.stop();
  },
});

export { expect };
