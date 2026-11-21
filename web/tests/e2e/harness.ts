// What every browser test shares: a server per test (so one test can stop it or swap the
// build without touching another) and a recorder of everything the page must not do.
import { expect, type Page, test as base } from "@playwright/test";
import { fileURLToPath } from "node:url";
import { startServer } from "./static-server.mjs";

export const OUT_DIR = fileURLToPath(new URL("../../out", import.meta.url));
export const ARTIFACTS_DIR = fileURLToPath(new URL("./artifacts", import.meta.url));

export interface Server {
  origin: string;
  url: string;
  setRoot(root: string): void;
  close(): Promise<void>;
}

export interface Problems {
  /** Console errors, uncaught exceptions and failed same-origin requests. */
  errors: string[];
  /** URLs requested from anywhere but the test server. */
  external: string[];
  /** Reports of the `securitypolicyviolation` event. */
  csp(): Promise<string[]>;
}

/** Records console errors, page errors, CSP violations and requests that leave localhost. */
export async function watch(page: Page, server: Server): Promise<Problems> {
  const errors: string[] = [];
  const external: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(`console: ${message.text()}`);
  });
  page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
  page.on("request", (request) => {
    const url = request.url();
    if (url.startsWith("data:") || url.startsWith("blob:")) return;
    if (!url.startsWith(server.origin + "/")) external.push(url);
  });
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

/** The build version the controlling worker serves. */
export function workerVersion(page: Page): Promise<string> {
  return page.evaluate(() =>
    new Promise<string>((resolve) => {
      const channel = new MessageChannel();
      channel.port1.onmessage = (event) => resolve(event.data.version);
      navigator.serviceWorker.controller!.postMessage({ type: "GET_VERSION" }, [channel.port2]);
    })
  );
}

export const test = base.extend<{ server: Server }>({
  // deno-lint-ignore no-empty-pattern
  server: async ({}, use) => {
    const server = await startServer({ root: OUT_DIR });
    await use(server);
    await server.close();
  },
});

export { expect };
