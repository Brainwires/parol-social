// The platform proof: the export runs under /pwa/ behind the production CSP, the Rust core
// loads as wasm, the service worker takes control, the app starts offline, updates are
// offered, and the previous PWA's worker and caches are replaced.
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { controlled, expect, expectClean, OUT_DIR, test, watch, workerVersion } from "./harness.ts";

const LEGACY_DIR = fileURLToPath(new URL("./fixtures/legacy-pwa", import.meta.url));

test("renders under /pwa/ with the CSP header, no errors, nothing leaves localhost", async ({ page, server }) => {
  const problems = await watch(page, server);
  const response = await page.goto(server.url);
  expect(response?.headers()["content-security-policy"]).toContain(
    "script-src 'self' 'wasm-unsafe-eval'",
  );

  // Nothing on this device yet: the first-run screen, which only appears once the wasm core
  // has loaded and the device's storage has been opened.
  const firstRun = page.getByTestId("first-run");
  await expect(firstRun).toBeVisible();
  await expect(firstRun).toContainText(
    "Private calls and messages, straight from your device to theirs.",
  );
  await expect(firstRun).toContainText(
    "No account, no phone number, no email. Nothing is stored on a server.",
  );
  await expect(page.getByTestId("first-run-start")).toHaveText("Start");
  // No identity is made, and nothing is contacted, before the person presses Start.
  expect(
    await page.evaluate(() =>
      new Promise((resolve) => {
        const open = indexedDB.open("parolnet-web");
        open.onsuccess = () => {
          const rows = open.result.transaction("identity").objectStore("identity").count();
          rows.onsuccess = () => resolve(rows.result);
        };
      })
    ),
  ).toBe(0);

  // Fonts are the self-hosted ones.
  await page.evaluate(() => document.fonts.ready);
  expect(await page.evaluate(() => document.fonts.check('16px "Atkinson Hyperlegible Next"'))).toBe(
    true,
  );

  await expectClean(problems);
});

test("the production export has no state lab and no test hooks", async ({ page, server }) => {
  await page.goto(server.url + "#/lab");
  await expect(page.getByTestId("first-run")).toBeVisible();
  await expect(page.getByTestId("lab")).toHaveCount(0);
  expect(await page.evaluate(() => "__parolnetTest" in window)).toBe(false);
});

test("no layout shift while wasm loads", async ({ page, server, browserName }) => {
  test.skip(browserName !== "chromium", "the layout-shift entry type is Chromium-only");
  await page.addInitScript(() => {
    const state = { shift: 0 };
    (window as unknown as { __cls: typeof state }).__cls = state;
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        const shift = entry as unknown as { value: number; hadRecentInput: boolean };
        if (!shift.hadRecentInput) state.shift += shift.value;
      }
    }).observe({ type: "layout-shift", buffered: true });
  });
  await page.goto(server.url);
  await expect(page.getByTestId("first-run")).toBeVisible();
  await page.waitForTimeout(300);
  const shift = await page.evaluate(() =>
    (window as unknown as { __cls: { shift: number } }).__cls.shift
  );
  expect(shift).toBeLessThan(0.01);
});

test("the service worker controls the page and the app starts offline", async ({ page, server }) => {
  const problems = await watch(page, server);
  await page.goto(server.url);
  await controlled(page);
  // Polled: right after `controlled` the document can be one that has no controller for a
  // moment (see `workerVersion` in the harness).
  await expect.poll(() =>
    page.evaluate(() => navigator.serviceWorker.controller?.scriptURL).catch(() => undefined)
  ).toBe(server.url + "sw.js");
  expect(await page.evaluate(() => navigator.serviceWorker.ready.then((r) => r.scope))).toBe(
    server.url,
  );
  await expect(page.getByTestId("first-run")).toBeVisible();
  await expectClean(problems);

  // Stop the server: the next load has no network at all. The first-run screen needs the
  // shell, the bundle, the wasm core and the fonts, all from the worker's cache.
  await server.close();
  await page.reload();
  await expect(page.getByTestId("first-run")).toBeVisible();
  await page.evaluate(() => document.fonts.ready);
  expect(await page.evaluate(() => document.fonts.check('16px "Atkinson Hyperlegible Next"'))).toBe(
    true,
  );
  // The scanner's decoder is cached too: scanning works offline.
  expect(
    await page.evaluate(() =>
      caches.match(new URL("vendor/jsqr.js", document.baseURI).href).then((hit) => hit?.ok)
    ),
  ).toBe(true);
  expect(await problems.csp(), "CSP violations offline").toEqual([]);
  expect(problems.external, "requests that left localhost").toEqual([]);
});

test("a new build is offered and applied on reload", async ({ page, server }) => {
  const next = await mkdtemp(join(tmpdir(), "parolnet-next-"));
  try {
    // "Deploy" a second build: the same files with one changed and a new precache version.
    await cp(OUT_DIR, next, { recursive: true });
    const manifestPath = join(next, "manifest.webmanifest");
    await writeFile(
      manifestPath,
      (await readFile(manifestPath, "utf8")).replace('"ParolNet"', '"ParolNet "'),
    );
    const swPath = join(next, "sw.js");
    const sw = await readFile(swPath, "utf8");
    const version = /"version":"([0-9a-f]+)"/.exec(sw)![1];
    await writeFile(swPath, sw.replace(`"version":"${version}"`, '"version":"next-build"'));

    await page.goto(server.url);
    await controlled(page);
    expect(await workerVersion(page)).toBe(version);
    await expect(page.getByTestId("update-ready")).toHaveCount(0);

    server.setRoot(next);
    // Ask for the update and wait until the new build is installed, however long its install
    // takes under load; only then is the notice checked, with the usual timeout. (Waiting on
    // the notice alone tied the test to the install's speed.)
    await page.evaluate(async () => {
      const registration = await navigator.serviceWorker.ready;
      const found = new Promise<ServiceWorker>((resolve, reject) =>
        registration.addEventListener("updatefound", () => {
          if (registration.installing) resolve(registration.installing);
          else reject(new Error("updatefound without an installing worker"));
        }, { once: true })
      );
      await registration.update();
      const worker = await found;
      await new Promise<void>((resolve, reject) => {
        const settle = () => {
          if (worker.state === "installed" || worker.state === "activated") resolve();
          else if (worker.state === "redundant") reject(new Error("the new build did not install"));
        };
        worker.addEventListener("statechange", settle);
        settle();
      });
    });
    await expect(page.getByTestId("update-ready")).toContainText("A new version is ready");
    // Until the person reloads, the old build keeps serving this tab.
    expect(await workerVersion(page)).toBe(version);

    await Promise.all([page.waitForEvent("load"), page.getByTestId("update-reload").click()]);
    await controlled(page);
    await expect(page.getByTestId("first-run")).toBeVisible();
    expect(await workerVersion(page)).toBe("next-build");
    await expect(page.getByTestId("update-ready")).toHaveCount(0);
    const caches = await page.evaluate(() => caches.keys());
    expect(caches).toEqual(["parolnet-web-next-build"]);
  } finally {
    await rm(next, { recursive: true, force: true });
  }
});

test("replaces the previous PWA's worker and caches without the person doing anything", async ({ page, server }) => {
  // The previous PWA: its worker at /pwa/sw.js, its cache "parolnet-v10", cache-first.
  server.setRoot(LEGACY_DIR);
  await page.goto(server.url);
  await expect(page.locator("#legacy")).toBeVisible();
  await controlled(page);
  expect(await page.evaluate(() => caches.keys())).toEqual(["parolnet-v10"]);

  // The new app is deployed. The old page is still open; the browser checks sw.js for an
  // update (on its own on a navigation; here the test asks for it).
  server.setRoot(OUT_DIR);
  await page.evaluate(() => navigator.serviceWorker.ready.then((r) => r.update()));

  // The new worker takes over, clears the old caches and reloads the window into the app.
  await expect(page.getByTestId("first-run")).toBeVisible({ timeout: 30_000 });
  await controlled(page);
  const caches = await page.evaluate(() => caches.keys());
  expect(caches).toHaveLength(1);
  expect(caches[0]).toMatch(/^parolnet-web-[0-9a-f]{16}$/);
  expect(
    await page.evaluate(() => navigator.serviceWorker.getRegistrations().then((r) => r.length)),
  ).toBe(1);
});
