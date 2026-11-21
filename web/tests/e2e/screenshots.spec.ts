// Screenshots of the lab and of every conversation state: light and dark, left-to-right
// (English) and right-to-left (Arabic), phone and desktop width. They are written to
// tests/e2e/artifacts/<browser>/ as test artifacts for people to look at; there are no
// committed baselines to compare against yet.
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import type { Page } from "@playwright/test";
import { ARTIFACTS_DIR, expect, test } from "./harness.ts";

const SIZES = { phone: { width: 390, height: 844 }, desktop: { width: 1280, height: 900 } };
const CONVERSATIONS: Array<[string, string, string]> = [
  ["direct", "a1", "open"],
  ["waiting", "b2", "waiting"],
  ["connecting", "d4", "connecting"],
  ["no-path", "e5", "no-path"],
  ["blocked", "f6", "blocked"],
];

async function go(page: Page, hash: string): Promise<void> {
  await page.evaluate((h) => {
    location.hash = h;
  }, hash);
}

for (const theme of ["light", "dark"] as const) {
  for (const dir of ["ltr", "rtl"] as const) {
    for (const [size, viewport] of Object.entries(SIZES)) {
      test(`screenshots: ${theme} ${dir} ${size}`, async ({ page, server, browserName }) => {
        // The full matrix in Chromium; one combination each way in the other two.
        const smoke = (theme === "light" && dir === "ltr" && size === "phone") ||
          (theme === "dark" && dir === "rtl" && size === "desktop");
        test.skip(browserName !== "chromium" && !smoke, "full matrix runs in Chromium");

        const out = join(ARTIFACTS_DIR, browserName, `${theme}-${dir}-${size}`);
        await mkdir(out, { recursive: true });
        await page.setViewportSize(viewport);
        await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
        await page.goto(server.url + "#/lab");
        await expect(page.getByTestId("wasm-result")).toBeVisible();
        if (dir === "rtl") {
          await page.getByTestId("lab-locale-ar").click();
          await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
        }
        await page.evaluate(() => document.fonts.ready);
        await page.screenshot({ path: join(out, "lab.png"), fullPage: true });

        await go(page, "#/");
        await expect(page.getByTestId("conversation-list")).toBeVisible();
        await page.screenshot({ path: join(out, "list.png") });

        for (const [name, seed, state] of CONVERSATIONS) {
          await go(page, `#/c/${seed.repeat(32)}`);
          await expect(page.getByTestId("conversation")).toHaveAttribute("data-line", state);
          await page.screenshot({ path: join(out, `conversation-${name}.png`) });
        }

        await go(page, "#/lab");
        await page.getByTestId("lab-self-offline").click();
        await go(page, `#/c/${"b2".repeat(32)}`);
        await expect(page.getByTestId("conversation")).toHaveAttribute("data-line", "self-offline");
        await page.screenshot({ path: join(out, "conversation-self-offline.png") });

        await go(page, "#/lab");
        await page.getByTestId("lab-self-online").click();
        await page.getByTestId("lab-clear").click();
        await go(page, "#/");
        await expect(page.getByTestId("list-empty")).toBeVisible();
        await page.screenshot({ path: join(out, "list-empty.png") });
      });
    }
  }
}
