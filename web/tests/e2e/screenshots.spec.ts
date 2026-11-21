// Screenshots of the lab and of every screen and state, on the lab's made-up state: light
// and dark, left-to-right (English) and right-to-left (Arabic), phone and desktop width. They are written to
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

test.use({ build: "test" });

/** "#/c/…" in the lab's world is "#/lab/c/…"; "#/lab" is the lab itself. */
async function go(page: Page, hash: string): Promise<void> {
  await page.evaluate((h) => {
    location.hash = h;
  }, hash === "#/lab" ? hash : "#/lab" + hash.slice(1));
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

        // The screens that came with the real state: add a contact, naming, verification,
        // settings, calls.
        await go(page, "#/lab");
        await page.getByTestId("lab-self-online").click();
        await go(page, "#/add");
        await expect(page.getByTestId("pairing-qr")).toBeVisible();
        await page.screenshot({ path: join(out, "add.png"), fullPage: true });
        await page.getByTestId("pairing-paste-open").click();
        await page.screenshot({ path: join(out, "add-paste.png") });
        await page.getByTestId("pairing-code-input").fill("ab12cd34".repeat(10));
        await page.getByTestId("pairing-code-submit").click();
        await expect(page.getByTestId("pairing-name")).toBeVisible();
        await page.screenshot({ path: join(out, "add-name.png") });

        await go(page, `#/c/${"07".repeat(32)}`);
        await expect(page.getByTestId("verify-prompt")).toBeVisible();
        await page.screenshot({ path: join(out, "conversation-not-verified.png") });
        await page.getByTestId("verify-open").click();
        await expect(page.getByTestId("safety-number")).toBeVisible();
        await page.screenshot({ path: join(out, "verify.png") });
        await page.getByTestId("verify-no-match").click();
        await page.screenshot({ path: join(out, "verify-mismatch.png") });
        await page.getByTestId("sheet-verify-close").click();
        await page.getByTestId("conversation-details").click();
        await page.screenshot({ path: join(out, "contact-details.png") });
        await page.getByTestId("sheet-details-close").click();

        await go(page, "#/settings");
        await expect(page.getByTestId("settings-screen")).toBeVisible();
        await page.screenshot({ path: join(out, "settings.png") });
        await page.getByTestId("settings-screen").screenshot({
          path: join(out, "settings-full.png"),
        }).catch(() => {});
        await page.getByTestId("settings-wipe").click();
        await page.screenshot({ path: join(out, "settings-wipe.png") });
        await page.getByTestId("sheet-wipe-close").click();

        await go(page, "#/lab");
        await page.getByTestId("lab-contact").selectOption("a1".repeat(32));
        await page.getByTestId("lab-call-incoming").click();
        await expect(page.getByTestId("incoming-call")).toBeVisible();
        await page.screenshot({ path: join(out, "call-incoming.png") });
        await page.getByTestId("call-accept").click();
        await expect(page.getByTestId("call-screen")).toBeVisible();
        await page.screenshot({ path: join(out, "call-active.png") });
        await page.getByTestId("call-hangup").click();
        await page.getByTestId("lab-call-outgoing").click();
        await page.screenshot({ path: join(out, "call-outgoing.png") });
        await page.getByTestId("call-hangup").click();
        await page.getByTestId("lab-call-ended-no-answer").click();
        await page.screenshot({ path: join(out, "call-ended.png") });
        await page.getByTestId("call-close").click();

        await page.getByTestId("lab-clear").click();
        await go(page, "#/");
        await expect(page.getByTestId("list-empty")).toBeVisible();
        await page.screenshot({ path: join(out, "list-empty.png") });
      });
    }
  }
}
