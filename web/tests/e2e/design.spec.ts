// The design system and the conversation screen, on fake state: what each state looks like
// and how it behaves, in every browser.
import { expect, expectClean, type Server, test, watch } from "./harness.ts";
import type { Page } from "@playwright/test";

const PEER = {
  mira: "a1".repeat(32),
  tomasz: "b2".repeat(32),
  ines: "d4".repeat(32),
  kofi: "e5".repeat(32),
  sana: "f6".repeat(32),
};
const PHONE = { width: 390, height: 844 };
const DESKTOP = { width: 1280, height: 900 };

async function open(page: Page, server: Server, hash: string): Promise<void> {
  await page.goto(server.url + hash);
  await page.evaluate(() => document.fonts.ready);
}

/** In-page navigation: the fake store (and the lab's settings) survive it. */
async function go(page: Page, hash: string): Promise<void> {
  await page.evaluate((h) => {
    location.hash = h;
  }, hash);
}

test.describe("phone", () => {
  test.use({ viewport: PHONE });

  test("stack navigation: list, then conversation, then back", async ({ page, server }) => {
    const problems = await watch(page, server);
    await open(page, server, "#/");
    await expect(page.getByTestId("conversation-list")).toBeVisible();
    await expect(page.getByTestId("conversation-placeholder")).toBeHidden();

    await page.getByTestId("row-b2b2b2b2").click();
    await expect(page.getByTestId("conversation")).toBeVisible();
    await expect(page.getByTestId("conversation-list")).toBeHidden();
    await expect(page.getByTestId("conversation-name")).toBeFocused();

    await page.getByTestId("conversation-back").click();
    await expect(page.getByTestId("conversation-list")).toBeVisible();
    await expectClean(problems);
  });

  test("every control in the app is at least 44px", async ({ page, server }) => {
    await open(page, server, `#/c/${PEER.kofi}`);
    await expect(page.getByTestId("panel-no-path")).toBeVisible();
    for (const hash of [`#/c/${PEER.kofi}`, "#/"]) {
      await go(page, hash);
      await page.waitForTimeout(50);
      const small = await page.evaluate(() =>
        [...document.querySelectorAll<HTMLElement>("button, a, input, textarea, select")]
          .filter((el) => el.offsetParent !== null)
          .map((el) => ({ id: el.dataset.testid, box: el.getBoundingClientRect() }))
          .filter(({ box }) => box.width < 44 || box.height < 44)
          .map(({ id, box }) => `${id}: ${Math.round(box.width)}x${Math.round(box.height)}`)
      );
      expect(small, `controls under 44px on ${hash}`).toEqual([]);
    }
  });
});

test.describe("desktop", () => {
  test.use({ viewport: DESKTOP });

  test("list and conversation side by side", async ({ page, server }) => {
    await open(page, server, "#/");
    await expect(page.getByTestId("conversation-list")).toBeVisible();
    await expect(page.getByTestId("conversation-placeholder")).toBeVisible();
    await page.getByTestId("row-a1a1a1a1").click();
    await expect(page.getByTestId("conversation")).toBeVisible();
    await expect(page.getByTestId("conversation-list")).toBeVisible();
    await expect(page.getByTestId("conversation-back")).toBeHidden();
    await expect(page.getByTestId("row-a1a1a1a1")).toHaveAttribute("aria-current", "page");
  });

  test("the list: online first, then away, with waiting chips", async ({ page, server }) => {
    await open(page, server, "#/");
    await expect(page.getByTestId("section-online").getByRole("link")).toHaveText([
      /Mira/,
      /Reading group/,
      /Ines/,
      /Kofi/,
      /Sana/,
    ]);
    await expect(page.getByTestId("section-away").getByRole("link")).toHaveText([/Tomasz/, /Jun/]);
    await expect(page.getByTestId("row-b2b2b2b2").getByTestId("waiting-chip")).toHaveText(
      "3 waiting",
    );
    await expect(page.getByTestId("row-a1a1a1a1").getByTestId("waiting-chip")).toHaveCount(0);
  });
});

test("every state of the line, in words", async ({ page, server }) => {
  await open(page, server, `#/c/${PEER.mira}`);
  const line = page.getByTestId("conversation").getByTestId("line");
  await expect(line).toHaveAttribute("aria-live", "polite");
  const expected: Array<[string, string, string]> = [
    [PEER.mira, "open", "Direct, end-to-end encrypted"],
    [PEER.tomasz, "waiting", "Waiting for Tomasz to come online"],
    [PEER.ines, "connecting", "Connecting to Ines"],
    [PEER.kofi, "no-path", "No direct path to Kofi"],
    [PEER.sana, "blocked", "Blocked for your safety"],
  ];
  for (const [peer, state, words] of expected) {
    await go(page, `#/c/${peer}`);
    await expect(line).toHaveAttribute("data-state", state);
    await expect(line).toHaveText(words);
  }
  // This device goes offline: that wins over whatever the contact's state is.
  await go(page, "#/lab");
  await page.getByTestId("lab-self-offline").click();
  await go(page, `#/c/${PEER.mira}`);
  await expect(line).toHaveAttribute("data-state", "self-offline");
  await expect(line).toHaveText("You are offline");
  await expect(page.getByTestId("list-line")).toHaveText("You are offline");
});

test("waiting: the composer stays usable and what is written waits here", async ({ page, server }) => {
  const problems = await watch(page, server);
  await open(page, server, `#/c/${PEER.tomasz}`);
  const field = page.getByTestId("composer-field");
  await expect(field).toBeEnabled();
  await expect(field).toHaveAttribute(
    "placeholder",
    "Tomasz is away. Your message will wait here.",
  );
  await expect(page.getByTestId("thread-caption")).toHaveText("Waiting on this device");
  await expect(page.locator('[data-kind="held"]')).toHaveCount(3);

  await field.fill("Back on Sunday.");
  await field.press("Enter");
  await expect(page.locator('[data-kind="held"]')).toHaveCount(4);
  await expect(page.locator('[data-kind="held"]').last()).toHaveText("Back on Sunday.");
  await expect(field).toHaveValue("");
  // One caption, under the last of our messages.
  await expect(page.getByTestId("thread-caption")).toHaveCount(1);

  await go(page, `#/c/${PEER.mira}`);
  await expect(page.getByTestId("composer-field")).toHaveAttribute("placeholder", "Message Mira");
  await page.getByTestId("composer-field").fill("See you there.");
  await page.getByTestId("composer-send").click();
  await expect(page.locator('[data-kind="delivered"]').last()).toHaveText("See you there.");
  await expect(page.getByTestId("thread-caption")).toHaveText("On Mira's device");
  await expectClean(problems);
});

test("a waiting message can be taken back or edited, by keyboard too", async ({ page, server }) => {
  await open(page, server, `#/c/${PEER.tomasz}`);
  const held = page.locator('button[data-kind="held"]');
  const first = held.first();
  await expect(first).toHaveText("The keys are with the neighbour at number 4.");

  // Keyboard: Enter opens the menu on its first item, arrows move, Escape returns.
  await first.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("menuitem", { name: "Take back" })).toBeFocused();
  await page.keyboard.press("ArrowDown");
  await expect(page.getByRole("menuitem", { name: "Edit" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("menu")).toHaveCount(0);
  await expect(first).toBeFocused();

  // Edit: the text goes to the composer, saving changes the waiting message.
  await first.click();
  await page.getByRole("menuitem", { name: "Edit" }).click();
  const field = page.getByTestId("composer-field");
  await expect(field).toBeFocused();
  await expect(field).toHaveValue("The keys are with the neighbour at number 4.");
  await expect(page.getByTestId("composer")).toContainText("Editing a waiting message");
  await field.fill("The keys are under the blue pot.");
  await field.press("Enter");
  await expect(first).toHaveText("The keys are under the blue pot.");
  await expect(page.getByTestId("toast")).toHaveText("Message changed");
  await expect(held).toHaveCount(3);

  // Take back: the message is gone, and a toast confirms what the person just did.
  await first.click();
  await page.getByRole("menuitem", { name: "Take back" }).click();
  await expect(held).toHaveCount(2);
  await expect(page.getByTestId("toast")).toHaveText("Message taken back");
});

test("calls: enabled on an open line, otherwise the buttons say why", async ({ page, server }) => {
  await open(page, server, `#/c/${PEER.tomasz}`);
  const voice = page.getByTestId("call-voice");
  await expect(voice).toHaveAttribute("aria-disabled", "true");
  await expect(voice).toHaveAccessibleName("Call Tomasz");
  await expect(page.getByTestId("call-hint")).toHaveText("");
  await voice.focus();
  await expect(page.getByTestId("call-hint")).toHaveText("Calls need Tomasz online");
  await page.getByTestId("composer-field").focus();
  await expect(page.getByTestId("call-hint")).toHaveText("");
  // (Playwright will not click an aria-disabled control; a person can, and a tap does this.)
  await page.getByTestId("call-video").dispatchEvent("click");
  await expect(page.getByTestId("call-hint")).toHaveText("Calls need Tomasz online");
  await expect(page.getByTestId("call-strip")).toHaveCount(0);

  await go(page, `#/c/${PEER.mira}`);
  await expect(page.getByTestId("call-voice")).not.toHaveAttribute("aria-disabled", "true");
  await page.getByTestId("call-voice").click();
  await expect(page.getByTestId("call-strip")).toContainText("Calling Mira");
  await page.getByTestId("call-end").click();
  await expect(page.getByTestId("call-strip")).toHaveCount(0);
});

test("no direct path: the amber panel says why and offers two fixes", async ({ page, server }) => {
  await open(page, server, `#/c/${PEER.kofi}`);
  const panel = page.getByTestId("panel-no-path");
  await expect(panel).toContainText("Your two networks will not connect directly.");
  await expect(panel).toContainText(
    "This happens on some mobile and office networks. Your messages are safe on this device and will send as soon as a path exists.",
  );
  await expect(panel.getByRole("button")).toHaveText(["Try again", "Use my own relay server"]);

  // A sheet: focus moves in, stays in, Escape closes and focus returns to what opened it.
  const opener = page.getByTestId("panel-own-relay");
  await opener.click();
  const sheet = page.getByTestId("sheet-relay");
  await expect(sheet).toBeVisible();
  for (let i = 0; i < 4; i++) {
    await page.keyboard.press("Tab");
    expect(
      await sheet.evaluate((el) =>
        el.contains(document.activeElement) || document.activeElement === document.body
      ),
    )
      .toBe(true);
  }
  await page.keyboard.press("Escape");
  await expect(sheet).toHaveCount(0);
  await expect(opener).toBeFocused();

  // Trying again is never silent: the line shows the attempt, then the same reason.
  await page.getByTestId("panel-try-again").click();
  await expect(page.getByTestId("conversation").getByTestId("line")).toHaveText(
    "Connecting to Kofi",
  );
  await expect(panel).toHaveCount(0);
  await expect(page.getByTestId("conversation").getByTestId("line")).toHaveText(
    "No direct path to Kofi",
  );
  await expect(page.getByTestId("panel-no-path")).toBeVisible();
});

test("blocked: the red panel", async ({ page, server }) => {
  await open(page, server, `#/c/${PEER.sana}`);
  const panel = page.getByTestId("panel-blocked");
  await expect(panel).toContainText("This connection did not pass its security check.");
  await expect(panel).toContainText(
    "Something between you and Sana changed the connection while it was being set up. ParolNet closed it. Nothing was sent.",
  );
  await expect(panel.getByRole("button")).toHaveText(["Try again", "What this means"]);
  await page.getByTestId("panel-what-this-means").click();
  await expect(page.getByTestId("sheet-blocked")).toBeVisible();
  await page.getByTestId("sheet-blocked-close").click();
  await expect(page.getByTestId("sheet-blocked")).toHaveCount(0);
});

/** Records when each bubble in the lab's live conversation turns from outlined to filled. */
async function recordFills(page: Page): Promise<void> {
  await page.evaluate(() => {
    const log: Array<{ id: string; at: number }> = [];
    (window as unknown as { __fills: typeof log }).__fills = log;
    const frame = document.querySelector('[data-testid="story-conversation"]')!;
    const kinds = new Map<string, string>();
    const scan = () => {
      for (const el of frame.querySelectorAll<HTMLElement>("[data-kind]")) {
        const id = el.dataset.testid!;
        const kind = el.dataset.kind!;
        if (kinds.get(id) === "held" && kind === "delivered") {
          log.push({ id, at: performance.now() });
        }
        kinds.set(id, kind);
      }
    };
    scan();
    new MutationObserver(scan).observe(frame, { subtree: true, childList: true, attributes: true });
  });
}

const fills = (page: Page) =>
  page.evaluate(() =>
    (window as unknown as { __fills: Array<{ id: string; at: number }> }).__fills
  );

test("the one animation: waiting messages fill in, in order, when the contact comes online", async ({ page, server }) => {
  await open(page, server, "#/lab");
  const frame = page.getByTestId("story-conversation");
  await expect(frame.locator('[data-kind="held"]')).toHaveCount(3);
  await expect(frame.getByTestId("thread-caption")).toHaveText("Waiting on this device");
  await recordFills(page);

  await page.getByTestId("lab-online").click();
  await expect(frame.getByTestId("line")).toHaveText("Direct, end-to-end encrypted");
  // While they fill, the caption still speaks for the ones that have not.
  await expect(frame.getByTestId("thread-caption")).toHaveText("Waiting on this device");
  await expect(frame.locator('[data-kind="held"]')).toHaveCount(0);
  await expect(frame.getByTestId("thread-caption")).toHaveText("On Tomasz's device");

  const log = await fills(page);
  expect(log.map((f) => f.id)).toEqual(["bubble-8", "bubble-9", "bubble-10"]);
  // About 350ms apart (generous bounds: timers on a loaded machine).
  for (let i = 1; i < log.length; i++) {
    const gap = log[i].at - log[i - 1].at;
    expect(gap).toBeGreaterThan(250);
    expect(gap).toBeLessThan(1500);
  }
  // The fill itself is a 450ms transition, and nothing else on the page transitions.
  const bubble = frame.getByTestId("bubble-10");
  expect(await bubble.evaluate((el) => getComputedStyle(el).transitionDuration)).toContain("0.45s");
  const other = frame.getByTestId("bubble-7");
  expect(await other.evaluate((el) => getComputedStyle(el).transitionDuration)).toBe("0s");
});

test("reduced motion: the waiting messages simply change", async ({ page, server }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await open(page, server, "#/lab");
  const frame = page.getByTestId("story-conversation");
  await expect(frame.locator('[data-kind="held"]')).toHaveCount(3);
  await recordFills(page);
  await page.getByTestId("lab-online").click();
  await expect(frame.locator('[data-kind="held"]')).toHaveCount(0);
  const log = await fills(page);
  expect(log).toHaveLength(3);
  expect(log[2].at - log[0].at).toBeLessThan(100);
  expect(
    await frame.getByTestId("bubble-10").evaluate((el) => getComputedStyle(el).transitionDuration),
  ).toBe("0s");
});

test("right to left mirrors the thread and the line; Arabic loads on demand", async ({ page, server }) => {
  const problems = await watch(page, server);
  const requests: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  await page.setViewportSize(DESKTOP);
  await open(page, server, "#/lab");
  const frame = page.getByTestId("story-conversation");
  const sent = frame.getByTestId("bubble-7");
  const near = frame.locator(".line__end--near");
  const far = frame.locator(".line__end--far");
  const centre = async () => {
    const box = (await frame.boundingBox())!;
    return box.x + box.width / 2;
  };

  expect((await sent.boundingBox())!.x).toBeGreaterThan(await centre());
  expect((await near.boundingBox())!.x).toBeLessThan((await far.boundingBox())!.x);
  expect(requests.some((url) => /vazirmatn/i.test(url))).toBe(false);
  expect(requests.some((url) => /assets\/ar-/.test(url))).toBe(false);

  await page.getByTestId("lab-locale-ar").click();
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  await expect(page.locator("html")).toHaveAttribute("lang", "ar");
  await expect(frame.getByTestId("line")).toHaveText("في انتظار اتصال Tomasz");
  await expect(frame.getByTestId("thread-caption")).toHaveText("في الانتظار على هذا الجهاز");
  const box = (await sent.boundingBox())!;
  expect(box.x + box.width).toBeLessThan(await centre());
  expect((await near.boundingBox())!.x).toBeGreaterThan((await far.boundingBox())!.x);
  // The catalogue chunk and the Arabic font came only now.
  expect(requests.some((url) => /assets\/ar-[A-Z0-9]{8}\.js$/.test(url))).toBe(true);
  await page.evaluate(() => document.fonts.ready);
  expect(requests.some((url) => url.endsWith("fonts/vazirmatn.css"))).toBe(true);
  // Codes stay left to right.
  expect(await page.getByTestId("lab-code").evaluate((el) => getComputedStyle(el).direction)).toBe(
    "ltr",
  );

  // Direction alone (English, right to left) also mirrors.
  await page.getByTestId("lab-locale-en").click();
  await expect(page.locator("html")).toHaveAttribute("dir", "ltr");
  await page.getByTestId("lab-dir-rtl").click();
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  await expect(frame.getByTestId("line")).toHaveText("Waiting for Tomasz to come online");
  await expectClean(problems);
});

test("theme: follows the system, and an override is kept on this device", async ({ page, server }) => {
  const paper = () =>
    page.evaluate(() => getComputedStyle(document.documentElement).backgroundColor);
  await page.emulateMedia({ colorScheme: "light" });
  await open(page, server, "#/lab");
  expect(await paper()).toBe("rgb(243, 245, 244)");
  await page.emulateMedia({ colorScheme: "dark" });
  expect(await paper()).toBe("rgb(15, 24, 29)");

  await page.getByTestId("lab-theme-light").click();
  expect(await paper()).toBe("rgb(243, 245, 244)");
  await page.reload();
  // Applied by theme-boot.js before the app's bundle runs.
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  expect(await paper()).toBe("rgb(243, 245, 244)");
  await expect(page.getByTestId("lab-theme-light")).toHaveAttribute("aria-pressed", "true");

  await page.getByTestId("lab-theme-system").click();
  await expect(page.locator("html")).not.toHaveAttribute("data-theme", /.+/);
  expect(await paper()).toBe("rgb(15, 24, 29)");
});

test("empty state invites adding the first contact; adding one opens its conversation", async ({ page, server }) => {
  await open(page, server, "#/lab");
  await page.getByTestId("lab-clear").click();
  await go(page, "#/");
  const empty = page.getByTestId("list-empty");
  await expect(empty).toContainText("No one here yet");
  await empty.getByTestId("add-contact").click();

  const sheet = page.getByTestId("sheet-add");
  await expect(sheet).toBeVisible();
  // The pairing code is grouped in fours.
  await expect(page.getByTestId("own-code").locator("span")).toHaveText([
    "7K4M",
    "Q2ZD",
    "9XTB",
    "H6RP",
  ]);
  // Never silent: an incomplete form says what is missing.
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("add-problem")).toHaveText("Enter their name and their code.");
  await page.getByTestId("add-name").fill("Noor");
  await page.getByTestId("add-code").fill("ab12 cd34 ef56 ab78");
  await page.getByTestId("add-submit").click();

  await expect(sheet).toHaveCount(0);
  await expect(page.getByTestId("toast")).toHaveText("Noor added");
  await expect(page.getByTestId("conversation-name")).toHaveText("Noor");
  await expect(page.getByTestId("composer-field")).toHaveAttribute(
    "placeholder",
    "Noor is away. Your message will wait here.",
  );
});
