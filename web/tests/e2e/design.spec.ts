// The design system and the screens, on the state lab's made-up state (the test build, under
// #/lab): what each state looks like and how it behaves, in every browser. The same screens
// on the real engine are in real.flows.ts.
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

test.use({ build: "test" });

/** "#/c/…" in the lab's world is "#/lab/c/…"; "#/lab" is the lab itself. */
function lab(hash: string): string {
  return hash === "#/lab" ? hash : "#/lab" + hash.slice(1);
}

async function open(page: Page, server: Server, hash: string): Promise<void> {
  await page.goto(server.url + lab(hash));
  await page.evaluate(() => document.fonts.ready);
}

/** In-page navigation: the fake store (and the lab's settings) survive it. */
async function go(page: Page, hash: string): Promise<void> {
  await page.evaluate((h) => {
    location.hash = h;
  }, lab(hash));
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
    for (
      const hash of [
        `#/c/${PEER.kofi}`,
        `#/c/${"07".repeat(32)}`,
        "#/",
        "#/add",
        "#/settings",
      ]
    ) {
      await go(page, hash);
      await page.waitForTimeout(50);
      const small = await page.evaluate(() =>
        [...document.querySelectorAll<HTMLElement>(
          "button, a, input, textarea, select",
        )]
          .filter((el) => el.offsetParent !== null)
          .map((el) => ({
            id: el.dataset.testid,
            box: el.getBoundingClientRect(),
          }))
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
    await expect(page.getByTestId("row-a1a1a1a1")).toHaveAttribute(
      "aria-current",
      "page",
    );
  });

  test("the list: online first, then away, with waiting chips", async ({ page, server }) => {
    await open(page, server, "#/");
    // Online first, then by last activity (newest first), then by name.
    await expect(page.getByTestId("section-online").getByRole("link"))
      .toHaveText([
        /Mira/,
        /Kofi/,
        /Ines/,
        /Reading group/,
        /Sana/,
      ]);
    await expect(page.getByTestId("section-away").getByRole("link")).toHaveText(
      [/Tomasz/, /Jun/],
    );
    await expect(page.getByTestId("row-b2b2b2b2").getByTestId("waiting-chip"))
      .toHaveText(
        "3 waiting",
      );
    await expect(page.getByTestId("row-a1a1a1a1").getByTestId("waiting-chip"))
      .toHaveCount(0);
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
  const field = page.getByTestId("composer-input");
  await expect(field).toBeEnabled();
  await expect(field).toHaveAttribute(
    "placeholder",
    "Tomasz is away. Your message will wait here.",
  );
  await expect(page.getByTestId("thread-caption")).toHaveText(
    "Waiting on this device",
  );
  await expect(page.locator('[data-kind="held"]')).toHaveCount(3);

  await field.fill("Back on Sunday.");
  await field.press("Enter");
  await expect(page.locator('[data-kind="held"]')).toHaveCount(4);
  await expect(page.locator('[data-kind="held"]').last()).toHaveText(
    "Back on Sunday.",
  );
  await expect(field).toHaveValue("");
  // One caption, under the last of our messages.
  await expect(page.getByTestId("thread-caption")).toHaveCount(1);

  await go(page, `#/c/${PEER.mira}`);
  await expect(page.getByTestId("composer-input")).toHaveAttribute(
    "placeholder",
    "Message Mira",
  );
  await page.getByTestId("composer-input").fill("See you there.");
  await page.getByTestId("composer-send").click();
  await expect(page.locator('[data-kind="delivered"]').last()).toHaveText(
    "See you there.",
  );
  await expect(page.getByTestId("thread-caption")).toHaveText(
    "On Mira's device",
  );
  await expectClean(problems);
});

test("a waiting message can be taken back or edited, by keyboard too", async ({ page, server }) => {
  await open(page, server, `#/c/${PEER.tomasz}`);
  const held = page.locator('button[data-kind="held"]');
  const first = held.first();
  await expect(first).toHaveText(
    "The keys are with the neighbour at number 4.",
  );

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
  const field = page.getByTestId("composer-input");
  await expect(field).toBeFocused();
  await expect(field).toHaveValue(
    "The keys are with the neighbour at number 4.",
  );
  await expect(page.getByTestId("composer")).toContainText(
    "Editing a waiting message",
  );
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
  await expect(page.getByTestId("call-hint")).toHaveText(
    "Calls need Tomasz online",
  );
  await page.getByTestId("composer-input").focus();
  await expect(page.getByTestId("call-hint")).toHaveText("");
  // (Playwright will not click an aria-disabled control; a person can, and a tap does this.)
  await page.getByTestId("call-video").dispatchEvent("click");
  await expect(page.getByTestId("call-hint")).toHaveText(
    "Calls need Tomasz online",
  );
  await expect(page.getByTestId("call-screen")).toHaveCount(0);

  // Online but unreachable is said differently from away.
  await go(page, `#/c/${PEER.kofi}`);
  await page.getByTestId("call-voice").focus();
  await expect(page.getByTestId("call-hint")).toHaveText(
    "Calls need a direct line to Kofi",
  );

  await go(page, `#/c/${PEER.mira}`);
  await expect(page.getByTestId("call-voice")).not.toHaveAttribute(
    "aria-disabled",
    "true",
  );
  await page.getByTestId("call-voice").click();
  const call = page.getByTestId("call-screen");
  await expect(call).toHaveAttribute("data-state", "Outgoing");
  await expect(page.getByTestId("call-status")).toHaveText("Calling Mira…");
  await page.getByTestId("call-hangup").click();
  await expect(call).toHaveCount(0);
});

test("the composer never says a contact is away when they are online", async ({ page, server }) => {
  await open(page, server, `#/c/${PEER.kofi}`);
  const field = page.getByTestId("composer-input");
  // No direct path: Kofi is online, the message waits for a path.
  await expect(field).toHaveAttribute(
    "placeholder",
    "Your message will wait here until a path exists.",
  );
  await go(page, `#/c/${PEER.sana}`);
  await expect(field).toHaveAttribute(
    "placeholder",
    "Your message will wait here until a path exists.",
  );
  await go(page, `#/c/${PEER.tomasz}`);
  await expect(field).toHaveAttribute(
    "placeholder",
    "Tomasz is away. Your message will wait here.",
  );
});

test("no direct path: the amber panel says why and offers two fixes", async ({ page, server }) => {
  await open(page, server, `#/c/${PEER.kofi}`);
  const panel = page.getByTestId("panel-no-path");
  await expect(panel).toContainText(
    "Your two networks will not connect directly.",
  );
  await expect(panel).toContainText(
    "This happens on some mobile and office networks. Your messages are safe on this device and will send as soon as a path exists.",
  );
  await expect(panel.getByRole("button")).toHaveText([
    "Try again",
    "Use my own relay server",
  ]);

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

  // The other fix leads to where a relay server of one's own is set up.
  await page.getByTestId("panel-own-relay").click();
  await expect(page.getByTestId("settings-turn")).toBeVisible();
  await expect(page.getByTestId("settings-screen-title")).toBeFocused();
});

test("blocked: the red panel", async ({ page, server }) => {
  await open(page, server, `#/c/${PEER.sana}`);
  const panel = page.getByTestId("panel-blocked");
  await expect(panel).toContainText(
    "This connection did not pass its security check.",
  );
  await expect(panel).toContainText(
    "Something between you and Sana changed the connection while it was being set up. ParolNet closed it. Nothing was sent.",
  );
  await expect(panel.getByRole("button")).toHaveText([
    "Try again",
    "What this means",
  ]);
  // A sheet: focus moves in, stays in, Escape closes and focus returns to what opened it.
  const opener = page.getByTestId("panel-what-this-means");
  await opener.click();
  const sheet = page.getByTestId("sheet-blocked");
  await expect(sheet).toBeVisible();
  for (let i = 0; i < 4; i++) {
    await page.keyboard.press("Tab");
    expect(
      await sheet.evaluate((el) =>
        el.contains(document.activeElement) ||
        document.activeElement === document.body
      ),
    )
      .toBe(true);
  }
  await page.keyboard.press("Escape");
  await expect(sheet).toHaveCount(0);
  await expect(opener).toBeFocused();
  await opener.click();
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
    new MutationObserver(scan).observe(frame, {
      subtree: true,
      childList: true,
      attributes: true,
    });
  });
}

const fills = (page: Page) =>
  page.evaluate(() =>
    (window as unknown as { __fills: Array<{ id: string; at: number }> })
      .__fills
  );

test("the one animation: waiting messages fill in, in order, when the contact comes online", async ({ page, server }) => {
  await open(page, server, "#/lab");
  const frame = page.getByTestId("story-conversation");
  await expect(frame.locator('[data-kind="held"]')).toHaveCount(3);
  await expect(frame.getByTestId("thread-caption")).toHaveText(
    "Waiting on this device",
  );
  await recordFills(page);

  await page.getByTestId("lab-online").click();
  await expect(frame.getByTestId("line")).toHaveText(
    "Direct, end-to-end encrypted",
  );
  // While they fill, the caption still speaks for the ones that have not.
  await expect(frame.getByTestId("thread-caption")).toHaveText(
    "Waiting on this device",
  );
  await expect(frame.locator('[data-kind="held"]')).toHaveCount(0);
  await expect(frame.getByTestId("thread-caption")).toHaveText(
    "On Tomasz's device",
  );

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
  expect(await bubble.evaluate((el) => getComputedStyle(el).transitionDuration))
    .toContain("0.45s");
  const other = frame.getByTestId("bubble-7");
  expect(await other.evaluate((el) => getComputedStyle(el).transitionDuration))
    .toBe("0s");
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
  expect((await near.boundingBox())!.x).toBeLessThan(
    (await far.boundingBox())!.x,
  );
  expect(requests.some((url) => /vazirmatn/i.test(url))).toBe(false);
  expect(requests.some((url) => /assets\/ar-/.test(url))).toBe(false);

  await page.getByTestId("lab-locale-ar").click();
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  await expect(page.locator("html")).toHaveAttribute("lang", "ar");
  await expect(frame.getByTestId("line")).toHaveText("في انتظار أن يصبح Tomasz متصلًا");
  await expect(frame.getByTestId("thread-caption")).toHaveText(
    "في الانتظار على هذا الجهاز",
  );
  const box = (await sent.boundingBox())!;
  expect(box.x + box.width).toBeLessThan(await centre());
  expect((await near.boundingBox())!.x).toBeGreaterThan(
    (await far.boundingBox())!.x,
  );
  // The catalogue chunk and the Arabic font came only now.
  expect(requests.some((url) => /assets\/ar-[A-Z0-9]{8}\.js$/.test(url))).toBe(
    true,
  );
  await page.evaluate(() => document.fonts.ready);
  expect(requests.some((url) => url.endsWith("fonts/vazirmatn.css"))).toBe(
    true,
  );
  // Codes stay left to right.
  expect(
    await page.getByTestId("lab-code").evaluate((el) => getComputedStyle(el).direction),
  ).toBe(
    "ltr",
  );

  // Direction alone (English, right to left) also mirrors.
  await page.getByTestId("lab-locale-en").click();
  await expect(page.locator("html")).toHaveAttribute("dir", "ltr");
  await page.getByTestId("lab-dir-rtl").click();
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  await expect(frame.getByTestId("line")).toHaveText(
    "Waiting for Tomasz to come online",
  );
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
  await expect(page.getByTestId("lab-theme-light")).toHaveAttribute(
    "aria-pressed",
    "true",
  );

  await page.getByTestId("lab-theme-system").click();
  await expect(page.locator("html")).not.toHaveAttribute("data-theme", /.+/);
  expect(await paper()).toBe("rgb(15, 24, 29)");
});

test("empty state invites adding the first contact; adding one names it and opens its conversation", async ({ page, server }) => {
  await open(page, server, "#/lab");
  await page.getByTestId("lab-clear").click();
  await go(page, "#/");
  const empty = page.getByTestId("list-empty");
  await expect(empty).toContainText("No one here yet");
  await empty.getByTestId("add-contact").click();

  // One screen: this device's code as a picture and as text, and two ways to take theirs.
  await expect(page.getByTestId("add-screen-title")).toBeFocused();
  await expect(page.getByTestId("pairing-qr")).toBeVisible();
  await expect(page.getByTestId("pairing-code").locator("span").first())
    .toHaveText(
      /^[0-9a-f]{4}$/,
    );
  await expect(page.getByTestId("pairing-expiry")).toHaveText(
    "Good for 28 minutes. Works once.",
  );
  await expect(page.getByTestId("pairing-ip")).toContainText(
    "Contacts you add can see your IP address.",
  );
  await expect(page.getByTestId("pairing-hide-ip")).toHaveText("Hide it");

  // Never silent: a missing or broken code says what is wrong and what to do.
  await page.getByTestId("pairing-paste-open").click();
  await expect(page.getByTestId("pairing-code-input")).toBeFocused();
  await page.getByTestId("pairing-code-submit").click();
  await expect(page.getByTestId("pairing-problem")).toHaveText(
    "Paste the code from your contact.",
  );
  await page.getByTestId("pairing-code-input").fill("ab12 cd34");
  await page.getByTestId("pairing-code-submit").click();
  await expect(page.getByTestId("pairing-problem")).toHaveText(
    "That is not a complete ParolNet code. Ask them to copy the whole code again.",
  );
  await page.getByTestId("pairing-code-input").fill("ab12cd34".repeat(10));
  await page.getByTestId("pairing-code-submit").click();

  // Then a name, which is the person's own business.
  await expect(page.getByTestId("pairing-name-body")).toHaveText(
    "Their code was sent to you. Compare safety numbers with them when you can.",
  );
  await expect(page.getByTestId("contact-name-input")).toBeFocused();
  await page.getByTestId("contact-name-submit").click();
  await expect(page.getByTestId("contact-name-problem")).toHaveText(
    "The name cannot be empty.",
  );
  await page.getByTestId("contact-name-input").fill("Noor");
  await page.keyboard.press("Enter");

  await expect(page.getByTestId("toast")).toHaveText("Noor added");
  await expect(page.getByTestId("conversation-name")).toHaveText("Noor");
  await expect(page.getByTestId("composer-input")).toHaveAttribute(
    "placeholder",
    "Noor is away. Your message will wait here.",
  );
  // A pasted code proves nothing about who sent it.
  await expect(page.getByTestId("verify-prompt")).toContainText(
    "Not verified yet",
  );
});

test("comparing safety numbers: a match verifies, a mismatch offers to start over", async ({ page, server }) => {
  const jun = "07".repeat(32);
  await open(page, server, `#/c/${jun}`);
  await expect(page.getByTestId("verify-prompt")).toContainText(
    "Not verified yet",
  );

  // Keyboard only: open, read, confirm.
  await page.getByTestId("verify-open").focus();
  await page.keyboard.press("Enter");
  const sheet = page.getByTestId("sheet-verify");
  await expect(sheet).toBeVisible();
  const groups = page.getByTestId("safety-number").locator("span");
  await expect(groups).toHaveCount(12);
  for (const group of await groups.allInnerTexts()) {
    expect(group).toMatch(/^\d{5}$/);
  }
  expect(
    await page.getByTestId("safety-number").evaluate((el) => getComputedStyle(el).direction),
  ).toBe("ltr");

  // They don't match: why that matters, and the one safe thing to do.
  await page.getByTestId("verify-no-match").click();
  await expect(page.getByTestId("verify-mismatch")).toContainText(
    "Remove this contact and add each other again",
  );
  await page.getByTestId("verify-back").click();
  await page.getByTestId("verify-match").click();
  await expect(sheet).toHaveCount(0);
  await expect(page.getByTestId("toast")).toHaveText("Jun is verified");
  await expect(page.getByTestId("verify-prompt")).toHaveCount(0);

  // The details sheet says how the contact was verified, and renames.
  await page.getByTestId("conversation-details").click();
  await expect(page.getByTestId("details-verified")).toHaveText(
    "Verified: you compared safety numbers.",
  );
  await page.getByTestId("details-name").fill("Jun K.");
  await page.getByTestId("details-save").click();
  await expect(page.getByTestId("conversation-name")).toHaveText("Jun K.");

  // A mismatch, taken to its end: the contact is removed and the add screen opens.
  await page.getByTestId("conversation-details").click();
  await page.getByTestId("details-verify").click();
  await page.getByTestId("verify-no-match").click();
  await page.getByTestId("verify-remove").click();
  await expect(page.getByTestId("add-screen")).toBeVisible();
  await expect(page.getByTestId("toast")).toHaveText("Jun K. removed");
  await go(page, "#/");
  await expect(page.getByTestId("conversation-list")).not.toContainText("Jun");
});

test("removing a contact asks first", async ({ page, server }) => {
  await open(page, server, `#/c/${PEER.tomasz}`);
  await page.getByTestId("conversation-details").click();
  await page.getByTestId("details-remove").click();
  const sheet = page.getByTestId("sheet-remove");
  await expect(sheet).toContainText("Remove Tomasz?");
  await expect(sheet).toContainText("Tomasz is not told.");
  await page.getByTestId("remove-cancel").click();
  await expect(page.getByTestId("conversation-name")).toHaveText("Tomasz");
  await page.getByTestId("conversation-details").click();
  await page.getByTestId("details-remove").click();
  await page.getByTestId("remove-confirm").click();
  await expect(page.getByTestId("conversation-missing")).toHaveCount(0);
  await expect(page.getByTestId("conversation-list")).not.toContainText(
    "Tomasz",
  );
});

test.describe("an incoming call", () => {
  test("phone: the whole screen; Accept and Decline by keyboard", async ({ page, server }) => {
    await page.setViewportSize(PHONE);
    await open(page, server, "#/lab");
    await page.getByTestId("lab-contact").selectOption(PEER.mira);
    await page.getByTestId("lab-call-incoming").click();
    const incoming = page.getByTestId("incoming-call");
    await expect(incoming).toBeVisible();
    await expect(page.getByTestId("incoming-call-words")).toHaveText(
      "Mira is calling with video",
    );
    const box = (await incoming.boundingBox())!;
    expect(box.width).toBe(PHONE.width);
    expect(box.height).toBe(PHONE.height);
    // Focus is on the words: Enter or Space pressed for something else answers nothing.
    await expect(page.getByTestId("incoming-call-words")).toBeFocused();
    await page.keyboard.press("Enter");
    await page.keyboard.press("Escape");
    await expect(incoming).toBeVisible();
    await page.keyboard.press("Tab");
    await expect(page.getByTestId("call-accept")).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(page.getByTestId("call-decline")).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(incoming).toHaveCount(0);
    await expect(page.getByTestId("call-screen")).toHaveCount(0);
  });

  test("wide: a banner over the app, also over an open sheet", async ({ page, server }) => {
    await page.setViewportSize(DESKTOP);
    await open(page, server, "#/lab");
    await page.getByTestId("lab-contact").selectOption(PEER.mira);
    await page.getByTestId("lab-open-sheet").click();
    await expect(page.getByTestId("lab-sheet")).toBeVisible();
    await page.getByTestId("lab-call-incoming").dispatchEvent("click");
    const incoming = page.getByTestId("incoming-call");
    await expect(incoming).toBeVisible();
    const box = (await incoming.boundingBox())!;
    expect(box.width).toBeLessThan(700);
    expect(box.height).toBeLessThan(200);
    expect(box.y).toBeLessThan(40);
    await page.getByTestId("call-accept").click();
    await expect(page.getByTestId("call-screen")).toHaveAttribute(
      "data-state",
      "Active",
    );
  });
});

test("a call under way: controls with names and states; Escape does not end it", async ({ page, server }) => {
  await open(page, server, "#/lab");
  await page.getByTestId("lab-contact").selectOption(PEER.mira);
  await page.getByTestId("lab-call-active").click();
  const call = page.getByTestId("call-screen");
  await expect(call).toHaveAttribute("data-state", "Active");
  await expect(page.getByTestId("call-status")).toHaveText(
    "Direct, end-to-end encrypted",
  );
  await expect(page.getByTestId("call-timer")).toHaveText(/^0:0\d$/);

  const mute = page.getByTestId("call-mute");
  await expect(mute).toHaveAccessibleName("Mute microphone");
  await expect(mute).toHaveAttribute("aria-pressed", "false");
  await mute.click();
  await expect(mute).toHaveAccessibleName("Unmute microphone");
  await expect(mute).toHaveAttribute("aria-pressed", "true");
  const camera = page.getByTestId("call-camera");
  await camera.click();
  await expect(camera).toHaveAccessibleName("Turn camera on");

  await page.keyboard.press("Escape");
  await expect(call).toBeVisible();
  // The rest of the app is inert behind it.
  expect(
    await page.evaluate(() => {
      const control = document.querySelector<HTMLElement>(
        '[data-testid="lab-reset"]',
      )!;
      control.focus();
      return document.activeElement === control;
    }),
  ).toBe(false);
  await expect(page.getByTestId("call-hangup")).toHaveAccessibleName(
    "End call",
  );
  await page.getByTestId("call-hangup").click();
  await expect(call).toHaveCount(0);

  // A voice call has no camera control.
  await page.getByTestId("lab-call-voice").click();
  await expect(page.getByTestId("call-mute")).toBeVisible();
  await expect(page.getByTestId("call-camera")).toHaveCount(0);
  await page.getByTestId("call-hangup").click();
});

test("how a call ended, in plain words", async ({ page, server }) => {
  await open(page, server, "#/lab");
  await page.getByTestId("lab-contact").selectOption(PEER.mira);
  const expected: Array<[string, string]> = [
    ["they-ended", "Mira ended the call"],
    ["they-declined", "Mira declined"],
    ["no-answer", "Mira did not answer"],
    ["missed", "Missed call from Mira"],
    [
      "failed",
      "The call could not connect. Check that you are both online, then call again.",
    ],
  ];
  for (const [id, words] of expected) {
    await page.getByTestId(`lab-call-ended-${id}`).click();
    await expect(page.getByTestId("call-screen")).toHaveAttribute(
      "data-state",
      "Ended",
    );
    await expect(page.getByTestId("call-status")).toHaveText(words);
    await page.getByTestId("call-close").click();
    await expect(page.getByTestId("call-screen")).toHaveCount(0);
  }
});

test("settings: five groups, a typed confirmation before everything is deleted", async ({ page, server }) => {
  const problems = await watch(page, server);
  await open(page, server, "#/settings");
  await expect(page.getByTestId("settings-screen-title")).toBeFocused();
  await expect(
    page.getByTestId("settings-screen").getByRole("heading", { level: 2 }),
  ).toHaveText([
    "You",
    "Connection",
    "Calls and devices",
    "Appearance and language",
    "About",
  ]);
  await expect(page.getByTestId("settings-status")).toHaveText(
    "Connected. Your contacts can reach you.",
  );
  await expect(page.getByTestId("settings-about")).toContainText(
    "ParolNet rings and receives only while it is open.",
  );

  // Theme and language, kept on this device.
  await page.getByTestId("theme-dark").click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.getByTestId("theme-system").click();
  await page.getByTestId("settings-language").selectOption("de");
  await expect(page.locator("html")).toHaveAttribute("lang", "de");
  // Every catalogue is complete: nothing on the screen stays in English.
  await expect(page.getByTestId("settings-screen-title")).toHaveText(
    "Einstellungen",
  );
  await expect(page.getByTestId("settings-wipe")).toHaveText(
    "Alle Daten auf diesem Gerät löschen",
  );
  await page.getByTestId("settings-language").selectOption("en");

  // A relay server of one's own: the password is never shown back.
  await page.getByTestId("turn-uri").fill("turn:turn.example.org:3478");
  await page.getByTestId("turn-username").fill("me");
  await page.getByTestId("turn-password").fill("s3cret-pass");
  await page.getByTestId("turn-only").click();
  await expect(page.getByTestId("turn-only")).toHaveAttribute(
    "aria-checked",
    "true",
  );
  await page.getByTestId("turn-save").click();
  await expect(page.getByTestId("toast")).toHaveText("Relay server saved");
  await expect(page.getByTestId("turn-password")).toHaveValue("");
  await expect(page.getByTestId("turn-password")).toHaveAttribute(
    "type",
    "password",
  );
  expect(await page.content()).not.toContain("s3cret-pass");
  await page.getByTestId("turn-remove").click();
  await expect(page.getByTestId("toast")).toHaveText("Relay server removed");

  // The app's own server, under Advanced: a wrong address is refused in words.
  await page.getByTestId("settings-advanced").locator("summary").click();
  await page.getByTestId("relay-url").fill("https://example.org");
  await page.getByTestId("relay-save").click();
  await expect(page.getByTestId("relay-problem")).toHaveText(
    "The address must start with wss:// or ws://",
  );

  // Delete all data: nothing happens until the word is typed.
  await page.getByTestId("settings-wipe").click();
  const confirm = page.getByTestId("wipe-confirm");
  await expect(confirm).toBeDisabled();
  await page.getByTestId("wipe-input").fill("delet");
  await expect(confirm).toBeDisabled();
  await page.getByTestId("wipe-input").fill("Delete");
  await expect(confirm).toBeEnabled();
  await confirm.click();
  await go(page, "#/");
  await expect(page.getByTestId("list-empty")).toBeVisible();
  await expectClean(problems);
});

test("the focus ring is visible in both themes", async ({ page, server }) => {
  const ring = async () => {
    await page.getByTestId("lab-btn-quiet").focus();
    await page.keyboard.press("Shift+Tab");
    await page.keyboard.press("Tab");
    return page.getByTestId("lab-btn-quiet").evaluate((el) => {
      const style = getComputedStyle(el);
      return `${style.outlineStyle} ${style.outlineWidth} ${style.outlineColor}`;
    });
  };
  await page.emulateMedia({ colorScheme: "light" });
  await open(page, server, "#/lab");
  // lamp (#8A5A00) in light: 5.4:1 on paper. lamp-line would be 2.3:1.
  expect(await ring()).toBe("solid 3px rgb(138, 90, 0)");
  await page.emulateMedia({ colorScheme: "dark" });
  expect(await ring()).toBe("solid 3px rgb(217, 152, 30)");
});

test("right to left on the new screens: nothing overflows, codes stay left to right", async ({ page, server }) => {
  await page.setViewportSize(PHONE);
  await open(page, server, "#/lab");
  await page.getByTestId("lab-locale-ar").click();
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  for (const hash of ["#/add", "#/settings", `#/c/${"07".repeat(32)}`]) {
    await go(page, hash);
    await page.waitForTimeout(100);
    const overflow = await page.evaluate(() =>
      document.documentElement.scrollWidth -
      document.documentElement.clientWidth
    );
    expect(overflow, `horizontal overflow on ${hash}`).toBeLessThanOrEqual(0);
  }
  await go(page, "#/add");
  expect(
    await page.getByTestId("pairing-code").evaluate((el) => getComputedStyle(el).direction),
  ).toBe("ltr");
  // The back arrow points the other way, and sits at the other edge.
  const back = (await page.getByTestId("add-screen-back").boundingBox())!;
  expect(back.x).toBeGreaterThan(PHONE.width / 2);
});

/** Whether two boxes share any area. */
function overlaps(
  a: { x: number; y: number; width: number; height: number },
  b: { x: number; y: number; width: number; height: number },
): boolean {
  return a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height &&
    b.y < a.y + a.height;
}

for (
  const [size, viewport] of [["phone", { width: 390, height: 800 }], [
    "wide",
    DESKTOP,
  ]] as const
) {
  test(`add a contact on a ${size}: the code, its actions and the other direction on the first screen`, async ({ page, server, browserName }) => {
    await page.setViewportSize(viewport);
    if (browserName === "chromium") {
      await page.context().grantPermissions([
        "clipboard-read",
        "clipboard-write",
      ]);
    }
    await open(page, server, "#/add");
    await expect(page.getByTestId("pairing-own")).toHaveAttribute(
      "data-state",
      "ready",
    );

    // Without scrolling: the picture, how long it is good for, Copy and Share, and the two
    // ways to take theirs.
    const visible = [
      "pairing-qr",
      "pairing-expiry",
      "pairing-copy",
      "pairing-code-toggle",
      "pairing-scan-open",
      "pairing-paste-open",
    ];
    if (await page.getByTestId("pairing-share").count()) {
      visible.push("pairing-share");
    }
    for (const id of visible) {
      const box = (await page.getByTestId(id).boundingBox())!;
      expect(box.y + box.height, `${id} is on the first screen`)
        .toBeLessThanOrEqual(
          viewport.height,
        );
    }
    expect(await page.evaluate(() => document.scrollingElement!.scrollTop))
      .toBe(0);
    await expect(page.getByTestId("pairing-expiry")).toHaveText(
      "Good for 28 minutes. Works once.",
    );
    await expect(page.getByTestId("pairing-help")).toHaveText(
      "Keep this screen open while they add you.",
    );

    // The QR code keeps modules a camera can read: at least 3px each, quiet zone included.
    const qr = await page.getByTestId("pairing-qr").evaluate((svg) => ({
      width: svg.getBoundingClientRect().width,
      units: Number(svg.getAttribute("viewBox")!.split(" ")[2]),
    }));
    expect(qr.width / qr.units).toBeGreaterThanOrEqual(3);

    // The code as text is behind a disclosure that opens in place.
    const toggle = page.getByTestId("pairing-code-toggle");
    await expect(toggle).toHaveText("Show the code as text");
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    const region = page.locator(
      `#${await toggle.getAttribute("aria-controls")}`,
    );
    await expect(region).toBeHidden();
    await expect(page.getByTestId("pairing-code")).toBeHidden();

    // Copy works with the text closed.
    await page.getByTestId("pairing-copy").click();
    await expect(page.getByTestId("toast")).toHaveText(
      /Code copied|Could not copy/,
    );
    if (browserName === "chromium") {
      const copied = await page.evaluate(() => navigator.clipboard.readText());
      const shown = (await page.getByTestId("pairing-code").textContent())!
        .replace(/\s+/g, "");
      expect(copied).toBe(shown);
      expect(copied.length).toBeGreaterThan(300);
    }

    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    await expect(region).toBeVisible();
    const code = page.getByTestId("pairing-code");
    await expect(code).toBeVisible();
    await expect(code.locator("span").first()).toHaveText(/^[0-9a-f]{4}$/);
    // Focusing the text selects all of it, ready to copy by hand.
    await code.focus();
    const selected = await page.evaluate(() => getSelection()!.toString().replace(/\s+/g, ""));
    expect(selected).toBe((await code.textContent())!.replace(/\s+/g, ""));
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await expect(region).toBeHidden();
  });

  test(`toasts on a ${size} never cover the composer, the call controls or a sheet's actions`, async ({ page, server }) => {
    await page.setViewportSize(viewport);
    const problems = await watch(page, server);
    await open(page, server, "#/lab");
    /** Show a toast from the lab, then go where it is checked (it lasts four seconds). */
    const toastThen = async (hash: string) => {
      await go(page, "#/lab");
      await page.getByTestId("lab-show-toast").click();
      await go(page, hash);
    };
    const clearOf = async (ids: string[]) => {
      const toast = page.getByTestId("toast");
      await expect(toast).toHaveCount(1);
      const box = (await toast.boundingBox())!;
      for (const id of ids) {
        const other = (await page.getByTestId(id).boundingBox())!;
        expect(overlaps(box, other), `the toast covers ${id}`).toBe(false);
      }
      // Polite, and it never takes focus.
      await expect(page.getByTestId("toast-host")).toHaveAttribute(
        "aria-live",
        "polite",
      );
      expect(
        await page.evaluate(() => !!document.activeElement?.closest(".toast-host")),
      )
        .toBe(false);
    };

    // A conversation: the header with its call buttons, and the composer.
    await toastThen(`#/c/${PEER.mira}`);
    await expect(page.getByTestId("conversation")).toBeVisible();
    await clearOf([
      "conversation-name",
      "call-voice",
      "call-video",
      "composer-input",
      "composer-send",
    ]);

    // A panel's actions above the composer.
    await toastThen(`#/c/${PEER.kofi}`);
    await expect(page.getByTestId("panel-no-path")).toBeVisible();
    await clearOf(["panel-try-again", "panel-own-relay", "composer-input"]);

    // A sheet's actions.
    await toastThen(`#/c/${"07".repeat(32)}`);
    await page.getByTestId("verify-open").click();
    await expect(page.getByTestId("safety-number")).toBeVisible();
    await clearOf(["verify-match", "verify-no-match"]);
    await page.getByTestId("sheet-verify-close").click();

    // A call under way: its controls. The call is drawn over every screen, the lab's too.
    await go(page, "#/lab");
    await page.getByTestId("lab-contact").selectOption(PEER.mira);
    await page.getByTestId("lab-call-incoming").click();
    await page.getByTestId("call-accept").click();
    await expect(page.getByTestId("call-screen")).toBeVisible();
    await page.getByTestId("lab-show-toast").dispatchEvent("click");
    await clearOf(["call-mute", "call-camera", "call-hangup"]);
    await page.getByTestId("call-hangup").click();
    await expectClean(problems);
  });
}

test("someone used this device's code while the person was elsewhere: the conversation asks for a name, once", async ({ page, server }) => {
  await page.setViewportSize(PHONE);
  await open(page, server, "#/lab");
  await page.getByTestId("lab-someone-used-code").click();
  await go(page, "#/");
  const row = page.getByTestId("row-c3c3c3c3");
  await expect(row).toContainText("New contact");

  await row.click();
  await expect(page.getByTestId("conversation-name")).toHaveText("New contact");
  // Not a dialog: it takes no focus and leaves the composer usable.
  await expect(page.getByTestId("conversation-name")).toBeFocused();
  await expect(page.getByTestId("name-prompt-text")).toHaveText(
    "Someone used your code. Give them a name.",
  );
  await expect(page.getByTestId("composer-input")).toBeEnabled();
  // Nobody compared anything: as for a pasted code.
  await expect(page.getByTestId("verify-prompt")).toContainText(
    "Not verified yet",
  );

  await page.getByTestId("name-prompt-save").click();
  await expect(page.getByTestId("name-prompt-problem")).toHaveText(
    "The name cannot be empty.",
  );
  await page.getByTestId("name-prompt-input").fill("Lea");
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("toast")).toHaveText("Lea added");
  await expect(page.getByTestId("name-prompt")).toHaveCount(0);
  await expect(page.getByTestId("conversation-name")).toHaveText("Lea");
  await expect(page.getByTestId("verify-prompt")).toBeVisible();
  await page.getByTestId("conversation-back").click();
  await expect(page.getByTestId("row-c3c3c3c3")).toContainText("Lea");
});

test("the naming prompt can be put away; the row keeps saying New contact", async ({ page, server }) => {
  await open(page, server, "#/lab");
  await page.getByTestId("lab-someone-used-code").click();
  await go(page, `#/c/${"c3".repeat(32)}`);
  await expect(page.getByTestId("name-prompt")).toBeVisible();
  await page.getByTestId("name-prompt-later").click();
  await expect(page.getByTestId("name-prompt")).toHaveCount(0);
  await expect(page.getByTestId("row-c3c3c3c3")).toContainText("New contact");
  // Once: coming back to the conversation does not ask again during this visit.
  await go(page, `#/c/${PEER.mira}`);
  await go(page, `#/c/${"c3".repeat(32)}`);
  await expect(page.getByTestId("conversation-name")).toHaveText("New contact");
  await expect(page.getByTestId("name-prompt")).toHaveCount(0);
});

test("a contact added here and left without a name is asked for in its conversation", async ({ page, server }) => {
  await open(page, server, "#/add");
  await page.getByTestId("pairing-paste-open").click();
  await page.getByTestId("pairing-code-input").fill("ab12cd34".repeat(10));
  await page.getByTestId("pairing-code-submit").click();
  await expect(page.getByTestId("pairing-name")).toBeVisible();
  // The person leaves the naming step without a name.
  await go(page, "#/");
  await expect(page.getByTestId("row-ab12cd34")).toContainText("New contact");
  await page.getByTestId("row-ab12cd34").click();
  await expect(page.getByTestId("name-prompt-text")).toHaveText(
    "Give this contact a name.",
  );
});

test("the passphrase lock, the backup and the restore, from the keyboard", async ({ page, server }) => {
  const problems = await watch(page, server);
  await open(page, server, "#/settings");
  await expect(page.getByTestId("settings-lock")).toHaveAttribute("data-on", "false");

  // Set a passphrase: the sheet takes focus, says what cannot be undone, and refuses a
  // short one and a pair that differs, each in words.
  await page.getByTestId("lock-set").focus();
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("sheet-lock-set")).toBeVisible();
  await expect(page.getByTestId("lock-forgotten")).toContainText("nobody can recover it");
  await page.getByTestId("lock-new").fill("seven77");
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("lock-problem")).toHaveText("That passphrase is too short.");
  await page.getByTestId("lock-new").fill("eight888 or more");
  await page.getByTestId("lock-again").fill("eight888 or mor");
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("lock-problem")).toHaveText(
    "The two passphrases are not the same.",
  );
  for (const id of ["lock-new", "lock-again"]) {
    await expect(page.getByTestId(id)).toHaveAttribute("type", "password");
    await expect(page.getByTestId(id)).toHaveAttribute("autocomplete", "new-password");
  }
  await page.getByTestId("lock-again").fill("eight888 or more");
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("toast")).toHaveText("Passphrase set");
  await expect(page.getByTestId("sheet-lock-set")).toHaveCount(0);
  await expect(page.getByTestId("settings-lock")).toHaveAttribute("data-on", "true");
  await expect(page.getByTestId("settings-lock-on")).toBeVisible();

  // Lock now: the passphrase field has focus; a wrong one is said under it; Escape does
  // not get past it.
  await page.getByTestId("lock-now").click();
  await expect(page.getByTestId("locked")).toBeVisible();
  await expect(page.getByTestId("unlock-passphrase")).toBeFocused();
  await expect(page.getByTestId("app")).toHaveCount(0);
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("locked")).toBeVisible();
  await page.keyboard.type("wrong");
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("unlock-problem")).toHaveText("That is not the passphrase.");
  await expect(page.getByTestId("unlock-passphrase")).toHaveValue("");
  await page.getByTestId("unlock-forgot").click();
  await expect(page.getByTestId("sheet-forget")).toContainText("cannot be recovered");
  await expect(page.getByTestId("forget-confirm")).toBeDisabled();
  await page.keyboard.press("Escape");
  await page.getByTestId("unlock-passphrase").fill("anything else");
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("app")).toBeVisible();

  // Remove it again: the current passphrase is asked for.
  await page.getByTestId("lock-remove").click();
  await page.getByTestId("lock-current").fill("wrong");
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("lock-problem")).toHaveText("That is not the passphrase.");
  await page.getByTestId("lock-current").fill("the current one");
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("toast")).toHaveText("Passphrase removed");
  await expect(page.getByTestId("settings-lock")).toHaveAttribute("data-on", "false");

  // Back up: history is off unless asked for; the file is a link to press, with a name.
  await expect(page.getByTestId("backup-last")).toHaveText(
    "No backup has been made on this device.",
  );
  await page.getByTestId("backup-open").click();
  await expect(page.getByTestId("backup-history")).not.toBeChecked();
  await page.getByTestId("backup-new").fill("four random words here");
  await page.getByTestId("backup-again").fill("four random words here");
  await page.getByTestId("backup-make").click();
  const save = page.getByTestId("backup-save");
  await expect(save).toHaveAttribute("href", /^blob:/);
  await expect(save).toHaveAttribute("download", /^parolnet-backup-\d{4}-\d{2}-\d{2}\.pnbackup$/);
  await expect(page.getByTestId("sheet-backup")).toContainText(
    "Use a backup on one device at a time",
  );
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("backup-last")).toContainText("Last backup:");

  // Restore, where there is something to replace: a word is typed first.
  await page.getByTestId("restore-open").click();
  await expect(page.getByTestId("restore-replaces")).toContainText("It cannot be undone.");
  await expect(page.getByTestId("restore-submit")).toBeDisabled();
  await page.getByTestId("restore-confirm-input").fill("Replace ");
  await expect(page.getByTestId("restore-submit")).toBeEnabled();
  await page.getByTestId("restore-submit").click();
  await expect(page.getByTestId("restore-problem")).toHaveText("Choose the backup file first.");
  await page.keyboard.press("Escape");

  // First run offers the restore too, with nothing to confirm.
  await go(page, "#/lab");
  await page.getByTestId("lab-phase-first-run").click();
  await go(page, "#/");
  await page.getByTestId("first-run-restore").click();
  await expect(page.getByTestId("sheet-restore")).toBeVisible();
  await expect(page.getByTestId("restore-replaces")).toHaveCount(0);
  await expect(page.getByTestId("restore-submit")).toBeEnabled();
  await expectClean(problems);
});

test("the list suggests a backup once there is a contact, and can be told not now", async ({ page, server }) => {
  await open(page, server, "#/");
  await expect(page.getByTestId("backup-hint")).toContainText("Make a backup");
  await page.getByTestId("backup-hint-later").click();
  await expect(page.getByTestId("backup-hint")).toHaveCount(0);
  await page.reload();
  await expect(page.getByTestId("conversation-list")).toBeVisible();
  await expect(page.getByTestId("backup-hint")).toHaveCount(0);
  // With no one to lose there is nothing to suggest.
  await page.evaluate(() => localStorage.clear());
  await page.reload();
  await go(page, "#/lab");
  await page.getByTestId("lab-clear").click();
  await go(page, "#/");
  await expect(page.getByTestId("list-empty")).toBeVisible();
  await expect(page.getByTestId("backup-hint")).toHaveCount(0);
});
