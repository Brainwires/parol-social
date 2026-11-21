// Real flows on the production export: two (or three) people, each in a browser context of
// their own, talking through a real relay served at the same origin. Everything here is
// driven through the interface, the way a person would; nothing reads the engine. Every
// page is watched: no CSP violation, no console error, no request that leaves localhost.
//
//   npx playwright test --project=flows-chromium      (needs the relay binary, see harness.ts)
import { readFileSync } from "node:fs";
import type { Browser, BrowserContext, Page } from "@playwright/test";
import { expect, expectClean, type Problems, type Server, test, watch } from "./harness.ts";

const PHONE = { width: 390, height: 844 };
const WIDE = { width: 1280, height: 900 };
/** A connection between two pages on one machine is quick, but browsers differ. */
const CONNECT = { timeout: 45_000 };

interface Person {
  context: BrowserContext;
  page: Page;
  problems: Problems;
}

/**
 * WebKit only. Until a page captures media, WebKit offers its host addresses as mDNS names,
 * and a test machine (a container, a CI runner) has nothing to resolve them, so two WebKit
 * pages could not reach each other. A page that holds a microphone, as a page in a call does,
 * offers its real addresses. The project grants the permission; this holds the capture on
 * every load. It is the test's surroundings, not the app: in Chromium and Firefox the flows
 * run without it.
 */
async function exposeHostAddresses(context: BrowserContext): Promise<void> {
  await context.addInitScript(() => {
    void navigator.mediaDevices?.getUserMedia({ audio: true }).then(
      (
        stream,
      ) => ((window as unknown as { __held: MediaStream }).__held = stream),
      () => {},
    );
  });
}

/**
 * Keep every RTCPeerConnection a page makes, with a timed log of its ICE events, so a flow
 * that fails to connect can say why (`connectionReport`). Diagnostics only: nothing in a
 * flow reads it unless it failed.
 */
async function recordPeerConnections(context: BrowserContext): Promise<void> {
  await context.addInitScript(() => {
    type Kept = { pc: RTCPeerConnection; t0: number; log: string[] };
    const kept: Kept[] = [];
    (window as unknown as { __pcs: Kept[] }).__pcs = kept;
    const Native = window.RTCPeerConnection;
    if (!Native) return;
    window.RTCPeerConnection = new Proxy(Native, {
      construct(target, args, newTarget) {
        const pc = Reflect.construct(
          target,
          args,
          newTarget,
        ) as RTCPeerConnection;
        const entry: Kept = { pc, t0: performance.now(), log: [] };
        const note = (what: string) =>
          entry.log.push(
            `+${Math.round(performance.now() - entry.t0)}ms ${what}`,
          );
        pc.addEventListener(
          "icegatheringstatechange",
          () => note(`gathering ${pc.iceGatheringState}`),
        );
        pc.addEventListener(
          "iceconnectionstatechange",
          () => note(`ice ${pc.iceConnectionState}`),
        );
        pc.addEventListener(
          "connectionstatechange",
          () => note(`connection ${pc.connectionState}`),
        );
        const watched = new Set<RTCDtlsTransport>();
        pc.addEventListener("signalingstatechange", () => {
          note(`signaling ${pc.signalingState}`);
          for (const t of pc.getTransceivers()) {
            const dtls = t.sender.transport;
            if (!dtls || watched.has(dtls)) continue;
            watched.add(dtls);
            const n = watched.size;
            note(`dtls transport ${n} (mid ${t.mid}) ${dtls.state}`);
            dtls.addEventListener("statechange", () => note(`dtls transport ${n} ${dtls.state}`));
          }
        });
        pc.addEventListener(
          "icecandidate",
          (e) =>
            note(
              `local candidate ${e.candidate ? e.candidate.candidate || "(end)" : "(null)"}`,
            ),
        );
        pc.addEventListener("icecandidateerror", (e) => {
          const err = e as RTCPeerConnectionIceErrorEvent;
          note(`candidate error ${err.errorCode} ${err.errorText} ${err.url}`);
        });
        kept.push(entry);
        return pc;
      },
    });
  });
}

/**
 * What each page's engine logged about its calls (`[Call] …`: how a call ended, and a line
 * before each step of letting its media go), with the time. Diagnostics only: if a page
 * freezes while a call is torn down, the last line names the browser call that did not
 * return (see repro/README.md).
 */
const callLogs = new WeakMap<Page, string[]>();

function recordCallLog(page: Page): void {
  const lines: string[] = [];
  const t0 = Date.now();
  callLogs.set(page, lines);
  page.on("console", (message) => {
    const text = message.text();
    if (text.startsWith("[Call]")) lines.push(`+${Date.now() - t0}ms ${text}`);
  });
}

/** Whether the page still runs script: a blocked main thread does not answer. */
function answers(page: Page): Promise<string> {
  return Promise.race([
    page.evaluate(() => "the page answers"),
    new Promise<string>((done) =>
      setTimeout(() => done("the page does not answer: its main thread is blocked"), 5_000)
    ),
  ]).catch((e) => `the page does not answer: ${e}`);
}

/** Every connection a page made: states, the timed ICE log, SDP candidates, candidate pairs. */
function connectionReport(page: Page): Promise<string> {
  return page.evaluate(async () => {
    type Kept = { pc: RTCPeerConnection; t0: number; log: string[] };
    const kept = (window as unknown as { __pcs?: Kept[] }).__pcs ?? [];
    const out: string[] = [];
    for (const video of document.querySelectorAll("video")) {
      const tracks = (video.srcObject as MediaStream | null)?.getTracks().map((t) =>
        `${t.kind} ${t.readyState}${t.enabled ? "" : " disabled"}${t.muted ? " muted" : ""}`
      );
      out.push(
        `video ${video.dataset.testid}: ${video.paused ? "paused" : "playing"}, ` +
          `readyState ${video.readyState}, ${video.videoWidth}x${video.videoHeight}, ` +
          `tracks: ${tracks ? tracks.join("; ") || "none" : "no stream"}`,
      );
    }
    for (const [i, { pc, log }] of kept.entries()) {
      const lines = (sdp: string | undefined) =>
        // The description without its codec lists.
        (sdp ?? "").split(/\r?\n/).filter((l) =>
          l !== "" && !/^a=(rtpmap|fmtp|rtcp-fb|extmap|ssrc|msid)/.test(l)
        );
      out.push(
        `connection ${i}: signaling ${pc.signalingState}, gathering ${pc.iceGatheringState}, ` +
          `ice ${pc.iceConnectionState}, connection ${pc.connectionState}`,
        ...log.map((l) => `  ${l}`),
        "  local description:",
        ...lines(pc.localDescription?.sdp).map((l) => `    ${l}`),
        "  remote description:",
        ...lines(pc.remoteDescription?.sdp).map((l) => `    ${l}`),
        ...pc.getTransceivers().map((t) => {
          const dtls = t.sender.transport;
          return `  transceiver ${t.mid} ${t.currentDirection}: dtls ${dtls?.state}, ` +
            `ice ${dtls?.iceTransport?.state}`;
        }),
      );
      try {
        const stats = await pc.getStats();
        const byId = new Map<string, Record<string, unknown>>();
        stats.forEach((r: Record<string, unknown>) => byId.set(r.id as string, r));
        const where = (id: unknown) => {
          const c = byId.get(id as string);
          return c ? `${c.candidateType} ${c.protocol} ${c.address ?? c.ip}:${c.port}` : "?";
        };
        stats.forEach((r: Record<string, unknown>) => {
          if (r.type === "candidate-pair") {
            out.push(
              `  pair ${r.state}${r.nominated ? " nominated" : ""}: ${
                where(r.localCandidateId)
              } -> ` +
                `${
                  where(r.remoteCandidateId)
                } (requests ${r.requestsSent}, responses ${r.responsesReceived})`,
            );
          }
        });
      } catch (e) {
        out.push(`  getStats failed: ${e}`);
      }
    }
    return out.join("\n") || "no RTCPeerConnection was made";
  });
}

/**
 * The one failure of these flows that is expected, and only in Linux WebKit: the browser
 * can block a page's main thread for good when a playing stream is detached from its element
 * right after its camera track was switched off, which is what "Turn camera off" does to
 * the self view. It is the browser's defect: repro/README.md ("A second freeze") shows it
 * with no app code, and docs/web-port/app.md ("Owed") says what is left to try. A step that
 * names this, fails, and finds a page that no longer answers ends the test as skipped with
 * this reason, so that the report says what happened; any other failure of the step, in any
 * browser, is a failure. The freeze at hang-up, which the app does avoid, is not excused.
 */
const KNOWN_WEBKIT_FREEZE =
  'Linux WebKit froze the page at "Turn camera off" (tests/e2e/repro, camera-off)';

/**
 * Run `step`; if it throws, or takes longer than `within`, attach each page's call log,
 * whether it still answers, and its connection report to the failure. With `knownFreeze`,
 * a failure that left a page frozen in WebKit skips the test with that reason.
 * `PAROLNET_CONNECTION_REPORT=1` prints the reports after a success too.
 */
async function withConnectionReport(
  people: Record<string, Page>,
  step: () => Promise<void>,
  within?: number,
  knownFreeze?: string,
): Promise<void> {
  let frozen = false;
  const report = async () => {
    // All at once, and none waited for longer than a few seconds: the test may be close to
    // its own timeout, and a frozen page never answers.
    const texts = await Promise.all(
      Object.values(people).map(async (page) => {
        const state = await answers(page);
        if (state !== "the page answers") frozen = true;
        const connections = state === "the page answers"
          ? await Promise.race([
            connectionReport(page),
            new Promise<string>((done) => setTimeout(() => done("no report in 10 s"), 10_000)),
          ]).catch((e) => `no report: ${e}`)
          : "no report";
        const calls = (callLogs.get(page) ?? []).map((l) => `  ${l}`).join("\n");
        return `${state}\ncall log:\n${calls || "  (nothing)"}\n${connections}`;
      }),
    );
    for (const [i, name] of Object.keys(people).entries()) {
      await test.info().attach(`connections-${name}.txt`, {
        body: texts[i],
        contentType: "text/plain",
      });
      console.log(`--- ${name}'s connections ---\n${texts[i]}`);
    }
  };
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      step(),
      new Promise<void>((_done, fail) => {
        if (within !== undefined) {
          timer = setTimeout(
            () => fail(new Error(`this step did not finish in ${within / 1000} s`)),
            within,
          );
        }
      }),
    ]);
  } catch (error) {
    await report();
    // The one expected failure: see `KNOWN_WEBKIT_FREEZE`.
    test.skip(
      knownFreeze !== undefined && frozen && test.info().project.name === "flows-webkit",
      knownFreeze,
    );
    throw error;
  } finally {
    clearTimeout(timer);
  }
  if (process.env.PAROLNET_CONNECTION_REPORT === "1") await report();
}

/** The QR code a page is showing, as a picture (a data URL) another page's camera can see. */
function shownCode(page: Page): Promise<string> {
  return page.getByTestId("pairing-qr").evaluate((shown) => {
    // A copy with its colours as attributes: an image has no stylesheet.
    const svg = shown.cloneNode(true) as SVGSVGElement;
    svg.setAttribute("xmlns", "http://www.w3.org/2000/svg");
    svg.setAttribute("width", "400");
    svg.setAttribute("height", "400");
    svg.querySelector("rect")!.setAttribute("fill", "#ffffff");
    svg.querySelector("path")!.setAttribute("fill", "#000000");
    return `data:image/svg+xml;base64,${btoa(new XMLSerializer().serializeToString(svg))}`;
  });
}

/**
 * Give a page a camera that sees `picture`. `window.__camera` is then the stream the app got,
 * so a test can tell whether the camera was let go.
 *
 * Chromium and Firefox: the camera is a canvas showing the picture (`captureStream`).
 * WebKit (Playwright's Linux build): a canvas stream delivers no frames there, so the camera
 * is the browser's own mock device, and the picture is put in where the scanner copies the
 * video frame to its canvas. Everything after that copy (decoding, pairing) is the app's.
 */
async function pointCameraAt(
  page: Page,
  picture: string,
  webkit: boolean,
): Promise<void> {
  await page.evaluate(async ({ picture, webkit }) => {
    const image = new Image();
    image.src = picture;
    await image.decode();
    const paint = (
      context: CanvasRenderingContext2D,
      width: number,
      height: number,
    ) => {
      context.fillStyle = "#8a8f8c";
      context.fillRect(0, 0, width, height);
      const side = Math.min(width, height) * 0.8;
      context.drawImage(
        image,
        (width - side) / 2,
        (height - side) / 2,
        side,
        side,
      );
    };
    const hold = window as unknown as { __camera?: MediaStream };
    const media = navigator.mediaDevices;
    if (webkit) {
      const real = media.getUserMedia.bind(media);
      media.getUserMedia = async (constraints) => {
        const stream = await real(constraints);
        if (constraints?.video) hold.__camera = stream;
        return stream;
      };
      const draw = CanvasRenderingContext2D.prototype.drawImage;
      CanvasRenderingContext2D.prototype.drawImage = function (
        this: CanvasRenderingContext2D,
        source: CanvasImageSource,
        ...rest: number[]
      ) {
        if (source instanceof HTMLVideoElement) {
          paint(this, this.canvas.width, this.canvas.height);
        } else {(draw as (...args: unknown[]) => void).call(
            this,
            source,
            ...rest,
          );}
      } as typeof draw;
      return;
    }
    const canvas = document.createElement("canvas");
    canvas.width = 640;
    canvas.height = 480;
    const context = canvas.getContext("2d")!;
    paint(context, canvas.width, canvas.height);
    setInterval(() => paint(context, canvas.width, canvas.height), 100);
    const stream = canvas.captureStream(10);
    hold.__camera = stream;
    media.getUserMedia = () => Promise.resolve(stream);
  }, { picture, webkit });
}

const cameraTracks = (page: Page) =>
  page.evaluate(() =>
    (window as unknown as { __camera?: MediaStream }).__camera?.getTracks().map(
      (t) => t.readyState,
    ) ?? []
  );

async function person(
  browser: Browser,
  live: Server,
  viewport = WIDE,
  init?: (context: BrowserContext) => Promise<void>,
): Promise<Person> {
  const context = await browser.newContext({ viewport });
  await recordPeerConnections(context);
  if (browser.browserType().name() === "webkit") {
    await exposeHostAddresses(context);
  }
  await init?.(context);
  const page = await context.newPage();
  recordCallLog(page);
  const problems = await watch(page, live);
  await page.goto(live.url);
  return { context, page, problems };
}

/** First run: Start makes the identity and goes straight to adding a contact. */
async function start(page: Page): Promise<void> {
  await page.getByTestId("first-run-start").click();
  await expect(page.getByTestId("pairing-own")).toHaveAttribute(
    "data-state",
    "ready",
  );
}

async function ownCode(page: Page): Promise<string> {
  return ((await page.getByTestId("pairing-code").textContent()) ?? "").trim();
}

async function nameContact(page: Page, name: string): Promise<void> {
  await expect(page.getByTestId("contact-name-input")).toBeFocused(CONNECT);
  await page.getByTestId("contact-name-input").fill(name);
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("conversation-name")).toHaveText(name);
}

/** `presenter` shows its code, `scanner` pastes it; each names the other. */
async function pairByPaste(
  presenter: Page,
  scanner: Page,
  names: { presenter: string; scanner: string },
): Promise<void> {
  const code = await ownCode(presenter);
  expect(code).toMatch(/^[0-9a-f]{100,}$/);
  await scanner.getByTestId("pairing-paste-open").click();
  await scanner.getByTestId("pairing-code-input").fill(code);
  await scanner.getByTestId("pairing-code-submit").click();
  await nameContact(scanner, names.presenter);
  await nameContact(presenter, names.scanner);
}

const lineOf = (page: Page) => page.getByTestId("conversation").getByTestId("line");

async function openLine(...pages: Page[]): Promise<void> {
  for (const page of pages) {
    await expect(page.getByTestId("conversation")).toHaveAttribute(
      "data-line",
      "open",
      CONNECT,
    );
  }
}

async function send(page: Page, text: string): Promise<void> {
  await page.getByTestId("composer-input").fill(text);
  await page.keyboard.press("Enter");
}

const bubble = (page: Page, text: string) =>
  page.getByTestId("thread").locator("[data-kind]").filter({ hasText: text });

async function allClean(...people: Person[]): Promise<void> {
  for (const one of people) await expectClean(one.problems);
}

test("first run, add a contact by pasted code, name them, talk both ways", async ({ browser, live }) => {
  const ana = await person(browser, live, PHONE);
  const ben = await person(browser, live, WIDE);

  // No name, no passphrase, no tour: the words, and Start.
  await expect(ana.page.getByTestId("first-run")).toContainText(
    "No account, no phone number, no email. Nothing is stored on a server.",
  );
  await start(ana.page);
  await start(ben.page);

  // The add screen: the code as a picture and as text, how long it is good for, and the
  // one sentence about the IP address with its link.
  await expect(ana.page.getByTestId("pairing-qr")).toBeVisible();
  await expect(ana.page.getByTestId("pairing-expiry")).toHaveText(
    /^Good for (2[5-9]|30) minutes\. Works once\.$/,
  );
  await expect(ana.page.getByTestId("pairing-ip")).toContainText(
    "Contacts you add can see your IP address.",
  );

  await pairByPaste(ana.page, ben.page, { presenter: "Ana", scanner: "Ben" });
  await openLine(ana.page, ben.page);
  await expect(lineOf(ben.page)).toHaveText("Direct, end-to-end encrypted");

  // A pasted code is not verified, on either side, until numbers are compared.
  await expect(ben.page.getByTestId("verify-prompt")).toContainText(
    "Not verified yet",
  );
  await expect(ana.page.getByTestId("verify-prompt")).toContainText(
    "Not verified yet",
  );

  await send(ben.page, "Hello Ana, Ben here.");
  await expect(bubble(ana.page, "Hello Ana, Ben here.")).toHaveAttribute(
    "data-kind",
    "received",
  );
  await expect(bubble(ben.page, "Hello Ana, Ben here.")).toHaveAttribute(
    "data-kind",
    "delivered",
  );
  await expect(ben.page.getByTestId("thread-caption")).toHaveText(
    "On Ana's device",
  );
  // What arrives is announced without moving focus.
  await expect(ana.page.getByTestId("announcer")).toHaveText(
    "Ben: Hello Ana, Ben here.",
  );

  await ana.page.getByTestId("composer-input").fill("Hello Ben.");
  await ana.page.getByTestId("composer-send").click();
  await expect(bubble(ben.page, "Hello Ben.")).toHaveAttribute(
    "data-kind",
    "received",
  );

  // The same safety number on both devices; "They match" verifies.
  await ben.page.getByTestId("verify-open").click();
  await ana.page.getByTestId("verify-open").click();
  const digits = async (page: Page) =>
    ((await page.getByTestId("safety-number").textContent()) ?? "").replace(
      /\D/g,
      "",
    );
  expect(await digits(ben.page)).toMatch(/^\d{60}$/);
  expect(await digits(ben.page)).toBe(await digits(ana.page));
  await ben.page.getByTestId("verify-match").click();
  await expect(ben.page.getByTestId("verify-prompt")).toHaveCount(0);
  await ana.page.getByTestId("sheet-verify-close").click();

  // The code was used once: going back to the add screen shows a fresh one.
  await ben.page.getByTestId("add-contact").click();
  await expect(ben.page.getByTestId("pairing-own")).toHaveAttribute(
    "data-state",
    "ready",
  );

  await allClean(ana, ben);
});

test("a code works only while its screen is open; someone who used it is asked for a name in the conversation", async ({ browser, live }) => {
  const ana = await person(browser, live, PHONE);
  const ben = await person(browser, live, WIDE);
  await start(ana.page);
  await start(ben.page);

  // Leaving "Add a contact" closes Ana's code; coming back makes a fresh one.
  const first = await ownCode(ana.page);
  expect(first).toMatch(/^[0-9a-f]{200,}$/);
  await expect(ana.page.getByTestId("pairing-help")).toHaveText(
    "Keep this screen open while they add you.",
  );
  await ana.page.getByTestId("add-screen-back").click();
  await ana.page.getByTestId("add-contact").click();
  await expect(ana.page.getByTestId("pairing-own")).toHaveAttribute(
    "data-state",
    "ready",
  );
  await expect.poll(() => ownCode(ana.page)).not.toBe(first);
  const second = await ownCode(ana.page);
  // A reload is not leaving: the same code is shown again and still works.
  await ana.page.reload();
  await expect(ana.page.getByTestId("pairing-own")).toHaveAttribute(
    "data-state",
    "ready",
  );
  expect(await ownCode(ana.page)).toBe(second);

  // Ben uses it. Ana is asked for a name, and leaves without giving one.
  await ben.page.getByTestId("pairing-paste-open").click();
  await ben.page.getByTestId("pairing-code-input").fill(second);
  await ben.page.getByTestId("pairing-code-submit").click();
  await nameContact(ben.page, "Ana");
  await expect(ana.page.getByTestId("pairing-name-body")).toHaveText(
    "Someone used your code. Compare safety numbers with them when you can.",
    CONNECT,
  );
  await ana.page.getByTestId("add-screen-back").click();

  // The list says "New contact"; its conversation asks for a name, without taking focus.
  const row = ana.page.getByTestId("conversation-list").getByRole("link", {
    name: /New contact/,
  });
  await expect(row).toBeVisible();
  await row.click();
  await expect(ana.page.getByTestId("conversation-name")).toBeFocused();
  await expect(ana.page.getByTestId("name-prompt-text")).toHaveText(
    "Someone used your code. Give them a name.",
  );
  await expect(ana.page.getByTestId("verify-prompt")).toContainText(
    "Not verified yet",
  );
  await ana.page.getByTestId("name-prompt-input").fill("Ben");
  await ana.page.getByTestId("name-prompt-save").click();
  await expect(ana.page.getByTestId("conversation-name")).toHaveText("Ben");
  await expect(ana.page.getByTestId("name-prompt")).toHaveCount(0);
  // The confirmation stays clear of the composer.
  const toast = (await ana.page.getByTestId("toast").boundingBox())!;
  const composer = (await ana.page.getByTestId("composer-input").boundingBox())!;
  expect(toast.y + toast.height).toBeLessThan(composer.y);

  await openLine(ana.page, ben.page);
  await send(ben.page, "It is Ben.");
  await expect(bubble(ana.page, "It is Ben.")).toHaveAttribute(
    "data-kind",
    "received",
  );
  await allClean(ana, ben);
});

test("what is written while they are away waits here, can be changed and taken back, and goes when they return", async ({ browser, live }) => {
  const ana = await person(browser, live);
  const ben = await person(browser, live);
  await start(ana.page);
  await start(ben.page);
  await pairByPaste(ana.page, ben.page, { presenter: "Ana", scanner: "Ben" });
  await openLine(ana.page, ben.page);
  await send(ben.page, "Before you go.");
  await expect(bubble(ana.page, "Before you go.")).toBeVisible();

  // Ana closes the app.
  const anaUrl = ana.page.url();
  await ana.page.close();
  await expect(lineOf(ben.page)).toHaveText(
    "Waiting for Ana to come online",
    CONNECT,
  );
  await expect(ben.page.getByTestId("composer-input")).toHaveAttribute(
    "placeholder",
    "Ana is away. Your message will wait here.",
  );

  await send(ben.page, "The keys are with the neighbour.");
  await send(ben.page, "Never mind this one.");
  await send(ben.page, "Call me when you are back.");
  const held = ben.page.locator('button[data-kind="held"]');
  await expect(held).toHaveCount(3);
  await expect(ben.page.getByTestId("thread-caption")).toHaveText(
    "Waiting on this device",
  );
  // The list counts what is still on this device.
  await expect(ben.page.getByTestId("waiting-chip")).toHaveText("3 waiting");

  // By keyboard: edit the first, take back the second.
  await held.nth(0).focus();
  await ben.page.keyboard.press("Enter");
  await ben.page.keyboard.press("ArrowDown");
  await expect(ben.page.getByRole("menuitem", { name: "Edit" })).toBeFocused();
  await ben.page.keyboard.press("Enter");
  await expect(ben.page.getByTestId("composer-input")).toBeFocused();
  await ben.page.getByTestId("composer-input").fill(
    "The keys are under the blue pot.",
  );
  await ben.page.keyboard.press("Enter");
  await expect(ben.page.getByTestId("toast")).toHaveText("Message changed");
  await held.nth(1).focus();
  await ben.page.keyboard.press("Enter");
  await expect(ben.page.getByRole("menuitem", { name: "Take back" }))
    .toBeFocused();
  await ben.page.keyboard.press("Enter");
  await expect(ben.page.getByTestId("toast")).toHaveText("Message taken back");
  await expect(held).toHaveCount(2);
  await expect(ben.page.getByTestId("waiting-chip")).toHaveText("2 waiting");

  // Ben reloads: what waits is on this device, not in the page.
  await ben.page.reload();
  await expect(ben.page.locator('button[data-kind="held"]')).toHaveCount(2);

  // Ana comes back, in the same browser: the same identity, no first run.
  const back = await ana.context.newPage();
  await back.goto(anaUrl);
  await expect(back.getByTestId("conversation-name")).toHaveText("Ben");
  await expect(bubble(back, "The keys are under the blue pot.")).toBeVisible(
    CONNECT,
  );
  await expect(bubble(back, "Call me when you are back.")).toBeVisible();
  await expect(back.getByTestId("thread")).not.toContainText(
    "Never mind this one.",
  );
  await expect(back.getByTestId("thread")).not.toContainText(
    "with the neighbour",
  );

  // On Ben's side they fill in and the caption changes.
  await expect(ben.page.locator('[data-kind="held"]')).toHaveCount(0, CONNECT);
  await expect(ben.page.getByTestId("thread-caption")).toHaveText(
    "On Ana's device",
  );
  await expect(ben.page.getByTestId("waiting-chip")).toHaveCount(0);
  await expectClean(ben.problems);
});

for (
  const decoder of [
    "the browser's decoder if it has one",
    "the bundled decoder",
  ] as const
) {
  test(`scanning their code with the camera (${decoder}) verifies in person and lets the camera go`, async ({ browser, browserName, live }) => {
    const ana = await person(browser, live);
    const ben = await person(browser, live, WIDE, async (context) => {
      if (decoder === "the bundled decoder") {
        await context.addInitScript(() => {
          delete (window as unknown as { BarcodeDetector?: unknown })
            .BarcodeDetector;
        });
      }
    });
    await start(ana.page);
    await start(ben.page);

    // Ben's camera looks at Ana's screen.
    await pointCameraAt(
      ben.page,
      await shownCode(ana.page),
      browserName === "webkit",
    );

    await ben.page.getByTestId("pairing-scan-open").click();
    await expect(ben.page.getByTestId("pairing-name-body")).toHaveText(
      "You scanned their code in person, so this contact is verified.",
      CONNECT,
    );
    // The camera is released as soon as the code is read.
    expect(await cameraTracks(ben.page)).toEqual(["ended"]);
    await nameContact(ben.page, "Ana");
    await nameContact(ana.page, "Ben");
    await openLine(ana.page, ben.page);

    // Ben scanned: verified in person, nothing to compare. Ana did not see Ben's code.
    await expect(ben.page.getByTestId("verify-prompt")).toHaveCount(0);
    await ben.page.getByTestId("conversation-details").click();
    await expect(ben.page.getByTestId("details-verified")).toHaveText(
      "Verified in person: you scanned their code.",
    );
    await expect(ana.page.getByTestId("verify-prompt")).toContainText(
      "Not verified yet",
    );
    await allClean(ana, ben);
  });
}

test("leaving the scanner releases the camera; a picture that is not a code says so", async ({ browser, browserName, live }) => {
  const ben = await person(browser, live);
  await start(ben.page);
  // A camera that sees a code the engine refuses: this device's own.
  await pointCameraAt(
    ben.page,
    await shownCode(ben.page),
    browserName === "webkit",
  );

  await ben.page.getByTestId("pairing-scan-open").click();
  await expect(ben.page.getByTestId("pairing-scan")).toHaveAttribute(
    "data-state",
    "scanning",
  );
  await expect(ben.page.getByTestId("pairing-scan-problem")).toHaveText(
    "That is your own code.",
  );
  expect(await cameraTracks(ben.page)).toEqual(["live"]);
  // Leaving the screen (not just pressing Stop) lets the camera go.
  await ben.page.getByTestId("open-settings").click();
  await expect(ben.page.getByTestId("settings-screen")).toBeVisible();
  expect(await cameraTracks(ben.page)).toEqual(["ended"]);
  await expectClean(ben.problems);
});

test("a video call: ring, accept, controls, end; and a declined call", async ({ browser, live }) => {
  // Every camera capture a page makes is kept (`window.__captures`), to see it let go.
  // Patched on the prototype: WebKit's `navigator.mediaDevices` is not yet the page's own
  // object when an init script runs.
  const keepCaptures = (context: BrowserContext) =>
    context.addInitScript(() => {
      const kept: MediaStream[] = [];
      (window as unknown as { __captures: MediaStream[] }).__captures = kept;
      if (typeof MediaDevices === "undefined") return;
      const real = MediaDevices.prototype.getUserMedia;
      MediaDevices.prototype.getUserMedia = async function (constraints) {
        const stream = await real.call(this, constraints);
        if (constraints?.video) kept.push(stream);
        return stream;
      };
    });
  const ana = await person(browser, live, PHONE, keepCaptures);
  const ben = await person(browser, live, WIDE, keepCaptures);
  await start(ana.page);
  await start(ben.page);
  await pairByPaste(ana.page, ben.page, { presenter: "Ana", scanner: "Ben" });
  await openLine(ana.page, ben.page);

  // Ben calls with video.
  await ben.page.getByTestId("call-video").click();
  await expect(ben.page.getByTestId("call-status")).toHaveText("Calling Ana…");
  const incoming = ana.page.getByTestId("incoming-call");
  await expect(incoming).toBeVisible(CONNECT);
  await expect(ana.page.getByTestId("incoming-call-words")).toHaveText(
    "Ben is calling with video",
  );
  await expect(ana.page.getByTestId("announcer")).toHaveText("Ben is calling");

  // Accept by keyboard: focus is on the words, Tab reaches Accept.
  await expect(ana.page.getByTestId("incoming-call-words")).toBeFocused();
  await ana.page.keyboard.press("Tab");
  await expect(ana.page.getByTestId("call-accept")).toBeFocused();
  await ana.page.keyboard.press("Enter");

  await withConnectionReport({ ana: ana.page, ben: ben.page }, async () => {
    for (const page of [ana.page, ben.page]) {
      await expect(page.getByTestId("call-screen")).toHaveAttribute(
        "data-state",
        "Active",
        CONNECT,
      );
    }
  });
  // From here to the end of the call each step has a time limit of its own: a page whose
  // main thread the browser's media stack has blocked answers nothing, and without the
  // limit the test would end with no report of which page, or where.
  await withConnectionReport({ ana: ana.page, ben: ben.page }, async () => {
    for (const page of [ana.page, ben.page]) {
      await expect(page.getByTestId("call-status")).toHaveText(
        "Direct, end-to-end encrypted",
      );
      await expect(page.getByTestId("call-timer")).toHaveText(/^\d+:\d\d$/);
      // Their video is playing, and our own floats beside it.
      await expect.poll(
        () =>
          page.getByTestId("call-remote").evaluate((video: HTMLVideoElement) =>
            video.videoWidth > 0 && !video.paused
          ),
        { timeout: 30_000 },
      ).toBe(true);
      await expect(page.getByTestId("call-self")).toBeVisible();
    }
    await expect(ben.page.getByTestId("call-timer")).not.toHaveText("0:00", {
      timeout: 15_000,
    });
  }, 70_000);

  // Mute and camera: named for what they will do, and the track really stops flowing.
  await withConnectionReport(
    { ana: ana.page, ben: ben.page },
    async () => {
      await ben.page.getByTestId("call-mute").click();
      await expect(ben.page.getByTestId("call-mute")).toHaveAccessibleName(
        "Unmute microphone",
      );
      await ben.page.getByTestId("call-camera").click();
      await expect(ben.page.getByTestId("call-camera")).toHaveAccessibleName(
        "Turn camera on",
      );
      await expect(ben.page.getByTestId("call-self")).toHaveCount(0);
      await ben.page.getByTestId("call-camera").click();
      await ben.page.getByTestId("call-mute").click();
    },
    30_000,
    KNOWN_WEBKIT_FREEZE,
  );

  // Ana ends it. Ben is told how it ended; both devices let the camera and the connection
  // go. The step has a time limit of its own, so that a page frozen in the browser's media
  // teardown is reported as such, with the engine's last line.
  const captures = (page: Page) =>
    page.evaluate(() =>
      (window as unknown as { __captures: MediaStream[] }).__captures.flatMap((stream) =>
        stream.getTracks().map((track) => track.readyState)
      )
    );
  type Kept = { pc: RTCPeerConnection };
  // The call's connection is the one that carries media.
  const callConnections = (page: Page) =>
    page.evaluate(() =>
      (window as unknown as { __pcs: Kept[] }).__pcs.flatMap(({ pc }, i) =>
        pc.getTransceivers().length > 0 ? [i] : []
      )
    );
  const signaling = (page: Page, which: number[]) =>
    page.evaluate(
      (which) =>
        which.map((i) => (window as unknown as { __pcs: Kept[] }).__pcs[i].pc.signalingState),
      which,
    );
  await withConnectionReport({ ana: ana.page, ben: ben.page }, async () => {
    const connections = new Map<Page, number[]>();
    for (const page of [ana.page, ben.page]) {
      connections.set(page, await callConnections(page));
      expect(connections.get(page)).toHaveLength(1);
    }
    await ana.page.getByTestId("call-hangup").click();
    // The screen says how the call ended for six seconds, so the two pages are read at the
    // same time. Ben closes his; Ana's goes away by itself.
    await Promise.all([
      (async () => {
        await expect(ana.page.getByTestId("call-status")).toHaveText("Call ended");
        await expect(ana.page.getByTestId("call-remote")).toHaveCount(0);
      })(),
      (async () => {
        await expect(ben.page.getByTestId("call-status")).toHaveText(
          "Ana ended the call",
        );
        await expect(ben.page.getByTestId("call-remote")).toHaveCount(0);
        await ben.page.getByTestId("call-close").click();
        await expect(ben.page.getByTestId("call-screen")).toHaveCount(0);
      })(),
    ]);
    await expect(ana.page.getByTestId("call-screen")).toHaveCount(0, {
      timeout: 15_000,
    });
    for (const page of [ana.page, ben.page]) {
      // The capture is stopped and the call's connection closed.
      await expect.poll(() => captures(page)).toEqual(["ended", "ended"]);
      await expect.poll(() => signaling(page, connections.get(page)!)).toEqual(["closed"]);
    }
  }, 60_000);

  // A voice call the other way, declined.
  await ana.page.getByTestId("call-voice").click();
  await expect(ben.page.getByTestId("incoming-call-words")).toHaveText(
    "Ana is calling",
    CONNECT,
  );
  // At a wide width the ringing call is a banner, not the whole window.
  const box = (await ben.page.getByTestId("incoming-call").boundingBox())!;
  expect(box.height).toBeLessThan(300);
  await ben.page.getByTestId("call-decline").click();
  await expect(ben.page.getByTestId("incoming-call")).toHaveCount(0);
  await expect(ana.page.getByTestId("call-status")).toHaveText("Ben declined");
  // It says so for six seconds and goes by itself ("Close" was pressed above).
  await expect(ana.page.getByTestId("call-screen")).toHaveCount(0, {
    timeout: 15_000,
  });

  // The conversation is still there, and still open.
  await send(ana.page, "Talk later then.");
  await expect(bubble(ben.page, "Talk later then.")).toBeVisible();
  await allClean(ana, ben);
});

test("the list: unread counts, newest first, read when opened", async ({ browser, live }) => {
  const ana = await person(browser, live);
  const ben = await person(browser, live);
  const cai = await person(browser, live);
  await start(ana.page);
  await start(ben.page);
  await start(cai.page);
  await pairByPaste(ana.page, ben.page, { presenter: "Ana", scanner: "Ben" });
  await openLine(ana.page, ben.page);
  // A second contact for Ana, with a fresh code.
  await ana.page.getByTestId("add-contact").click();
  await expect(ana.page.getByTestId("pairing-own")).toHaveAttribute(
    "data-state",
    "ready",
  );
  await pairByPaste(ana.page, cai.page, { presenter: "Ana", scanner: "Cai" });
  await openLine(ana.page, cai.page);

  // Ana is reading Cai's conversation; Ben writes twice.
  await send(ben.page, "One.");
  await send(ben.page, "Two.");
  const rows = ana.page.getByTestId("section-online").getByRole("link");
  await expect(rows.first()).toContainText("Ben");
  await expect(rows.first().getByTestId("unread-badge")).toContainText(
    "2 new messages",
  );
  await expect(rows.first()).toContainText("Two.");
  await expect(ana.page.getByTestId("announcer")).toHaveText(
    "New message from Ben",
  );

  // Cai writes: that conversation is on screen, so it is read, and it moves to the top.
  await send(cai.page, "Hi from Cai.");
  await expect(rows.first()).toContainText("Cai");
  await expect(rows.first().getByTestId("unread-badge")).toHaveCount(0);

  // Opening Ben's conversation reads it.
  await rows.nth(1).click();
  await expect(ana.page.getByTestId("conversation-name")).toHaveText("Ben");
  await expect(ana.page.getByTestId("unread-badge")).toHaveCount(0);
  await ana.page.reload();
  await expect(ana.page.getByTestId("conversation-name")).toHaveText("Ben");
  await expect(ana.page.getByTestId("unread-badge")).toHaveCount(0);
  await allClean(ana, ben, cai);
});

test("one tab at a time: a second tab says so and can take over", async ({ browser, live }) => {
  const ana = await person(browser, live);
  await start(ana.page);
  const second = await ana.context.newPage();
  await second.goto(live.url);
  const notice = second.getByTestId("other-tab");
  await expect(notice).toContainText("ParolNet is open in another tab");
  await expect(notice).toHaveAttribute("data-moved", "false");

  await second.getByTestId("other-tab-use-here").click();
  await expect(second.getByTestId("conversation-list")).toBeVisible({
    timeout: 20_000,
  });
  // The first tab stopped, and says where ParolNet went.
  await expect(ana.page.getByTestId("other-tab")).toContainText(
    "ParolNet moved to another tab",
  );
  await expect(ana.page.getByTestId("other-tab")).toHaveAttribute(
    "data-moved",
    "true",
  );

  // And back again.
  await ana.page.getByTestId("other-tab-use-here").click();
  await expect(ana.page.getByTestId("conversation-list")).toBeVisible({
    timeout: 20_000,
  });
  await expect(second.getByTestId("other-tab")).toHaveAttribute(
    "data-moved",
    "true",
  );
  await expectClean(ana.problems);
});

test("settings: a relay server of one's own is kept, its password never shown; delete all data starts over", async ({ browser, live }) => {
  const ana = await person(browser, live);
  await start(ana.page);
  // Rows in the identity store: the identity and the code on screen. Their keys are sealed
  // like everything else, so they are counted, not named.
  const identity = () =>
    ana.page.evaluate(() =>
      new Promise<number>((resolve) => {
        const open = indexedDB.open("parolnet-web");
        open.onsuccess = () => {
          const rows = open.result.transaction("identity").objectStore(
            "identity",
          ).count();
          rows.onsuccess = () => {
            open.result.close();
            resolve(rows.result);
          };
        };
      })
    );
  // The add screen's code is kept for a reload; leaving the screen (for settings) drops it.
  expect(await identity()).toBe(2);

  await ana.page.getByTestId("pairing-hide-ip").click();
  await expect(ana.page.getByTestId("settings-status")).toHaveText(
    "Connected. Your contacts can reach you.",
  );
  await expect(ana.page.getByTestId("settings-version")).toHaveText(
    /Version \d+\.\d+\.\d+/,
  );
  await expect.poll(() => identity()).toBe(1);

  // A wrong address is refused in words.
  await ana.page.getByTestId("turn-uri").fill("https://turn.example.org");
  await ana.page.getByTestId("turn-save").click();
  await expect(ana.page.getByTestId("turn-problem")).toHaveText(
    "Enter the address as turn:host:port, with the username and password of your server.",
  );
  await ana.page.getByTestId("turn-uri").fill("turn:127.0.0.1:3478");
  await ana.page.getByTestId("turn-username").fill("ana");
  await ana.page.getByTestId("turn-password").fill("s3cret-turn-pass");
  await ana.page.getByTestId("turn-save").click();
  await expect(ana.page.getByTestId("toast")).toHaveText("Relay server saved");

  // After a reload the server is still set; the password field is empty and the password is
  // nowhere in the page.
  await ana.page.reload();
  await expect(ana.page.getByTestId("turn-uri")).toHaveValue(
    "turn:127.0.0.1:3478",
  );
  await expect(ana.page.getByTestId("turn-username")).toHaveValue("ana");
  await expect(ana.page.getByTestId("turn-password")).toHaveValue("");
  expect(await ana.page.content()).not.toContain("s3cret-turn-pass");
  await ana.page.getByTestId("turn-remove").click();
  await expect(ana.page.getByTestId("toast")).toHaveText(
    "Relay server removed",
  );

  // Licences: the third-party notices, served with the app.
  const licences = await ana.page.getByTestId("settings-licences").getAttribute(
    "href",
  );
  const response = await ana.page.request.get(licences!);
  expect(response.ok()).toBe(true);
  expect(await response.text()).toContain(
    "Third-party material in the web app",
  );

  // Delete all data: typed confirmation, then first run again with nothing left.
  await ana.page.getByTestId("settings-wipe").click();
  await ana.page.getByTestId("wipe-input").fill("delete");
  await ana.page.getByTestId("wipe-confirm").click();
  await expect(ana.page.getByTestId("first-run")).toBeVisible({
    timeout: 20_000,
  });
  expect(await identity()).toBe(0);
  expect(await ana.page.evaluate(() => Object.keys(localStorage))).toEqual([]);
  await expectClean(ana.problems);
});

/**
 * Everything a copy of the page's database would show: every row of every store as text
 * (bytes as Latin-1), and what kind of thing the vault's keys are.
 */
function databaseAsKept(page: Page): Promise<{ text: string; rows: number; keys: string }> {
  return page.evaluate(() =>
    new Promise<{ text: string; rows: number; keys: string }>((resolve, reject) => {
      const open = indexedDB.open("parolnet-web");
      open.onerror = () => reject(open.error);
      open.onsuccess = () => {
        const db = open.result;
        const names = [...db.objectStoreNames];
        const tx = db.transaction(names, "readonly");
        const all: Record<string, unknown[]> = {};
        for (const name of names) {
          const request = tx.objectStore(name).getAll();
          request.onsuccess = () => (all[name] = request.result);
        }
        tx.oncomplete = () => {
          db.close();
          const keys = (all.vault as Array<Record<string, unknown>>).find((row) =>
            row.id === "keys"
          );
          const kind = !keys
            ? "none"
            : keys.mode === "device"
            ? `device:${keys.enc instanceof CryptoKey}:${(keys.enc as CryptoKey).extractable}:${
              (keys.mac as CryptoKey).extractable
            }`
            : `passphrase:${Object.keys(keys).sort().join(",")}`;
          const text = JSON.stringify(
            all,
            (_key, value) =>
              value instanceof Uint8Array
                ? new TextDecoder("latin1").decode(value)
                : value instanceof CryptoKey
                ? "[CryptoKey]"
                : value,
          );
          const rows = names.filter((name) => name !== "vault").reduce(
            (sum, name) => sum + all[name].length,
            0,
          );
          resolve({ text, rows, keys: kind });
        };
      };
    })
  );
}

const peerIdOf = (page: Page) =>
  page.evaluate(() => /#\/c\/([0-9a-f]{64})/.exec(location.hash)?.[1] ?? "");

async function unlock(page: Page, passphrase: string): Promise<number> {
  await expect(page.getByTestId("locked")).toBeVisible({ timeout: 20_000 });
  await page.getByTestId("unlock-passphrase").fill(passphrase);
  const started = Date.now();
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("app")).toBeVisible({ timeout: 60_000 });
  return Date.now() - started;
}

test("at rest: nothing readable in the database; a passphrase locks ParolNet, with wrong tries, change and remove", async ({ browser, live }) => {
  test.setTimeout(240_000);
  const ana = await person(browser, live);
  const ben = await person(browser, live);
  await start(ana.page);
  await start(ben.page);
  await pairByPaste(ana.page, ben.page, { presenter: "Ana", scanner: "Ben" });
  await openLine(ana.page, ben.page);
  await send(ana.page, "kept under lock and key");
  await expect(bubble(ben.page, "kept under lock and key")).toHaveAttribute(
    "data-kind",
    "received",
  );
  await send(ben.page, "and read on the other side");
  await expect(bubble(ana.page, "and read on the other side")).toBeVisible();
  const ben_id = await peerIdOf(ana.page);
  expect(ben_id).toMatch(/^[0-9a-f]{64}$/);

  // Without a passphrase: the keys are objects the browser will not export, and no name,
  // message, contact id or store key is readable in what the database keeps.
  const plainWords = [
    "Ben",
    "lock and key",
    "other side",
    ben_id,
    "secretHex",
    "timestampMs",
    "self",
  ];
  const before = await databaseAsKept(ana.page);
  expect(before.keys).toBe("device:true:false:false");
  expect(before.rows).toBeGreaterThanOrEqual(6);
  for (const word of plainWords) expect(before.text, word).not.toContain(word);

  // Set a passphrase: too short and mismatched are said in words; then it is set.
  await ana.page.goto(live.url + "#/settings");
  await expect(ana.page.getByTestId("settings-lock")).toHaveAttribute("data-on", "false");
  await ana.page.getByTestId("lock-set").click();
  await expect(ana.page.getByTestId("lock-forgotten")).toContainText("nobody can recover it");
  await ana.page.getByTestId("lock-new").fill("short");
  await ana.page.getByTestId("lock-again").fill("short");
  await ana.page.getByTestId("lock-submit").click();
  await expect(ana.page.getByTestId("lock-problem")).toHaveText("That passphrase is too short.");
  await ana.page.getByTestId("lock-new").fill("tidal copper lantern verse");
  await ana.page.getByTestId("lock-again").fill("tidal copper lantern vers");
  await ana.page.getByTestId("lock-submit").click();
  await expect(ana.page.getByTestId("lock-problem")).toHaveText(
    "The two passphrases are not the same.",
  );
  await ana.page.getByTestId("lock-again").fill("tidal copper lantern verse");
  await ana.page.getByTestId("lock-submit").click();
  await expect(ana.page.getByTestId("toast")).toHaveText("Passphrase set", { timeout: 60_000 });
  await expect(ana.page.getByTestId("settings-lock")).toHaveAttribute("data-on", "true");

  // Now the database holds no key at all: only what the passphrase can unwrap.
  const locked = await databaseAsKept(ana.page);
  expect(locked.keys).toBe("passphrase:format,id,kdf,mode,nonce,salt,wrapped");
  expect(locked.rows).toBe(before.rows);
  for (const word of [...plainWords, "tidal copper"]) expect(locked.text, word).not.toContain(word);

  // Every start asks for it. A wrong one is said so; the right one opens everything.
  await ana.page.reload();
  await expect(ana.page.getByTestId("locked")).toBeVisible({ timeout: 20_000 });
  await expect(ana.page.getByTestId("app")).toHaveCount(0);
  await ana.page.getByTestId("unlock-passphrase").fill("not the passphrase");
  await ana.page.getByTestId("unlock-submit").click();
  await expect(ana.page.getByTestId("unlock-problem")).toHaveText("That is not the passphrase.", {
    timeout: 60_000,
  });
  await expect(ana.page.getByTestId("locked")).toBeVisible();
  const took = await unlock(ana.page, "tidal copper lantern verse");
  console.log(`unlock (Argon2id 64 MiB, 3 passes, and the start of the engine): ${took} ms`);
  await ana.page.goto(live.url + `#/c/${ben_id}`);
  await expect(bubble(ana.page, "kept under lock and key")).toBeVisible();
  await expect(bubble(ana.page, "and read on the other side")).toBeVisible();
  await openLine(ana.page);
  await send(ana.page, "after unlocking");
  await expect(bubble(ben.page, "after unlocking")).toHaveAttribute("data-kind", "received");

  // Lock now; three wrong tries make the next one wait, and the wait is counted down.
  await ana.page.goto(live.url + "#/settings");
  await ana.page.getByTestId("lock-now").click();
  await expect(ana.page.getByTestId("locked")).toBeVisible({ timeout: 20_000 });
  for (let i = 0; i < 3; i++) {
    await expect(ana.page.getByTestId("unlock-submit")).toBeEnabled({ timeout: 60_000 });
    await ana.page.getByTestId("unlock-passphrase").fill(`wrong guess ${i}`);
    await ana.page.getByTestId("unlock-submit").click();
    await expect(ana.page.getByTestId("unlock-problem")).not.toBeEmpty({ timeout: 60_000 });
  }
  await expect(ana.page.getByTestId("unlock-problem")).toContainText("Too many wrong tries");
  await expect(ana.page.getByTestId("unlock-submit")).toBeDisabled();
  // The count is kept across a reload.
  await ana.page.reload();
  await expect(ana.page.getByTestId("unlock-problem")).toContainText("Too many wrong tries", {
    timeout: 20_000,
  });
  await expect(ana.page.getByTestId("unlock-submit")).toBeEnabled({ timeout: 20_000 });
  await unlock(ana.page, "tidal copper lantern verse");

  // Change it (the current one is asked for), then remove it.
  await ana.page.goto(live.url + "#/settings");
  await ana.page.getByTestId("lock-change").click();
  await ana.page.getByTestId("lock-current").fill("not the passphrase");
  await ana.page.getByTestId("lock-new").fill("marble orchard seven kites");
  await ana.page.getByTestId("lock-again").fill("marble orchard seven kites");
  await ana.page.getByTestId("lock-submit").click();
  await expect(ana.page.getByTestId("lock-problem")).toHaveText("That is not the passphrase.", {
    timeout: 60_000,
  });
  await ana.page.getByTestId("lock-current").fill("tidal copper lantern verse");
  await ana.page.getByTestId("lock-submit").click();
  await expect(ana.page.getByTestId("toast")).toHaveText("Passphrase changed", { timeout: 60_000 });
  await ana.page.reload();
  await unlock(ana.page, "marble orchard seven kites");
  await ana.page.goto(live.url + "#/settings");
  await ana.page.getByTestId("lock-remove").click();
  await ana.page.getByTestId("lock-current").fill("marble orchard seven kites");
  await ana.page.getByTestId("lock-submit").click();
  await expect(ana.page.getByTestId("toast")).toHaveText("Passphrase removed", { timeout: 60_000 });
  await expect(ana.page.getByTestId("settings-lock")).toHaveAttribute("data-on", "false");
  await ana.page.reload();
  await expect(ana.page.getByTestId("app")).toBeVisible({ timeout: 20_000 });
  expect((await databaseAsKept(ana.page)).keys).toBe("device:true:false:false");
  await ana.page.goto(live.url + `#/c/${ben_id}`);
  await expect(bubble(ana.page, "after unlocking")).toBeVisible();
  await allClean(ana, ben);
});

test("locked and the passphrase forgotten: delete everything and start again", async ({ browser, live }) => {
  test.setTimeout(180_000);
  const ana = await person(browser, live);
  await start(ana.page);
  await ana.page.goto(live.url + "#/settings");
  await ana.page.getByTestId("lock-set").click();
  await ana.page.getByTestId("lock-new").fill("soon to be forgotten");
  await ana.page.getByTestId("lock-again").fill("soon to be forgotten");
  await ana.page.getByTestId("lock-submit").click();
  await expect(ana.page.getByTestId("toast")).toHaveText("Passphrase set", { timeout: 60_000 });
  await ana.page.reload();
  await expect(ana.page.getByTestId("locked")).toBeVisible({ timeout: 20_000 });
  await ana.page.getByTestId("unlock-forgot").click();
  await expect(ana.page.getByTestId("sheet-forget")).toContainText("cannot be recovered");
  await expect(ana.page.getByTestId("forget-confirm")).toBeDisabled();
  await ana.page.getByTestId("forget-input").fill("delete");
  await ana.page.getByTestId("forget-confirm").click();
  await expect(ana.page.getByTestId("first-run")).toBeVisible({ timeout: 20_000 });
  expect((await databaseAsKept(ana.page)).rows).toBe(0);
  await expectClean(ana.problems);
});

test(
  "back up this device, delete all data, restore: the same person, still paired, and the two can chat",
  async ({ browser, live }, testInfo) => {
    test.setTimeout(240_000);
    const ana = await person(browser, live);
    const ben = await person(browser, live);
    await start(ana.page);
    await start(ben.page);
    await pairByPaste(ana.page, ben.page, { presenter: "Ana", scanner: "Ben" });
    await openLine(ana.page, ben.page);
    await send(ana.page, "written by Ana first");
    await expect(bubble(ben.page, "written by Ana first")).toHaveAttribute("data-kind", "received");
    await send(ben.page, "an answer from Ben");
    await expect(bubble(ana.page, "an answer from Ben")).toBeVisible();
    const ben_id = await peerIdOf(ana.page);

    // With a contact and no backup, the list suggests one, and blocks nothing.
    await ana.page.goto(live.url + "#/");
    await expect(ana.page.getByTestId("backup-hint")).toContainText("Make a backup");
    await ana.page.getByTestId("backup-hint-action").click();
    await expect(ana.page.getByTestId("backup-last")).toHaveText(
      "No backup has been made on this device.",
    );

    // Back up, with the history. The file is saved through a link the person presses.
    await ana.page.getByTestId("backup-open").click();
    await expect(ana.page.getByTestId("backup-history")).not.toBeChecked();
    await ana.page.getByTestId("backup-new").fill("quiet river paper moon");
    await ana.page.getByTestId("backup-again").fill("quiet river paper moon");
    await ana.page.getByTestId("backup-history").check();
    await ana.page.getByTestId("backup-make").click();
    await expect(ana.page.getByTestId("backup-ready")).toBeVisible({ timeout: 60_000 });
    await expect(ana.page.getByTestId("sheet-backup")).toContainText("one device at a time");
    const downloading = ana.page.waitForEvent("download");
    await ana.page.getByTestId("backup-save").click();
    const download = await downloading;
    expect(download.suggestedFilename()).toMatch(/^parolnet-backup-\d{4}-\d{2}-\d{2}\.pnbackup$/);
    const file = testInfo.outputPath("ana.pnbackup");
    await download.saveAs(file);
    const bytes = readFileSync(file);
    expect(bytes.subarray(0, 8).toString("latin1")).toBe("PNBACKUP");
    expect(bytes[8]).toBe(1);
    const text = bytes.toString("latin1");
    for (const word of ["Ben", "written by Ana first", ben_id, "secretHex"]) {
      expect(text, word).not.toContain(word);
    }
    await ana.page.getByTestId("sheet-backup-close").click();
    await expect(ana.page.getByTestId("backup-last")).toContainText("Last backup:");
    await ana.page.goto(live.url + "#/");
    await expect(ana.page.getByTestId("backup-hint")).toHaveCount(0);

    // Delete all data: first run, nothing left.
    await ana.page.goto(live.url + "#/settings");
    await ana.page.getByTestId("settings-wipe").click();
    await ana.page.getByTestId("wipe-input").fill("delete");
    await ana.page.getByTestId("wipe-confirm").click();
    await expect(ana.page.getByTestId("first-run")).toBeVisible({ timeout: 20_000 });
    await expect(ben.page.getByTestId("conversation")).not.toHaveAttribute(
      "data-line",
      "open",
      CONNECT,
    );

    // Restore on first run. Not a backup, then a wrong passphrase: each said in words, and
    // nothing changes. Then the right one.
    await ana.page.getByTestId("first-run-restore").click();
    await expect(ana.page.getByTestId("restore-replaces")).toHaveCount(0);
    await ana.page.getByTestId("restore-submit").click();
    await expect(ana.page.getByTestId("restore-problem")).toHaveText(
      "Choose the backup file first.",
    );
    await ana.page.getByTestId("restore-file").setInputFiles({
      name: "holiday.pnbackup",
      mimeType: "application/octet-stream",
      buffer: Buffer.from("this is not a backup at all"),
    });
    await ana.page.getByTestId("restore-passphrase").fill("quiet river paper moon");
    await ana.page.getByTestId("restore-submit").click();
    await expect(ana.page.getByTestId("restore-problem")).toHaveText(
      "That file is not a ParolNet backup.",
    );
    await ana.page.getByTestId("restore-file").setInputFiles(file);
    await ana.page.getByTestId("restore-passphrase").fill("quiet river paper sun");
    await ana.page.getByTestId("restore-submit").click();
    await expect(ana.page.getByTestId("restore-problem")).toHaveText(
      "The passphrase is wrong, or the file is damaged.",
      { timeout: 60_000 },
    );
    await expect(ana.page.getByTestId("first-run")).toBeVisible();
    await ana.page.getByTestId("restore-passphrase").fill("quiet river paper moon");
    await ana.page.getByTestId("restore-submit").click();
    await expect(ana.page.getByTestId("app")).toBeVisible({ timeout: 60_000 });

    // The same person: Ben is there by name, with the history, and marked as restored.
    await ana.page.goto(live.url + `#/c/${ben_id}`);
    await expect(ana.page.getByTestId("conversation-name")).toHaveText("Ben");
    await expect(bubble(ana.page, "written by Ana first")).toBeVisible();
    await expect(bubble(ana.page, "an answer from Ben")).toBeVisible();
    // Still paired: the line opens without adding each other again, and they can chat.
    await openLine(ana.page, ben.page);
    await send(ana.page, "from the restored device");
    await expect(bubble(ben.page, "from the restored device")).toHaveAttribute(
      "data-kind",
      "received",
    );
    await send(ben.page, "and to it");
    await expect(bubble(ana.page, "and to it")).toBeVisible();
    // The connection held, so the note about the backup goes away.
    await expect(ana.page.getByTestId("restored-note")).toHaveCount(0, { timeout: 30_000 });
    // The restored database is sealed like any other.
    const kept = await databaseAsKept(ana.page);
    for (const word of ["Ben", "written by Ana first", ben_id]) {
      expect(kept.text, word).not.toContain(word);
    }

    // In Settings a restore replaces what is here, so a word has to be typed first.
    await ana.page.goto(live.url + "#/settings");
    await ana.page.getByTestId("restore-open").click();
    await expect(ana.page.getByTestId("restore-replaces")).toContainText("cannot be undone");
    await expect(ana.page.getByTestId("restore-submit")).toBeDisabled();
    await ana.page.getByTestId("restore-confirm-input").fill("replace");
    await expect(ana.page.getByTestId("restore-submit")).toBeEnabled();
    await ana.page.getByTestId("sheet-restore-close").click();
    await allClean(ana, ben);
  },
);

test("a database of the earlier version, kept in plaintext, is sealed at the first start with nothing lost", async ({ browser, live }) => {
  const ana = await person(browser, live);
  await expect(ana.page.getByTestId("first-run")).toBeVisible();
  const friend = "c7".repeat(32);
  // What version 1 of the app left behind: the same stores, without the vault, rows in the
  // clear. (Deleting the open database makes the page let go of it.)
  await ana.page.evaluate((friend) =>
    new Promise<void>((resolve, reject) => {
      const gone = indexedDB.deleteDatabase("parolnet-web");
      gone.onerror = () => reject(gone.error);
      gone.onsuccess = () => {
        const open = indexedDB.open("parolnet-web", 1);
        open.onupgradeneeded = () => {
          const db = open.result;
          const paths: Record<string, string> = {
            identity: "id",
            sessions: "id",
            contacts: "peerId",
            messages: "id",
            outbox: "id",
            contactState: "peerId",
            settings: "key",
          };
          for (const [name, keyPath] of Object.entries(paths)) {
            const store = db.createObjectStore(name, { keyPath });
            if (name === "messages" || name === "outbox") store.createIndex("peerId", "peerId");
          }
        };
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
          const db = open.result;
          const tx = db.transaction(
            ["identity", "contacts", "messages", "contactState"],
            "readwrite",
          );
          tx.objectStore("identity").put({ id: "self", secretHex: "3b".repeat(32) });
          tx.objectStore("contacts").put({
            peerId: friend,
            name: "Old Friend",
            identityKey: null,
            addedMs: 1_700_000_000_000,
            verified: "no",
            verifiedMs: null,
          });
          tx.objectStore("contactState").put({
            peerId: friend,
            lastActivityMs: 1_700_000_000_500,
            unread: 0,
          });
          for (
            const [id, text] of [[1, "written before the update"], [2, "and so was this"]] as const
          ) {
            tx.objectStore("messages").put({
              id,
              peerId: friend,
              direction: id === 1 ? "Sent" : "Received",
              text,
              timestampMs: 1_700_000_000_000 + id,
              state: id === 1 ? "Sent" : "Received",
            });
          }
          tx.oncomplete = () => {
            db.close();
            resolve();
          };
          tx.onerror = () => reject(tx.error);
        };
      };
    }), friend);

  await ana.page.reload();
  // No first run: the identity that was there is the one that starts.
  await expect(ana.page.getByTestId("app")).toBeVisible({ timeout: 20_000 });
  await ana.page.goto(live.url + `#/c/${friend}`);
  await expect(ana.page.getByTestId("conversation-name")).toHaveText("Old Friend");
  await expect(bubble(ana.page, "written before the update")).toBeVisible();
  await expect(bubble(ana.page, "and so was this")).toBeVisible();
  const kept = await databaseAsKept(ana.page);
  expect(kept.keys).toBe("device:true:false:false");
  // The identity, the contact, its state and two messages; what is added later comes on top.
  expect(kept.rows).toBeGreaterThanOrEqual(5);
  for (
    const word of [
      "Old Friend",
      "before the update",
      "so was this",
      friend,
      "3b".repeat(32),
      "secretHex",
    ]
  ) {
    expect(kept.text, word).not.toContain(word);
  }
  // And it stays that way across another start.
  await ana.page.reload();
  await ana.page.goto(live.url + `#/c/${friend}`);
  await expect(bubble(ana.page, "and so was this")).toBeVisible({ timeout: 20_000 });
  await expectClean(ana.problems);
});
