// Real flows on the production export: two (or three) people, each in a browser context of
// their own, talking through a real relay served at the same origin. Everything here is
// driven through the interface, the way a person would; nothing reads the engine. Every
// page is watched: no CSP violation, no console error, no request that leaves localhost.
//
//   npx playwright test --project=flows-chromium      (needs the relay binary, see harness.ts)
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

/** A file bubble in the open conversation, by the file's name. */
const fileBubble = (page: Page, name: string) =>
  page.getByTestId("transfer-bubble").filter({ hasText: name });

/**
 * Chromium has `showSaveFilePicker`, a system dialog no test can answer; without it the app
 * saves through a download link, which is what every other browser does and what this checks.
 */
async function saveByDownload(context: BrowserContext): Promise<void> {
  await context.addInitScript(() => {
    delete (window as unknown as { showSaveFilePicker?: unknown }).showSaveFilePicker;
  });
}

test("a file: offered, accepted, progress in words, verified and saved; one declined; one withdrawn", async ({ browser, live }) => {
  const { createHash, randomBytes } = await import("node:crypto");
  const { readFile } = await import("node:fs/promises");
  // FLOW_FILE_MIB: the size of the file that goes across (the M1 bar for desktop <-> web
  // is 100 MiB, see the interop suite; Playwright hands a page at most 50 MiB this way).
  const mib = Math.min(48, Number(process.env.FLOW_FILE_MIB ?? 6));
  const data = randomBytes(mib * 1024 * 1024 + 4321);
  const sha256 = createHash("sha256").update(data).digest("hex");
  const patience = { timeout: 60_000 + mib * 3_000 };

  const ana = await person(browser, live, PHONE, saveByDownload);
  const ben = await person(browser, live, WIDE);
  await start(ana.page);
  await start(ben.page);
  await pairByPaste(ana.page, ben.page, { presenter: "Ana", scanner: "Ben" });
  await openLine(ana.page, ben.page);

  // Ben picks a file in the composer. It is offered at once: the line is open.
  await ben.page.getByTestId("composer-file").setInputFiles({
    name: "field notes.pdf",
    mimeType: "application/pdf",
    buffer: data,
  });
  const sent = fileBubble(ben.page, "field notes.pdf");
  await expect(sent).toHaveAttribute("data-direction", "sent", patience);
  await expect(sent).toHaveAttribute("data-state", "offered");
  await expect(sent).toHaveAttribute("data-pending", "false");

  // Ana sees the offer with its name and size, and nothing arrives before she says so.
  const got = fileBubble(ana.page, "field notes.pdf");
  await expect(got).toHaveAttribute("data-direction", "received");
  await expect(got).toHaveAttribute("data-state", "offered");
  await expect(got.getByTestId("transfer-name")).toHaveText("field notes.pdf");
  await expect(got.getByTestId("transfer-save")).toHaveCount(0);
  await got.getByTestId("transfer-accept").click();

  // It arrives, verifies, and both devices say so.
  await expect(got).toHaveAttribute("data-state", "complete", patience);
  await expect(sent).toHaveAttribute("data-state", "complete", patience);
  await expect(got.getByTestId("transfer-status")).not.toHaveText("");
  await expect(sent.getByTestId("transfer-status")).not.toHaveText("");

  // Saving gives exactly the file that was sent, under its name.
  const [download] = await Promise.all([
    ana.page.waitForEvent("download"),
    got.getByTestId("transfer-save").click(),
  ]);
  expect(download.suggestedFilename()).toBe("field notes.pdf");
  const saved = await readFile(await download.path());
  expect(saved.length).toBe(data.length);
  expect(createHash("sha256").update(saved).digest("hex")).toBe(sha256);

  // A name that tries to be a path arrives as a plain name; Ben declines it.
  await ana.page.getByTestId("composer-file").setInputFiles({
    name: "../../etc/passwd",
    mimeType: "text/plain",
    buffer: Buffer.from("not what it says"),
  });
  const refused = fileBubble(ben.page, "passwd");
  await expect(refused).toHaveAttribute("data-state", "offered");
  await expect(refused.getByTestId("transfer-name")).toHaveText("passwd");
  await refused.getByTestId("transfer-decline").click();
  await expect(refused).toHaveAttribute("data-state", "declined");
  await expect(
    ana.page.getByTestId("transfer-bubble").filter({ hasText: "passwd" }),
  ).toHaveAttribute("data-state", "declined");

  // An offer taken back before it was answered.
  await ben.page.getByTestId("composer-file").setInputFiles({
    name: "second thoughts.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("never mind"),
  });
  const withdrawn = fileBubble(ben.page, "second thoughts.txt");
  await expect(withdrawn).toHaveAttribute("data-state", "offered");
  await expect(fileBubble(ana.page, "second thoughts.txt")).toHaveAttribute(
    "data-state",
    "offered",
  );
  await withdrawn.getByTestId("transfer-cancel").click();
  await expect(withdrawn).toHaveAttribute("data-state", "cancelled");
  await expect(fileBubble(ana.page, "second thoughts.txt")).toHaveAttribute(
    "data-state",
    "cancelled",
  );
  await expect(
    fileBubble(ana.page, "second thoughts.txt").getByTestId("transfer-accept"),
  ).toHaveCount(0);

  await allClean(ana, ben);
});

test("a file offered while they are away waits on this device and goes when they return", async ({ browser, live }) => {
  const { randomBytes } = await import("node:crypto");
  const ana = await person(browser, live, PHONE);
  const ben = await person(browser, live, WIDE);
  await start(ana.page);
  await start(ben.page);
  await pairByPaste(ana.page, ben.page, { presenter: "Ana", scanner: "Ben" });
  await openLine(ana.page, ben.page);

  // Ana closes her tab.
  await ana.page.close();
  await expect(ben.page.getByTestId("conversation")).not.toHaveAttribute(
    "data-line",
    "open",
    CONNECT,
  );
  await ben.page.getByTestId("composer-file").setInputFiles({
    name: "for later.bin",
    mimeType: "application/octet-stream",
    buffer: randomBytes(300_000),
  });
  const waiting = fileBubble(ben.page, "for later.bin");
  await expect(waiting).toHaveAttribute("data-state", "offered");
  await expect(waiting).toHaveAttribute("data-pending", "true");

  // She comes back: the offer reaches her, she accepts, it arrives.
  const again = await ana.context.newPage();
  const problems = await watch(again, live);
  await again.goto(live.url);
  await expect(waiting).toHaveAttribute("data-pending", "false", { timeout: 90_000 });
  await again.getByTestId("conversation-list").getByRole("link", { name: /Ben/ }).click();
  const got = fileBubble(again, "for later.bin");
  await expect(got).toHaveAttribute("data-state", "offered", CONNECT);
  await got.getByTestId("transfer-accept").click();
  await expect(got).toHaveAttribute("data-state", "complete", { timeout: 60_000 });
  await expect(waiting).toHaveAttribute("data-state", "complete", { timeout: 60_000 });

  await expectClean(problems);
  await expectClean(ben.problems);
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
  // Rows in the identity store: the identity ("self") and the code on screen ("pairing").
  const identity = (key?: string) =>
    ana.page.evaluate((key) =>
      new Promise<number>((resolve) => {
        const open = indexedDB.open("parolnet-web");
        open.onsuccess = () => {
          const rows = open.result.transaction("identity").objectStore(
            "identity",
          ).count(key);
          rows.onsuccess = () => {
            open.result.close();
            resolve(rows.result);
          };
        };
      }), key);
  expect(await identity("self")).toBe(1);
  // The add screen's code is kept for a reload; leaving the screen (for settings) drops it.
  expect(await identity("pairing")).toBe(1);

  await ana.page.getByTestId("pairing-hide-ip").click();
  await expect(ana.page.getByTestId("settings-status")).toHaveText(
    "Connected. Your contacts can reach you.",
  );
  await expect(ana.page.getByTestId("settings-version")).toHaveText(
    /Version \d+\.\d+\.\d+/,
  );
  await expect.poll(() => identity("pairing")).toBe(0);

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
