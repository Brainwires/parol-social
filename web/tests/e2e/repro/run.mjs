// Runs pc-close.html in WebKit many times and says whether, and where, the page froze.
//
//   node run.mjs [order] [pages] [rounds-per-page] [parallel]
//
// See README.md. Exit code 1 when a page froze.
import { webkit } from "@playwright/test";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";

const [order = "close-first", pages = "20", rounds = "3", parallel = "3"] = process.argv.slice(2);
const html = readFileSync(new URL("./pc-close.html", import.meta.url));
const server = createServer((_request, response) => {
  response.writeHead(200, { "content-type": "text/html" });
  response.end(html);
});
await new Promise((done) => server.listen(0, "127.0.0.1", done));
const url = `http://localhost:${server.address().port}/?order=${order}&rounds=${rounds}&hold=1`;

const browser = await webkit.launch();
let frozen = 0;
let finished = 0;
let next = 0;

async function one(index) {
  const context = await browser.newContext({
    permissions: ["camera", "microphone"],
  });
  const page = await context.newPage();
  const lines = [];
  let lastAt = Date.now();
  page.on("console", (message) => {
    lines.push(message.text());
    lastAt = Date.now();
  });
  await page.goto(url);
  for (;;) {
    await new Promise((done) => setTimeout(done, 500));
    const last = lines.at(-1) ?? "";
    if (last.includes("ALL DONE")) {
      finished += 1;
      break;
    }
    if (last.includes("FAILED")) {
      console.log(`page ${index}: ${last}`);
      break;
    }
    if (Date.now() - lastAt > 30_000) {
      const answer = await Promise.race([
        page.evaluate(() => "the page still answers"),
        new Promise((done) =>
          setTimeout(
            () => done("the page does not answer (main thread blocked)"),
            5_000,
          )
        ),
      ]).catch((error) => `evaluate threw: ${error}`);
      // Slow, not frozen: it finished while it was being asked.
      if ((lines.at(-1) ?? "").includes("ALL DONE")) {
        finished += 1;
        break;
      }
      frozen += 1;
      console.log(
        `page ${index}: FROZEN, ${answer}. Last lines:\n  ${lines.slice(-4).join("\n  ")}`,
      );
      if (process.env.REPRO_ON_FREEZE) {
        const { execSync } = await import("node:child_process");
        try {
          console.log(
            execSync(process.env.REPRO_ON_FREEZE, {
              encoding: "utf8",
              maxBuffer: 1 << 28,
              shell: "/bin/bash",
            }),
          );
        } catch (error) {
          console.log(`REPRO_ON_FREEZE failed: ${error}`);
        }
      }
      break;
    }
  }
  await context.close().catch(() => {});
}

async function worker() {
  while (next < Number(pages)) await one(++next);
}
await Promise.all(Array.from({ length: Number(parallel) }, worker));
console.log(
  `${order}: ${finished} of ${pages} pages finished all ${rounds} rounds, ${frozen} froze`,
);
await Promise.race([
  browser.close(),
  new Promise((done) => setTimeout(done, 10_000)),
]);
server.close();
process.exit(frozen > 0 ? 1 : 0);
