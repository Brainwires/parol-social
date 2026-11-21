# ParolNet web app

The web client, rewritten as a [Denext](https://denext.dev) app (`mode: "spa"`, TypeScript and TSX)
with the design in [`docs/ux/web-app.md`](../docs/ux/web-app.md). It replaces the vanilla-JS PWA in
`pwa/` once the protocol services are ported.

**What it is today:** the whole client. The screens of the design run on the engine in `src/engine/`
(identity, relay, pairing, the bound data channel, chat with its queue, verification, 1:1 calls,
IndexedDB storage; see [`docs/web-port/engine.md`](../docs/web-port/engine.md)): first run, adding a
contact by QR code or pasted code, conversations, comparing safety numbers, calls, settings. How the
two are joined, the test layers, the languages and what is still owed before it replaces `pwa/` in
production: [`docs/web-port/app.md`](../docs/web-port/app.md).

## Commands

Needs the `denext` CLI (`curl -fsSL https://denext.dev/install.sh | sh`, then
`denext runtime install`), and for the wasm build: cargo with the `wasm32-unknown-unknown` target
and `wasm-pack`. Run from `web/`.

| Task                                            | What it does                                                                                                       |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `denext task build-wasm`                        | Builds `crates/parolnet-wasm` into `public/wasm/` (run once, and after Rust changes)                               |
| `denext task dev`                               | Dev server with Fast Refresh at http://localhost:3000, on the test build (`#/lab` is the state lab)                |
| `denext task build` (or `export`)               | The production export: tokens, `denext export`, then `scripts/postexport.ts`. The static site in `out/`            |
| `denext task build:test`                        | The test build in `out-test/`: the same app plus the state lab and the `window.__parolnetTest` hooks. Run it first |
| `denext task serve`                             | Serves `out/` at http://127.0.0.1:8787/pwa/ with the production CSP header (`RELAY_PORT=…` puts a relay behind it) |
| `denext task test`                              | Unit tests: the app's (`tests/unit`) and the engine's (`tests/engine`, also `denext task test:engine`)             |
| `denext task e2e`                               | Browser tests of the platform and the design: Chromium, Firefox and WebKit through Playwright (needs Node)         |
| `denext task e2e:flows`                         | Real flows between pages through a real relay (needs the relay binary: `PAROLNET_RELAY_BIN` or `target/debug`)     |
| `denext task engine:e2e:build`, `engine:e2e`    | The engine alone in a browser against the relay and the desktop bot (`tests/engine/e2e`)                           |
| `denext task lint`, `fmt`, `fmt:check`, `check` | Lint, format, type-check (the app and the engine)                                                                  |
| `denext task tokens`                            | Regenerates `src/design/tokens.css` from `tokens.json`                                                             |

`build:test` exports into `out/` and moves the result to `out-test/`, so run it before `build`.

## How it is put together

- **Base path.** The site is hosted under `/pwa/`. Denext's SPA mode has no base path, so the app
  never names a root-absolute URL: `spa.head` uses `./…`, the app resolves files against
  `document.baseURI` (`src/platform/base.ts`), stylesheets use relative `url()`s, and
  `scripts/postexport.ts` rewrites the two URLs Denext writes itself (`/assets/index.js`,
  `/assets/index.css`). Routing is in the URL hash (`src/router.ts`), so the document URL never
  changes and the host needs no rewrite rules. The same `out/` works under any path.
- **wasm.** `scripts/build-wasm.ts` runs wasm-pack (`--target web`), minifies the glue and writes
  both files to `public/wasm/` under content-hashed names, with a `manifest.json` that names them.
  `src/platform/wasm.ts` fetches the manifest, imports the glue by URL and streams the module in,
  reporting progress. Nothing goes through the bundler (Denext's native SPA bundler does not emit
  `.wasm` imports or rewrite `new URL("x.wasm", import.meta.url)`).
- **Service worker.** `public/sw.js` is hand-written. `scripts/postexport.ts` writes the precache
  list into it from the files really exported. Hashed and versioned files are served cache-first;
  the shell and the few unhashed files network-first with the cache as fallback. A new build waits
  until the person chooses "Reload". It takes over from the previous PWA's worker at the same URL
  and deletes its `parolnet-v*` caches.
- **CSP.** The app runs under the policy in `nginx.example.conf`, sent as an HTTP header: no inline
  script, no inline style, `'wasm-unsafe-eval'` for the Rust core. The theme is applied before first
  paint by an external script (`public/theme-boot.js`).
- **Design tokens.** `src/design/tokens.json` is the single source; `tokens.css` is generated and
  committed, and a unit test fails when the two differ.
- **Stylesheets.** Each file starts with the same `@layer` order statement, so the cascade does not
  depend on the order the bundler concatenates them in. No `@import` between CSS files (the SPA
  bundler leaves it unresolved); `src/main.tsx` imports each one.
- **Languages.** `src/i18n/`: English is bundled, the other eight locales (ar, de, es, fa, fr, it,
  ja, ko) are JSON chunks loaded on demand. They hold what could be taken from the old PWA's
  translations; a missing key falls back to English, key by key (coverage:
  [`docs/web-port/app.md`](../docs/web-port/app.md)).
- **State.** `src/state/store.ts` is the one interface the screens know. `engine-store.ts`
  implements it over the engine; `fake.ts` is the state lab's made-up version.
- **Two entries.** `src/main.tsx` is the production entry. `src/main.dev.tsx` adds the state lab
  (everything under `#/lab` runs on the fake store, with no engine) and the test hooks;
  `PAROLNET_BUILD=test` in `denext.config.ts` selects it, and `scripts/postexport.ts` fails a
  production build that contains either.
- **The relay.** The app finds its relay at the origin it was served from (`wss://<host>/ws`, and
  `GET /turn-credentials` for STUN addresses), so the host puts the relay behind the same origin. A
  person can name another under Settings, Advanced.
- **QR codes.** The encoder is the app's own (`src/qr/encode.ts`). The scanner uses the browser's
  `BarcodeDetector` once it has proven it can read a code, otherwise jsQR (`public/vendor/jsqr.js`,
  Apache-2.0), loaded only then.
- **One tab.** The engine runs in one tab at a time (Web Locks). A second tab offers "Use it here";
  tabs hand over through a `BroadcastChannel`.

## Tests

- `tests/unit/`: contrast of every token pair the components combine (the focus ring among them),
  the catalogue and its fallback, the state model, the store adapter against a scripted engine, the
  lab's fake store, the thread logic, the QR encoder against the scanner's decoder for every
  version, the build scripts, component rendering.
- `tests/engine/`: the engine over real wasm with a fake socket, peer connection and clock.
- `tests/e2e/`: Playwright. Each test serves an export itself under `/pwa/` with the CSP header
  (`static-server.mjs`).
  - `platform.spec.ts`, on the production export: CSP clean, first run, no lab and no test hooks,
    the service worker, offline start, the update flow, takeover from the previous PWA.
  - `design.spec.ts`, on the test build's lab: every state of every screen, keyboard use, focus,
    44px targets, right to left. `screenshots.spec.ts` writes screenshots of every screen and state
    to `tests/e2e/artifacts/`.
  - `real.flows.ts`, on the production export with a real relay behind it: two or three people, each
    in a browser context of their own, driven only through the interface. Run with
    `--project=flows-chromium` (or `-firefox`, `-webkit`).

  On macOS run WebKit in the Playwright container (for the flows, with a Linux build of the relay):

  ```sh
  docker run --rm --ipc=host -v "$PWD":/work -w /work/tests/e2e \
    mcr.microsoft.com/playwright:v1.65.1-noble npx playwright test --project=webkit
  ```
- The seven desktop ↔ browser interop cases run against this app with
  `INTEROP_APP=web node apps/desktop/interop/pwa-interop.mjs` (from the repository root, after
  `denext task build:test`).

## Hosting

`nginx.example.conf` has the headers, the index fallback, the cache rules and where the relay sits.
Third-party material and licences: `THIRD_PARTY.md` (the export serves it as `licences.txt`).
