# ParolNet web app

The web client, rewritten as a [Denext](https://denext.dev) app (`mode: "spa"`, TypeScript and TSX)
with the design in [`docs/ux/web-app.md`](../docs/ux/web-app.md). It replaces the vanilla-JS PWA in
`pwa/` once the protocol services are ported.

**Phase 1 (this directory today):** the platform is proven and the design system and the
conversation screens exist, on fake in-memory state. No messaging, relay, WebRTC, storage, pairing
or calls yet: `src/state/store.ts` is the interface the real services will implement in place of
`src/state/fake.ts`.

## Commands

Needs the `denext` CLI (`curl -fsSL https://denext.dev/install.sh | sh`, then
`denext runtime install`), and for the wasm build: cargo with the `wasm32-unknown-unknown` target
and `wasm-pack`. Run from `web/`.

| Task                                            | What it does                                                                         |
| ----------------------------------------------- | ------------------------------------------------------------------------------------ |
| `denext task build-wasm`                        | Builds `crates/parolnet-wasm` into `public/wasm/` (run once, and after Rust changes) |
| `denext task dev`                               | Dev server with Fast Refresh at http://localhost:3000 (`#/lab` is the state lab)     |
| `denext task build` (or `export`)               | Tokens, `denext export`, then `scripts/postexport.ts`: the static site in `out/`     |
| `denext task serve`                             | Serves `out/` at http://127.0.0.1:8787/pwa/ with the production CSP header           |
| `denext task test`                              | Unit tests (`denext test`)                                                           |
| `denext task e2e`                               | Browser tests: Chromium, Firefox and WebKit through Playwright (needs Node)          |
| `denext task lint`, `fmt`, `fmt:check`, `check` | Lint, format, type-check                                                             |
| `denext task tokens`                            | Regenerates `src/design/tokens.css` from `tokens.json`                               |

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
- **Languages.** `src/i18n/`: English is bundled, other locales are JSON chunks loaded on demand.
  Arabic exists to prove right-to-left; the old PWA's other locales come later.

## Tests

- `tests/unit/`: contrast of every token pair the components combine, the catalogue, the state model
  and fake store, the thread logic, the build scripts, component rendering.
- `tests/e2e/`: Playwright. Each test serves `out/` itself under `/pwa/` with the CSP header
  (`static-server.mjs`). `platform.spec.ts` proves the platform (CSP clean, wasm, service worker,
  offline start, update flow, takeover from the previous PWA), `design.spec.ts` the screens,
  `screenshots.spec.ts` writes screenshots of every state to `tests/e2e/artifacts/`. On macOS run
  WebKit in the Playwright container:

  ```sh
  docker run --rm --ipc=host -v "$PWD":/work -w /work/tests/e2e \
    mcr.microsoft.com/playwright:v1.65.1-noble npx playwright test --project=webkit
  ```

## Hosting

`nginx.example.conf` has the headers, the index fallback and the cache rules. Third-party material
and licences: `THIRD_PARTY.md`.
