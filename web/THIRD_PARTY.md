# Third-party material in the web app

Everything the web app ships or builds with that ParolNet did not write. Permissive licences only
(see the repository's dependency policy).

## Shipped to the browser

| What                                                                       | Version                                              | Licence                                               | Where                                             | Source                                                         |
| -------------------------------------------------------------------------- | ---------------------------------------------------- | ----------------------------------------------------- | ------------------------------------------------- | -------------------------------------------------------------- |
| Atkinson Hyperlegible Next (variable, Latin and Latin Extended subsets)    | 5.3.0 (Fontsource build of the Google Fonts release) | SIL Open Font License 1.1                             | `public/fonts/atkinson-hyperlegible-next-*.woff2` | https://github.com/googlefonts/atkinson-hyperlegible-next      |
| Atkinson Hyperlegible Mono (variable, Latin and Latin Extended subsets)    | 5.3.0 (Fontsource build)                             | SIL Open Font License 1.1                             | `public/fonts/atkinson-hyperlegible-mono-*.woff2` | https://github.com/googlefonts/atkinson-hyperlegible-next-mono |
| Vazirmatn (variable, Arabic subset; linked only for Arabic-script locales) | 5.3.0 (Fontsource build)                             | SIL Open Font License 1.1                             | `public/fonts/vazirmatn-arabic-*.woff2`           | https://github.com/rastikerdar/vazirmatn                       |
| Denext client runtime (bundled into `assets/`)                             | `jsr:@denext/denext@^4.21.0`                         | MIT                                                   | bundled                                           | https://jsr.io/@denext/denext                                  |
| `parolnet-wasm` and its Rust dependencies (compiled to `wasm/`)            | this repository                                      | MIT OR Apache-2.0; dependencies gated by `cargo deny` | `public/wasm/` (built, not committed)             | `crates/parolnet-wasm`                                         |

The fonts' licence texts are next to the files: `public/fonts/OFL-AtkinsonHyperlegibleNext.txt`,
`OFL-AtkinsonHyperlegibleMono.txt`, `OFL-Vazirmatn.txt`. Copyright: The Atkinson Hyperlegible Next
Project Authors (2020-2024), The Atkinson Hyperlegible Mono Project Authors (2020-2024), The
Vazirmatn Project Authors (2015). The font files are unmodified subsets as published by Fontsource
(`@fontsource-variable/*` on npm); `scripts/fetch-fonts.ts` fetches them again byte for byte. CJK
text uses the system's fonts.

The app icons (`public/icons/`) are ParolNet's own, copied from `pwa/icons/`.

## Build and test only (not shipped)

| What                                                                     | Version   | Licence                 | Used for                                          |
| ------------------------------------------------------------------------ | --------- | ----------------------- | ------------------------------------------------- |
| Denext CLI and its Deno runtime                                          | 4.21+     | MIT (Deno runtime: MIT) | dev server, bundling, export, tests, lint, format |
| `@std/assert`, `@std/path`, `@std/fs`, `@std/encoding`, `@std/tar` (JSR) | ^1 / ^0.1 | MIT                     | build scripts and unit tests                      |
| wasm-pack (with wasm-bindgen, wasm-opt)                                  | 0.13+     | MIT OR Apache-2.0       | building `parolnet-wasm`                          |
| `@playwright/test`                                                       | 1.65.1    | Apache-2.0              | browser tests (`tests/e2e`)                       |
