import type { DenextConfig } from "denext/server";

// Every URL the shell names is relative ("./…"): the export is hosted under a sub-path
// (https://parol.social/pwa/) and Denext's SPA mode has no base path. `scripts/postexport.ts`
// makes the two URLs Denext writes itself (the entry and the stylesheet) relative as well.
const head = [
  `<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />`,
  `<meta name="color-scheme" content="light dark" />`,
  `<meta name="theme-color" content="#F3F5F4" media="(prefers-color-scheme: light)" />`,
  `<meta name="theme-color" content="#0F181D" media="(prefers-color-scheme: dark)" />`,
  `<meta name="description" content="Private calls, messages and files, straight between devices." />`,
  `<link rel="manifest" href="./manifest.webmanifest" />`,
  `<link rel="icon" href="./icons/icon.svg" type="image/svg+xml" />`,
  `<link rel="apple-touch-icon" href="./icons/icon-192.png" />`,
  `<link rel="preload" href="./fonts/atkinson-hyperlegible-next-latin-5.3.0.woff2" as="font" type="font/woff2" crossorigin />`,
  // A classic external script (CSP allows no inline script): sets the saved theme before paint.
  `<script src="./theme-boot.js"></script>`,
].join("\n    ");

export default {
  mode: "spa",
  spa: {
    entry: "./src/main.tsx",
    title: "ParolNet",
    lang: "en",
    assetsDir: "assets",
    // The static host compresses; `.gz` siblings would only bloat the precache list.
    precompress: false,
    head,
    // Painted until the bundle renders: the page ground and the app name, no words to translate.
    loading: `<div class="boot" aria-hidden="true"><span class="boot__name">ParolNet</span></div>`,
  },
} satisfies DenextConfig;
