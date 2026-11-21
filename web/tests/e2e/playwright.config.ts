import { defineConfig, devices } from "@playwright/test";

// The tests serve the exports themselves (tests/e2e/static-server.mjs), so there is no
// webServer here. Build first: `denext task build-wasm && denext task build:test &&
// denext task build`.
//
// Two groups, by file name:
//   *.spec.ts       the platform and the design, on static files alone;
//   *.flows.ts      real flows between two pages through a real relay (needs the relay
//                   binary, see harness.ts). Run with `--project=flows-<browser>`.
//
// The flows need a camera, a microphone and a direct path between two pages of one browser
// on one machine: fake capture devices, and ICE candidates on the loopback interface
// (Chromium and Firefox) or the machine's own address (WebKit on Linux, its only mode).
const chromium = {
  ...devices["Desktop Chrome"],
  // The full browser in its headless mode, as a person's Chromium, not the headless shell.
  channel: "chromium",
  launchOptions: {
    args: [
      "--use-fake-device-for-media-stream",
      "--use-fake-ui-for-media-stream",
      "--allow-loopback-in-peer-connection",
      "--disable-features=WebRtcHideLocalIpsWithMdns",
      "--autoplay-policy=no-user-gesture-required",
    ],
  },
};
const firefox = {
  ...devices["Desktop Firefox"],
  launchOptions: {
    firefoxUserPrefs: {
      "media.navigator.streams.fake": true,
      "media.navigator.permission.disabled": true,
      "media.peerconnection.ice.loopback": true,
      "media.peerconnection.ice.obfuscate_host_addresses": false,
      "media.autoplay.default": 0,
      "media.autoplay.blocking_policy": 0,
    },
  },
};
const webkit = { ...devices["Desktop Safari"] };

export default defineConfig({
  testDir: ".",
  outputDir: "test-results",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  use: {
    trace: "retain-on-failure",
    serviceWorkers: "allow",
  },
  projects: [
    { name: "chromium", testMatch: "*.spec.ts", use: chromium },
    { name: "firefox", testMatch: "*.spec.ts", use: firefox },
    { name: "webkit", testMatch: "*.spec.ts", use: webkit },
    { name: "flows-chromium", testMatch: "*.flows.ts", timeout: 120_000, use: chromium },
    { name: "flows-firefox", testMatch: "*.flows.ts", timeout: 120_000, use: firefox },
    {
      name: "flows-webkit",
      testMatch: "*.flows.ts",
      timeout: 120_000,
      use: { ...webkit, permissions: ["camera", "microphone"] },
    },
  ],
});
