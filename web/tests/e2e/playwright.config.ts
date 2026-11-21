import { defineConfig, devices } from "@playwright/test";

// The tests serve web/out themselves (tests/e2e/static-server.mjs), so there is no webServer
// here. Build first: `denext task build-wasm && denext task build`.
export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
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
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
});
