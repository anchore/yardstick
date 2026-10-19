import { defineConfig, devices } from "@playwright/test";

// make e2e runs this inside Playwright's docker image, where the seed (built for linux by make e2e)
// builds a fresh workspace with a scanned gate and serves it
const port = 7656;
const seed = new URL("../../../../../.tmp/e2e/seed", import.meta.url).pathname;
// the tests read labels from the workspace on disk; workers inherit it from here
process.env.YARDSTICK_E2E_WORKSPACE ??= "/tmp/yardstick-e2e";

export default defineConfig({
  testDir: "e2e",
  outputDir: "test-results",
  // one server and one workspace, which every test resets to the seeded state
  workers: 1,
  forbidOnly: !!process.env.CI,
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `${seed} -dir ${process.env.YARDSTICK_E2E_WORKSPACE} -addr 127.0.0.1:${port}`,
    url: `http://127.0.0.1:${port}/ui/map/gates/`,
    stdout: "pipe",
  },
});
