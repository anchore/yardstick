import { defineConfig, devices } from "@playwright/test";

// the seed (built by make e2e) builds a fresh workspace with a scanned gate and serves it. Each
// worker starts its own (the seed fixture in e2e/fixtures.ts); workers inherit where from here
const tmp = new URL("../../../../../.tmp/e2e/", import.meta.url).pathname;
// a worker's workspace is this with its parallel index on the end
process.env.YARDSTICK_E2E_WORKSPACE ??= tmp + "workspace";
// make e2e:container runs a linux build of the seed beside the host's
process.env.YARDSTICK_E2E_SEED ??= tmp + "seed";

export default defineConfig({
  testDir: "e2e",
  outputDir: "test-results",
  // a server and a workspace per worker, which every test resets to the seeded state. Files spread
  // across workers and a file's tests run in order; -- --workers=N changes how many
  workers: 4,
  forbidOnly: !!process.env.CI,
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  use: {
    trace: "retain-on-failure",
    // HEADED=1 shows the browser, the same as --headed
    headless: !process.env.HEADED,
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
