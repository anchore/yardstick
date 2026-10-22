import { spawn } from "node:child_process";
import { test as base, expect, type Page } from "@playwright/test";

// failed holds the URLs a test answered with an error status itself, per page: the browser logs
// each such load as a console error, which is the test's doing rather than the page's
const failed = new WeakMap<Page, Set<string>>();

// answersWithError marks url as one the test fails on purpose, so its load error is not the page's
export const answersWithError = (page: Page, url: string) => { failed.get(page)?.add(url); };

// workspace is the directory this worker's seed builds and serves. The parallel index is stable
// across a worker's restarts, so a restarted worker takes over its predecessor's directory
export const workspace = `${process.env.YARDSTICK_E2E_WORKSPACE}-${process.env.TEST_PARALLEL_INDEX}`;

// test is Playwright's, failing any test whose page throws or logs a console error
export const test = base.extend<{ fresh: void }, { seed: string }>({
  // every worker serves its own workspace from its own seed, on a port the kernel picks, so neither
  // workers nor another checkout's e2e run share a server
  seed: [async ({}, use) => {
    const proc = spawn(process.env.YARDSTICK_E2E_SEED!, ["-dir", workspace, "-addr", "127.0.0.1:0"], { stdio: ["ignore", "pipe", "inherit"] });
    const exited = new Promise<void>((resolve) => proc.once("exit", () => resolve()));
    const url = await new Promise<string>((resolve, reject) => {
      let out = "";
      proc.stdout!.on("data", (b) => {
        out += b;
        const m = out.match(/serving (http:\/\/[^/\s]+)/);
        if (m) resolve(m[1]);
      });
      void exited.then(() => reject(new Error(`seed exited before serving:\n${out}`)));
    });
    await use(url);
    // ponytail: a worker killed outright leaves its seed running; the next run's seed for that
    // index replaces the directory and takes a fresh port, so the orphan only costs memory
    proc.kill();
    await exited;
  }, { scope: "worker", timeout: 60_000 }],
  baseURL: async ({ seed }, use) => use(seed),
  // every test starts on the seeded workspace: the seed puts the claims and agent records back and
  // starts a new server (a test-only route that `claims serve` does not have)
  fresh: [async ({ request }, use) => {
    const res = await request.post("/__e2e/reset");
    expect(res.status(), "reset the workspace").toBe(204);
    await use();
  }, { auto: true }],
  page: async ({ page }, use) => {
    const errors: string[] = [];
    failed.set(page, new Set());
    page.on("pageerror", (e) => errors.push(`page error: ${e.message}`));
    page.on("console", (m) => {
      // a headed browser also asks for /favicon.ico, which the server does not have
      if (m.type() !== "error" || m.location().url.endsWith("/favicon.ico")) return;
      if (m.text().startsWith("Failed to load resource") && failed.get(page)?.has(m.location().url)) return;
      errors.push(`console error: ${m.text()}`);
    });
    await use(page);
    expect(errors, "errors on the page").toEqual([]);
  },
});

export { expect };
