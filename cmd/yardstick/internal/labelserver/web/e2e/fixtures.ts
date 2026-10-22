import { test as base, expect, type Page } from "@playwright/test";

// failed holds the URLs a test answered with an error status itself, per page: the browser logs
// each such load as a console error, which is the test's doing rather than the page's
const failed = new WeakMap<Page, Set<string>>();

// answersWithError marks url as one the test fails on purpose, so its load error is not the page's
export const answersWithError = (page: Page, url: string) => { failed.get(page)?.add(url); };

// test is Playwright's, failing any test whose page throws or logs a console error
export const test = base.extend<{ fresh: void }>({
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

// workspace is the directory the seed built and serves (playwright.config.ts)
export const workspace = process.env.YARDSTICK_E2E_WORKSPACE!;
