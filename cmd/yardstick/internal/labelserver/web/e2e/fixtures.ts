import { test as base, expect } from "@playwright/test";

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
    page.on("pageerror", (e) => errors.push(`page error: ${e.message}`));
    page.on("console", (m) => {
      // a headed browser also asks for /favicon.ico, which the server does not have
      if (m.type() === "error" && !m.location().url.endsWith("/favicon.ico")) errors.push(`console error: ${m.text()}`);
    });
    await use(page);
    expect(errors, "errors on the page").toEqual([]);
  },
});

export { expect };

// workspace is the directory the seed built and serves (playwright.config.ts)
export const workspace = process.env.YARDSTICK_E2E_WORKSPACE!;
