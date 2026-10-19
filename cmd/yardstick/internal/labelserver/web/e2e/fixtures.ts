import { test as base, expect } from "@playwright/test";

// test is Playwright's, failing any test whose page throws or logs a console error
export const test = base.extend({
  page: async ({ page }, use) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(`page error: ${e.message}`));
    page.on("console", (m) => {
      if (m.type() === "error") errors.push(`console error: ${m.text()}`);
    });
    await use(page);
    expect(errors, "errors on the page").toEqual([]);
  },
});

export { expect };

// workspace is the directory the seed built and serves (playwright.config.ts)
export const workspace = process.env.YARDSTICK_E2E_WORKSPACE!;
