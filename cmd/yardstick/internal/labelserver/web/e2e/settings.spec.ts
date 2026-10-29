import type { Page } from "@playwright/test";
import { expect, test } from "./fixtures";
import { findingPage, onFinding, openFinding, rows } from "./helpers";

// the app bar's settings cog: a popover holding the reader's standing choices, each kept in this browser
const cog = (page: Page) => page.getByTestId("settings-button");
const panel = (page: Page) => page.getByTestId("settings-panel");
const theme = (page: Page, t: string) => page.locator(`[data-testid=theme-option][value=${t}]`);
const html = (page: Page) => page.locator("html");

test("the cog opens and closes by click, Esc and a click outside; Esc doesn't walk up a crumb", async ({ page }) => {
  await openFinding(page, rows.tarDropped);
  const url = page.url();
  await expect(cog(page)).toHaveAccessibleName("Settings");
  await expect(panel(page)).toBeHidden();

  await cog(page).click();
  await expect(panel(page)).toBeVisible();
  await expect(cog(page)).toHaveAttribute("aria-expanded", "true");
  await cog(page).click();
  await expect(panel(page)).toBeHidden();

  await cog(page).click();
  // the panel fades in from visibility: hidden, and focus() on a switch it still hides does nothing
  await expect(panel(page)).toBeVisible();
  await page.getByTestId("advance-checkbox").focus();
  await page.keyboard.press("Escape");
  await expect(panel(page)).toBeHidden();
  expect(page.url()).toBe(url);

  await cog(page).click();
  await page.getByTestId("title").click();
  await expect(panel(page)).toBeHidden();
  expect(page.url()).toBe(url);

  // closed, Esc is the page's again
  await page.keyboard.press("Escape");
  await expect(page).toHaveURL(/\/checks\/unlabeledChangesAtMost$/);
});

test("j and n typed inside the open cog stay there", async ({ page }) => {
  await openFinding(page, rows.tarDropped);
  const url = page.url();
  await cog(page).click();
  await expect(panel(page)).toBeVisible();
  await page.getByTestId("queue-skip").focus();
  for (const k of ["j", "n", "k", "h"]) await page.keyboard.press(k);
  await expect(panel(page)).toBeVisible();
  expect(page.url()).toBe(url);
  await onFinding(page, rows.tarDropped);
});

test("each switch takes effect at once and stays across a reload", async ({ page }) => {
  await openFinding(page, rows.tarDropped);
  await expect(page.getByTestId("save-label")).toHaveText("Save and next");
  await cog(page).click();
  await expect(page.getByTestId("advance-checkbox")).toBeChecked();
  await expect(page.getByTestId("queue-skip")).toBeChecked();
  await page.getByTestId("advance-checkbox").uncheck();
  await expect(page.getByTestId("save-label")).toHaveText("Save");
  await page.getByTestId("queue-skip").uncheck();
  await expect(panel(page)).toBeVisible();

  await page.reload();
  await onFinding(page, rows.tarDropped);
  await expect(page.getByTestId("save-label")).toHaveText("Save");
  await cog(page).click();
  await expect(page.getByTestId("advance-checkbox")).not.toBeChecked();
  await expect(page.getByTestId("queue-skip")).not.toBeChecked();
  await page.getByTestId("advance-checkbox").check();
  await expect(page.getByTestId("save-label")).toHaveText("Save and next");
});

test("Skip labeled changes the queue's walk from inside an open queue, cog still open", async ({ page }) => {
  // jfhA isn't the gate's first row: the queue moves on from it to the first, so the walk below
  // starts with the two jars done
  await page.goto(`/ui/queue/${rows.jfhA}?scope=gate:deb-java`);
  await onFinding(page, rows.jfhA);
  await page.keyboard.press("a");
  // one jfh8 label covers both jars, so both are done and the queue moves on
  await expect(page.getByTestId("label-panel")).not.toHaveAttribute("data-row", rows.jfhA);
  const next = (await page.getByTestId("label-panel").getAttribute("data-row"))!;
  await expect(page.getByTestId("queue-pager")).toHaveText(/1 of 10/);

  await cog(page).click();
  await page.getByTestId("queue-skip").uncheck();
  await expect(page.getByTestId("queue-pager")).toHaveText(/3 of 12/);
  await expect(panel(page)).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(panel(page)).toBeHidden();
  await expect(page).toHaveURL(new RegExp(`/ui/queue/${next}`));
  await page.keyboard.press("k");
  await onFinding(page, rows.jfhB);

  await cog(page).click();
  await page.getByTestId("queue-skip").check();
  await expect(page.getByTestId("queue-pager")).toHaveAttribute("data-index", "0");
});

test("Light and Dark set the theme and survive a reload; System follows the OS", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "light" });
  await page.goto(findingPage(rows.tarDropped));
  await cog(page).click();
  await expect(theme(page, "system")).toBeChecked();
  await expect(html(page)).not.toHaveAttribute("data-theme");

  await theme(page, "dark").check();
  await expect(html(page)).toHaveAttribute("data-theme", "dark");
  await expect(html(page)).toHaveClass(/\bdark\b/);
  await theme(page, "light").check();
  await expect(html(page)).toHaveAttribute("data-theme", "light");
  await expect(html(page)).not.toHaveClass(/\bdark\b/);

  await theme(page, "dark").check();
  await page.reload();
  await expect(html(page)).toHaveAttribute("data-theme", "dark");
  await expect(html(page)).toHaveClass(/\bdark\b/);
  await cog(page).click();
  await expect(theme(page, "dark")).toBeChecked();

  await theme(page, "system").check();
  await expect(html(page)).not.toHaveAttribute("data-theme");
  await expect(html(page)).not.toHaveClass(/\bdark\b/);
  await page.emulateMedia({ colorScheme: "dark" });
  await expect(html(page)).toHaveClass(/\bdark\b/);
  await page.reload();
  await expect(html(page)).not.toHaveAttribute("data-theme");
  await expect(html(page)).toHaveClass(/\bdark\b/);
});
