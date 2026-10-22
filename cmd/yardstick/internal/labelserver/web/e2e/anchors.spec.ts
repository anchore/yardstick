import { expect, test } from "./fixtures";
import { checkPage, gatePage, gatesPage, openFinding, rows } from "./helpers";

// the anchors in ANCHORS.md exist where it says they do; a UI refactor keeps these or updates both
test("every level carries its anchors", async ({ page }) => {
  // level 0
  await page.goto(gatesPage);
  for (const id of ["app-bar", "history-entry", "settings-button", "breadcrumb", "title-row", "title", "tabs", "gate-rows", "work-banner", "review-hints", "label-left"]) await expect(page.getByTestId(id), id).toBeVisible();
  await page.getByTestId("settings-button").click();
  for (const id of ["settings-panel", "advance-checkbox", "queue-skip", "settings-theme"]) await expect(page.getByTestId(id), id).toBeVisible();
  await expect(page.getByTestId("theme-option")).toHaveCount(3);
  await page.keyboard.press("Escape");
  const gate = page.getByTestId("gate-row").first();
  await expect(gate).toHaveAttribute("data-gate", /.+/);
  await expect(gate).toHaveAttribute("data-state", /^(pass|fail|undecided)$/);
  await expect(gate.getByTestId("status")).toBeVisible();
  await expect(gate.getByTestId("gate-unlabeled")).toBeVisible();

  // level 1
  await page.goto(gatePage());
  for (const id of ["verdict-bar", "image-rail", "rail-filter", "rail-collapse", "rail-sort", "check-rows"]) await expect(page.getByTestId(id), id).toBeVisible();
  await expect(page.getByTestId("title-row").getByTestId("status")).toHaveText(/^(pass|fail|undecided)$/);
  await expect(page.getByTestId("rail-image").first()).toHaveAttribute("data-slug", "");
  await expect(page.getByTestId("rail-image").nth(1)).toHaveAttribute("data-slug", /.+/);
  const check = page.getByTestId("check-row").first();
  await expect(check).toHaveAttribute("data-check", /.+/);
  await expect(check).toHaveAttribute("data-state", /^(pass|fail|undecided)$/);
  await expect(check.getByTestId("meter")).toBeVisible();
  await expect(check.getByTestId("check-count")).toBeVisible();
  await page.getByTestId("rail-collapse").click();
  await expect(page.getByTestId("image-picker-button")).toBeVisible();
  await page.getByTestId("rail-expand").click();

  // level 2
  await page.goto(checkPage("unlabeledChangesAtMost"));
  for (const id of ["check-table", "images-toggle", "group-by"]) await expect(page.getByTestId(id), id).toBeVisible();
  const row = page.getByTestId("check-table").locator("tbody tr[data-id]").first();
  await expect(row).toHaveAttribute("data-id", /^[0-9a-f]{16}$/);
  await expect(row.getByTestId("verdict")).toHaveText(/^(TP|FP|unclear|unlabeled)$/);
  await row.getByRole("checkbox").check();
  for (const id of ["bulk-bar", "bulk-accept", "label-as"]) await expect(page.getByTestId(id), id).toBeVisible();

  // level 3
  await openFinding(page, rows.tarDropped);
  for (const id of ["pager", "finding-tabs", "finding-package", "finding-image", "finding-direction", "label-panel", "hint-card", "accept-hint",
    "reason-picker", "note-input", "save-label", "skip-button", "research-button", "match-path"]) {
    await expect(page.getByTestId(id), id).toBeVisible();
  }
  await expect(page.getByTestId("pager")).toHaveAttribute("data-total", /\d+/);
  await expect(page.getByTestId("finding")).toHaveAttribute("data-row", rows.tarDropped);
  await expect(page.getByTestId("label-panel")).toHaveAttribute("data-verdict", "unlabeled");
  for (const v of ["tp", "fp", "unclear"]) await expect(page.locator(`[data-testid=verdict-button][data-verdict=${v}]`)).toBeVisible();
  await expect(page.getByTestId("hint-card")).toHaveAttribute("data-status", "pending");
});
