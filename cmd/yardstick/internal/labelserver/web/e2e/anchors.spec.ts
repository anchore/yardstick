import { expect, test } from "./fixtures";
import { openGate } from "./helpers";

// the anchors in ANCHORS.md exist where it says they do; a UI refactor keeps these or updates both
test("the board and the tile carry their anchors", async ({ page }) => {
  await openGate(page);
  for (const id of ["header", "compared", "gate-ribbon", "images", "map", "board", "theme-button", "help-button"]) {
    await expect(page.getByTestId(id), id).toBeVisible();
  }
  await expect(page.getByTestId("gate-outcome")).toHaveAttribute("data-state", /pass|fail|undecided/);
  await expect(page.getByTestId("image-all")).toHaveAttribute("data-active", "true");
  await expect(page.getByTestId("image").first()).toHaveAttribute("data-subject", /.+/);
  const panel = page.getByTestId("check-panel").first();
  await expect(panel).toHaveAttribute("data-check", /.+/);
  await expect(panel.getByTestId("panel-head")).toBeVisible();

  const group = page.getByTestId("group-row").first();
  await expect(group).toHaveAttribute("data-group", /.+/);
  await expect(group).toHaveAttribute("data-count", /\d+/);
  await group.getByTestId("group-open").click();

  const tile = page.getByTestId("tile");
  await expect(tile).toHaveAttribute("data-row", /.+/);
  await expect(tile).toHaveAttribute("data-verdict", "unlabeled");
  await expect(tile).toHaveAttribute("data-vulnerability", /^(CVE|GHSA)-/);
  await expect(page.getByTestId("tile-position")).toHaveAttribute("data-total", /\d+/);
  for (const v of ["tp", "fp", "unclear"]) {
    await expect(page.locator(`[data-testid=verdict-button][data-verdict=${v}]`)).toBeVisible();
  }
  await expect(page.getByTestId("justification-picker")).toBeVisible();
  await expect(page.getByTestId("hint-card")).toHaveAttribute("data-status", /.+/);
  await expect(page.getByTestId("note-input")).toBeVisible();
  await expect(page.getByTestId("research-button")).toBeVisible();
  await expect(page.getByTestId("breadcrumb").getByTestId("crumb").first()).toHaveAttribute("data-kind", "home");
});
