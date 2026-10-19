import { expect, test } from "./fixtures";
import { labelsOf, openGate, openGroup, rows, tarGroup } from "./helpers";

// a research run is a process per match
test.setTimeout(120_000);

// the seed's research runs a stand-in, never claude: it records a tp proposal for each row it is
// asked about, and the label UI shows it as an agent hint

test("research started on the board finishes, marks the matches and leaves hints", async ({ page }) => {
  await openGate(page);
  const hand = tarGroup(page, false);
  await expect(hand.getByTestId("group-hint")).toContainText("no agent hint");
  await expect(hand.getByTestId("researched-mark")).toHaveCount(0);
  await expect(page.getByTestId("research-finished")).toHaveCount(0);

  await page.locator("[data-testid=research-select][data-select=could-move-check]").click();
  await expect(page.getByTestId("research-running").or(page.getByTestId("research-finished"))).toBeVisible();
  await expect(page.getByTestId("research-finished")).toBeVisible({ timeout: 60_000 });
  await expect(page.getByTestId("research-finished")).toHaveAttribute("data-count", "10");

  // the stand-in's tp proposal is now the hint on the match that had none
  // both tar matches are researched now, so they share one group with a tp hint
  const tar = page.locator("[data-testid=group-row][data-package=tar]");
  await expect(tar).toHaveCount(1);
  await expect(tar).toHaveAttribute("data-count", "2");
  await expect(tar).toHaveAttribute("data-hinted", "2");
  await expect(tar).toHaveAttribute("data-verdict", "tp");
  await expect(tar.getByTestId("researched-mark")).toHaveAttribute("data-researched", "2");
  await expect(page.getByTestId("research-none").first()).toBeVisible();
});

test("research started from the tile leaves a researched hint on the match", async ({ page }) => {
  await openGate(page);
  await openGroup(page, tarGroup(page, false));
  await expect(page.getByTestId("tile")).toHaveAttribute("data-row", rows.tarHand);
  await expect(page.getByTestId("hint-card")).toHaveAttribute("data-status", "none");
  await expect(page.getByTestId("research-button")).toHaveAttribute("data-researched", "false");

  await page.keyboard.press("R");
  await expect(page.getByTestId("toast")).toContainText("research started");
  await expect(page.getByTestId("research-status")).toContainText("research");

  // the hint moves the match out of the no-hint group, so look for it on the board
  await page.keyboard.press("Escape");
  const g = page.locator("[data-testid=group-row][data-package=tar]");
  await expect(g.getByTestId("researched-mark")).toHaveAttribute("data-researched", "1", { timeout: 60_000 });
  // joined the other tar match (triaged, fp) in the hinted group
  await expect(g).toHaveAttribute("data-count", "2");
  await expect(g).toHaveAttribute("data-hinted", "2");

  await openGroup(page, g);
  await page.goBack();
  await expect(page.getByTestId("board")).toBeVisible();
});

test("the new hint reads as researched on the tile, and can be accepted", async ({ page }) => {
  await openGate(page);
  await openGroup(page, tarGroup(page, false));
  await page.keyboard.press("R");
  await page.keyboard.press("Escape");
  const g = page.locator("[data-testid=group-row][data-package=tar]");
  await expect(g.getByTestId("researched-mark")).toHaveAttribute("data-researched", "1", { timeout: 60_000 });

  await openGroup(page, g);
  await page.locator(`[data-testid=breadcrumb]`).waitFor();
  // the group holds both tar rows; walk to the researched one
  while ((await page.getByTestId("tile").getAttribute("data-row")) !== rows.tarHand) await page.keyboard.press("j");
  const card = page.getByTestId("hint-card");
  await expect(card).toHaveAttribute("data-status", "pending");
  await expect(card).toHaveAttribute("data-verdict", "tp");
  await expect(card.getByTestId("researched-mark")).toBeVisible();
  await expect(page.getByTestId("research-button")).toHaveAttribute("data-researched", "true");
  await expect(page.getByTestId("research-button")).toContainText("research again");
  await page.keyboard.press("w");
  await expect(page.getByTestId("hint-note")).toContainText("e2e research stand-in");

  await page.keyboard.press("a");
  await expect.poll(() => labelsOf("CVE-2026-18508").map((l) => l.verdict)).toEqual(["tp"]);
});
