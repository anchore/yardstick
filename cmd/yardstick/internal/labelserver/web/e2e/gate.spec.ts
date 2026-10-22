import { expect, test } from "./fixtures";
import { checkPage, checkRow, checkStates, gatePage, outcome, railImage, rows, tableRow } from "./helpers";

// a gate (level 1) and its checks (level 2) as SCENARIO.md states them; lists.spec.ts has the
// tables' filters and bulk actions
const meter = (page: import("@playwright/test").Page, name: string) => checkRow(page, name).getByTestId("meter");

test.describe("deb-java", () => {
  test.beforeEach(async ({ page }) => { await page.goto(gatePage()); });

  test("starts failing, with each check's state and its worst value against its limit", async ({ page }) => {
    await expect(outcome(page)).toHaveText("fail");
    await expect(page.getByTestId("title-row")).toContainText("grype candidate-a vs reference-a · 2 images");
    await checkStates(page, { f1NotWorse: "fail", noNewFalseNegatives: "fail", noNewFalsePositives: "fail", unlabeledChangesAtMost: "fail" });
    await expect(meter(page, "f1NotWorse")).toContainText("0.500 worse · limit 0");
    await expect(meter(page, "noNewFalseNegatives")).toContainText("2 new · limit 0");
    await expect(meter(page, "noNewFalsePositives")).toContainText("4 new · limit 0");
    await expect(meter(page, "unlabeledChangesAtMost")).toContainText("6 unlabeled · limit 0");
    await expect(checkRow(page, "unlabeledChangesAtMost").getByTestId("check-count")).toContainText("10 open");
  });

  test("the verdict bar and the rail count the changed matches by label", async ({ page }) => {
    const bar = page.getByTestId("verdict-bar");
    for (const part of ["TP 0", "FP 2", "unclear 2", "unlabeled with a hint 7", "unlabeled 1", "12 changed matches"]) await expect(bar).toContainText(part);
    // open is unlabeled or unclear, so java's two unclear vc5p rows count
    await expect(railImage(page, "deb")).toContainText("6 open · 8");
    await expect(railImage(page, "java")).toContainText("4 open · 4");
    await expect(page.getByTestId("tabs").getByRole("tab", { name: /Matches/ })).toContainText("12");
  });

  test("a check lists the labels that decide it as well as what is open, with the agent's hints", async ({ page }) => {
    await page.goto(checkPage("f1NotWorse"));
    await expect(outcome(page)).toHaveText("fail");
    // the two fp labels on dropped changes stay reachable on a failed check
    await expect(tableRow(page, "check-table", "c54934489d4ac861").getByTestId("verdict")).toHaveText("FP");
    await expect(tableRow(page, "check-table", "6d210210168e93db").getByTestId("verdict")).toHaveText("FP");
    await expect(tableRow(page, "check-table", rows.jfhA).getByTestId("hint")).toHaveText("TP · medium");
    await expect(tableRow(page, "check-table", rows.tarDropped).getByTestId("hint")).toHaveText("FP · medium");
    await expect(tableRow(page, "check-table", rows.utilLinux[0]).getByTestId("hint")).toHaveText("TP · medium");
    await expect(tableRow(page, "check-table", rows.tarHand).getByTestId("hint")).toHaveCount(0);
    await expect(tableRow(page, "check-table", rows.vc5pA).getByTestId("verdict")).toHaveText("unclear");
  });

  test("Group by gathers a check's findings by package", async ({ page }) => {
    await page.goto(checkPage("unlabeledChangesAtMost"));
    await page.getByTestId("group-by").selectOption("package");
    const groups = page.getByTestId("check-table").locator("tr.group");
    await expect(groups).toHaveCount(6);
    await expect(groups.filter({ hasText: "log4j-core" })).toContainText("4 · 2 unlabeled");
  });
});

test.describe("deb-npm", () => {
  test.beforeEach(async ({ page }) => { await page.goto(gatePage("deb-npm")); });

  test("starts failing with its one check", async ({ page }) => {
    await expect(outcome(page)).toHaveText("fail");
    await expect(page.getByTestId("check-row")).toHaveCount(1);
    await checkStates(page, { unlabeledChangesAtMost: "fail" });
    // worst image: deb has 2 open, npm 1
    await expect(meter(page, "unlabeledChangesAtMost")).toContainText("2 unlabeled · limit 1");
  });

  test("shows the deb and npm images", async ({ page }) => {
    await expect(railImage(page, "deb")).toContainText("2 open · 2");
    await expect(railImage(page, "npm")).toContainText("1 open · 1");
  });

  test("its check lists three dropped findings, two with a hint that could move it", async ({ page }) => {
    await checkRow(page, "unlabeledChangesAtMost").click();
    const table = page.getByTestId("check-table");
    await expect(table.locator("tbody tr[data-id]")).toHaveCount(3);
    // each is open and only the reference reports it, so its outcome is the question a TP would answer
    await expect(table.getByTestId("outcome")).toHaveText(["new FN?", "new FN?", "new FN?"]);
    for (const id of [rows.gzip, rows.tarDropped]) {
      await expect(tableRow(page, "check-table", id).getByTestId("hint")).toHaveText("FP · medium");
      await expect(tableRow(page, "check-table", id)).toContainText("could move");
    }
    await expect(tableRow(page, "check-table", rows.babel).getByTestId("hint")).toHaveCount(0);
  });
});
