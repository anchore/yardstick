import { expect, test } from "./fixtures";
import { checkPage, diskLabels, gatePage, images, labelsOf, openFinding, rows, setPref, tableRow, verdictButton } from "./helpers";

test.describe("a single hint", () => {
  test("the card shows the proposal, who made it and why, apart from the verdict buttons", async ({ page }) => {
    await openFinding(page, rows.tarDropped);
    const card = page.getByTestId("hint-card");
    await expect(card).toHaveAttribute("data-status", "pending");
    await expect(card).toHaveAttribute("data-verdict", "fp");
    await expect(card).toHaveAttribute("data-confidence", "medium");
    await expect(card).toContainText("triage-deltas");
    await expect(page.getByTestId("hint-reason")).not.toBeEmpty();
    // a hint never looks like a choice already made
    for (const v of ["tp", "fp", "unclear"]) await expect(verdictButton(page, v)).toHaveAttribute("aria-pressed", "false");
    await expect(page.getByTestId("accept-hint")).toBeVisible();
  });

  test("a accepts it as the label the proposal says", async ({ page }) => {
    await openFinding(page, rows.tarDropped);
    await page.keyboard.press("a");
    await expect.poll(() => labelsOf("CVE-2005-2541").length).toBe(1);
    expect(labelsOf("CVE-2005-2541")[0]).toMatchObject({
      subject: images.deb.name, package: "pkg:deb/debian/tar", vulnerability: "CVE-2005-2541", verdict: "fp", justification: "fix-installed",
    });
  });

  test("the card's Accept button accepts it too, and the label then shows as on file", async ({ page }) => {
    await openFinding(page, rows.tarDropped);
    await setPref(page, "advance-checkbox", false);
    await page.getByTestId("accept-hint").click();
    await expect.poll(() => labelsOf("CVE-2005-2541").map((l) => `${l.verdict} ${l.justification}`)).toEqual(["fp fix-installed"]);
    await expect(page.getByTestId("label-on-file")).toHaveAttribute("data-verdict", "fp");
    await expect(page.getByTestId("hint-card")).toHaveCount(0);
  });

  test("a label against the hint replaces it on file", async ({ page }) => {
    await openFinding(page, rows.tarDropped);
    await setPref(page, "advance-checkbox", false);
    await page.keyboard.press("t");
    await page.getByTestId("save-label").click();
    await expect.poll(() => labelsOf("CVE-2005-2541").map((l) => l.verdict)).toEqual(["tp"]);
    await expect(page.getByTestId("label-on-file")).toHaveAttribute("data-verdict", "tp");
  });

  test("a on a match with no hint writes nothing", async ({ page }) => {
    await openFinding(page, rows.tarHand);
    await expect(page.getByTestId("hint-card")).toHaveCount(0);
    await page.keyboard.press("a");
    await expect(page.getByTestId("toast")).toContainText("no agent hint to accept here");
    expect(labelsOf("CVE-2026-18508")).toEqual([]);
  });
});

test.describe("a package hint", () => {
  test("A accepts it for every member from the keyboard", async ({ page }) => {
    await openFinding(page, rows.utilLinux[0]);
    await expect(page.getByTestId("cause-card")).toHaveAttribute("data-verdict", "tp");
    await page.keyboard.press("Shift+A");
    await expect.poll(() => labelsOf("CVE-2026-3184").length).toBe(4);
    for (const l of labelsOf("CVE-2026-3184")) expect(l).toMatchObject({ subject: images.deb.name, verdict: "tp", justification: "no-fix" });
  });

  test("a accepts it for this row alone", async ({ page }) => {
    await openFinding(page, rows.utilLinux[0]);
    await page.keyboard.press("a");
    await expect.poll(() => labelsOf("CVE-2026-3184").map((l) => l.package)).toEqual(["pkg:deb/debian/util-linux"]);
  });

  test("A on a finding with no package hint writes nothing", async ({ page }) => {
    await openFinding(page, rows.jfhA, "f1NotWorse");
    const before = diskLabels().length;
    await page.keyboard.press("Shift+A");
    await expect(page.getByTestId("toast")).toContainText("no package hint to accept here");
    expect(diskLabels().length).toBe(before);
  });
});

test.describe("accepting from a table", () => {
  test("Accept hints on log4j's four rows writes both advisories as tp", async ({ page }) => {
    await page.goto(`${gatePage()}findings?q=log4j`);
    const table = page.getByTestId("findings-table");
    await table.getByRole("checkbox", { name: "Select every row shown" }).check();
    await expect(page.getByTestId("bulk-bar")).toContainText("4 selected");
    await page.getByTestId("bulk-accept").click();
    await expect.poll(() => labelsOf("GHSA-jfh8-c2jp-5v3q").length).toBe(1);
    // the seeded unclear stays on file beside the tp, which is on the exact version and so decides
    await expect.poll(() => diskLabels().filter((l) => l.package === "pkg:maven/org.apache.logging.log4j/log4j-core")
      .map((l) => `${l.vulnerability} ${l.verdict} ${l.justification}`).sort()).toEqual([
      "GHSA-jfh8-c2jp-5v3q tp no-fix", "GHSA-vc5p-v9hr-52mj tp no-fix", "GHSA-vc5p-v9hr-52mj unclear not-assessed",
    ]);
    for (const id of [rows.jfhA, rows.jfhB, rows.vc5pA, rows.vc5pB]) await expect(tableRow(page, "findings-table", id).getByTestId("verdict")).toHaveText("TP");
  });

  test("Accept hints on the cause's rows labels all four", async ({ page }) => {
    // f1NotWorse counts the rows labeled or not, so they stay in its table
    await page.goto(`${checkPage("f1NotWorse")}?q=CVE-2026-3184`);
    await page.getByTestId("check-table").getByRole("checkbox", { name: "Select every row shown" }).check();
    await expect(page.getByTestId("bulk-accept")).toHaveText("Accept hints (4)");
    await page.getByTestId("bulk-accept").click();
    await expect.poll(() => labelsOf("CVE-2026-3184").length).toBe(4);
    for (const id of rows.utilLinux) await expect(tableRow(page, "check-table", id).getByTestId("verdict")).toHaveText("TP");
  });

  test("Label as against a hint says it overrides the hint", async ({ page }) => {
    await page.goto(`${gatePage()}findings`);
    await tableRow(page, "findings-table", rows.tarDropped).getByRole("checkbox").check();
    await page.getByTestId("label-as").selectOption("tp:");
    await expect.poll(() => labelsOf("CVE-2005-2541").map((l) => l.verdict)).toEqual(["tp"]);
    await expect(page.getByRole("status")).toContainText("overriding the agent hint");
    // the finding the hint was on shows the label instead
    await openFinding(page, rows.tarDropped);
    await expect(page.getByTestId("hint-card")).toHaveCount(0);
  });
});
