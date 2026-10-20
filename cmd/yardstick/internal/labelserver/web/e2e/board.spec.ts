import { expect, test } from "./fixtures";
import { causeGroup, check, group, imageTile, openGate } from "./helpers";

test.describe("deb-java", () => {
  test.beforeEach(async ({ page }) => openGate(page, "deb-java"));

  test("starts failing, with the checks as SCENARIO.md states them", async ({ page }) => {
    await expect(page.getByTestId("gate-outcome")).toHaveAttribute("data-state", "fail");
    await expect(page.getByTestId("gate-summary")).toContainText("deb-java · 4 checks: 0 pass, 3 fail, 1 undecided");
    for (const [name, state] of [["f1NotWorse", "fail"], ["noNewFalseNegatives", "fail"], ["noNewFalsePositives", "fail"], ["unjudgedChangesAtMost", "undecided"]]) {
      await expect(check(page, name), name).toHaveAttribute("data-state", state);
    }
    // the worst-subject value of each check, and the threshold it is held to
    await expect(check(page, "noNewFalseNegatives").getByTestId("panel-bar")).toHaveAttribute("data-worst", "2");
    await expect(check(page, "noNewFalsePositives").getByTestId("panel-bar")).toHaveAttribute("data-worst", "4");
    await expect(check(page, "unjudgedChangesAtMost").getByTestId("panel-bar")).toHaveAttribute("data-worst", "6");
    // f1 is a float: 0.5 to the precision it is computed in
    await expect.poll(async () => Number(await check(page, "f1NotWorse").getByTestId("panel-bar").getAttribute("data-worst"))).toBeCloseTo(0.5, 6);
    await expect(page.getByTestId("gate-footer")).toContainText("8 unlabeled of 12");
  });

  test("shows the deb and java images with their counts", async ({ page }) => {
    await expect(page.getByTestId("image-all")).toHaveAttribute("data-active", "true");
    await expect(page.getByTestId("image")).toHaveCount(2);
    // open leaves out the unclear rows, which have their own mark
    const deb = imageTile(page, "deb");
    await expect(deb).toHaveAttribute("data-index", "0");
    await expect(deb).toHaveAttribute("data-diffs", "8");
    await expect(deb).toHaveAttribute("data-open", "6");
    const java = imageTile(page, "java");
    await expect(java).toHaveAttribute("data-index", "1");
    await expect(java).toHaveAttribute("data-diffs", "4");
    await expect(java).toHaveAttribute("data-open", "2");
  });

  test("lists the open groups by tier", async ({ page }) => {
    const unjudged = check(page, "unjudgedChangesAtMost");
    await expect(unjudged.getByTestId("group-row")).toHaveCount(4);
    // tier 0: a label ends the gate (log4j's rows are the only ones java has to be judged by),
    // 2: one accept can label them, 3: the rest
    await expect(unjudged.locator("[data-testid=tier][data-tier='0']")).toHaveAttribute("data-count", "1");
    await expect(unjudged.locator("[data-testid=tier][data-tier='2']")).toHaveAttribute("data-count", "1");
    await expect(unjudged.locator("[data-testid=tier][data-tier='3']")).toHaveAttribute("data-count", "2");

    // the first group is log4j, with its four rows (two of them labeled unclear) and a tp hint
    const log4j = group(page, "p|0|added|org.apache.logging.log4j");
    await expect(log4j).toHaveAttribute("data-count", "4");
    await expect(log4j).toHaveAttribute("data-hinted", "4");
    await expect(log4j).toHaveAttribute("data-verdict", "tp");
    const tar = group(page, "p|2|dropped|tar");
    await expect(tar).toHaveAttribute("data-count", "1");
    await expect(tar.getByTestId("group-hint")).toHaveAttribute("data-verdict", "fp");
    await expect(tar.getByTestId("group-hint")).toHaveAttribute("data-confidence", "medium");

    const cause = causeGroup(page);
    await expect(cause).toHaveAttribute("data-count", "4");
    await expect(cause).toHaveAttribute("data-package", "util-linux");
    await expect(cause).toHaveAttribute("data-verdict", "tp");
    await expect(cause.getByTestId("group-title")).toContainText("CVE-2026-3184 on util-linux");

    const handTar = group(page, "p|3|dropped|tar");
    await expect(handTar).toHaveAttribute("data-hinted", "0");
    await expect(handTar.getByTestId("group-hint")).toContainText("no agent hint");
  });

  test("lists the claims the failed checks fail on", async ({ page }) => {
    await expect(page.getByTestId("failing-claim")).not.toHaveCount(0);
    const gnutls = page.locator("[data-testid=failing-claim][data-vulnerability=CVE-2011-3389]");
    await expect(gnutls.first()).toHaveAttribute("data-verdict", "fp");
    const tar = page.locator("[data-testid=failing-claim][data-vulnerability=CVE-2026-5704]");
    await expect(tar.first()).toHaveAttribute("data-package", "tar");
  });

  test("marks the groups an agent triaged", async ({ page }) => {
    await expect(group(page, "p|2|dropped|tar").getByTestId("researched-mark")).toHaveAttribute("data-triaged", "1");
    await expect(causeGroup(page).getByTestId("researched-mark")).toHaveAttribute("data-triaged", "4");
    await expect(group(page, "p|3|dropped|tar").getByTestId("researched-mark")).toHaveCount(0);
  });

  test("names the setups it compares", async ({ page }) => {
    await expect(page.locator("[data-testid=compared-field][data-k=gate]")).toContainText("deb-java");
  });
});

test.describe("deb-npm", () => {
  test.beforeEach(async ({ page }) => openGate(page, "deb-npm"));

  test("starts undecided, which the ribbon says counts as a CI fail", async ({ page }) => {
    await expect(page.getByTestId("gate-outcome")).toHaveAttribute("data-state", "undecided");
    await expect(page.getByTestId("gate-summary")).toContainText("CI reads it as fail");
    await expect(page.getByTestId("check-panel")).toHaveCount(1);
    const panel = check(page, "unjudgedChangesAtMost");
    await expect(panel).toHaveAttribute("data-state", "undecided");
    // worst subject: deb has 2 open, npm 1
    await expect(panel.getByTestId("panel-bar")).toHaveAttribute("data-worst", "2");
  });

  test("shows the deb and npm images", async ({ page }) => {
    const deb = imageTile(page, "deb");
    await expect(deb).toHaveAttribute("data-diffs", "2");
    await expect(deb).toHaveAttribute("data-open", "2");
    const npm = imageTile(page, "npm");
    await expect(npm).toHaveAttribute("data-diffs", "1");
    await expect(npm).toHaveAttribute("data-open", "1");
  });

  test("lists three dropped groups, two of them decisive", async ({ page }) => {
    await expect(page.getByTestId("group-row")).toHaveCount(3);
    for (const [key, hint] of [["p|0|dropped|gzip", "fp"], ["p|0|dropped|tar", "fp"]]) {
      await expect(group(page, key).getByTestId("group-hint")).toHaveAttribute("data-verdict", hint);
      await expect(group(page, key)).toHaveAttribute("data-count", "1");
    }
    const babel = group(page, "p|3|dropped|@babel/traverse");
    await expect(babel).toHaveAttribute("data-hinted", "0");
    await expect(babel.getByTestId("group-hint")).toContainText("no agent hint");
  });
});
