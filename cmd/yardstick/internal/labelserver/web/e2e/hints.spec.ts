import { expect, test } from "./fixtures";
import { causeGroup, check, diskLabels, images, labelsOf, log4jGroup, openGate, openGroup, pick, rows, tarGroup, verdictButton } from "./helpers";

async function openTar(page: import("@playwright/test").Page) {
  await openGate(page);
  await openGroup(page, tarGroup(page, true));
  await expect(page.getByTestId("tile")).toHaveAttribute("data-row", rows.tarDropped);
}

test.describe("a single hint", () => {
  test("the card shows the proposal, who made it and why", async ({ page }) => {
    await openTar(page);
    const card = page.getByTestId("hint-card");
    await expect(card).toHaveAttribute("data-status", "pending");
    await expect(card).toHaveAttribute("data-verdict", "fp");
    await expect(card).toHaveAttribute("data-confidence", "medium");
    await expect(card).toHaveAttribute("data-open", "false");
    await expect(page.getByTestId("hint-skill")).toContainText("triage-deltas");
    await expect(page.getByTestId("hint-reason")).not.toBeEmpty();
    // the verdict button that carries the hint says so
    await expect(page.locator("[data-testid=verdict-button][data-hinted=true]")).toHaveAttribute("data-verdict", "fp");

    await page.keyboard.press("w");
    await expect(card).toHaveAttribute("data-open", "true");
    await expect(page.getByTestId("hint-toggle")).toHaveAttribute("aria-expanded", "true");
    await expect(page.getByTestId("hint-note")).toBeVisible();
    await page.keyboard.press("w");
    await expect(card).toHaveAttribute("data-open", "false");
  });

  test("a accepts it as the label the proposal says", async ({ page }) => {
    await openTar(page);
    await page.keyboard.press("a");
    await expect.poll(() => labelsOf("CVE-2005-2541").length).toBe(1);
    expect(labelsOf("CVE-2005-2541")[0]).toMatchObject({
      subject: images.deb.name, package: "pkg:deb/debian/tar", vulnerability: "CVE-2005-2541", verdict: "fp", justification: "fix-installed",
    });
  });

  test("the hinted verdict button accepts it too", async ({ page }) => {
    await openTar(page);
    await page.locator("[data-testid=verdict-button][data-hinted=true]").click();
    await expect.poll(() => labelsOf("CVE-2005-2541").length).toBe(1);
    expect(labelsOf("CVE-2005-2541")[0]).toMatchObject({ verdict: "fp", justification: "fix-installed" });
  });

  test("the card agrees once the label is the hint, and disagrees when it is not", async ({ page }) => {
    await openTar(page);
    await page.getByTestId("advance-checkbox").uncheck();
    await page.keyboard.press("a");
    await expect(page.getByTestId("tile")).toHaveAttribute("data-verdict", "fp");
    await expect(page.getByTestId("hint-card")).toHaveAttribute("data-status", /accepted|agrees/);

    // a different verdict on the same match
    await verdictButton(page, "tp").click();
    await expect(page.getByTestId("tile")).toHaveAttribute("data-verdict", "tp");
    await expect(page.getByTestId("hint-card")).toHaveAttribute("data-status", "disagrees");
    await expect.poll(() => labelsOf("CVE-2005-2541")[0]?.verdict).toBe("tp");
  });

  test("a label against the hint says it overrides it", async ({ page }) => {
    await openTar(page);
    await page.getByTestId("advance-checkbox").uncheck();
    await verdictButton(page, "tp").click();
    await expect(page.getByTestId("receipt")).toContainText("overrides the agent hint");
  });

  test("a on a match with no hint writes nothing", async ({ page }) => {
    await openGate(page);
    await openGroup(page, tarGroup(page, false));
    await page.keyboard.press("a");
    await expect(page.getByTestId("toast")).toContainText("no agent hint");
    expect(labelsOf("CVE-2026-18508")).toEqual([]);
  });
});

test.describe("a package hint", () => {
  async function openCause(page: import("@playwright/test").Page) {
    await openGate(page);
    await openGroup(page, causeGroup(page));
  }

  test("the tile offers the same reasoning on all four matches", async ({ page }) => {
    await openCause(page);
    await expect(page.getByTestId("cause-offer")).toHaveAttribute("data-count", "4");
    await expect(page.getByTestId("accept-all")).toHaveAttribute("data-count", "4");
    await expect(page.getByTestId("accept-all")).toHaveAttribute("data-verdict", "tp");
  });

  test("accept all labels every member with the cause's verdict", async ({ page }) => {
    await openCause(page);
    await page.getByTestId("accept-all").click();
    await expect.poll(() => labelsOf("CVE-2026-3184").length).toBe(4);
    const written = labelsOf("CVE-2026-3184");
    expect(written.map((l) => l.package).sort()).toEqual(["pkg:deb/debian/libblkid1", "pkg:deb/debian/libmount1", "pkg:deb/debian/mount", "pkg:deb/debian/util-linux"]);
    for (const l of written) expect(l).toMatchObject({ subject: images.deb.name, verdict: "tp", justification: "no-fix" });
  });

  test("A does the same from the keyboard", async ({ page }) => {
    await openCause(page);
    await page.keyboard.press("A");
    await expect.poll(() => labelsOf("CVE-2026-3184").length).toBe(4);
    for (const l of labelsOf("CVE-2026-3184")) expect(l).toMatchObject({ verdict: "tp", justification: "no-fix" });
  });

  test("A in a group of medium hints with no cause writes nothing", async ({ page }) => {
    await openGate(page);
    await openGroup(page, log4jGroup(page));
    const before = diskLabels().length;
    await page.keyboard.press("A");
    await expect(page.getByTestId("toast")).toContainText("no agent hint");
    expect(diskLabels().length).toBe(before);
  });
});

test.describe("accepting from the board", () => {
  test("a group's accept control labels its rows", async ({ page }) => {
    await openGate(page);
    await tarGroup(page, true).getByTestId("group-accept").click();
    await expect.poll(() => labelsOf("CVE-2005-2541").length).toBe(1);
    expect(labelsOf("CVE-2005-2541")[0]).toMatchObject({ verdict: "fp", justification: "fix-installed" });
    // the group is settled: it leaves the board
    await expect(tarGroup(page, true)).toHaveCount(0);
  });

  test("the log4j group's accept writes both advisories as tp", async ({ page }) => {
    await openGate(page);
    const g = log4jGroup(page);
    await expect(g.getByTestId("group-accept")).toHaveAttribute("data-count", "4");
    await g.getByTestId("group-accept").click();
    await expect(g).toHaveCount(0);
    const log4j = diskLabels().filter((l) => l.package === "pkg:maven/org.apache.logging.log4j/log4j-core");
    // the seeded unclear stays on file beside the tp, which is on the exact version and so decides
    expect(log4j.map((l) => `${l.vulnerability} ${l.verdict} ${l.justification}`).sort()).toEqual([
      "GHSA-jfh8-c2jp-5v3q tp no-fix", "GHSA-vc5p-v9hr-52mj tp no-fix", "GHSA-vc5p-v9hr-52mj unclear not-assessed",
    ]);
  });

  test("the cause's accept labels its four rows", async ({ page }) => {
    await openGate(page);
    await causeGroup(page).getByTestId("group-accept").click();
    await expect.poll(() => labelsOf("CVE-2026-3184").length).toBe(4);
  });

  test("hovering an accept draws the preview, and the flip it causes", async ({ page }) => {
    await openGate(page);
    const unjudged = check(page, "unjudgedChangesAtMost");

    // the util-linux rows narrow the range of what is unjudged, and flip nothing
    await causeGroup(page).getByTestId("group-accept").hover();
    await expect(page.getByTestId("preview-note")).toBeVisible();
    await expect(unjudged.getByTestId("preview-range")).toBeVisible();
    await expect(unjudged.getByTestId("panel-bar")).not.toHaveAttribute("data-flips-to", /.+/);
    await page.getByTestId("header").hover();
    await expect(page.getByTestId("preview-note")).toHaveCount(0);

    // with everything else labeled, accepting log4j's hints is what passes the gate
    await tarGroup(page, true).getByTestId("group-accept").click();
    await openGroup(page, tarGroup(page, false));
    await pick(page, "fp:fix-installed");
    await page.keyboard.press("Escape");
    await causeGroup(page).getByTestId("group-accept").click();
    await expect(causeGroup(page)).toHaveCount(0);
    await log4jGroup(page).getByTestId("group-accept").hover();
    await expect(page.getByTestId("preview-note")).toContainText("the gate would be pass");
    for (const name of ["f1NotWorse", "noNewFalseNegatives", "noNewFalsePositives", "unjudgedChangesAtMost"]) {
      await expect(check(page, name).getByTestId("panel-bar"), name).toHaveAttribute("data-flips-to", "pass");
    }

    // moving away takes it back, and the preview wrote nothing
    await page.getByTestId("header").hover();
    await expect(page.getByTestId("preview-note")).toHaveCount(0);
    await expect(unjudged.getByTestId("panel-bar")).not.toHaveAttribute("data-flips-to", /.+/);
    expect(labelsOf("GHSA-jfh8-c2jp-5v3q")).toEqual([]);
  });

  test("hovering the hinted button on the tile previews the accept", async ({ page }) => {
    await openGate(page);
    await openGroup(page, tarGroup(page, true));
    await page.locator("[data-testid=verdict-button][data-hinted=true]").hover();
    await expect(page.getByTestId("preview-note")).toBeVisible();
    await expect(page.getByTestId("check-bar").first()).toBeVisible();
  });
});
