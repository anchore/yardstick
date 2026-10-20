import { expect, test } from "./fixtures";
import { causeGroup, check, claimSet, gatesPage, group, images, imageTile, labelsOf, log4jGroup, openGate, openGroup, pick, rows, tarGroup } from "./helpers";
import type { Page } from "@playwright/test";

const states = async (page: Page, want: Record<string, string>) => {
  for (const [name, state] of Object.entries(want)) await expect(check(page, name), name).toHaveAttribute("data-state", state);
};

// the labels the seed starts with, which the workflow leaves alone, and what it adds. The unclear on
// log4j's vc5p stays on file beside the tp that decides it (the tp names the exact version).
const deb = images.deb.name, java = images.java.name;
const seeded = [
  "global pkg:deb/debian/libgnutls30 CVE-2011-3389 fp fix-installed",
  `${deb} pkg:deb/debian/libc6 CVE-2026-5450 tp no-fix`,
  `${deb} pkg:deb/debian/tar CVE-2026-5704 fp fix-installed`,
  `${java} pkg:maven/org.apache.logging.log4j/log4j-core GHSA-vc5p-v9hr-52mj unclear not-assessed`,
];
const flipped = [
  `${deb} pkg:deb/debian/tar CVE-2005-2541 fp fix-installed`,
  `${deb} pkg:deb/debian/tar CVE-2026-18508 fp fix-installed`,
  ...["util-linux", "libblkid1", "libmount1", "mount"].map((p) => `${deb} pkg:deb/debian/${p} CVE-2026-3184 tp no-fix`),
  `${java} pkg:maven/org.apache.logging.log4j/log4j-core GHSA-jfh8-c2jp-5v3q tp no-fix`,
  `${java} pkg:maven/org.apache.logging.log4j/log4j-core GHSA-vc5p-v9hr-52mj tp no-fix`,
];

test("the seeded claims are what SCENARIO.md lists", () => {
  expect(claimSet()).toEqual([...seeded].sort());
});

test("labeling through the UI flips deb-java to pass and settles deb-npm", async ({ page }) => {
  await openGate(page);
  await expect(page.getByTestId("gate-outcome")).toHaveAttribute("data-state", "fail");

  // the tar hint, then the hand label on the tar row with none
  await tarGroup(page, true).getByTestId("group-accept").click();
  await expect(tarGroup(page, true)).toHaveCount(0);
  await openGroup(page, tarGroup(page, false));
  await expect(page.getByTestId("tile")).toHaveAttribute("data-row", rows.tarHand);
  await pick(page, "fp:fix-installed");
  await expect(page.getByTestId("group-done")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("board")).toBeVisible();
  await expect.poll(() => labelsOf("CVE-2026-18508").length).toBe(1);

  // both tar rows fp, four deb matches still open. java has no tp or fp label yet, which fails the
  // three checks that score labels until it has one
  await expect(page.getByTestId("gate-outcome")).toHaveAttribute("data-state", "fail");
  await states(page, { f1NotWorse: "fail", noNewFalseNegatives: "fail", noNewFalsePositives: "fail", unjudgedChangesAtMost: "undecided" });
  await expect(imageTile(page, "deb")).toHaveAttribute("data-open", "4");

  // the util-linux cause, accepted for its four rows: deb has nothing open, java is all that is left
  await causeGroup(page).getByTestId("group-accept").click();
  await expect(causeGroup(page)).toHaveCount(0);
  await states(page, { f1NotWorse: "fail", noNewFalseNegatives: "fail", noNewFalsePositives: "fail", unjudgedChangesAtMost: "undecided" });
  await expect(imageTile(page, "deb")).toHaveAttribute("data-open", "0");

  // the log4j advisories on the tile: jfh8 first, which gives java a tp label and leaves two checks undecided
  await openGroup(page, log4jGroup(page));
  await expect(page.getByTestId("tile")).toHaveAttribute("data-vulnerability", "GHSA-jfh8-c2jp-5v3q");
  await page.keyboard.press("a");
  await expect.poll(() => labelsOf("GHSA-jfh8-c2jp-5v3q").length).toBe(1);
  // the label covers both jars, so the tile is on a vc5p row now
  await expect(page.getByTestId("tile")).toHaveAttribute("data-vulnerability", "GHSA-vc5p-v9hr-52mj");
  for (const [name, state] of [["f1NotWorse", "pass"], ["noNewFalseNegatives", "pass"], ["noNewFalsePositives", "undecided"], ["unjudgedChangesAtMost", "undecided"]]) {
    await expect(page.locator(`[data-testid=check-bar][data-check=${name}]`), name).toHaveAttribute("data-state", state);
  }
  await expect(page.getByTestId("gate-outcome")).toHaveAttribute("data-state", "undecided");

  // vc5p replaces the unclear as the deciding label, and the last open match goes: the gate passes
  await page.keyboard.press("a");
  await expect.poll(() => labelsOf("GHSA-vc5p-v9hr-52mj").length).toBe(2);
  await expect(page.getByTestId("group-done")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("board")).toBeVisible();
  await expect(page.getByTestId("gate-outcome")).toHaveAttribute("data-state", "pass");
  await states(page, { f1NotWorse: "pass", noNewFalseNegatives: "pass", noNewFalsePositives: "pass", unjudgedChangesAtMost: "pass" });
  await expect(page.getByTestId("group-row")).toHaveCount(0);
  await expect(page.getByTestId("gate-footer")).toHaveText("0 unlabeled of 12");

  // the claims on disk are exactly the seeded ones and the labels the workflow wrote
  expect(claimSet()).toEqual([...seeded, ...flipped].sort());

  // every gate: deb-java passes with nothing open, and the tar label settled deb-npm
  await page.goto(gatesPage);
  await expect(page.getByTestId("gate-card")).toHaveCount(2);
  const java = page.locator("[data-testid=gate-card][data-gate=deb-java]");
  await expect(java).toHaveAttribute("data-state", "pass");
  await expect(java).toHaveAttribute("data-open", "0");
  await expect(java.getByTestId("gate-outcome")).toHaveAttribute("data-state", "pass");
  const npm = page.locator("[data-testid=gate-card][data-gate=deb-npm]");
  await expect(npm).toHaveAttribute("data-state", "pass");
  await npm.getByTestId("gate-board-link").click();
  await expect(page.getByTestId("gate-outcome")).toHaveAttribute("data-state", "pass");
  // gzip and the babel row are still open, one in each image
  await expect(imageTile(page, "deb")).toHaveAttribute("data-open", "1");
  await expect(imageTile(page, "npm")).toHaveAttribute("data-open", "1");
});

test("a tar label in one gate moves the other", async ({ page }) => {
  await openGate(page, "deb-npm");
  await expect(page.getByTestId("gate-outcome")).toHaveAttribute("data-state", "undecided");
  await group(page, "p|0|dropped|tar").getByTestId("group-accept").click();
  await expect(page.getByTestId("gate-outcome")).toHaveAttribute("data-state", "pass");

  await openGate(page, "deb-java");
  // the same row, already judged here: only the labels the deb-java page counts moved
  await expect(tarGroup(page, true)).toHaveCount(0);
  await expect(imageTile(page, "deb")).toHaveAttribute("data-open", "5");
  await expect(page.getByTestId("gate-outcome")).toHaveAttribute("data-state", "fail");
});

test("hand labels on both tar rows by key and picker write what the hints would", async ({ page }) => {
  await openGate(page);
  // hand labels on both tar rows by key and picker
  for (const hinted of [true, false]) {
    await openGroup(page, tarGroup(page, hinted));
    await page.keyboard.press("f");
    await pick(page, "fp:fix-installed");
    await expect(page.getByTestId("group-done")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByTestId("board")).toBeVisible();
  }
  await states(page, { f1NotWorse: "fail", noNewFalseNegatives: "fail", noNewFalsePositives: "fail", unjudgedChangesAtMost: "undecided" });
  await expect(page.getByTestId("gate-footer")).toContainText("unlabeled");
  expect(labelsOf("CVE-2005-2541")[0]).toMatchObject({ verdict: "fp", justification: "fix-installed" });
  expect(labelsOf("CVE-2026-18508")[0]).toMatchObject({ verdict: "fp", justification: "fix-installed" });
});
