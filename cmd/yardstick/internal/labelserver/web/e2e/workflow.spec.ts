import { expect, test } from "./fixtures";
import { checkPage, checkRow, checkStates, claimSet, gatePage, gatesPage, images, label, labelsOf, onFinding, openFinding, outcome, railImage, rows, tableRow } from "./helpers";
import type { Page } from "@playwright/test";

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

const gateRow = (page: Page, gate: string) => page.locator(`[data-testid=gate-row][data-gate=${gate}]`);
const checksTab = (page: Page) => page.getByTestId("tabs").getByRole("tab", { name: /Checks/ }).click();

test("the seeded claims are what SCENARIO.md lists", () => {
  expect(claimSet()).toEqual([...seeded].sort());
});

test("labeling through the UI flips deb-java to pass and settles deb-npm", async ({ page }) => {
  await page.goto(gatesPage);
  await gateRow(page, "deb-java").click();
  await expect(outcome(page)).toHaveText("fail");
  await checkStates(page, { f1NotWorse: "fail", noNewFalseNegatives: "fail", noNewFalsePositives: "fail", unjudgedChangesAtMost: "undecided" });

  // the check every open finding bears on, and the tar row with a hint: accepted, and the page moves
  // on to the tar row with none, labeled by hand
  await checkRow(page, "unjudgedChangesAtMost").click();
  await tableRow(page, "check-table", rows.tarDropped).click();
  await onFinding(page, rows.tarDropped);
  await page.keyboard.press("a");
  await onFinding(page, rows.tarHand);
  await label(page, "f", "fix-installed");
  await expect.poll(() => labelsOf("CVE-2026-18508").length).toBe(1);

  // the util-linux package hint, accepted for its four rows; the page moves on to java's log4j
  await onFinding(page, rows.utilLinux[0]);
  await page.keyboard.press("A");
  await expect.poll(() => labelsOf("CVE-2026-3184").length).toBe(4);
  await onFinding(page, rows.jfhA);

  // back on the check and the gate: deb has nothing open, and java has no tp or fp label yet, which
  // fails the three checks that score labels until it has one
  await page.keyboard.press("Escape");
  await expect(page).toHaveURL(new RegExp(`${checkPage("unjudgedChangesAtMost")}$`));
  // what's judged leaves the check that counts the unjudged: java's four are left
  await expect(page.getByTestId("check-table").locator("tbody tr[data-id]")).toHaveCount(4);
  await expect(tableRow(page, "check-table", rows.tarHand)).toHaveCount(0);
  await page.keyboard.press("Escape");
  await checkStates(page, { f1NotWorse: "fail", noNewFalseNegatives: "fail", noNewFalsePositives: "fail", unjudgedChangesAtMost: "undecided" });
  await expect(railImage(page, "deb")).toContainText("0 open · 8");
  await expect(railImage(page, "java")).toContainText("2 open · 4");

  // n opens the next open finding, jfh8; its hint covers both jars and gives java a tp label, which
  // leaves two checks undecided
  await page.keyboard.press("n");
  await onFinding(page, rows.jfhA);
  await page.keyboard.press("a");
  await expect.poll(() => labelsOf("GHSA-jfh8-c2jp-5v3q").length).toBe(1);
  await page.goto(gatePage());
  await checkStates(page, { f1NotWorse: "pass", noNewFalseNegatives: "pass", noNewFalsePositives: "undecided", unjudgedChangesAtMost: "undecided" });
  await expect(outcome(page)).toHaveText("undecided");

  // vc5p replaces the unclear as the deciding label, and the last open match goes: the gate passes
  await page.keyboard.press("n");
  await onFinding(page, rows.vc5pA);
  await page.keyboard.press("a");
  await expect.poll(() => labelsOf("GHSA-vc5p-v9hr-52mj").length).toBe(2);
  await page.goto(gatePage());
  await expect(outcome(page)).toHaveText("pass");
  await checkStates(page, { f1NotWorse: "pass", noNewFalseNegatives: "pass", noNewFalsePositives: "pass", unjudgedChangesAtMost: "pass" });
  await expect(page.getByTestId("label-next")).toBeDisabled();
  await expect(railImage(page, "java")).toContainText("0 open · 4");

  // the claims on disk are exactly the seeded ones and the labels the workflow wrote
  expect(claimSet()).toEqual([...seeded, ...flipped].sort());

  // every gate: deb-java passes with nothing unlabeled, and the tar label settled deb-npm
  await page.getByTestId("breadcrumb").getByRole("link", { name: "Gates" }).click();
  await expect(gateRow(page, "deb-java")).toHaveAttribute("data-state", "pass");
  await expect(gateRow(page, "deb-java").getByTestId("gate-unlabeled")).toHaveText(/^0 unlabeled\s*of 12 changed$/);
  await expect(gateRow(page, "deb-npm")).toHaveAttribute("data-state", "pass");
  await gateRow(page, "deb-npm").click();
  await expect(outcome(page)).toHaveText("pass");
  // gzip and the babel row are still open, one in each image
  await expect(railImage(page, "deb")).toContainText("1 open · 2");
  await expect(railImage(page, "npm")).toContainText("1 open · 1");
});

test("a tar label in one gate moves the other", async ({ page }) => {
  await openFinding(page, rows.tarDropped, "unjudgedChangesAtMost", "deb-npm");
  await page.keyboard.press("a");
  await expect.poll(() => labelsOf("CVE-2005-2541").length).toBe(1);
  await page.goto(gatePage("deb-npm"));
  await expect(outcome(page)).toHaveText("pass");

  // the same row, already judged in deb-java: only the counts deb-java reads moved
  await page.goto(gatePage("deb-java"));
  await expect(railImage(page, "deb")).toContainText("5 open · 8");
  await expect(outcome(page)).toHaveText("fail");
  await page.getByTestId("tabs").getByRole("tab", { name: /Findings/ }).click();
  await expect(tableRow(page, "findings-table", rows.tarDropped).getByTestId("verdict")).toHaveText("FP");
});

test("hand labels on both tar rows by key and picker write what the hints would", async ({ page }) => {
  await openFinding(page, rows.tarDropped);
  await label(page, "f", "fix-installed");
  await onFinding(page, rows.tarHand);
  await label(page, "f", "fix-installed");
  await onFinding(page, rows.utilLinux[0]);
  expect(labelsOf("CVE-2005-2541")[0]).toMatchObject({ verdict: "fp", justification: "fix-installed" });
  expect(labelsOf("CVE-2026-18508")[0]).toMatchObject({ verdict: "fp", justification: "fix-installed" });

  await page.goto(gatePage());
  await checksTab(page);
  await checkStates(page, { f1NotWorse: "fail", noNewFalseNegatives: "fail", noNewFalsePositives: "fail", unjudgedChangesAtMost: "undecided" });
  await expect(page.getByTestId("verdict-bar")).toContainText("FP 4");
});
