import type { Page } from "@playwright/test";
import { expect, test } from "./fixtures";
import { gatePage, gatesPage, images, labelsOf } from "./helpers";

// hint review (/ui/hints) and its ways in: the gates page's work banner, the h key, and the image
// rail's "Accept…". The seed's five hints are tar CVE-2005-2541 (both gates), gzip (deb-npm), the
// util-linux package hint, and log4j's jfh8 and vc5p, vc5p replacing a person's unclear label.

const item = (page: Page, vuln: string) => page.getByTestId("hint-item").filter({ hasText: vuln });
const box = (page: Page, vuln: string) => item(page, vuln).getByTestId("hint-check");
const impactGate = (page: Page, gate: string) => page.locator(`[data-testid=impact-gate][data-gate=${gate}]`);
const impactCheck = (page: Page, gate: string, check: string) => impactGate(page, gate).locator(`[data-testid=impact-check][data-check=${check}]`);
const accept = (page: Page) => page.getByTestId("accept-hints");
const outcome = (page: Page, gate: string) => page.locator(`[data-testid=work-outcome][data-gate=${gate}]`);
const gateRow = (page: Page, gate: string) => page.locator(`[data-testid=gate-row][data-gate=${gate}]`);

async function openReview(page: Page, query = "") {
  await page.goto(`/ui/hints${query}`);
  await expect(page.getByTestId("impact")).toBeVisible();
}

test.describe("hint review", () => {
  test("groups the hints by effect and checks all but the one replacing a person's label", async ({ page }) => {
    await openReview(page);
    await expect(page.getByTestId("hint-item")).toHaveCount(5);
    await expect(page.locator("[data-testid=hint-group][data-group=decides] [data-testid=hint-item]")).toHaveCount(4);
    await expect(page.locator("[data-testid=hint-group][data-group=needed] [data-testid=hint-item]")).toHaveCount(1);
    for (const v of ["CVE-2005-2541", "CVE-2026-41992", "CVE-2026-3184", "GHSA-jfh8-c2jp-5v3q"]) await expect(box(page, v)).toBeChecked();
    await expect(box(page, "GHSA-vc5p-v9hr-52mj")).not.toBeChecked();
    await expect(item(page, "GHSA-vc5p-v9hr-52mj")).toHaveAttribute("data-replaces", "true");
    await expect(item(page, "GHSA-vc5p-v9hr-52mj").getByTestId("hint-replaces")).toHaveText('replaces an unclear label: "needs a look at the JNDI lookup config"');
    // tar in both gates is one row
    await expect(accept(page)).toHaveText("Accept 4 hints on 8 rows");

    // together they pass deb-npm and lift deb-java to undecided
    await expect(impactGate(page, "deb-npm")).toHaveAttribute("data-before", "undecided");
    await expect(impactGate(page, "deb-npm")).toHaveAttribute("data-after", "pass");
    await expect(impactGate(page, "deb-java")).toHaveAttribute("data-before", "fail");
    await expect(impactGate(page, "deb-java")).toHaveAttribute("data-after", "undecided");
    const left = page.getByTestId("impact-left");
    await expect(left).toContainText("tar CVE-2026-18508");
    await expect(left).toContainText("log4j-core GHSA-vc5p-v9hr-52mj (2 rows)");
    await expect(left).toContainText("hint unchecked");
    await expect(left).toContainText("traverse GHSA-67hx-6x53-jw92");
  });

  test("vc5p stays unchecked until chosen, and choosing it moves deb-java's checks", async ({ page }) => {
    await openReview(page);
    await expect(impactCheck(page, "deb-java", "noNewFalsePositives")).toHaveAttribute("data-after", "undecided");
    await box(page, "GHSA-vc5p-v9hr-52mj").check();
    await expect(accept(page)).toHaveText("Accept 5 hints on 10 rows");
    await expect(impactCheck(page, "deb-java", "noNewFalsePositives")).toHaveAttribute("data-after", "pass");
    await expect(page.getByTestId("impact-left")).not.toContainText("GHSA-vc5p");

    // unchecking the java hints puts deb-java back where it is: no tp or fp on the java image
    await box(page, "GHSA-vc5p-v9hr-52mj").uncheck();
    await box(page, "GHSA-jfh8-c2jp-5v3q").uncheck();
    await expect(impactGate(page, "deb-java")).toHaveAttribute("data-after", "fail");
    // a group's checkbox selects every hint in it
    await page.locator("[data-testid=hint-group][data-group=decides] [data-testid=hint-group-toggle]").check();
    await expect(box(page, "GHSA-vc5p-v9hr-52mj")).toBeChecked();
    await expect(accept(page)).toHaveText("Accept 5 hints on 10 rows");
  });

  test("accepting writes the labels SCENARIO.md predicts; deb-npm passes and deb-java waits on tar CVE-2026-18508", async ({ page }) => {
    await openReview(page);
    await accept(page).click();
    await expect(page.getByTestId("toast")).toContainText("written from 4 hints");
    await expect.poll(() => labelsOf("CVE-2005-2541").map((l) => `${l.subject} ${l.package} ${l.verdict} ${l.justification}`))
      .toEqual([`${images.deb.name} pkg:deb/debian/tar fp fix-installed`]);
    expect(labelsOf("CVE-2026-41992").map((l) => `${l.package} ${l.verdict}`)).toEqual(["pkg:deb/debian/gzip fp"]);
    expect(labelsOf("CVE-2026-3184").map((l) => `${l.package} ${l.verdict}`).sort())
      .toEqual(["libblkid1", "libmount1", "mount", "util-linux"].map((p) => `pkg:deb/debian/${p} tp`));
    // one label covers both jars; vc5p keeps only the person's unclear
    expect(labelsOf("GHSA-jfh8-c2jp-5v3q").map((l) => `${l.subject} ${l.verdict}`)).toEqual([`${images.java.name} tp`]);
    expect(labelsOf("GHSA-vc5p-v9hr-52mj").map((l) => l.verdict)).toEqual(["unclear"]);
    expect(labelsOf("CVE-2026-18508")).toEqual([]);

    // the page reloads with only vc5p left, and nothing in deb-npm
    await expect(page.getByTestId("hint-item")).toHaveCount(1);
    await expect(impactGate(page, "deb-java")).toHaveCount(0);
    await box(page, "GHSA-vc5p-v9hr-52mj").check();
    await expect(impactGate(page, "deb-java")).toHaveAttribute("data-before", "undecided");
    await expect(impactGate(page, "deb-java")).toHaveAttribute("data-after", "undecided");
    await accept(page).click();
    await expect(page.getByTestId("hints-empty")).toBeVisible();
    expect(labelsOf("GHSA-vc5p-v9hr-52mj").map((l) => l.verdict).sort()).toEqual(["tp", "unclear"]);

    await page.goto(gatesPage);
    await expect(gateRow(page, "deb-npm")).toHaveAttribute("data-state", "pass");
    await expect(gateRow(page, "deb-java")).toHaveAttribute("data-state", "undecided");
    await expect(gateRow(page, "deb-java").getByTestId("gate-unlabeled")).toHaveText(/^1 open/);
    await expect(page.getByTestId("work-open")).toHaveText("2");
    await expect(page.getByTestId("work-need")).toHaveText("2");
    await expect(page.getByTestId("work-foot")).toContainText("deb-java then waits on 1 row with no hint: tar CVE-2026-18508.");
  });

  test("low-confidence hints are hidden until asked for, and never preselected", async ({ page }) => {
    // the seed has none, so make gzip's low
    await page.route("**/api/hints?low=1", async (route) => {
      const res = await route.fetch(), body = await res.json();
      for (const h of body.hints) if (h.rows[0].vulnerability === "CVE-2026-41992") h.confidence = "low";
      await route.fulfill({ response: res, json: body });
    });
    await openReview(page);
    await expect(page.getByTestId("hint-item")).toHaveCount(4);
    await expect(page.getByTestId("hint-low-count")).toHaveText("1 low-confidence hint hidden");
    await expect(page.getByTestId("hint-low-toggle")).not.toBeChecked();
    await page.getByTestId("hint-low-toggle").check();
    await expect(page).toHaveURL(/\/ui\/hints\?low=1$/);
    await expect(page.getByTestId("hint-item")).toHaveCount(5);
    await expect(item(page, "CVE-2026-41992")).toHaveAttribute("data-confidence", "low");
    await expect(box(page, "CVE-2026-41992")).not.toBeChecked();
    await page.getByTestId("hint-low-toggle").uncheck();
    await expect(page.getByTestId("hint-item")).toHaveCount(4);
  });

  test("the gate chips scope it to one gate", async ({ page }) => {
    await openReview(page);
    await page.locator("[data-testid=hint-gate-chip][data-gate=deb-npm]").click();
    await expect(page).toHaveURL(/\/ui\/hints\?gate=deb-npm$/);
    await expect(page.getByTestId("hint-item")).toHaveCount(2);
    await expect(page.locator("[data-testid=hint-gate-chip][data-gate=deb-npm]")).toHaveAttribute("aria-pressed", "true");
  });
});

test.describe("the work banner", () => {
  test("counts open findings once across gates and previews every hint per gate", async ({ page }) => {
    await page.goto(gatesPage);
    await expect(page.getByTestId("work-open")).toHaveText("10");
    await expect(page.getByTestId("work-hinted")).toHaveText("8");
    await expect(page.getByTestId("work-need")).toHaveText("2");
    await expect(page.getByTestId("review-hints")).toContainText("Review 5 hints");
    // one primary button: review while hints are pending, and no "Label next" in the title row
    await expect(page.getByTestId("review-hints")).not.toHaveAttribute("data-variant", /.+/);
    await expect(page.getByTestId("label-left")).toHaveAttribute("data-variant", "outline");
    await expect(page.getByTestId("label-next")).toHaveCount(0);
    await expect(outcome(page, "deb-npm")).toHaveAttribute("data-after", "pass");
    await expect(outcome(page, "deb-java")).toHaveAttribute("data-before", "fail");
    await expect(outcome(page, "deb-java")).toHaveAttribute("data-after", "undecided");
    await expect(page.getByTestId("work-foot")).toHaveText("deb-java then waits on 1 row with no hint: tar CVE-2026-18508.");
    // per gate in rows: deb-java's 10 open rows, 9 of them hinted
    await expect(gateRow(page, "deb-java").getByTestId("gate-work")).toHaveText(/^9 hinted · 1 needs you\s*4 hints · undecided on hints alone$/);
    await expect(gateRow(page, "deb-npm").getByTestId("gate-work")).toHaveText(/^2 hinted · 1 needs you\s*2 hints · passes on hints alone$/);
    await page.getByTestId("review-hints").click();
    await expect(page).toHaveURL(/\/ui\/hints$/);
    await expect(page.getByTestId("hint-item")).toHaveCount(5);
  });

  test("h opens review for the scope on screen", async ({ page }) => {
    await page.goto(gatesPage);
    await expect(page.getByTestId("work-banner")).toBeVisible();
    await page.keyboard.press("h");
    await expect(page).toHaveURL(/\/ui\/hints$/);
    await page.goto(`${gatePage("deb-java")}?image=${images.java.slug}`);
    await expect(page.getByTestId("rail-review-all")).toBeVisible();
    await page.keyboard.press("h");
    await expect(page).toHaveURL(`/ui/hints?gate=deb-java&image=${images.java.slug}`);
    await expect(page.getByTestId("hint-item")).toHaveCount(2);
  });

  test("the palette's review action opens review", async ({ page }) => {
    await page.goto(gatesPage);
    await page.getByTestId("goto-button").click();
    await page.locator("[data-testid=palette-item][data-id=hints]").click();
    await expect(page).toHaveURL(/\/ui\/hints$/);
    await expect(page.getByTestId("hint-item")).toHaveCount(5);
  });
});

test("the rail counts each image's hints, flags the one replacing a label, and Accept… scopes review to the image", async ({ page }) => {
  await page.goto(gatePage("deb-java"));
  const act = (image: keyof typeof images) => page.locator(`[data-testid=rail-act][data-image="${images[image].slug}"]`);
  await expect(page.getByTestId("rail-review-all")).toHaveText("Review all 4 hints");
  await expect(act("deb").getByTestId("rail-hints")).toHaveText("2 hints on 5 rows");
  await expect(act("deb").getByTestId("rail-replaces")).toHaveCount(0);
  await expect(act("java").getByTestId("rail-hints")).toHaveText("2 hints on 4 rows");
  await expect(act("java").getByTestId("rail-replaces")).toHaveText("1 overrides a label");
  await act("java").getByTestId("rail-accept").click();
  await expect(page).toHaveURL(`/ui/hints?gate=deb-java&image=${images.java.slug}`);
  await expect(page.getByTestId("hint-item")).toHaveCount(2);
  await expect(page.getByTestId("scope-chip")).toContainText(images.java.name.split(":")[0]);
  // nothing is written until accepted
  expect(labelsOf("GHSA-jfh8-c2jp-5v3q")).toEqual([]);
});
