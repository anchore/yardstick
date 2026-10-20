import type { Page } from "@playwright/test";
import { expect, test } from "./fixtures";
import { checkPage, gatePage, gatesPage, images, labelsOf, openFinding, label, rows } from "./helpers";

// the edges around hint review (hints-review.spec.ts has the main flow): selection states, image and
// gate scope, unclear hints, the banner and rail once hints are gone or left out, and the hints
// that replace a person's label beyond vc5p's seeded one

const item = (page: Page, vuln: string) => page.getByTestId("hint-item").filter({ hasText: vuln });
const box = (page: Page, vuln: string) => item(page, vuln).getByTestId("hint-check");
const group = (page: Page, id: string) => page.locator(`[data-testid=hint-group][data-group=${id}]`);
const impactGate = (page: Page, gate: string) => page.locator(`[data-testid=impact-gate][data-gate=${gate}]`);
const accept = (page: Page) => page.getByTestId("accept-hints");
const gateRow = (page: Page, gate: string) => page.locator(`[data-testid=gate-row][data-gate=${gate}]`);
const railAct = (page: Page, image: keyof typeof images) => page.locator(`[data-testid=rail-act][data-image="${images[image].slug}"]`);

async function openReview(page: Page, query = "") {
  await page.goto(`/ui/hints${query}`);
  await expect(page.getByTestId("impact")).toBeVisible();
}

// edit changes the hints the page gets, which the review, the banner and the rail all read from
// this one request. The seed has no unclear hints, so the tests make them
async function edit(page: Page, change: (hint: any) => void) {
  await page.route("**/api/hints?low=1", async (route) => {
    try {
      const res = await route.fetch(), body = await res.json();
      for (const h of body.hints) change(h);
      await route.fulfill({ response: res, json: body });
    } catch {
      // the page went on (a goto) while the top bar's chip was still reading: nothing waits on it
    }
  });
}
const vulnOf = (h: any) => h.rows[0].vulnerability;
const gzip = "CVE-2026-41992", tar = "CVE-2005-2541";

test.describe("selection", () => {
  test("an empty selection disables accept, and a partial one makes the group's checkbox indeterminate", async ({ page }) => {
    await openReview(page);
    const toggle = group(page, "decides").getByTestId("hint-group-toggle");
    // vc5p sits in this group and starts unchecked
    await expect(toggle).toHaveJSProperty("indeterminate", true);
    await box(page, "GHSA-vc5p-v9hr-52mj").check();
    await expect(toggle).toBeChecked();
    await expect(toggle).toHaveJSProperty("indeterminate", false);
    await box(page, gzip).uncheck();
    await expect(toggle).toHaveJSProperty("indeterminate", true);
    await expect(toggle).not.toBeChecked();

    await toggle.check();
    await expect(toggle).toHaveJSProperty("indeterminate", false);
    await toggle.uncheck();
    await group(page, "needed").getByTestId("hint-group-toggle").uncheck();
    await expect(page.getByTestId("hint-check")).toHaveCount(5);
    for (const b of await page.getByTestId("hint-check").all()) await expect(b).not.toBeChecked();
    await expect(accept(page)).toBeDisabled();
    await expect(accept(page)).toHaveText("Select hints to accept");
    await expect(page.getByTestId("impact")).toContainText("Select hints to see what they do to each gate.");
  });
});

test.describe("scope", () => {
  test("picking an image on the rail scopes review to it, and the chip clears it", async ({ page }) => {
    await openReview(page);
    await page.locator(`[data-testid=rail-image][data-slug="${images.deb.slug}"]`).click();
    await expect(page).toHaveURL(`/ui/hints?image=${images.deb.slug}`);
    // gzip, tar and the util-linux package hint
    await expect(page.getByTestId("hint-item")).toHaveCount(3);
    await expect(page.getByTestId("scope-chip")).toContainText(images.deb.name.split(":")[0]);
    await page.getByTestId("scope-chip").getByRole("button", { name: "Clear image filter" }).click();
    await expect(page).toHaveURL("/ui/hints");
    await expect(page.getByTestId("hint-item")).toHaveCount(5);
    await expect(page.getByTestId("scope-chip")).toBeHidden();
  });

  test("the number key picks an image, together with the gate", async ({ page }) => {
    // deb-java's images are in a fixed order: deb, java
    await openReview(page, "?gate=deb-java");
    await expect(page.getByTestId("hint-item")).toHaveCount(4);
    await page.keyboard.press("1");
    await expect(page).toHaveURL(`/ui/hints?gate=deb-java&image=${images.deb.slug}`);
    // tar and the util-linux package hint; gzip is deb-npm's
    await expect(page.getByTestId("hint-item")).toHaveCount(2);
    await expect(item(page, tar)).toBeVisible();
    await expect(item(page, "CVE-2026-3184")).toBeVisible();
    await page.keyboard.press("2");
    await expect(page).toHaveURL(`/ui/hints?gate=deb-java&image=${images.java.slug}`);
    await expect(page.getByTestId("hint-item")).toHaveCount(2);
  });

  test("accepting from one gate's review writes the labels there, and the shared tar row moves the other gate", async ({ page }) => {
    await openReview(page, "?gate=deb-npm");
    await expect(page.getByTestId("hint-item")).toHaveCount(2);
    await expect(impactGate(page, "deb-npm")).toHaveAttribute("data-after", "pass");
    await accept(page).click();
    await expect(page.getByTestId("hints-empty")).toBeVisible();
    await expect.poll(() => labelsOf(tar).map((l) => l.verdict)).toEqual(["fp"]);
    expect(labelsOf(gzip).map((l) => l.verdict)).toEqual(["fp"]);
    // nothing else was written
    expect(labelsOf("CVE-2026-3184")).toEqual([]);
    expect(labelsOf("GHSA-jfh8-c2jp-5v3q")).toEqual([]);

    await page.goto(gatesPage);
    await expect(gateRow(page, "deb-npm")).toHaveAttribute("data-state", "pass");
    // the tar row is the same row in deb-java, so it is no longer open there
    await page.goto(`/ui/gates/deb-java/findings?q=${tar}`);
    await expect(page.getByTestId("findings-table").locator("tbody tr[data-id]")).toHaveCount(1);
    await expect(page.getByTestId("findings-table").locator(`tbody tr[data-id="${rows.tarDropped}"]`).getByTestId("verdict")).toHaveText("FP");
  });
});

test.describe("unclear hints", () => {
  test("the count is plural, says so when there are none, and low=1 in the URL keeps the toggle checked", async ({ page }) => {
    await openReview(page);
    await expect(page.getByTestId("hint-low-count")).toHaveText("no unclear hints");

    await edit(page, (h) => { if ([gzip, tar].includes(vulnOf(h))) { h.verdict = "unclear"; h.confidence = ""; } });
    await openReview(page);
    await expect(page.getByTestId("hint-item")).toHaveCount(3);
    await expect(page.getByTestId("hint-low-count")).toHaveText("2 unclear hints hidden");

    await openReview(page, "?low=1");
    await expect(page.getByTestId("hint-low-toggle")).toBeChecked();
    await expect(page.getByTestId("hint-item")).toHaveCount(5);
    await expect(page.getByTestId("hint-low-count")).toHaveText("");
    for (const v of [gzip, tar]) await expect(box(page, v)).not.toBeChecked();
  });

  test("an unclear cause leaves the util-linux hint out", async ({ page }) => {
    await edit(page, (h) => { if (h.kind === "cause") { h.verdict = "unclear"; h.confidence = ""; } });
    await openReview(page);
    await expect(page.getByTestId("hint-item")).toHaveCount(4);
    await expect(page.getByTestId("hint-low-count")).toHaveText("1 unclear hint hidden");
    await expect(item(page, "CVE-2026-3184")).toHaveCount(0);
    // it was the only hint in the needed group
    await expect(group(page, "needed")).toHaveCount(0);
    // the four rows it covered are open and have no hint now
    await expect(page.getByTestId("impact-left")).toContainText("util-linux CVE-2026-3184");
    await expect(page.getByTestId("impact-left")).toContainText("no hint");
  });

  test("a hint with no confidence shows unchecked", async ({ page }) => {
    await edit(page, (h) => { if (vulnOf(h) === gzip) h.confidence = ""; });
    await openReview(page);
    await expect(item(page, gzip)).toHaveAttribute("data-confidence", "");
    await expect(box(page, gzip)).not.toBeChecked();
    await expect(accept(page)).toHaveText("Accept 3 hints on 7 matches");
  });

  test("an unclear hint checked by hand is written", async ({ page }) => {
    await edit(page, (h) => { if (vulnOf(h) === gzip) { h.verdict = "unclear"; h.confidence = ""; } });
    await openReview(page, "?low=1");
    await expect(box(page, gzip)).not.toBeChecked();
    await box(page, gzip).check();
    await accept(page).click();
    await expect(page.getByTestId("toast")).toContainText("written from 4 hints");
    await expect.poll(() => labelsOf(gzip).map((l) => `${l.package} ${l.verdict}`)).toEqual(["pkg:deb/debian/gzip fp"]);
    // the page's reload has finished, so no intercepted request is left in flight
    await expect(page.getByTestId("hint-item")).toHaveCount(1);
  });
});

test.describe("the work banner", () => {
  test("an unclear hint is left out of the count and says so", async ({ page }) => {
    await edit(page, (h) => { if (vulnOf(h) === gzip) { h.verdict = "unclear"; h.confidence = ""; } });
    await page.goto(gatesPage);
    await expect(page.getByTestId("review-hints")).toContainText("Review 4 hints");
    await expect(page.getByTestId("work-foot")).toHaveText(/ 1 unclear hint left out\.$/);
    await page.goto(gatePage("deb-npm"));
    await expect(page.getByTestId("rail-review-all")).toHaveText("Review all 1 hint");
  });

  test("once every hint is accepted research of the row deb-java waits on leads, Label what's left stays, review is gone and h opens an empty review", async ({ page }) => {
    await openReview(page);
    await box(page, "GHSA-vc5p-v9hr-52mj").check();
    await accept(page).click();
    await expect(page.getByTestId("hints-empty")).toBeVisible();

    await page.goto(gatesPage);
    await expect(page.getByTestId("work-banner")).toHaveAttribute("data-research", "offered");
    await expect(page.getByTestId("review-hints")).toBeHidden();
    // tar CVE-2026-18508 now decides deb-java and has no hint: researching it is the primary
    await expect(page.getByTestId("research-rows")).not.toHaveAttribute("data-variant", /.+/);
    await expect(page.getByTestId("work-foot")).toHaveText("1 match across 1 gate can still change an outcome. The other 1 changes none.");
    await expect(page.getByTestId("work-rcaps")).toHaveText("Research this match");
    await expect(page.getByTestId("work-legend").locator("[data-segment=hinted]")).toHaveCount(0);
    await expect(page.getByTestId("label-left")).toHaveAttribute("data-variant", "outline");
    await expect(page.getByTestId("label-left")).toBeVisible();
    for (const g of ["deb-java", "deb-npm"]) await expect(gateRow(page, g).getByTestId("gate-work")).toContainText("no hints");
    await page.keyboard.press("h");
    await expect(page).toHaveURL(/\/ui\/hints$/);
    await expect(page.getByTestId("hints-empty")).toBeVisible();
  });

  test("the Unlabeled and Labels tabs carry Label next and no banner", async ({ page }) => {
    for (const tab of ["unlabeled", "labels"]) {
      await page.goto(`${gatesPage}?tab=${tab}`);
      await expect(page.getByTestId("label-next")).toBeVisible();
      await expect(page.getByTestId("work-banner")).toHaveCount(0);
    }
  });
});

test.describe("the image rail", () => {
  test("deb-npm's rail counts its two hints, and Review all scopes review to the gate", async ({ page }) => {
    await page.goto(gatePage("deb-npm"));
    await expect(page.getByTestId("rail-review-all")).toHaveText("Review all 2 hints");
    await expect(railAct(page, "deb").getByTestId("rail-hints")).toHaveText("2 hints on 2 matches");
    await expect(railAct(page, "npm")).toHaveCount(0);
    await page.getByTestId("rail-review-all").click();
    await expect(page).toHaveURL("/ui/hints?gate=deb-npm");
    await expect(page.getByTestId("hint-item")).toHaveCount(2);
  });

  test("a check screen's rail carries the hints, the Labels tab's does not, and accepted hints leave the rail", async ({ page }) => {
    await page.goto(checkPage("unjudgedChangesAtMost"));
    await expect(page.getByTestId("rail-review-all")).toHaveText("Review all 4 hints");
    await page.goto(`${gatePage()}labels`);
    await expect(page.getByTestId("image-rail")).toBeVisible();
    await expect(page.getByTestId("rail-review-all")).toHaveCount(0);

    // both java hints, vc5p's too, which review leaves unchecked
    await openReview(page, `?gate=deb-java&image=${images.java.slug}`);
    await box(page, "GHSA-vc5p-v9hr-52mj").check();
    await accept(page).click();
    await expect(page.getByTestId("hints-empty")).toBeVisible();
    await page.goto(gatePage());
    await expect(page.getByTestId("rail-review-all")).toHaveText("Review all 2 hints");
    await expect(railAct(page, "deb")).toBeVisible();
    await expect(railAct(page, "java")).toHaveCount(0);
  });
});

test.describe("hints that replace a person's label", () => {
  test("an unclear label written in the UI holds its hint back, and accepting the hint replaces it", async ({ page }) => {
    await openFinding(page, rows.jfhA, "f1NotWorse");
    await page.keyboard.press("u");
    await page.getByTestId("reason-picker").selectOption("not-assessed");
    await page.getByTestId("note-input").fill("check the jar");
    await page.getByTestId("save-label").click();
    await expect.poll(() => labelsOf("GHSA-jfh8-c2jp-5v3q").map((l) => l.verdict)).toEqual(["unclear"]);

    await openReview(page);
    await expect(item(page, "GHSA-jfh8-c2jp-5v3q")).toHaveAttribute("data-replaces", "true");
    await expect(box(page, "GHSA-jfh8-c2jp-5v3q")).not.toBeChecked();
    await expect(item(page, "GHSA-jfh8-c2jp-5v3q").getByTestId("hint-replaces")).toHaveText('replaces an unclear label: "check the jar"');
    await expect(accept(page)).toHaveText("Accept 3 hints on 6 matches");

    // both java hints now override a label
    await page.goto(gatePage());
    await expect(railAct(page, "java").getByTestId("rail-replaces")).toHaveText("2 override a label");

    await openReview(page);
    await box(page, "GHSA-jfh8-c2jp-5v3q").check();
    await accept(page).click();
    // unlike vc5p's seeded unclear, which stays beside the tp, this unclear is the same key and is replaced
    await expect.poll(() => labelsOf("GHSA-jfh8-c2jp-5v3q").map((l) => l.verdict)).toEqual(["tp"]);
  });

  test("a hand label on a hinted row takes its hint out of review and regroups the rest", async ({ page }) => {
    await openFinding(page, rows.gzip, "unjudgedChangesAtMost", "deb-npm");
    await label(page, "t");
    await expect.poll(() => labelsOf(gzip).map((l) => l.verdict)).toEqual(["tp"]);

    await openReview(page);
    await expect(page.getByTestId("hint-item")).toHaveCount(4);
    await expect(item(page, gzip)).toHaveCount(0);
    // with gzip judged, deb-npm needs tar's row too, so tar no longer decides a gate alone
    await expect(group(page, "needed").getByTestId("hint-item").filter({ hasText: tar })).toBeVisible();
    await expect(group(page, "decides").getByTestId("hint-item").filter({ hasText: tar })).toHaveCount(0);
  });

  test("the replaces flag's wording, with a label and without (bug: 'an TP label')", async ({ page }) => {
    // the seed has no tp label under a hint and no replaced row without one, so make both
    let withLabel = true;
    await edit(page, (h) => {
      if (vulnOf(h) !== gzip) return;
      h.replaces = true;
      if (withLabel) h.rows[0].label = { verdict: "tp" };
    });
    await openReview(page);
    await expect(item(page, gzip).getByTestId("hint-replaces")).toHaveText("replaces an TP label");
    withLabel = false;
    await openReview(page);
    await expect(item(page, gzip).getByTestId("hint-replaces")).toHaveText("replaces a label");
  });
});
