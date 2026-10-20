import type { Page } from "@playwright/test";
import { expect, test } from "./fixtures";
import { images, labelsOf, rows } from "./helpers";

// the /ui/gates/ list screens: gates (level 0), a gate's tabs (level 1) and a check (level 2), on
// the seed SCENARIO.md describes

const chip = (page: Page, c: string) => page.locator(`.chip[data-chip=${c}] b`);
const tableRows = (page: Page, testid: string) => page.getByTestId(testid).locator("tbody tr[data-id]");

test("the gates screen lists each gate with its images, and its tabs list the open findings and every label", async ({ page }) => {
  await page.goto("/ui/gates/");
  const gates = page.getByTestId("gate-row");
  await expect(gates).toHaveCount(2);
  const java = page.locator("[data-testid=gate-row][data-gate=deb-java]");
  await expect(java).toHaveAttribute("data-state", "fail");
  // unclear is not unlabeled: 8 of deb-java's 10 open rows have no label at all
  await expect(java.getByTestId("gate-unlabeled")).toHaveText(/8 unlabeled\s*of 12 changed/);
  await expect(java.locator(".sq.open")).toHaveCount(2);
  await expect(page.locator("[data-testid=gate-row][data-gate=deb-npm]")).toHaveAttribute("data-state", "undecided");

  const tabs = page.getByTestId("tabs");
  await expect(tabs.getByRole("tab", { name: /Unlabeled/ })).toContainText("10");
  await tabs.getByRole("tab", { name: /Unlabeled/ }).click();
  await expect(page).toHaveURL(/\/ui\/gates\/\?tab=unlabeled$/);
  await expect(tableRows(page, "unlabeled-table")).toHaveCount(10);
  await page.getByRole("searchbox", { name: "Filter findings" }).fill("log4j");
  await expect(tableRows(page, "unlabeled-table")).toHaveCount(2);

  // deb's labels count in both gates and are listed once
  await tabs.getByRole("tab", { name: /Labels/ }).click();
  await expect(page).toHaveURL(/tab=labels$/);
  await expect(tableRows(page, "labels-table")).toHaveCount(4);
  await expect(chip(page, "fp")).toHaveText("2");
  // paged, so newest first and no column sorts (a sort would order one page)
  await expect(page.getByTestId("labels-table").locator("th button.sort")).toHaveCount(0);

  await tabs.getByRole("tab", { name: /Gates/ }).click();
  await java.click();
  await expect(page).toHaveURL(/\/ui\/gates\/deb-java\/$/);
});

test("a gate lists its checks with meters, and a check row opens the check", async ({ page }) => {
  await page.goto("/ui/gates/deb-java/");
  await expect(page.getByTestId("verdict-bar")).toContainText("12 changed matches");
  const checks = page.getByTestId("check-row");
  await expect(checks).toHaveCount(4);
  await expect(page.locator("[data-testid=check-row][data-check=unjudgedChangesAtMost]")).toHaveAttribute("data-state", "undecided");
  await expect(page.locator("[data-testid=check-row][data-check=f1NotWorse] [data-testid=meter]")).toContainText("0.500 worse · limit 0");
  // a check row says what the check means in a line, and its definition on hover
  const f1desc = page.locator("[data-testid=check-row][data-check=f1NotWorse] .desc");
  await expect(f1desc).toHaveText("Candidate F1 must not fall below the reference's");
  await expect(f1desc).toHaveAttribute("title", /^Fails when the candidate's F1 is lower/);
  // deb passes f1NotWorse, so its two fp labels count without deciding it, as the check screen says
  await expect(page.locator("[data-testid=check-row][data-check=f1NotWorse] [data-testid=check-count]")).toContainText("4 could move it alone");
  await page.locator("[data-testid=check-row][data-check=f1NotWorse]").click();
  await expect(page).toHaveURL(/\/ui\/gates\/deb-java\/checks\/f1NotWorse$/);
  await expect(page.getByTestId("breadcrumb")).toHaveText(/Gates\s*›\s*deb-java\s*›\s*f1NotWorse/);
  await expect(tableRows(page, "check-table")).toHaveCount(12);
});

test("on a check the rail scopes the table, the chips follow it, and Images hides it", async ({ page }) => {
  await page.goto("/ui/gates/deb-java/checks/f1NotWorse");
  const table = page.getByTestId("check-table");
  await expect(tableRows(page, "check-table")).toHaveCount(12);
  await expect(chip(page, "all")).toHaveText("12");
  await expect(chip(page, "unclear")).toHaveText("2");
  await expect(table.locator("th", { hasText: "Image" })).toHaveCount(1);

  // 2 is the java image: four findings, two of them unclear, and no Image column
  await page.keyboard.press("2");
  await expect(page).toHaveURL(new RegExp(`image=${images.java.slug}$`));
  await expect(page.getByTestId("scope-chip")).toContainText(images.java.name);
  await expect(tableRows(page, "check-table")).toHaveCount(4);
  await expect(chip(page, "all")).toHaveText("4");
  await expect(chip(page, "unlabeled")).toHaveText("2");
  await expect(chip(page, "fp")).toHaveText("0");
  await expect(table.locator("th", { hasText: "Image" })).toHaveCount(0);

  // a chip filters inside the image, and the rail keeps it
  await page.locator(".chip[data-chip=unclear]").click();
  await expect(tableRows(page, "check-table")).toHaveCount(2);
  await page.getByTestId("image-rail").locator(`[data-slug="${images.deb.slug}"]`).click();
  await expect(page).toHaveURL(/verdict=unclear/);
  await expect(chip(page, "all")).toHaveText("8");
  await expect(tableRows(page, "check-table")).toHaveCount(0);

  await page.getByTestId("images-toggle").click();
  await expect(page.getByTestId("image-rail")).toBeHidden();
  await page.getByTestId("images-toggle").click();
  await expect(page.getByTestId("image-rail")).toBeVisible();
});

test("j and k move through a check's table and Enter opens the finding", async ({ page }) => {
  await page.goto(`/ui/gates/deb-java/checks/f1NotWorse?image=${images.java.slug}`);
  await expect(tableRows(page, "check-table")).toHaveCount(4);
  await page.keyboard.press("j");
  await page.keyboard.press("j");
  await page.keyboard.press("k");
  await expect(page.locator("tr.cursor")).toHaveAttribute("data-id", rows.jfhA);
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(new RegExp(`/ui/gates/deb-java/checks/f1NotWorse/${rows.jfhA}\\?image=${images.java.slug}$`));
});

test("the gate's Labels tab shows deb-java's four labels with verdict counts, paged", async ({ page }) => {
  await page.goto("/ui/gates/deb-java/labels");
  await expect(tableRows(page, "labels-table")).toHaveCount(4);
  await expect(chip(page, "all")).toHaveText("4");
  await expect(chip(page, "tp")).toHaveText("1");
  await expect(chip(page, "fp")).toHaveText("2");
  await expect(chip(page, "unclear")).toHaveText("1");
  await expect(page.getByTestId("page-info")).toHaveText("1–4 of 4");
  // the rail counts labels per image
  await expect(page.getByTestId("image-rail").locator(`[data-slug="${images.deb.slug}"]`)).toContainText("3 labels");

  await page.locator(".chip[data-chip=fp]").click();
  await expect(page).toHaveURL(/verdict=fp$/);
  await expect(tableRows(page, "labels-table")).toHaveCount(2);
  // a label on a changed row opens its finding
  await page.locator("[data-testid=labels-table] tbody tr", { hasText: "CVE-2026-5704" }).click();
  await expect(page).toHaveURL(/\/ui\/gates\/deb-java\/findings\/6d210210168e93db$/);
});

test("bulk Accept hints on a check writes the agent's labels, a proposal's and a package hint's", async ({ page }) => {
  await page.goto("/ui/gates/deb-java/checks/f1NotWorse");
  const table = page.getByTestId("check-table");
  await table.locator(`tr[data-id="${rows.jfhA}"] input[type=checkbox]`).check();
  await table.locator(`tr[data-id="${rows.utilLinux[0]}"] input[type=checkbox]`).check();
  await expect(page.getByTestId("bulk-bar")).toContainText("2 selected");
  await page.getByTestId("bulk-accept").click();

  await expect.poll(() => labelsOf("GHSA-jfh8-c2jp-5v3q").map((l) => `${l.subject} ${l.verdict}`)).toContain(`${images.java.name} tp`);
  await expect.poll(() => labelsOf("CVE-2026-3184").filter((l) => l.verdict === "tp").length).toBeGreaterThan(0);
  // the table reloads with the labels on it
  await expect(table.locator(`tr[data-id="${rows.jfhA}"] [data-testid=verdict]`)).toHaveText("TP");
});

test("Label as… on the gate's Findings tab labels the rows selected", async ({ page }) => {
  await page.goto("/ui/gates/deb-java/findings");
  const table = page.getByTestId("findings-table");
  await table.locator(`tr[data-id="${rows.tarHand}"] input[type=checkbox]`).check();
  await page.getByTestId("label-as").selectOption("fp:fix-installed");
  await expect.poll(() => labelsOf("CVE-2026-18508").map((l) => `${l.verdict} ${l.justification}`)).toEqual(["fp fix-installed"]);
  await expect(table.locator(`tr[data-id="${rows.tarHand}"] [data-testid=verdict]`)).toHaveText("FP");
});

test("n on a gate filtered to an image enters the queue for that image", async ({ page }) => {
  await page.goto(`/ui/gates/deb-java/?image=${images.java.slug}`);
  await expect(page.getByTestId("check-row")).toHaveCount(4);
  await page.keyboard.press("n");
  await expect(page).toHaveURL(new RegExp(`/ui/queue/${rows.jfhA}\\?scope=image%3A${images.java.slug}$`));
});

test("the scan map's blocks open the Findings tab filtered to their package", async ({ page }) => {
  await page.goto("/ui/gates/deb-java/map");
  await page.locator("[data-testid=block][data-package=tar]").click();
  await expect(page).toHaveURL(/\/ui\/gates\/deb-java\/findings\?pkg=tar$/);
  await expect(tableRows(page, "findings-table")).toHaveCount(3);
});
