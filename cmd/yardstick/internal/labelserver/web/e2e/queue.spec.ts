import { expect, test } from "./fixtures";
import { claimSet, gatesPage, images, label, onFinding, rows } from "./helpers";
import type { Page } from "@playwright/test";

// the queue: n from the gates screen labels the whole seed one row at a time, crossing gates with a
// card between them, and stops when every gate is decided. Its order is the server's (GET
// /api/queue): gzip first (it alone passes deb-npm), then deb-java's rows.
const deb = images.deb.name, java = images.java.name;
const seeded = [
  "global pkg:deb/debian/libgnutls30 CVE-2011-3389 fp fix-installed",
  `${deb} pkg:deb/debian/libc6 CVE-2026-5450 tp no-fix`,
  `${deb} pkg:deb/debian/tar CVE-2026-5704 fp fix-installed`,
  `${java} pkg:maven/org.apache.logging.log4j/log4j-core GHSA-vc5p-v9hr-52mj unclear not-assessed`,
];
// SCENARIO.md's flipped set, and gzip, the queue's first row, whose hint passes deb-npm
const flipped = [
  `${deb} pkg:deb/debian/tar CVE-2005-2541 fp fix-installed`,
  `${deb} pkg:deb/debian/tar CVE-2026-18508 fp fix-installed`,
  ...["util-linux", "libblkid1", "libmount1", "mount"].map((p) => `${deb} pkg:deb/debian/${p} CVE-2026-3184 tp no-fix`),
  `${java} pkg:maven/org.apache.logging.log4j/log4j-core GHSA-jfh8-c2jp-5v3q tp no-fix`,
  `${java} pkg:maven/org.apache.logging.log4j/log4j-core GHSA-vc5p-v9hr-52mj tp no-fix`,
  `${deb} pkg:deb/debian/gzip CVE-2026-41992 fp fix-installed`,
];

const card = (page: Page) => page.getByTestId("queue-card");
const panelRow = (page: Page) => page.getByTestId("label-panel").getAttribute("data-row");
const cardGate = (page: Page, gate: string) => card(page).locator(`[data-testid=card-gate][data-gate=${gate}]`);

test("n from the gates screen labels the seed through the queue until every gate is decided", async ({ page }) => {
  await page.goto(gatesPage);
  await expect(page.getByTestId("gate-row")).toHaveCount(2);
  await page.keyboard.press("n");

  // the first row: gzip, deb-npm's, with why it's next and what each verdict does
  await onFinding(page, rows.gzip);
  await expect(page.getByTestId("queue-progress")).toHaveText("0 of 12 done · 12 left");
  await expect(page.getByTestId("why-next")).toContainText("deb-npm is undecided, with 3 open rows. A label here decides it: either label passes it.");
  await expect(page.getByTestId("queue-outcomes")).toHaveText("FP: deb-npm passes. TP: deb-npm passes.");
  await expect(page.getByTestId("breadcrumb")).toContainText("deb-npm");
  await page.keyboard.press("a");

  // deb-npm's outcome changed and the queue moves on to deb-java: a card says so
  await expect(card(page)).toHaveAttribute("data-card", "boundary");
  await expect(page.getByTestId("title")).toHaveText("deb-npm passes");
  await expect(cardGate(page, "deb-npm")).toHaveAttribute("data-state", "pass");
  await expect(card(page)).toContainText("Next in the queue: deb-java, 10 open rows.");
  await page.keyboard.press("Enter");
  await onFinding(page, rows.jfhA);
  await expect(page.getByTestId("breadcrumb")).toContainText("deb-java");

  // the rest: accept each hint, and label tar CVE-2026-18508 by hand, until a card stops the queue
  for (let i = 0; i < 12 && !(await card(page).isVisible()); i++) {
    const row = await panelRow(page);
    if (row === rows.tarHand) {
      // no hint: a tp here would be a new false negative
      await expect(page.getByTestId("why-next")).toContainText("TP fails noNewFalseNegatives");
      await expect(page.getByTestId("queue-outcomes")).toContainText("TP: deb-java fails noNewFalseNegatives.");
      await label(page, "f", "fix-installed");
    } else await page.keyboard.press("a");
    // the next row, or a card; while the queue reads itself fresh the page shows neither
    await expect(card(page).or(page.locator(`[data-testid=label-panel]:not([data-row="${row}"])`))).toBeVisible();
  }

  // the stopping point: both gates pass, and the babel row left changes neither
  await expect(card(page)).toHaveAttribute("data-card", "stop");
  await expect(page.getByTestId("title")).toHaveText("Every gate is decided");
  await expect(cardGate(page, "deb-java")).toHaveAttribute("data-state", "pass");
  await expect(cardGate(page, "deb-npm")).toHaveAttribute("data-state", "pass");
  await expect(page.getByTestId("card-left").locator("li")).toHaveCount(1);
  await expect(page.getByTestId("card-left").locator(`li[data-row="${rows.babel}"]`)).toContainText("changes no outcome");
  await expect(page.getByTestId("queue-progress")).toHaveText("11 of 12 done · 1 left");
  expect(claimSet()).toEqual([...seeded, ...flipped].sort());

  // keep labeling: the babel row by hand, and the queue is empty
  await page.getByTestId("card-continue").click();
  await onFinding(page, rows.babel);
  await expect(page.getByTestId("why-next")).toContainText("No label here changes any gate's outcome");
  await label(page, "f", "fix-installed");
  await expect(card(page)).toHaveAttribute("data-card", "end");
  await expect(cardGate(page, "deb-java")).toHaveAttribute("data-state", "pass");
  await expect(page.getByTestId("card-session")).toContainText("10 labels written this session, closing 12 rows: 10 from hints, 2 by hand.");

  // history: every label on disk, the written ones first, newest first, each linking to its finding
  await page.getByTestId("card-history").click();
  await expect(page).toHaveURL(/\/ui\/history$/);
  await expect(page.getByTestId("breadcrumb")).toHaveText(/^Gates\s*›\s*History$/);
  const table = page.getByTestId("history-table");
  await expect(table.locator("tbody tr[data-id]")).toHaveCount(seeded.length + flipped.length + 1);
  const times = await table.locator("time").evaluateAll((ts) => ts.map((t) => t.getAttribute("datetime")!));
  expect(times).toEqual([...times].sort().reverse());
  await expect(page.getByTestId("history-day").first()).toHaveText(/^Today/);
  const tar = table.locator("tbody tr[data-id]").filter({ hasText: "CVE-2005-2541" });
  await expect(tar.getByTestId("history-note")).toContainText("carries the fix");
  await expect(tar.getByTestId("history-link")).toHaveCount(2);

  // filters: by verdict, then by text
  await page.locator("[data-chip=unclear]").click();
  await expect(page).toHaveURL(/\/ui\/history\?verdict=unclear$/);
  await expect(table.locator("tbody tr[data-id]")).toHaveCount(1);
  await page.locator("[data-chip=all]").click();
  await page.getByRole("searchbox", { name: "Filter history" }).fill("gzip");
  await expect(table.locator("tbody tr[data-id]")).toHaveCount(1);
  await table.locator("tbody tr[data-id]").getByTestId("history-link").first().click();
  await onFinding(page, rows.gzip);
});

test("Skip labeled steps over what the queue labeled; off, k goes back to it", async ({ page }) => {
  await page.goto("/ui/queue?scope=gate:deb-java");
  await onFinding(page, rows.jfhA);
  await page.keyboard.press("a");
  // one jfh8 label covers both jars, so both are done and the queue moves on
  await expect(page.getByTestId("label-panel")).not.toHaveAttribute("data-row", rows.jfhA);
  const next = (await panelRow(page))!;
  expect([rows.jfhB, rows.jfhA]).not.toContain(next);
  await expect(page.getByTestId("queue-progress")).toHaveText("2 of 12 done · 10 left");
  await expect(page.getByTestId("queue-pager")).toHaveText(/1 of 10/);
  await page.keyboard.press("k");
  await expect(page.getByTestId("toast")).toContainText("first one in the queue");
  await onFinding(page, next);

  await page.getByTestId("queue-skip").uncheck();
  await expect(page.getByTestId("queue-pager")).toHaveText(/3 of 12/);
  await page.keyboard.press("k");
  await onFinding(page, rows.jfhB);
  await expect(page.getByTestId("label-panel")).toHaveAttribute("data-verdict", "tp");

  await page.getByTestId("queue-skip").check();
  await page.keyboard.press("j");
  await onFinding(page, next);

  // Esc leaves the queue for the gate it was entered from
  await page.keyboard.press("Escape");
  await expect(page).toHaveURL(/\/ui\/gates\/deb-java\/$/);
});
