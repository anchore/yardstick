import { expect, test } from "./fixtures";
import { checkPage, gatePage, gatesPage, images, onFinding, rows } from "./helpers";
import type { Page } from "@playwright/test";

// moving through the work: "Label next" lands at the top of what j walks, j and k skip labeled
// rows, ⇧J / ⇧K and the gate crumb move between gates, and ⌘K goes anywhere. The seed's two gates
// are listed newest scan first, which can swap, so with two gates "the next one" is the other.
const pager = (page: Page) => page.getByTestId("pager");
const palette = (page: Page) => page.getByTestId("palette");
const item = (page: Page, group: string, id: string) => palette(page).locator(`[data-testid=palette-item][data-group=${group}][data-id="${id}"]`);
const libgnutls = "c54934489d4ac861"; // CVE-2011-3389, labeled fp

test.describe("Label next", () => {
  // the reported bug was "9 of 12", from a list in report order: Label next enters the queue, whose
  // pager counts open rows from the first. Across every gate the queue starts at gzip, which alone
  // passes deb-npm
  const queuePager = (page: Page) => page.getByTestId("queue-pager");
  test("Label what's left on the gates screen enters the queue at its first row, 1 of 12", async ({ page }) => {
    await page.goto(gatesPage);
    await expect(page.getByTestId("label-next")).toHaveCount(0);
    await page.getByTestId("label-left").click();
    await onFinding(page, rows.gzip);
    await expect(page).toHaveURL(new RegExp(`/ui/queue/${rows.gzip}$`));
    await expect(queuePager(page)).toHaveText(/1 of 12/);
    await expect(queuePager(page)).toHaveAttribute("data-index", "1");
  });

  test("and n on a gate enter it at that gate's first row", async ({ page }) => {
    await page.goto(gatePage());
    await page.getByTestId("label-next").click();
    // every open row counts toward the failing unlabeledChangesAtMost, so the deb image's come first
    await onFinding(page, rows.utilLinux[1]);
    await expect(page).toHaveURL(new RegExp(`/ui/queue/${rows.utilLinux[1]}\\?scope=gate%3Adeb-java$`));
    await expect(queuePager(page)).toHaveText(/1 of 12/);

    await page.goto(gatePage("deb-npm"));
    await expect(page.getByTestId("check-row")).toHaveCount(2);
    await page.keyboard.press("n");
    await expect(page).toHaveURL(new RegExp(`/ui/queue/${rows.gzip}\\?scope=gate%3Adeb-npm$`));
    await expect(queuePager(page)).toHaveText(/1 of 12/);
  });
});

test("j and k skip labeled rows, ⌥j and ⌥k walk every row", async ({ page }) => {
  // the gate's Findings list by effect: log4j's four, d257 (libblkid1), 781d (libmount1), the rest
  // of the open deb rows ending at util-linux, then the two fp labels, which count toward no check
  const findings = "/ui/gates/deb-java/findings";
  const tarFp = "6d210210168e93db"; // CVE-2026-5704, labeled fp
  await page.goto(`${findings}/${rows.utilLinux[1]}`);
  await expect(pager(page)).toHaveText(/5 of 10 open/);
  await page.keyboard.press("j");
  await onFinding(page, rows.utilLinux[2]);
  await expect(pager(page)).toHaveText(/6 of 10 open/);

  await page.goto(`${findings}/${rows.utilLinux[0]}`);
  await expect(pager(page)).toHaveText(/10 of 10 open/);
  await page.keyboard.press("Alt+j");
  await onFinding(page, libgnutls);
  await expect(pager(page)).toHaveText(/labeled · 10 open/);
  await expect(pager(page)).toHaveAttribute("data-index", "0");
  await page.keyboard.press("Alt+j");
  await onFinding(page, tarFp);
  // from a labeled row k goes to the nearest open row, past the other labeled one
  await page.keyboard.press("k");
  await onFinding(page, rows.utilLinux[0]);
});

test.describe("between gates", () => {
  test("⇧J and ⇧K go to the other gate with open rows, keeping the tab or going up to the gate", async ({ page }) => {
    await page.goto(`${gatePage()}labels`);
    await expect(page.getByTestId("labels-table")).toBeVisible();
    await page.keyboard.press("Shift+J");
    await expect(page).toHaveURL(/\/ui\/gates\/deb-npm\/labels$/);
    await page.keyboard.press("Shift+K");
    await expect(page).toHaveURL(/\/ui\/gates\/deb-java\/labels$/);

    await page.goto(checkPage("f1NotWorse"));
    await expect(page.getByTestId("check-table")).toBeVisible();
    await page.keyboard.press("Shift+J");
    await expect(page).toHaveURL(/\/ui\/gates\/deb-npm\/$/);
    await expect(page.getByTestId("check-row")).toHaveCount(2);
  });

  test("the gate crumb is a switcher listing every gate with its outcome and open rows", async ({ page }) => {
    await page.goto(checkPage("f1NotWorse"));
    await expect(page.getByTestId("check-table")).toBeVisible();
    await page.getByTestId("gate-switch-button").click();
    const option = (gate: string) => page.locator(`[data-testid=gate-option][data-gate=${gate}]`);
    await expect(option("deb-java")).toHaveAttribute("aria-current", "true");
    await expect(option("deb-java")).toHaveAttribute("data-open", "10");
    await expect(option("deb-npm")).toHaveAttribute("data-state", "fail");
    await expect(option("deb-npm")).toContainText("3 open");

    // Esc closes the menu and leaves the screen alone
    await page.keyboard.press("Escape");
    await expect(option("deb-npm")).toBeHidden();
    await expect(page).toHaveURL(new RegExp(`${checkPage("f1NotWorse")}$`));

    await page.getByTestId("gate-switch-button").click();
    await option("deb-npm").click();
    await expect(page).toHaveURL(/\/ui\/gates\/deb-npm\/$/);
    await expect(page.getByTestId("check-row")).toHaveCount(2);
  });
});

test.describe("the go-to palette", () => {
  test("lists gates, each image once, checks and actions, and finds findings by ID or package", async ({ page }) => {
    await page.goto(gatesPage);
    await expect(page.getByTestId("gate-row")).toHaveCount(2);
    await page.keyboard.press("Control+k");
    await expect(palette(page)).toBeVisible();
    await expect(page.getByTestId("palette-input")).toBeFocused();
    await expect(item(page, "Gates", "deb-npm")).toBeVisible();
    await expect(item(page, "Checks", "deb-java/f1NotWorse")).toBeVisible();
    // deb is in both gates and listed once
    const imgs = palette(page).locator("[data-testid=palette-item][data-group=Images]");
    await expect(imgs).toHaveCount(3);
    await expect(imgs.filter({ hasText: images.deb.name })).toContainText(/deb-(java|npm) \d+ open · deb-(java|npm) \d+ open/);
    for (const a of ["hints", "queue", "research", "history"]) await expect(item(page, "Actions", a)).toBeVisible();
    await expect(palette(page).locator("[data-group=Matches]")).toHaveCount(0);

    // the tar row is in both gates and is one finding
    await page.getByTestId("palette-input").fill("CVE-2005-2541");
    await expect(palette(page).locator("[data-group=Matches]")).toHaveCount(1);
    // in gate list order, which two scans across a minute boundary swap
    await expect(item(page, "Matches", rows.tarDropped)).toContainText(/deb-java, deb-npm|deb-npm, deb-java/);
    await page.getByTestId("palette-input").fill("babel");
    await expect(item(page, "Matches", rows.babel)).toBeVisible();

    // keyboard only: the first match is active and Enter goes there
    await page.getByTestId("palette-input").fill("tar 18508");
    await page.keyboard.press("Enter");
    await expect(palette(page)).toBeHidden();
    await onFinding(page, rows.tarHand);
    await expect(page).toHaveURL(new RegExp(`/ui/gates/deb-java/findings/${rows.tarHand}$`));
  });

  test("opens from any screen, closes on Esc, and goes to the flow's screens", async ({ page }) => {
    await page.goto(checkPage("f1NotWorse"));
    await expect(page.getByTestId("check-table")).toBeVisible();
    await page.keyboard.press("Meta+k");
    await expect(palette(page)).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(palette(page)).toBeHidden();
    await expect(page).toHaveURL(new RegExp(`${checkPage("f1NotWorse")}$`));

    await page.getByTestId("goto-button").click();
    await page.getByTestId("palette-input").fill("history");
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/\/ui\/history$/);
    await expect(page.getByTestId("title")).toHaveText("History");
    await expect(page.getByTestId("breadcrumb")).toHaveText(/^Gates\s*›\s*History$/);

    // a flow screen loads by URL too, and Esc goes up to Gates
    await page.goto("/ui/hints");
    await expect(page.getByTestId("title")).toHaveText("Agent hints");
    await page.keyboard.press("Escape");
    await expect(page).toHaveURL(/\/ui\/gates\/$/);
  });

  test("never opens while typing in a field", async ({ page }) => {
    await page.goto(`${gatePage()}findings`);
    await page.getByRole("searchbox", { name: "Filter matches" }).fill("tar");
    await page.keyboard.press("Control+k");
    await expect(palette(page)).toBeHidden();
    await expect(page.getByRole("searchbox", { name: "Filter matches" })).toBeFocused();
  });
});
