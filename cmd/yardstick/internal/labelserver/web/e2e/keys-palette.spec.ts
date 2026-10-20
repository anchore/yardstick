import type { Page } from "@playwright/test";
import { expect, test } from "./fixtures";
import { checkPage, gatePage, gatesPage, images, label, labelsOf, onFinding, openFinding, rows, verdictButton } from "./helpers";

// keys while typing, the ⌘K palette's edges, the gate crumb switcher and ⇧J / ⇧K. moving.spec.ts
// has the basics of the last three. The gates are listed newest scan first, which can swap, so
// where a test leaves a gate for "the other one" it never assumes which that is.
const palette = (page: Page) => page.getByTestId("palette");
const input = (page: Page) => page.getByTestId("palette-input");
const item = (page: Page, group: string, id: string) => palette(page).locator(`[data-testid=palette-item][data-group=${group}][data-id="${id}"]`);
const group = (page: Page, g: string) => palette(page).locator(`[data-testid=palette-item][data-group=${g}]`);
const option = (page: Page, gate: string) => page.locator(`[data-testid=gate-option][data-gate=${gate}]`);
const typed = "nhJ2j"; // every key that would go somewhere if it were not text

// openPalette opens ⌘K and waits for the gate states, so the checks and findings are in
async function openPalette(page: Page) {
  await page.keyboard.press("Control+k");
  await expect(palette(page)).toBeVisible();
  await expect(group(page, "Checks")).toHaveCount(5);
}

test.describe("keys typed into a field", () => {
  test("the Findings search takes n h J 2 j as text, and only q changes in the URL", async ({ page }) => {
    await page.goto(`${gatePage()}findings`);
    const search = page.getByRole("searchbox", { name: "Filter findings" });
    await search.click();
    await search.pressSequentially(typed);
    await expect(search).toHaveValue(typed);
    await expect(page).toHaveURL(new RegExp(`/ui/gates/deb-java/findings\\?q=${typed}$`));
  });

  test("the history search does too", async ({ page }) => {
    await page.goto("/ui/history");
    const search = page.getByRole("searchbox", { name: "Filter history" });
    await search.click();
    await search.pressSequentially(typed);
    await expect(search).toHaveValue(typed);
    await expect(page).toHaveURL(new RegExp(`/ui/history(\\?q=${typed})?$`));
    await expect(page.getByTestId("title")).toHaveText("History");
  });

  test("the rail filter does, and the image scope stays", async ({ page }) => {
    const url = `${gatePage()}?image=${images.java.slug}`;
    await page.goto(url);
    const filter = page.getByTestId("rail-filter");
    await filter.click();
    await filter.pressSequentially(typed);
    await expect(filter).toHaveValue(typed);
    await expect(page).toHaveURL(new RegExp(`/ui/gates/deb-java/\\?image=${images.java.slug}$`));
    await expect(palette(page)).toBeHidden();
  });

  test("in the queue, typing into the note picks no verdict; Escape blurs first and a second one exits", async ({ page }) => {
    await page.goto(`/ui/queue/${rows.jfhA}?scope=gate:deb-java`);
    await onFinding(page, rows.jfhA);
    const url = page.url();
    const note = page.getByTestId("note-input");
    await note.click();
    // t would pick tp, a would accept the hint, n and j would move on
    await note.pressSequentially("jnat");
    await expect(note).toHaveValue("jnat");
    for (const v of ["tp", "fp", "unclear"]) await expect(verdictButton(page, v)).toHaveAttribute("aria-pressed", "false");
    await onFinding(page, rows.jfhA);

    await page.keyboard.press("Escape");
    await expect(note).not.toBeFocused();
    expect(page.url()).toBe(url);
    await page.keyboard.press("Escape");
    await expect(page).toHaveURL(/\/ui\/gates\/deb-java\/$/);
  });

  test("a focused select swallows n, and a focused checkbox does not swallow j", async ({ page }) => {
    await openFinding(page, rows.jfhA);
    await page.keyboard.press("f");
    const picker = page.getByTestId("reason-picker");
    await expect(picker).toBeFocused();
    await page.keyboard.press("n");
    await expect(page).toHaveURL(new RegExp(`${checkPage("unjudgedChangesAtMost")}/${rows.jfhA}$`));

    await page.goto(`/ui/queue/${rows.jfhA}?scope=gate:deb-java`);
    await onFinding(page, rows.jfhA);
    const url = page.url();
    await page.getByTestId("queue-scope").focus();
    await page.keyboard.press("n");
    await page.keyboard.press("h");
    expect(page.url()).toBe(url);

    // a button takes no text, so j is still a command; only the open settings cog keeps keys
    await page.getByTestId("settings-button").focus();
    await page.keyboard.press("j");
    await expect(page.getByTestId("label-panel")).not.toHaveAttribute("data-row", rows.jfhA);
  });

  test("keys typed into the palette go nowhere, and Alt+n does not enter the queue", async ({ page }) => {
    await page.goto(gatesPage);
    await expect(page.getByTestId("gate-row")).toHaveCount(2);
    await page.keyboard.press("Alt+n");
    await expect(page).toHaveURL(/\/ui\/gates\/$/);

    await page.keyboard.press("Control+k");
    await expect(input(page)).toBeFocused();
    await input(page).pressSequentially("hn");
    await expect(input(page)).toHaveValue("hn");
    await expect(palette(page)).toBeVisible();
    await expect(page).toHaveURL(/\/ui\/gates\/$/);
  });
});

test.describe("palette queries", () => {
  test("no match shows no items and says so", async ({ page }) => {
    await page.goto(gatesPage);
    await openPalette(page);
    await input(page).fill("zzzzzz");
    await expect(palette(page).getByTestId("palette-item")).toHaveCount(0);
    await expect(palette(page).locator("[data-empty]")).toHaveAttribute("data-empty", "Nothing matches.");
  });

  test("a lowercase ID still matches, and a package or advisory finds every row it is on", async ({ page }) => {
    await page.goto(gatesPage);
    await openPalette(page);
    await input(page).fill("cve-2026-18508");
    await expect(item(page, "Findings", rows.tarHand)).toBeVisible();
    // two jars, two rows
    await input(page).fill("GHSA-jfh8");
    await expect(group(page, "Findings")).toHaveCount(2);
    // jfh8 and vc5p, two jars each
    await input(page).fill("log4j-core");
    await expect(group(page, "Findings")).toHaveCount(4);
  });

  test("a gate's name finds the gate, its check, the images it scans and no findings", async ({ page }) => {
    await page.goto(gatesPage);
    await openPalette(page);
    await input(page).fill("deb-npm");
    await expect(group(page, "Gates")).toHaveCount(1);
    await expect(group(page, "Checks")).toHaveCount(1);
    await expect(item(page, "Checks", "deb-npm/unjudgedChangesAtMost")).toBeVisible();
    await expect(group(page, "Images")).toHaveCount(2);
    await expect(group(page, "Findings")).toHaveCount(0);
  });

  test("a labeled finding shows its verdict", async ({ page }) => {
    await page.goto(gatesPage);
    await openPalette(page);
    await input(page).fill("CVE-2011-3389");
    await expect(item(page, "Findings", "c54934489d4ac861").getByTestId("verdict")).toHaveText("FP");
  });
});

test.describe("palette keys and closing", () => {
  test("ArrowDown then Enter picks the second entry", async ({ page }) => {
    await page.goto(gatesPage);
    await openPalette(page);
    // by its own href, since the gates come in scan order
    const second = (await palette(page).getByTestId("palette-item").nth(1).getAttribute("href"))!;
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("Enter");
    await expect(palette(page)).toBeHidden();
    await expect(page).toHaveURL(new RegExp(`${second}$`));
  });

  test("reopening starts with an empty query", async ({ page }) => {
    await page.goto(gatesPage);
    await page.keyboard.press("Control+k");
    await input(page).fill("babel");
    await page.keyboard.press("Escape");
    await expect(palette(page)).toBeHidden();
    await page.keyboard.press("Control+k");
    await expect(input(page)).toHaveValue("");
  });

  test("a click on the backdrop closes it", async ({ page }) => {
    await page.goto(gatesPage);
    await page.keyboard.press("Control+k");
    await expect(palette(page)).toBeVisible();
    await page.mouse.click(2, 2);
    await expect(palette(page)).toBeHidden();
    await expect(page).toHaveURL(/\/ui\/gates\/$/);
  });

  test("opens from the queue, hint review and history", async ({ page }) => {
    for (const url of [`/ui/queue/${rows.jfhA}?scope=gate:deb-java`, "/ui/hints", "/ui/history"]) {
      await page.goto(url);
      await expect(page.getByTestId("title")).toBeVisible();
      await page.keyboard.press("Control+k");
      await expect(palette(page), url).toBeVisible();
      await page.keyboard.press("Escape");
      await expect(palette(page), url).toBeHidden();
    }
  });
});

test.describe("palette destinations", () => {
  test("an image opens its gate scoped to it, and a check opens the check", async ({ page }) => {
    await page.goto(gatesPage);
    await openPalette(page);
    await group(page, "Images").filter({ hasText: images.npm.name }).click();
    await expect(page).toHaveURL(new RegExp(`/ui/gates/deb-npm/\\?image=${images.npm.slug}$`));
    await expect(palette(page)).toBeHidden();

    await openPalette(page);
    await group(page, "Images").filter({ hasText: images.java.name }).click();
    await expect(page).toHaveURL(new RegExp(`/ui/gates/deb-java/\\?image=${images.java.slug}$`));
    await expect(palette(page)).toBeHidden();

    await openPalette(page);
    await item(page, "Checks", "deb-java/f1NotWorse").click();
    await expect(page).toHaveURL(new RegExp(`${checkPage("f1NotWorse")}$`));
    await expect(page.getByTestId("check-table")).toBeVisible();
  });

  test("the queue action lands on the queue's first row", async ({ page }) => {
    await page.goto(gatesPage);
    await openPalette(page);
    await item(page, "Actions", "queue").click();
    // across every gate the queue starts at gzip (moving.spec.ts)
    await onFinding(page, rows.gzip);
    await expect(page).toHaveURL(new RegExp(`/ui/queue/${rows.gzip}$`));
  });
});

test.describe("between gates", () => {
  test("⇧J on a gate's Findings tab keeps the tab, and wraps round with two gates", async ({ page }) => {
    await page.goto(`${gatePage()}findings`);
    await expect(page.getByRole("searchbox", { name: "Filter findings" })).toBeVisible();
    await page.keyboard.press("Shift+J");
    await expect(page).toHaveURL(/\/ui\/gates\/deb-npm\/findings$/);
    await page.keyboard.press("Shift+J");
    await expect(page).toHaveURL(/\/ui\/gates\/deb-java\/findings$/);
    await page.keyboard.press("Shift+K");
    await expect(page).toHaveURL(/\/ui\/gates\/deb-npm\/findings$/);
  });

  test("⇧J from a finding goes to the other gate's Checks", async ({ page }) => {
    await openFinding(page, rows.jfhA);
    await page.keyboard.press("Shift+J");
    await expect(page).toHaveURL(/\/ui\/gates\/deb-npm\/$/);
    await expect(page.getByTestId("check-row")).toHaveCount(1);
  });

  test("⇧J drops the image filter", async ({ page }) => {
    await page.goto(`${gatePage()}?image=${images.java.slug}`);
    await expect(page.getByTestId("image-rail")).toBeVisible();
    await page.keyboard.press("Shift+J");
    await expect(page).toHaveURL(/\/ui\/gates\/deb-npm\/$/);
  });

  test("from the hints and history screens it lands in a gate", async ({ page }) => {
    await page.goto("/ui/hints");
    await expect(page.getByTestId("impact")).toBeVisible();
    await page.keyboard.press("Shift+J");
    await expect(page).toHaveURL(/\/ui\/gates\/deb-(java|npm)\/$/);

    await page.goto("/ui/history");
    await expect(page.getByTestId("title")).toHaveText("History");
    await page.keyboard.press("Shift+K");
    await expect(page).toHaveURL(/\/ui\/gates\/deb-(java|npm)\/$/);
  });

  test("with no other gate open, ⇧J says so and stays", async ({ page }) => {
    // the review scoped to deb-npm takes tar and gzip, a hand fp on babel closes the gate's last row
    await page.goto("/ui/hints?gate=deb-npm");
    await expect(page.getByTestId("accept-hints")).toHaveText(/Accept 2 hints/);
    await page.getByTestId("accept-hints").click();
    await expect(page.getByTestId("toast")).toContainText("written from 2 hints");
    await openFinding(page, rows.babel, null, "deb-npm");
    await label(page, "f", "fix-installed");
    await expect.poll(() => labelsOf("GHSA-67hx-6x53-jw92").map((l) => l.verdict)).toEqual(["fp"]);

    await page.goto(gatePage());
    await expect(page.getByTestId("check-row")).toHaveCount(4);
    await page.keyboard.press("Shift+J");
    await expect(page.getByTestId("toast")).toContainText("no other gate has open matches");
    await expect(page).toHaveURL(/\/ui\/gates\/deb-java\/$/);
  });
});

test.describe("the gate crumb switcher", () => {
  test("opens from the keyboard and Enter on an option goes there", async ({ page }) => {
    await page.goto(checkPage("f1NotWorse"));
    await expect(page.getByTestId("check-table")).toBeVisible();
    await page.getByTestId("gate-switch-button").focus();
    await page.keyboard.press("ArrowDown");
    await expect(option(page, "deb-npm")).toBeVisible();
    // the menu's active option follows the arrows; deb-npm may be either one
    await option(page, "deb-npm").hover();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/\/ui\/gates\/deb-npm\/$/);
  });

  test("from the Findings tab an option links to the same tab", async ({ page }) => {
    await page.goto(`${gatePage()}findings`);
    await expect(page.getByRole("searchbox", { name: "Filter findings" })).toBeVisible();
    await page.getByTestId("gate-switch-button").click();
    await expect(option(page, "deb-npm")).toHaveAttribute("href", "/ui/gates/deb-npm/findings");
    await option(page, "deb-npm").click();
    await expect(page).toHaveURL(/\/ui\/gates\/deb-npm\/findings$/);
  });
});
