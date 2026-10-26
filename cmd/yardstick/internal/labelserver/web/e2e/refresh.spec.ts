import type { Page } from "@playwright/test";
import { expect, test } from "./fixtures";
import { checkPage, expectFreshLoad, gatePage, gatesPage, keeps, labelsOf, openFinding, rows, setPref, tableRow } from "./helpers";

// a write refreshes the screen in place: no loading frame, the table (or the label panel) is the
// same element as before it, and the screen then shows what a fresh load of its URL shows

const toast = (page: Page) => page.getByTestId("toast");

test.describe("lists", () => {
  test("Label as… on a check", async ({ page }) => {
    await page.goto(checkPage("f1NotWorse"));
    await tableRow(page, "check-table", rows.jfhA).getByRole("checkbox").check();
    const kept = await keeps(page, page.getByTestId("check-table"));
    await page.getByTestId("label-as").selectOption("fp:fix-installed");
    await expect.poll(() => labelsOf("GHSA-jfh8-c2jp-5v3q").map((l) => l.verdict)).toEqual(["fp"]);
    await expect(tableRow(page, "check-table", rows.jfhA).getByTestId("verdict")).toHaveText("FP");
    await expectFreshLoad(page);
    await kept();
  });

  test("Accept hints on a check", async ({ page }) => {
    await page.goto(checkPage("f1NotWorse"));
    await tableRow(page, "check-table", rows.utilLinux[0]).getByRole("checkbox").check();
    const kept = await keeps(page, page.getByTestId("check-table"));
    await page.getByTestId("bulk-accept").click();
    await expect.poll(() => labelsOf("CVE-2026-3184").length).toBeGreaterThan(0);
    // a tp on an added row raises the candidate's F1, so f1NotWorse no longer lists it
    await expect(tableRow(page, "check-table", rows.utilLinux[0])).toHaveCount(0);
    await expectFreshLoad(page);
    await kept();
  });

  test("Label as… on the gate's Matches tab, with its counts, verdict bar and rail", async ({ page }) => {
    await page.goto(`${gatePage()}findings`);
    await tableRow(page, "findings-table", rows.tarHand).getByRole("checkbox").check();
    const kept = await keeps(page, page.getByTestId("findings-table"));
    await page.getByTestId("label-as").selectOption("fp:fix-installed");
    await expect.poll(() => labelsOf("CVE-2026-18508").length).toBe(1);
    await expectFreshLoad(page);
    await kept();
  });

  test("Label as… and Accept hints on the Unlabeled tab", async ({ page }) => {
    await page.goto(`${gatesPage}?tab=unlabeled`);
    const table = page.getByTestId("unlabeled-table");
    const kept = await keeps(page, table);
    await table.locator("tbody tr", { hasText: "CVE-2026-18508" }).getByRole("checkbox").check();
    await page.getByTestId("label-as").selectOption("fp:fix-installed");
    await expect.poll(() => labelsOf("CVE-2026-18508").length).toBe(1);
    await expect(table.locator("tbody tr", { hasText: "CVE-2026-18508" })).toHaveCount(0);
    await expectFreshLoad(page);

    await table.locator("tbody tr", { hasText: "CVE-2005-2541" }).getByRole("checkbox").check();
    await page.getByTestId("bulk-accept").click();
    await expect.poll(() => labelsOf("CVE-2005-2541").length).toBe(1);
    await expect(table.locator("tbody tr", { hasText: "CVE-2005-2541" })).toHaveCount(0);
    await expectFreshLoad(page);
    await kept();
  });

  test("a toast's Undo on the Labels tab", async ({ page }) => {
    await page.goto(`${gatesPage}?tab=unlabeled`);
    await page.getByTestId("unlabeled-table").locator("tbody tr", { hasText: "CVE-2026-18508" }).getByRole("checkbox").check();
    await page.getByTestId("label-as").selectOption("fp:fix-installed");
    await expect(page.getByTestId("toast-action")).toBeVisible();
    // the toast outlives a move to another tab, so its Undo lands on the Labels tab
    await page.getByTestId("tabs").getByRole("tab", { name: /Labels/ }).click();
    await expect(page.getByTestId("labels-table").locator("tbody tr", { hasText: "CVE-2026-18508" })).toBeVisible();
    const kept = await keeps(page, page.getByTestId("labels-table"));
    await page.getByTestId("toast-action").click();
    await expect.poll(() => labelsOf("CVE-2026-18508").length).toBe(0);
    await expect(page.getByTestId("labels-table").locator("tbody tr", { hasText: "CVE-2026-18508" })).toHaveCount(0);
    await expectFreshLoad(page);
    await kept();
  });

  test("a toast's Undo on a check", async ({ page }) => {
    await page.goto(checkPage("f1NotWorse"));
    await tableRow(page, "check-table", rows.jfhA).getByRole("checkbox").check();
    await page.getByTestId("label-as").selectOption("fp:fix-installed");
    await expect(tableRow(page, "check-table", rows.jfhA).getByTestId("verdict")).toHaveText("FP");
    const kept = await keeps(page, page.getByTestId("check-table"));
    await page.getByTestId("toast-action").click();
    await expect(toast(page)).toContainText("1 label removed");
    await expect(tableRow(page, "check-table", rows.jfhA).getByTestId("verdict")).toHaveText("unlabeled");
    await expectFreshLoad(page);
    await kept();
  });
});

test.describe("history", () => {
  const line = (page: Page, vuln: string) => page.getByTestId("history-table").locator("tbody tr[data-id]", { hasText: vuln });

  // writeTwo labels both tar findings from the Unlabeled tab, two labels this server wrote
  async function writeTwo(page: Page) {
    await page.goto(`${gatesPage}?tab=unlabeled&q=debian%2Ftar%40`);
    await page.getByTestId("unlabeled-table").getByRole("checkbox", { name: "Select every row shown" }).check();
    await page.getByTestId("label-as").selectOption("fp:fix-installed");
    await expect.poll(() => labelsOf("CVE-2026-18508").length + labelsOf("CVE-2005-2541").length).toBe(2);
    await page.goto("/ui/history");
    await expect(page.getByTestId("history-table").locator("tbody tr[data-id]")).toHaveCount(2);
  }

  test("Remove on a row", async ({ page }) => {
    await writeTwo(page);
    const kept = await keeps(page, page.getByTestId("history-table"));
    await line(page, "CVE-2026-18508").getByTestId("history-remove").click();
    await expect(toast(page)).toContainText("1 label removed");
    await expect(line(page, "CVE-2026-18508")).toHaveCount(0);
    await expectFreshLoad(page);
    await kept();
  });

  test("Remove selected", async ({ page }) => {
    await writeTwo(page);
    const kept = await keeps(page, page.getByTestId("history-table"));
    await page.getByTestId("history-table").getByRole("checkbox", { name: "Select every row shown" }).check();
    await page.getByTestId("history-remove-selected").click();
    await page.getByTestId("history-confirm-remove").click();
    await expect(toast(page)).toContainText("2 labels removed");
    await expect(page.getByTestId("history-table").locator("tbody tr[data-id]")).toHaveCount(0);
    await expectFreshLoad(page);
    await kept();
  });
});

test.describe("the finding page", () => {
  test("Save with Go to the next match off stays and keeps the panel", async ({ page }) => {
    await openFinding(page, rows.tarHand);
    await setPref(page, "advance-checkbox", false);
    const kept = await keeps(page, page.getByTestId("label-panel"));
    await page.keyboard.press("f");
    await page.getByTestId("reason-picker").selectOption("fix-installed");
    await page.getByTestId("save-label").click();
    await expect.poll(() => labelsOf("CVE-2026-18508").length).toBe(1);
    await expect(page.getByTestId("label-on-file")).toHaveAttribute("data-verdict", "fp");
    await expect(page.getByTestId("save-label")).toBeFocused();
    await expectFreshLoad(page);
    await kept();
  });

  test("a note being typed keeps its focus and text while research polls the row", async ({ page }) => {
    test.setTimeout(120_000);
    await openFinding(page, rows.tarHand);
    await page.keyboard.press("Shift+R");
    await expect(page.getByTestId("toast")).toContainText("research started");
    const kept = await keeps(page, page.getByTestId("label-panel"));
    const note = page.getByTestId("note-input");
    await note.click();
    await page.keyboard.type("checked the changelog");
    // the hint arrives through the page's polling, which repaints the row while the note has focus
    await expect(page.getByTestId("hint-card")).toHaveAttribute("data-verdict", "tp", { timeout: 60_000 });
    await expect(note).toBeFocused();
    await page.keyboard.type(" too");
    await expect(note).toHaveValue("checked the changelog too");
    await kept();
  });

  test("an open gate switcher stays open while research polls the row", async ({ page }) => {
    test.setTimeout(120_000);
    await openFinding(page, rows.tarHand);
    await page.keyboard.press("Shift+R");
    await expect(page.getByTestId("toast")).toContainText("research started");
    await page.getByTestId("gate-switch-button").click();
    const option = page.locator("[data-testid=gate-option][data-gate=deb-npm]");
    await expect(option).toBeVisible();
    await expect(page.getByTestId("hint-card")).toHaveAttribute("data-verdict", "tp", { timeout: 60_000 });
    await expect(page.getByTestId("gate-switch-button")).toHaveAttribute("aria-expanded", "true");
    await expect(option).toBeVisible();
  });
});
