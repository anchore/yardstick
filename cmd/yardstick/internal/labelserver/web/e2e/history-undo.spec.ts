import type { Page } from "@playwright/test";
import { expect, test } from "./fixtures";
import { claimSet, label, labelsOf, onFinding, openFinding, rows, setPref } from "./helpers";

// undo: history since the server started (the default), its per-row and bulk remove, and a write's
// toast Undo. Each removes the labels from ./claims; the seed's own labels predate the server, so
// they only show with since=all and are never what these remove.

const lines = (page: Page) => page.getByTestId("history-table").locator("tbody tr[data-id]");
const line = (page: Page, vuln: string) => lines(page).filter({ hasText: vuln });
const toast = (page: Page) => page.getByTestId("toast");

async function openHistory(page: Page, query = "") {
  await page.goto(`/ui/history${query}`);
  await expect(page.getByTestId("page-info")).toBeVisible();
}

// acceptAll accepts the preselected hints on review: seven labels from four hints
async function acceptAll(page: Page) {
  await page.goto("/ui/hints");
  await page.getByTestId("accept-hints").click();
  await expect(toast(page)).toContainText("7 labels written from 4 hints");
}

test.describe("since", () => {
  test("defaults to the server's start, so only what this server wrote shows", async ({ page }) => {
    await openHistory(page);
    await expect(page.getByTestId("history-since")).toHaveValue("start");
    await expect(page.getByTestId("history-since").locator("option:checked")).toHaveText(/^Since the server started, /);
    await expect(page.getByTestId("history-since-time")).toBeHidden();
    await expect(lines(page)).toHaveCount(0);
    await expect(page.getByTestId("history-table")).toContainText("No labels written since the server started");
    await expect(page.getByTestId("history-remove-all")).toBeDisabled();

    await openFinding(page, rows.tarHand);
    await label(page, "f", "fix-installed");
    await expect.poll(() => labelsOf("CVE-2026-18508").length).toBe(1);
    await openHistory(page);
    await expect(lines(page)).toHaveCount(1);
    await expect(line(page, "CVE-2026-18508")).toHaveCount(1);

    await page.getByTestId("history-since").selectOption("all");
    await expect(page).toHaveURL(/\/ui\/history\?since=all$/);
    await expect(lines(page)).toHaveCount(5);
  });

  test("a picked time rides the URL and filters on it", async ({ page }) => {
    await acceptAll(page);
    await openHistory(page);
    await page.getByTestId("history-since").selectOption("pick");
    await expect(page).toHaveURL(/\/ui\/history\?since=\d{4}-/);
    await expect(page.getByTestId("history-since-time")).toBeVisible();
    await expect(page.getByTestId("history-since")).toHaveValue("pick");
    await expect(lines(page)).toHaveCount(7);
    // a time after every label leaves none
    await page.getByTestId("history-since-time").fill("2099-01-01T00:00");
    await expect(page).toHaveURL(/since=2099-/);
    await expect(lines(page)).toHaveCount(0);
    await page.reload();
    await expect(page.getByTestId("history-since-time")).toHaveValue("2099-01-01T00:00");
    await expect(page.getByTestId("history-table")).toContainText("No labels match.");
  });
});

test.describe("remove", () => {
  test("one row goes at once and its finding is open again", async ({ page }) => {
    const before = claimSet();
    await openFinding(page, rows.tarHand);
    await label(page, "f", "fix-installed");
    await expect.poll(() => labelsOf("CVE-2026-18508").length).toBe(1);
    await openHistory(page);
    await line(page, "CVE-2026-18508").getByTestId("history-remove").click();
    await expect(toast(page)).toContainText("1 label removed");
    await expect(lines(page)).toHaveCount(0);
    await expect(page.getByTestId("history-confirm")).toBeHidden();
    expect(claimSet()).toEqual(before);
    await openFinding(page, rows.tarHand);
    await expect(page.getByTestId("finding")).toHaveAttribute("data-verdict", "unlabeled");
  });

  test("selected rows and all shown ask first, in the page", async ({ page }) => {
    const before = claimSet();
    await acceptAll(page);
    await openHistory(page);
    await expect(lines(page)).toHaveCount(7);
    for (const v of ["CVE-2026-41992", "GHSA-jfh8-c2jp-5v3q"]) await line(page, v).getByRole("checkbox").check();
    await page.getByTestId("history-remove-selected").click();
    const confirm = page.getByTestId("history-confirm");
    await expect(confirm).toBeVisible();
    await expect(confirm).toContainText("Remove 2 labels from");
    // cancel removes nothing, and Esc closes it too
    await page.getByTestId("history-confirm-cancel").click();
    await expect(confirm).toBeHidden();
    await expect(lines(page)).toHaveCount(7);
    await page.getByTestId("history-remove-selected").click();
    await page.keyboard.press("Escape");
    await expect(confirm).toBeHidden();
    await expect(page).toHaveURL(/\/ui\/history$/);

    await page.getByTestId("history-remove-selected").click();
    await page.getByTestId("history-confirm-remove").click();
    await expect(toast(page)).toContainText("2 labels removed");
    await expect(lines(page)).toHaveCount(5);
    expect(labelsOf("CVE-2026-41992")).toHaveLength(0);
    expect(labelsOf("GHSA-jfh8-c2jp-5v3q")).toHaveLength(0);

    // all shown is every label the filters match: the fp chip leaves the tar fp
    await page.locator("[data-chip=fp]").click();
    await expect(lines(page)).toHaveCount(1);
    await expect(page.getByTestId("history-remove-all")).toHaveText("Remove all shown");
    await page.locator("[data-chip=all]").click();
    await expect(page.getByTestId("history-remove-all")).toHaveText("Remove all 5 shown");
    await page.getByTestId("history-remove-all").click();
    await expect(confirm).toContainText("Remove 5 labels from");
    await page.getByTestId("history-confirm-remove").click();
    await expect(toast(page)).toContainText("5 labels removed");
    await expect(lines(page)).toHaveCount(0);
    expect(claimSet()).toEqual(before);
    // the hints are pending again
    await page.goto("/ui/hints");
    await expect(page.getByTestId("hint-item")).toHaveCount(5);
  });
});

test.describe("toast undo", () => {
  test("a hand label's Undo removes it and the finding reads as before", async ({ page }) => {
    const before = claimSet();
    await openFinding(page, rows.tarHand);
    await setPref(page, "advance-checkbox", false);
    await label(page, "f", "fix-installed");
    await expect(page.getByTestId("finding")).toHaveAttribute("data-verdict", "fp");
    await expect(toast(page).getByTestId("toast-action")).toHaveText("Undo");
    await toast(page).getByTestId("toast-action").click();
    await expect(toast(page)).toContainText("1 label removed");
    await expect(page.getByTestId("finding")).toHaveAttribute("data-verdict", "unlabeled");
    await onFinding(page, rows.tarHand);
    expect(claimSet()).toEqual(before);
    await openHistory(page);
    await expect(lines(page)).toHaveCount(0);
  });

  test("a relabel's Undo puts the earlier label back rather than leaving the match unlabeled", async ({ page }) => {
    await openFinding(page, rows.tarHand);
    await setPref(page, "advance-checkbox", false);
    await label(page, "f", "fix-installed");
    await expect(page.getByTestId("finding")).toHaveAttribute("data-verdict", "fp");
    const fp = claimSet();
    await label(page, "t");
    await expect(page.getByTestId("finding")).toHaveAttribute("data-verdict", "tp");
    await expect.poll(() => labelsOf("CVE-2026-18508").map((l) => l.verdict)).toEqual(["tp"]);
    await toast(page).getByTestId("toast-action").click();
    await expect(toast(page)).toContainText("1 earlier label put back");
    await expect(page.getByTestId("finding")).toHaveAttribute("data-verdict", "fp");
    expect(labelsOf("CVE-2026-18508").map((l) => `${l.verdict} ${l.justification}`)).toEqual(["fp fix-installed"]);
    expect(claimSet()).toEqual(fp);
  });

  test("an accepted hint's Undo puts back the person's label it replaced, note and all", async ({ page }) => {
    await openFinding(page, rows.jfhA, "f1NotWorse");
    await page.keyboard.press("u");
    await page.getByTestId("reason-picker").selectOption("not-assessed");
    await page.getByTestId("note-input").fill("check the jar");
    await page.getByTestId("save-label").click();
    await expect.poll(() => labelsOf("GHSA-jfh8-c2jp-5v3q").map((l) => l.verdict)).toEqual(["unclear"]);
    const unclear = claimSet();

    await page.goto("/ui/hints");
    await page.getByTestId("hint-item").filter({ hasText: "GHSA-jfh8-c2jp-5v3q" }).getByTestId("hint-check").check();
    await page.getByTestId("accept-hints").click();
    await expect.poll(() => labelsOf("GHSA-jfh8-c2jp-5v3q").map((l) => l.verdict)).toEqual(["tp"]);
    await toast(page).getByTestId("toast-action").click();
    await expect(toast(page)).toContainText("earlier label put back");
    await expect.poll(() => labelsOf("GHSA-jfh8-c2jp-5v3q").map((l) => `${l.verdict} ${l.notes.join(" ")}`)).toEqual(["unclear check the jar"]);
    expect(claimSet().filter((l) => l.includes("GHSA-jfh8"))).toEqual(unclear.filter((l) => l.includes("GHSA-jfh8")));
  });

  test("accepting hints in review undoes as one batch", async ({ page }) => {
    const before = claimSet();
    await acceptAll(page);
    await expect(page.getByTestId("hint-item")).toHaveCount(1);
    await toast(page).getByTestId("toast-action").click();
    await expect(toast(page)).toContainText("7 labels removed");
    expect(claimSet()).toEqual(before);
    await expect(page.getByTestId("hint-item")).toHaveCount(5);
  });

  test("a message with no write carries no Undo", async ({ page }) => {
    await openFinding(page, rows.tarHand);
    await page.keyboard.press("f");
    await page.getByTestId("save-label").click();
    await expect(toast(page)).toContainText("FP needs a reason");
    await expect(toast(page).getByTestId("toast-action")).toHaveCount(0);
  });
});

test.describe("the app bar's history entry", () => {
  const entry = (page: Page) => page.getByTestId("history-entry");
  const counts = async (page: Page, n: number) => {
    await expect(entry(page)).toHaveAttribute("data-count", String(n));
    if (n) await expect(page.getByTestId("history-count")).toHaveText(String(n));
    else await expect(page.getByTestId("history-count")).toBeHidden();
    await expect(entry(page)).toHaveText(n ? `History${n}` : "History");
  };

  test("counts what this server wrote, after writes, an Undo and a remove, and opens history", async ({ page }) => {
    await page.goto("/ui/gates/");
    await counts(page, 0);
    await expect(entry(page)).toHaveAttribute("title", /^0 labels written to .+ since the server started$/);

    // a hand label, then an accepted hint
    await openFinding(page, rows.tarHand);
    await setPref(page, "advance-checkbox", false);
    await label(page, "f", "fix-installed");
    await counts(page, 1);
    await openFinding(page, rows.tarDropped);
    await page.keyboard.press("a");
    await expect(toast(page)).toContainText(/hint accepted/);
    await counts(page, 2);
    await expect(entry(page)).toHaveAttribute("title", /^2 labels written to /);

    // the hint's Undo takes it back off
    await toast(page).getByTestId("toast-action").click();
    await expect(toast(page)).toContainText("1 label removed");
    await counts(page, 1);

    // the entry opens history since the server started, where a remove counts down too
    await entry(page).click();
    await expect(page).toHaveURL(/\/ui\/history$/);
    await expect(lines(page)).toHaveCount(1);
    await line(page, "CVE-2026-18508").getByTestId("history-remove").click();
    await expect(toast(page)).toContainText("1 label removed");
    await counts(page, 0);
  });
});
