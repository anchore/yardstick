import type { Page, Route } from "@playwright/test";
import type { LabelKey, WriteError } from "../src/gen/wire";
import { expect, test } from "./fixtures";
import { claimSet, labelsOf, onFinding, openFinding, rows, setPref, tableRow, verdictButton } from "./helpers";

// a write per path that the server refuses (400, plain text, nothing written) or that fails after
// some labels landed (500 with a WriteError naming them): the error toast says what landed and
// offers its Undo, and what the reader had chosen stays. The server can't be made to fail on cue,
// so each test answers the request itself, after letting it through when labels should land.

const toast = (page: Page) => page.getByTestId("toast");
const undo = (page: Page) => toast(page).getByTestId("toast-action");

// refuses answers a POST as the server does when it rejects a write before anything lands
async function refuses(page: Page, url: string, message: string) {
  await page.route(url, (r) => (r.request().method() === "POST" ? r.fulfill({ status: 400, contentType: "text/plain", body: message }) : r.fallback()));
}

// landsThenFails lets a POST write its labels, then answers as a write that failed afterwards
async function landsThenFails(page: Page, url: string) {
  await page.route(url, async (r: Route) => {
    if (r.request().method() !== "POST" || r.request().postDataJSON()?.dryRun) return r.fallback();
    const res = await r.fetch(), body = (await res.json()) as { labels: LabelKey[] };
    await r.fulfill({ status: 500, json: { error: "append override: disk full", labels: body.labels } satisfies WriteError });
  });
}

// failsWith expects the error toast with the server's message, and an Undo only when labels landed
async function failsWith(page: Page, text: string | RegExp, landed: boolean) {
  await expect(toast(page)).toHaveClass(/error/);
  await expect(toast(page)).toContainText(text);
  await expect(undo(page)).toHaveCount(landed ? 1 : 0);
}

test.describe("a match's Save", () => {
  test("refused, writes nothing and keeps the match and the verdict picked", async ({ page }) => {
    const before = claimSet();
    await refuses(page, "**/api/gates/deb-java/labels", "verdict tp is not allowed here");
    await openFinding(page, rows.tarHand);
    await page.keyboard.press("t");
    await page.getByTestId("save-label").click();
    await failsWith(page, "400: verdict tp is not allowed here", false);
    await onFinding(page, rows.tarHand);
    await expect(verdictButton(page, "tp")).toHaveAttribute("aria-pressed", "true");
    expect(claimSet()).toEqual(before);
  });

  test("failing after the label landed, says so and undoes it", async ({ page }) => {
    const before = claimSet();
    await landsThenFails(page, "**/api/gates/deb-java/labels");
    await openFinding(page, rows.tarHand);
    await setPref(page, "advance-checkbox", false);
    await page.keyboard.press("t");
    await page.getByTestId("save-label").click();
    await failsWith(page, "500: append override: disk full; 1 label written before it failed", true);
    await expect.poll(() => labelsOf("CVE-2026-18508").map((l) => l.verdict)).toEqual(["tp"]);
    await expect(page.getByTestId("finding")).toHaveAttribute("data-verdict", "tp");
    await undo(page).click();
    await expect(toast(page)).toContainText("1 label removed");
    await expect(page.getByTestId("finding")).toHaveAttribute("data-verdict", "unlabeled");
    expect(claimSet()).toEqual(before);
  });
});

test.describe("a match's hint accept", () => {
  test("refused, writes nothing", async ({ page }) => {
    const before = claimSet();
    await refuses(page, "**/api/gates/deb-java/accept", "the hint changed: read again");
    await openFinding(page, rows.jfhA, "f1NotWorse");
    await page.keyboard.press("a");
    await failsWith(page, "400: the hint changed: read again", false);
    await onFinding(page, rows.jfhA);
    expect(claimSet()).toEqual(before);
  });

  test("a package hint failing part way keeps the Undo for what it wrote", async ({ page }) => {
    const before = claimSet();
    await landsThenFails(page, "**/api/gates/deb-java/package-hints/*/accept");
    await openFinding(page, rows.utilLinux[0]);
    await page.getByTestId("cause-card").getByTestId("accept-all").click();
    await failsWith(page, "4 labels written before it failed", true);
    await expect.poll(() => labelsOf("CVE-2026-3184").length).toBe(4);
    await undo(page).click();
    await expect(toast(page)).toContainText("4 labels removed");
    expect(claimSet()).toEqual(before);
  });
});

test.describe("hint review's accept", () => {
  const box = (page: Page, vuln: string) => page.getByTestId("hint-item").filter({ hasText: vuln }).getByTestId("hint-check");
  const accept = (page: Page) => page.getByTestId("accept-hints");

  test("refused, keeps the reviewer's own checks rather than the preselection", async ({ page }) => {
    const before = claimSet();
    await refuses(page, "**/api/hints/accept", "a hint went stale");
    await page.goto("/ui/hints");
    await box(page, "CVE-2026-41992").uncheck();
    const asked = await accept(page).textContent();
    await accept(page).click();
    await failsWith(page, "400: a hint went stale", false);
    await expect(box(page, "CVE-2026-41992")).not.toBeChecked();
    await expect(box(page, "CVE-2005-2541")).toBeChecked();
    await expect(accept(page)).toHaveText(asked!);
    expect(claimSet()).toEqual(before);
  });

  test("failing after the labels landed, says so and undoes them", async ({ page }) => {
    const before = claimSet();
    await landsThenFails(page, "**/api/hints/accept");
    await page.goto("/ui/hints");
    await accept(page).click();
    await failsWith(page, "7 labels written before it failed", true);
    await expect.poll(() => claimSet()).not.toEqual(before);
    await undo(page).click();
    await expect(toast(page)).toContainText("7 labels removed");
    expect(claimSet()).toEqual(before);
  });
});

test.describe("a table's Label as…", () => {
  test("failing part way across gates keeps the Undo for what it wrote", async ({ page }) => {
    const before = claimSet();
    await landsThenFails(page, "**/api/gates/*/labels");
    await page.goto("/ui/gates/?tab=unlabeled&q=CVE-2026-18508");
    await page.getByTestId("unlabeled-table").locator("tbody tr[data-id]").getByRole("checkbox").check();
    await page.getByTestId("label-as").selectOption("tp:");
    await failsWith(page, "1 label written before it failed", true);
    await expect.poll(() => labelsOf("CVE-2026-18508").map((l) => l.verdict)).toEqual(["tp"]);
    await undo(page).click();
    await expect(toast(page)).toContainText("1 label removed");
    expect(claimSet()).toEqual(before);
  });
});

test.describe("Undo", () => {
  test("refused, leaves the label and says why", async ({ page }) => {
    await openFinding(page, rows.tarHand);
    await setPref(page, "advance-checkbox", false);
    await page.keyboard.press("t");
    await page.getByTestId("save-label").click();
    await expect(page.getByTestId("finding")).toHaveAttribute("data-verdict", "tp");
    await refuses(page, "**/api/history/revert", "claims are read-only here");
    await undo(page).click();
    await failsWith(page, "400: claims are read-only here", false);
    expect(labelsOf("CVE-2026-18508").map((l) => l.verdict)).toEqual(["tp"]);
    await expect(page.getByTestId("finding")).toHaveAttribute("data-verdict", "tp");
  });
});

test.describe("starting research", () => {
  test("refused from a table row, leaves the row offering it", async ({ page }) => {
    await refuses(page, "**/api/gates/deb-java/research", "research is off: no runner");
    await page.goto("/ui/gates/deb-java/findings?verdict=unlabeled");
    const cell = tableRow(page, "findings-table", rows.tarHand).getByTestId("research-cell");
    await cell.click();
    await failsWith(page, "400: research is off: no runner", false);
    await expect(cell).toHaveAttribute("data-state", "offer");
  });

  test("refused from the research page, stays there to try again", async ({ page }) => {
    // the dry runs that price the page still go through
    await page.route("**/api/research", (r) => (r.request().postDataJSON()?.dryRun ? r.fallback() : r.fulfill({ status: 400, contentType: "text/plain", body: "research is off: no runner" })));
    await page.goto(`/ui/research?scope=gate%3Adeb-java&rows=${rows.tarHand}`);
    const start = page.getByTestId("research-start");
    await expect(start).toHaveText("Start 1 research job");
    await start.click();
    await failsWith(page, "400: research is off: no runner", false);
    await expect(page).toHaveURL(/\/ui\/research\?/);
    await expect(start).toBeEnabled();
  });
});
