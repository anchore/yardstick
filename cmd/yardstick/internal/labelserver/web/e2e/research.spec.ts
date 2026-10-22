import { expect, test } from "./fixtures";
import { checkPage, labelsOf, openFinding, rows, tableRow } from "./helpers";

// a research run is a process per match
test.setTimeout(120_000);

// the seed's research runs a stand-in, never claude: it records a tp proposal for each row it is
// asked about, and the label UI shows it as an agent hint. finding.spec.ts accepts it on the page.

test("research started on a finding reaches the lists as an agent hint, and can be accepted there", async ({ page }) => {
  await openFinding(page, rows.tarHand);
  await expect(page.getByTestId("research-button")).toHaveText(/^Research/);
  await page.keyboard.press("Shift+R");
  await expect(page.getByTestId("toast")).toContainText("research started");
  await expect(page.getByTestId("hint-card")).toHaveAttribute("data-verdict", "tp", { timeout: 60_000 });
  await expect(page.getByTestId("research-button")).toHaveText(/^Research again/);

  // the check's table and the every-gate queue show the hint the match had none of
  await page.keyboard.press("Escape");
  await expect(page).toHaveURL(new RegExp(`${checkPage("unlabeledChangesAtMost")}$`));
  const row = tableRow(page, "check-table", rows.tarHand);
  await expect(row.getByTestId("hint")).toHaveText("TP · medium");
  await page.goto("/ui/gates/?tab=unlabeled&q=CVE-2026-18508");
  await expect(page.getByTestId("unlabeled-table").locator("tbody tr[data-id]").getByTestId("hint")).toHaveText("TP · medium");

  await page.goto(checkPage("unlabeledChangesAtMost"));
  await row.getByRole("checkbox").check();
  await page.getByTestId("bulk-accept").click();
  await expect.poll(() => labelsOf("CVE-2026-18508").map((l) => l.verdict)).toEqual(["tp"]);
  // judged, it no longer counts toward what is left unlabeled
  await expect(row).toHaveCount(0);
});
