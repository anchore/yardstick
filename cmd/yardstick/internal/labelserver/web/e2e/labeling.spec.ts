import { expect, test } from "./fixtures";
import { checkPage, images, label, labelsOf, onFinding, openFinding, rows, verdictButton } from "./helpers";

// labeling on the finding page; finding.spec.ts has the reason, note and relabel cases. The util-linux
// rows are the ones to walk: several rows, no labels, no hand-made state
const [, libblkid1, libmount1] = rows.utilLinux;

test.describe("a label from the finding page", () => {
  test("t and Save write a tp label, and the page moves on to the next open finding", async ({ page }) => {
    await openFinding(page, libblkid1);
    await expect(page.getByTestId("title-row").getByTestId("verdict")).toHaveText("unlabeled");
    await label(page, "t");
    await expect.poll(() => labelsOf("CVE-2026-3184").length).toBe(1);
    expect(labelsOf("CVE-2026-3184")[0]).toMatchObject({ subject: images.deb.name, package: "pkg:deb/debian/libblkid1", verdict: "tp" });
    await onFinding(page, libmount1);
    await expect(page.getByTestId("toast")).toContainText("CVE-2026-3184: ● TP");

    // back goes to the finding just labeled, which shows its label
    await page.goBack();
    await onFinding(page, libblkid1);
    await expect(page.getByTestId("title-row").getByTestId("verdict")).toHaveText("TP");
    await expect(page.getByTestId("label-on-file")).toHaveAttribute("data-verdict", "tp");
    await expect(verdictButton(page, "tp")).toHaveAttribute("aria-pressed", "true");
  });

  test("the TP button picks the same verdict", async ({ page }) => {
    await openFinding(page, libblkid1);
    await verdictButton(page, "tp").click();
    await expect(verdictButton(page, "tp")).toHaveAttribute("aria-pressed", "true");
    await page.getByTestId("save-label").click();
    await expect.poll(() => labelsOf("CVE-2026-3184").map((l) => l.verdict)).toEqual(["tp"]);
  });

  test("unclear without a reason writes nothing, with one it writes unclear", async ({ page }) => {
    await openFinding(page, libblkid1);
    await page.keyboard.press("u");
    await expect(page.getByTestId("reason-picker")).toBeFocused();
    await page.getByTestId("save-label").click();
    await expect(page.getByTestId("toast")).toContainText("unclear needs a reason");
    expect(labelsOf("CVE-2026-3184")).toEqual([]);

    await page.getByTestId("reason-picker").selectOption("not-assessed");
    await page.getByTestId("save-label").click();
    await expect.poll(() => labelsOf("CVE-2026-3184").map((l) => `${l.verdict} ${l.justification}`)).toEqual(["unclear not-assessed"]);
    await onFinding(page, libmount1);
  });

  test("keys typed into the note are text, not commands", async ({ page }) => {
    await openFinding(page, libblkid1);
    await page.getByTestId("note-input").click();
    await page.keyboard.type("a fat tuna");
    for (const v of ["tp", "fp", "unclear"]) await expect(verdictButton(page, v)).toHaveAttribute("aria-pressed", "false");
    await expect(page.getByTestId("note-input")).toHaveValue("a fat tuna");
    expect(labelsOf("CVE-2026-3184")).toEqual([]);
  });

  test("labeling the last open finding of a list says nothing is left", async ({ page }) => {
    // the search narrows the check's list to the four util-linux rows
    await page.goto(`${checkPage("unjudgedChangesAtMost")}/${libblkid1}?q=CVE-2026-3184`);
    await expect(page.getByTestId("pager")).toHaveAttribute("data-total", "4");
    for (let i = 0; i < 4; i++) {
      await expect(page.getByTestId("label-panel")).toHaveAttribute("data-verdict", "unlabeled");
      await label(page, "t");
      await expect.poll(() => labelsOf("CVE-2026-3184").length).toBe(i + 1);
    }
    await expect(page.getByTestId("toast")).toContainText("nothing left to label in this list");
    await expect(page.getByTestId("label-panel")).toHaveAttribute("data-verdict", "tp");
    expect(labelsOf("CVE-2026-3184").map((l) => l.package.replace(/.*\//, "")).sort()).toEqual(["libblkid1", "libmount1", "mount", "util-linux"]);
    // n enters the queue: this check's open rows first, then the gate's
    await page.keyboard.press("n");
    await expect(page).toHaveURL(/\/ui\/queue\/[0-9a-f]{16}\?scope=gate%3Adeb-java&check=unjudgedChangesAtMost$/);
    await expect(page.getByTestId("queue-bar")).toBeVisible();
  });
});
