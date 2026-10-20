import { expect, test } from "./fixtures";
import { gatesPage, images, labelsOf, tableRows } from "./helpers";
import type { Page } from "@playwright/test";

// the gates screen (level 0): every gate, and the Unlabeled tab, the open findings across gates that
// the old every-gate page listed. lists.spec.ts has its search and the Labels tab.
const gateRow = (page: Page, gate: string) => page.locator(`[data-testid=gate-row][data-gate=${gate}]`);
const unlabeled = (page: Page) => tableRows(page, "unlabeled-table");
const finding = (page: Page, text: string) => unlabeled(page).filter({ hasText: text });

async function openUnlabeled(page: Page, q = "") {
  await page.goto(`${gatesPage}?tab=unlabeled${q ? `&q=${encodeURIComponent(q)}` : ""}`);
  await expect(page.getByTestId("unlabeled-table")).toBeVisible();
}

test.describe("every gate", () => {
  test("shows both gates with their outcomes and how much is open", async ({ page }) => {
    await page.goto(gatesPage);
    await expect(gateRow(page, "deb-java")).toHaveAttribute("data-state", "fail");
    await expect(gateRow(page, "deb-npm")).toHaveAttribute("data-state", "undecided");
    await expect(gateRow(page, "deb-npm").getByTestId("gate-unlabeled")).toHaveText(/^3 open\s*of 3 changed$/);
    await expect(gateRow(page, "deb-npm")).toHaveAttribute("href", "/ui/gates/deb-npm/");
    await expect(gateRow(page, "deb-npm")).toContainText("grype candidate-b vs reference-b");
  });

  test("the Unlabeled tab lists the ten open findings, the tar one in both gates", async ({ page }) => {
    await openUnlabeled(page);
    await expect(unlabeled(page)).toHaveCount(10);
    await expect(page.getByTestId("unlabeled-table")).toContainText("10 open findings");
    const tar = finding(page, "CVE-2005-2541");
    await expect(tar).toContainText("deb-java");
    await expect(tar).toContainText("deb-npm");
    await expect(tar).toContainText(images.deb.name);
    await expect(tar.getByTestId("hint")).toHaveText("FP · medium");
    // both gates see only the reference report it, so the question is asked once on the row
    await expect(tar.getByTestId("outcome")).toHaveText("new FN?");
    // labeling it decides deb-npm either way
    await expect(tar).toContainText("could move in 1 gate");
    await expect(finding(page, "CVE-2026-18508").getByTestId("hint")).toHaveCount(0);
    await expect(finding(page, "CVE-2026-3184")).toHaveCount(4);
    for (const r of await finding(page, "CVE-2026-3184").all()) await expect(r.getByTestId("hint")).toHaveText("package hint");
  });

  test("a gate's name in the search narrows the list to it", async ({ page }) => {
    await openUnlabeled(page, "deb-npm");
    await expect(unlabeled(page)).toHaveCount(3);
    await expect(finding(page, "CVE-2026-3184")).toHaveCount(0);
  });

  test("a row opens its finding in a gate that reports it", async ({ page }) => {
    await openUnlabeled(page, "CVE-2026-18508");
    await unlabeled(page).click();
    await expect(page).toHaveURL(/\/ui\/gates\/deb-java\/findings\/e3bfd3b0b0c30ee6$/);
    await expect(page.getByTestId("title")).toHaveText("CVE-2026-18508");
  });
});

test.describe("labeling from every gate", () => {
  const select = async (page: Page, text: string) => {
    for (const r of await finding(page, text).all()) await r.getByRole("checkbox").check();
  };

  test("accepting the tar hint labels it and decides deb-npm without touching deb-java's outcome", async ({ page }) => {
    await openUnlabeled(page);
    await select(page, "CVE-2005-2541");
    await page.getByTestId("bulk-accept").click();
    await expect.poll(() => labelsOf("CVE-2005-2541").length).toBe(1);
    expect(labelsOf("CVE-2005-2541")[0]).toMatchObject({ subject: images.deb.name, package: "pkg:deb/debian/tar", verdict: "fp", justification: "fix-installed" });
    // and deb-npm, decided, takes gzip and babel off the queue with it
    await expect(unlabeled(page)).toHaveCount(7);
    await expect(finding(page, "CVE-2026-41992")).toHaveCount(0);

    // deb has gzip left and npm has babel, one each, which is what deb-npm allows
    await page.getByTestId("tabs").getByRole("tab", { name: /Gates/ }).click();
    await expect(gateRow(page, "deb-npm")).toHaveAttribute("data-state", "pass");
    await expect(gateRow(page, "deb-java")).toHaveAttribute("data-state", "fail");
    // open is unlabeled or unclear: 7 unlabeled and vc5p's two unclear rows
    await expect(gateRow(page, "deb-java").getByTestId("gate-unlabeled")).toHaveText(/^9 open/);
  });

  test("Label as TP on one finding writes a tp label", async ({ page }) => {
    // the image's name has util-linux in it too, and the binary packages name it as upstream
    await openUnlabeled(page, "debian/util-linux@");
    await expect(unlabeled(page)).toHaveCount(1);
    await select(page, "CVE-2026-3184");
    await page.getByTestId("label-as").selectOption("tp:");
    await expect.poll(() => labelsOf("CVE-2026-3184").map((l) => `${l.subject} ${l.package} ${l.verdict}`)).toEqual([`${images.deb.name} pkg:deb/debian/util-linux tp`]);
  });

  test("Label as FP with a reason on both tar findings labels them both", async ({ page }) => {
    await openUnlabeled(page, "debian/tar@");
    await expect(unlabeled(page)).toHaveCount(2);
    await page.getByTestId("unlabeled-table").getByRole("checkbox", { name: "Select every row shown" }).check();
    await page.getByTestId("label-as").selectOption("fp:fix-installed");
    await expect.poll(() => labelsOf("CVE-2026-18508").length).toBe(1);
    await expect.poll(() => labelsOf("CVE-2005-2541").length).toBe(1);
    for (const v of ["CVE-2026-18508", "CVE-2005-2541"]) expect(labelsOf(v)[0]).toMatchObject({ verdict: "fp", justification: "fix-installed" });
  });

  test("Label as TP on the four util-linux findings labels them all", async ({ page }) => {
    await openUnlabeled(page, "CVE-2026-3184");
    await page.getByTestId("unlabeled-table").getByRole("checkbox", { name: "Select every row shown" }).check();
    await page.getByTestId("label-as").selectOption("tp:");
    await expect.poll(() => labelsOf("CVE-2026-3184").length).toBe(4);
    for (const l of labelsOf("CVE-2026-3184")) expect(l).toMatchObject({ subject: images.deb.name, verdict: "tp" });
    await expect(unlabeled(page)).toHaveCount(0);
    await page.getByTestId("tabs").getByRole("tab", { name: /Gates/ }).click();
    await expect(gateRow(page, "deb-java").getByTestId("gate-unlabeled")).toHaveText(/^6 open/);
  });
});
