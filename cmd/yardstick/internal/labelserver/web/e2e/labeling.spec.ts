import { expect, test } from "./fixtures";
import { causeGroup, images, labelsOf, openGate, openGroup, pick, rows, tarGroup, verdictButton } from "./helpers";

// the four util-linux rows are the group to walk: several rows, no labels, no hand-made state
async function openUtilLinux(page: import("@playwright/test").Page) {
  await openGate(page);
  await openGroup(page, causeGroup(page));
  await expect(page.getByTestId("tile-position")).toHaveAttribute("data-total", "4");
}

test.describe("a label from the tile", () => {
  test("tp by key writes the label, updates the verdict anchor and moves on", async ({ page }) => {
    await openUtilLinux(page);
    const first = (await page.getByTestId("tile").getAttribute("data-row"))!;
    expect(rows.utilLinux).toContain(first);
    await expect(page.getByTestId("tile")).toHaveAttribute("data-verdict", "unlabeled");

    await page.keyboard.press("t");

    await expect.poll(() => labelsOf("CVE-2026-3184").length).toBe(1);
    const [l] = labelsOf("CVE-2026-3184");
    expect(l).toMatchObject({ subject: images.deb.name, verdict: "tp" });
    await expect(page.getByTestId("receipt")).toBeVisible();
    await expect(page.getByTestId("receipt")).toHaveAttribute("data-moved", "true");
    // the tile is on the next unlabeled match, which is another row of the group
    await expect(page.getByTestId("tile")).not.toHaveAttribute("data-row", first);
    await expect(page.getByTestId("tile")).toHaveAttribute("data-verdict", "unlabeled");
    expect(rows.utilLinux).toContain((await page.getByTestId("tile").getAttribute("data-row"))!);
  });

  test("tp by button writes the same label", async ({ page }) => {
    await openUtilLinux(page);
    await verdictButton(page, "tp").click();
    await expect.poll(() => labelsOf("CVE-2026-3184").length).toBe(1);
    expect(labelsOf("CVE-2026-3184")[0]).toMatchObject({ verdict: "tp" });
  });

  test("z returns to the match just labeled, which shows its verdict", async ({ page }) => {
    await openUtilLinux(page);
    const first = (await page.getByTestId("tile").getAttribute("data-row"))!;
    await page.keyboard.press("t");
    await expect(page.getByTestId("tile")).not.toHaveAttribute("data-row", first);

    await page.keyboard.press("z");

    await expect(page.getByTestId("tile")).toHaveAttribute("data-row", first);
    await expect(page.getByTestId("tile")).toHaveAttribute("data-verdict", "tp");
    await expect(verdictButton(page, "tp")).toHaveAttribute("data-current", "true");
    await expect(page.getByTestId("label-line")).toHaveAttribute("data-verdict", "tp");
  });

  test("fp without a justification writes nothing and asks for one", async ({ page }) => {
    await openUtilLinux(page);
    await page.keyboard.press("f");
    await expect(page.getByTestId("toast")).toContainText("needs a reason");
    await expect(page.getByTestId("justification-picker")).toBeFocused();
    await verdictButton(page, "fp").click();
    await expect(page.getByTestId("toast")).toContainText("needs a reason");
    expect(labelsOf("CVE-2026-3184")).toEqual([]);
    await expect(page.getByTestId("tile")).toHaveAttribute("data-verdict", "unlabeled");
  });

  test("picking an fp justification writes the fp label", async ({ page }) => {
    await openUtilLinux(page);
    const row = (await page.getByTestId("tile").getAttribute("data-row"))!;
    await pick(page, "fp:fix-installed");
    await expect.poll(() => labelsOf("CVE-2026-3184").length).toBe(1);
    expect(labelsOf("CVE-2026-3184")[0]).toMatchObject({ verdict: "fp", justification: "fix-installed" });
    await expect(page.getByTestId("tile")).not.toHaveAttribute("data-row", row);
    await page.keyboard.press("z");
    await expect(page.getByTestId("tile")).toHaveAttribute("data-row", row);
    await expect(page.getByTestId("tile")).toHaveAttribute("data-verdict", "fp");
  });

  test("unclear without a justification writes nothing, with one it writes unclear", async ({ page }) => {
    await openUtilLinux(page);
    const row = (await page.getByTestId("tile").getAttribute("data-row"))!;
    await page.keyboard.press("u");
    await expect(page.getByTestId("toast")).toContainText("needs a reason");
    expect(labelsOf("CVE-2026-3184")).toEqual([]);

    await pick(page, "unclear:not-assessed");
    await expect.poll(() => labelsOf("CVE-2026-3184").length).toBe(1);
    expect(labelsOf("CVE-2026-3184")[0]).toMatchObject({ verdict: "unclear", justification: "not-assessed" });
    await expect(page.getByTestId("tile")).not.toHaveAttribute("data-row", row);
    await page.keyboard.press("z");
    await expect(page.getByTestId("tile")).toHaveAttribute("data-row", row);
    await expect(page.getByTestId("tile")).toHaveAttribute("data-verdict", "unclear");
  });

  test("a note written with n lands on the label", async ({ page }) => {
    await openUtilLinux(page);
    const row = (await page.getByTestId("tile").getAttribute("data-row"))!;
    await page.keyboard.press("n");
    await expect(page.getByTestId("note-input")).toBeFocused();
    await page.keyboard.type("checked against the debian tracker");
    // typing in the field does not trigger the label keys; the button does
    await verdictButton(page, "tp").click();
    await expect.poll(() => labelsOf("CVE-2026-3184").length).toBe(1);
    expect(labelsOf("CVE-2026-3184")[0].notes).toEqual(["checked against the debian tracker"]);
    await expect(page.getByTestId("tile")).not.toHaveAttribute("data-row", row);
    await page.keyboard.press("z");
    await expect(page.getByTestId("tile")).toHaveAttribute("data-row", row);
    await expect(page.getByTestId("label-note")).toContainText("checked against the debian tracker");
  });

  test("with the advance switch off the tile stays on the match it labeled", async ({ page }) => {
    await openUtilLinux(page);
    const row = (await page.getByTestId("tile").getAttribute("data-row"))!;
    await page.getByTestId("advance-checkbox").uncheck();
    await page.keyboard.press("t");
    await expect.poll(() => labelsOf("CVE-2026-3184").length).toBe(1);
    await expect(page.getByTestId("tile")).toHaveAttribute("data-row", row);
    await expect(page.getByTestId("tile")).toHaveAttribute("data-verdict", "tp");
  });

  test("labeling every match of a group says the group is done and offers the next one", async ({ page }) => {
    await openUtilLinux(page);
    for (let i = 0; i < 4; i++) {
      const row = await page.getByTestId("tile").getAttribute("data-row");
      await page.keyboard.press("t");
      await expect.poll(() => labelsOf("CVE-2026-3184").length).toBe(i + 1);
      // the next key press needs the tile to be on the next match
      if (i < 3) await expect(page.getByTestId("tile")).not.toHaveAttribute("data-row", row!);
    }
    await expect(page.getByTestId("group-done")).toBeVisible();
    await expect(page.getByTestId("tile-position")).toContainText("labeled");
    await expect(page.getByTestId("back-to-last")).toBeVisible();
    await expect(page.getByTestId("next-group")).toBeVisible();
    await page.getByTestId("next-group").click();
    await expect(page.getByTestId("tile")).toBeVisible();
  });

  test("the hand label on the tar row without a hint lands as fp", async ({ page }) => {
    await openGate(page);
    await openGroup(page, tarGroup(page, false));
    await expect(page.getByTestId("tile")).toHaveAttribute("data-row", rows.tarHand);
    await expect(page.getByTestId("hint-card")).toHaveAttribute("data-status", "none");
    await pick(page, "fp:fix-installed");
    await expect.poll(() => labelsOf("CVE-2026-18508").length).toBe(1);
    expect(labelsOf("CVE-2026-18508")[0]).toMatchObject({ subject: images.deb.name, package: "pkg:deb/debian/tar", verdict: "fp", justification: "fix-installed" });
  });
});
