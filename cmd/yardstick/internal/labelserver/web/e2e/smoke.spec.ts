import { expect, test } from "./fixtures";
import { labelsOf, openGate } from "./helpers";

test("a finding labeled from the gate board lands in the claims", async ({ page }) => {
  await openGate(page);
  await expect(page.getByText("unjudgedChangesAtMost").first()).toBeVisible();

  // tar's CVE-2005-2541 is a change the candidate drops in deb-java
  await page.getByRole("button", { name: /tar · CVE-2005-2541/ }).click();
  await expect(page.getByRole("button", { name: "← gate board" })).toBeVisible();
  await expect(page.getByText("1 of 1", { exact: true })).toBeVisible();

  await page.keyboard.press("t");
  await expect.poll(() => labelsOf("CVE-2005-2541").map((l) => l.verdict)).toEqual(["tp"]);
});
