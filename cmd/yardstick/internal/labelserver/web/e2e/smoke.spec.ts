import { expect, test } from "./fixtures";
import { labelsOf, onFinding, rows } from "./helpers";

test("a finding labeled from the gate lands in the claims", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("link", { name: /deb-java/ }).click();
  await page.getByRole("link", { name: /unjudgedChangesAtMost/ }).click();

  // tar's CVE-2005-2541 is a change the candidate drops in deb-java
  await page.getByRole("row", { name: /CVE-2005-2541/ }).getByText("CVE-2005-2541").click();
  await onFinding(page, rows.tarDropped);
  await page.keyboard.press("t");
  await page.getByRole("button", { name: /^Save/ }).click();
  await expect.poll(() => labelsOf("CVE-2005-2541").map((l) => l.verdict)).toEqual(["tp"]);
});
