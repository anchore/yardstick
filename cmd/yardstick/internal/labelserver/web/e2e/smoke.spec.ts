import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { expect, test, workspace } from "./fixtures";

// labelOf is the verdict of the label on disk for a vulnerability, if there is one
function labelOf(vuln: string): string | undefined {
  const claims = join(workspace, "claims");
  for (const f of readdirSync(claims, { recursive: true, encoding: "utf8" })) {
    // the deb image's labels, not the global ones
    if (!f.includes("yardstick-fixture-deb") || !f.endsWith("deb.json")) continue;
    const doc = JSON.parse(readFileSync(join(claims, f), "utf8"));
    return doc.labels?.find((l: { vulnerability: string }) => l.vulnerability === vuln)?.verdict;
  }
}

test("a finding labeled from the gate board lands in the claims", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("unjudgedChangesAtMost")).toBeVisible();

  // tar's CVE-2005-2541 is a change the candidate drops in deb-java, the gate opened first
  await page.getByRole("button", { name: /tar · CVE-2005-2541/ }).click();
  await expect(page.getByRole("button", { name: "← gate board" })).toBeVisible();
  await expect(page.getByText("1 of 1", { exact: true })).toBeVisible();

  await page.keyboard.press("t");
  await expect.poll(() => labelOf("CVE-2005-2541")).toBe("tp");
});
