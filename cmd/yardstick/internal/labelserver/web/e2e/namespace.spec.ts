import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Page } from "@playwright/test";
import { answersWithError, expect, test, workspace } from "./fixtures";
import { gatePage, openFinding, rows } from "./helpers";

// a namespace the claims vocabulary lacks: the gate says so before research, research on it asks to
// add it in a dialog rather than a toast, and adding it writes vocabulary.yaml and starts the research.
// The seed's vocabulary lists GHSA; each test takes it out, so the babel row (GHSA-67hx-6x53-jw92,
// which names CVE-2023-45133) is in an unlisted namespace.

const vocab = () => join(workspace, "claims", "vocabulary.yaml");
const unlistGHSA = () => writeFileSync(vocab(), readFileSync(vocab(), "utf8").replace("vulnerability-namespaces: [CVE, GHSA]", "vulnerability-namespaces: [CVE]"));
const listed = () => /vulnerability-namespaces: \[CVE, GHSA\]/.test(readFileSync(vocab(), "utf8"));

// research expects the per-gate research route's refusal, which the browser logs as a load error
async function research(page: Page) {
  answersWithError(page, new URL("/api/gates/deb-npm/research", page.url()).href);
  await page.getByTestId("research-button").click();
}

test("research on an unlisted namespace asks to add it, and adding it starts the research", async ({ page }) => {
  unlistGHSA();
  await openFinding(page, rows.babel, null, "deb-npm");
  await research(page);
  const dialog = page.getByTestId("namespace-dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("heading")).toHaveText("GHSA isn't in the claims vocabulary");
  await expect(dialog).toContainText("The one GHSA id in this scan names one vulnerability (GHSA-67hx-6x53-jw92 → CVE-2023-45133), so it looks like a disclosure namespace.");
  await expect(dialog.getByTestId("namespace-file")).toHaveText("Writes claims/vocabulary.yaml; your PR will show the change.");
  // the suggested list is the primary, the other list beside it
  const adds = dialog.getByTestId("namespace-add");
  await expect(adds).toHaveText(["Add as advisory namespace", "Add as disclosure namespace"]);
  await expect(dialog.locator('[data-list="vulnerability-namespaces"]')).not.toHaveAttribute("data-variant", "outline");
  // it stays until answered, unlike a toast
  await page.waitForTimeout(3000);
  await expect(dialog).toBeVisible();

  await dialog.locator('[data-list="vulnerability-namespaces"]').click();
  await expect(dialog).toBeHidden();
  await expect(page.getByTestId("toast")).toContainText("research started");
  expect(listed()).toBe(true);
});

test("cancelling adds nothing and starts nothing", async ({ page }) => {
  unlistGHSA();
  await openFinding(page, rows.babel, null, "deb-npm");
  await research(page);
  await page.getByTestId("namespace-cancel").click();
  await expect(page.getByTestId("namespace-dialog")).toHaveCount(0);
  expect(listed()).toBe(false);
});

test("the gate says so before research, and adds it from there", async ({ page }) => {
  unlistGHSA();
  await page.goto(gatePage("deb-npm"));
  const notice = page.getByTestId("unlisted-namespaces");
  await expect(notice).toContainText("GHSA isn't in the claims vocabulary");
  await expect(notice).toContainText("Writes claims/vocabulary.yaml");
  await notice.locator('[data-list="vulnerability-namespaces"]').click();
  await expect(page.getByTestId("toast")).toHaveText(/^GHSA added as a disclosure namespace in claims\/vocabulary\.yaml/);
  await expect(notice).toHaveCount(0);
  expect(listed()).toBe(true);
});
