import { expect, test } from "./fixtures";

// /ui/gates/ is the four-level UI taking over from /ui/map/; until its screens land, the component
// kit is the page with something on it

test("the component kit's image rail filters by number key, collapses to a dropdown and back", async ({ page }) => {
  await page.goto("/ui/gates/_kit");
  const rail = page.getByTestId("image-rail"), table = page.getByTestId("kit-table");
  await expect(rail).toBeVisible();
  await expect(table.locator("tbody tr")).toHaveCount(12);

  await page.keyboard.press("5");
  await expect(page).toHaveURL(/\/ui\/gates\/_kit\?image=grype-quality-golang-d89207b$/);
  await expect(page.getByTestId("scope-chip")).toContainText("grype-quality-golang:d89207b");
  await expect(table.locator("tbody tr")).toHaveCount(3);
  await page.keyboard.press("]");
  await expect(page).toHaveURL(/image=vulnerabilities-package-name-normalization-984794b$/);
  await page.keyboard.press("0");
  await expect(page).toHaveURL(/\/_kit$/);

  await page.getByTestId("rail-collapse").click();
  await expect(rail).toBeHidden();
  await page.getByTestId("image-picker-button").click();
  await page.keyboard.type("cor"); // the dropdown's search box has the focus
  await expect(page.getByRole("option", { name: /^wolfi-base/ })).toBeHidden();
  await page.getByRole("option", { name: /^core/ }).click();
  await expect(page).toHaveURL(/image=core$/);
  // / opens the dropdown when the rail is collapsed, and Esc closes it without leaving the page
  await page.keyboard.press("/");
  await expect(page.getByRole("combobox", { name: "Filter images" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(page).toHaveURL(/\/_kit\?image=core$/);

  // the collapse is the reader's standing choice
  await page.reload();
  await expect(rail).toBeHidden();
  await expect(page.getByTestId("image-picker-button")).toContainText("core");
  await page.getByTestId("rail-expand").click();
  await expect(rail).toBeVisible();
  await expect(rail.locator('[aria-pressed="true"]')).toContainText("core");
});

test("Esc walks up one crumb at a time, but not out of a text field", async ({ page }) => {
  await page.goto("/ui/gates/deb-java/checks/f1NotWorse/0fe9fc814bcd060a?image=core");
  const crumbs = page.getByTestId("breadcrumb");
  // the finding's crumb is its vulnerability ID once the page has the row
  await expect(crumbs).toHaveText(/Gates\s*›\s*deb-java\s*›\s*f1NotWorse\s*›\s*CVE-2005-2541/);

  await page.keyboard.press("Escape");
  await expect(page).toHaveURL(/\/ui\/gates\/deb-java\/checks\/f1NotWorse\?image=core$/);
  await page.keyboard.press("Escape");
  await expect(page).toHaveURL(/\/ui\/gates\/deb-java\/\?image=core$/);
  await expect(page.getByTestId("tabs").getByRole("tab", { name: "Checks" })).toHaveAttribute("aria-selected", "true");

  await page.goto("/ui/gates/_kit");
  await page.getByRole("searchbox", { name: "Filter findings" }).fill("curl");
  await page.keyboard.press("Escape");
  await expect(page).toHaveURL(/\/_kit\?q=curl$/);
  await page.keyboard.press("Escape");
  await expect(page).toHaveURL(/\/ui\/gates\/$/);
  await expect(crumbs).toHaveText("Gates");
});
