import { expect, test } from "./fixtures";
import { checkPage, checkRow, findingPage, gatePage, images, onFinding, openFinding, railImage, rows, tableRow, tableRows } from "./helpers";
import type { Page } from "@playwright/test";

const allImages = (page: Page) => page.getByTestId("image-rail").locator("[data-testid=rail-image][data-slug='']");
const f1 = "f1NotWorse";

test.describe("moving around", () => {
  test("j walks to the end of the list and stops there", async ({ page }) => {
    await page.goto(`${findingPage(rows.vc5pA, f1)}?image=${images.java.slug}`);
    const pager = page.getByTestId("pager");
    await expect(pager).toHaveText(/3 of 4/);
    await page.keyboard.press("j");
    await onFinding(page, rows.vc5pB);
    await expect(pager).toHaveText(/4 of 4/);
    await page.keyboard.press("j");
    await expect(page.getByTestId("toast")).toContainText("last one in this list");
    await expect(page).toHaveURL(new RegExp(`/${rows.vc5pB}\\?image=`));
  });

  test("the finding is in the URL, so a reload lands on it", async ({ page }) => {
    await openFinding(page, rows.jfhA, f1);
    await page.keyboard.press("j");
    await onFinding(page, rows.jfhB);
    await page.reload();
    await onFinding(page, rows.jfhB);
    await expect(page.getByTestId("title")).toHaveText("GHSA-jfh8-c2jp-5v3q");
  });

  test("the breadcrumb goes back up a level at a time", async ({ page }) => {
    await openFinding(page, rows.tarDropped);
    const crumb = (name: string) => page.getByTestId("breadcrumb").getByRole("link", { name, exact: true });
    await crumb("unlabeledChangesAtMost").click();
    await expect(page).toHaveURL(new RegExp(`${checkPage("unlabeledChangesAtMost")}$`));
    await expect(tableRows(page, "check-table")).toHaveCount(10);
    await crumb("deb-java").click();
    await expect(page).toHaveURL(new RegExp(`${gatePage()}$`));
    await expect(page.getByTestId("check-row")).toHaveCount(5);
    await crumb("Gates").click();
    await expect(page).toHaveURL(/\/ui\/gates\/$/);
    await expect(page.getByTestId("gate-row")).toHaveCount(2);
  });

  test("the browser's back and forward buttons walk the levels", async ({ page }) => {
    await page.goto(gatePage());
    await checkRow(page, "unlabeledChangesAtMost").click();
    await tableRow(page, "check-table", rows.tarDropped).click();
    await onFinding(page, rows.tarDropped);
    await page.goBack();
    await expect(page).toHaveURL(new RegExp(`${checkPage("unlabeledChangesAtMost")}$`));
    await expect(tableRows(page, "check-table")).toHaveCount(10);
    await page.goBack();
    await expect(page.getByTestId("check-row")).toHaveCount(5);
    await page.goForward();
    await expect(tableRows(page, "check-table")).toHaveCount(10);
    await page.goForward();
    await onFinding(page, rows.tarDropped);
  });
});

test.describe("image scope", () => {
  test("1 and 2 scope the gate to an image, 0 to every image", async ({ page }) => {
    await page.goto(`${gatePage()}findings`);
    await expect(allImages(page)).toHaveAttribute("aria-pressed", "true");
    await expect(tableRows(page, "findings-table")).toHaveCount(12);

    await page.keyboard.press("2");
    await expect(page).toHaveURL(new RegExp(`/findings\\?image=${images.java.slug}$`));
    await expect(railImage(page, "java")).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByTestId("scope-chip")).toContainText(images.java.name);
    await expect(tableRows(page, "findings-table")).toHaveCount(4);
    await expect(page.getByTestId("findings-table").locator("th", { hasText: "Image" })).toHaveCount(0);

    await page.keyboard.press("1");
    await expect(page).toHaveURL(new RegExp(`\\?image=${images.deb.slug}$`));
    await expect(tableRows(page, "findings-table")).toHaveCount(8);

    await page.keyboard.press("0");
    await expect(allImages(page)).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByTestId("scope-chip")).toBeHidden();
    await expect(tableRows(page, "findings-table")).toHaveCount(12);
    expect(page.url()).not.toContain("image=");
  });

  test("the rail and the scope chip scope too, and the tabs keep the image", async ({ page }) => {
    await page.goto(gatePage());
    await railImage(page, "java").click();
    await expect(page).toHaveURL(new RegExp(`\\?image=${images.java.slug}$`));
    await page.getByTestId("tabs").getByRole("tab", { name: /Matches/ }).click();
    await expect(page).toHaveURL(new RegExp(`/findings\\?image=${images.java.slug}$`));
    await expect(tableRows(page, "findings-table")).toHaveCount(4);
    await page.getByTestId("scope-chip").getByRole("button", { name: "Clear image filter" }).click();
    await expect(tableRows(page, "findings-table")).toHaveCount(12);
    await railImage(page, "deb").click();
    await allImages(page).click();
    await expect(allImages(page)).toHaveAttribute("aria-pressed", "true");
    expect(page.url()).not.toContain("image=");
  });

  test("an image the gate doesn't have means every image", async ({ page }) => {
    await page.goto(`${gatePage()}findings?image=nope`);
    await expect(allImages(page)).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByTestId("scope-chip")).toBeHidden();
    await expect(tableRows(page, "findings-table")).toHaveCount(12);
  });
});

test.describe("the scan map", () => {
  test("draws added and dropped, with a block per source package", async ({ page }) => {
    await page.goto(`${gatePage()}map`);
    await expect(page.locator("[data-testid=dir-region][data-dir=added]")).toHaveAttribute("data-count", "8");
    await expect(page.locator("[data-testid=dir-region][data-dir=dropped]")).toHaveAttribute("data-count", "4");
    await expect(page.locator("[data-testid=block][data-package=util-linux]")).toHaveAttribute("data-count", "4");
    await expect(page.locator("[data-testid=block][data-package='org.apache.logging.log4j']")).toHaveAttribute("data-count", "4");
    await expect(page.locator("[data-testid=block][data-package=tar]")).toHaveAttribute("data-count", "3");
    await expect(page.locator("[data-testid=block][data-package=gnutls28]")).toHaveAttribute("data-count", "1");

    // scoped to java, only its four added log4j rows are drawn
    await page.keyboard.press("2");
    await expect(page.getByTestId("dir-region")).toHaveCount(1);
    await expect(page.locator("[data-testid=dir-region][data-dir=added]")).toHaveAttribute("data-count", "4");
  });
});

test.describe("old links", () => {
  test("the /ui/map/ pages land on their new screens", async ({ page }) => {
    await page.goto("/");
    await expect(page).toHaveURL(/\/ui\/gates\/$/);
    await page.goto("/ui/map/gates/?gate=deb-npm");
    await expect(page).toHaveURL(/\/ui\/gates\/deb-npm\/$/);
    await expect(page.getByTestId("check-row")).toHaveCount(2);
    await page.goto(`/ui/map/gates/deb-java/delta?image=${images.java.slug}`);
    await expect(page).toHaveURL(new RegExp(`/ui/gates/deb-java/map\\?image=${images.java.slug}$`));
    await expect(page.getByTestId("treemap")).toBeVisible();
    await page.goto(`/ui/map/gates/deb-java/check/${f1}/fails#row=${rows.jfhA}`);
    // the browser keeps a fragment across a redirect; the check screen ignores it
    await expect(page).toHaveURL(new RegExp(`${checkPage(f1)}(#.*)?$`));
    await expect(tableRows(page, "check-table")).toHaveCount(10);
  });
});
