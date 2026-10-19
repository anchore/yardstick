import { expect, test } from "./fixtures";
import { causeGroup, check, log4jGroup, openGate, openGroup } from "./helpers";

test.describe("moving around", () => {
  test("j and k walk the group, and stop at its ends", async ({ page }) => {
    await openGate(page);
    await openGroup(page, log4jGroup(page));
    const pos = page.getByTestId("tile-position");
    await expect(pos).toHaveAttribute("data-total", "4");
    await expect(pos).toHaveAttribute("data-index", "1");
    const first = await page.getByTestId("tile").getAttribute("data-row");

    await page.keyboard.press("j");
    await expect(pos).toHaveAttribute("data-index", "2");
    await expect(page.getByTestId("tile")).not.toHaveAttribute("data-row", first!);
    await page.keyboard.press("j");
    await page.keyboard.press("j");
    await expect(pos).toHaveAttribute("data-index", "4");
    await page.keyboard.press("j");
    await expect(page.getByTestId("toast")).toContainText("last one in this group");
    await expect(pos).toHaveAttribute("data-index", "4");

    for (let i = 0; i < 3; i++) await page.keyboard.press("k");
    await expect(pos).toHaveAttribute("data-index", "1");
    await expect(page.getByTestId("tile")).toHaveAttribute("data-row", first!);
    await page.keyboard.press("k");
    await expect(page.getByTestId("toast")).toContainText("first one in this group");
  });

  test("the selected match is in the URL, so a reload lands on it", async ({ page }) => {
    await openGate(page);
    await openGroup(page, log4jGroup(page));
    await page.keyboard.press("j");
    const row = await page.getByTestId("tile").getAttribute("data-row");
    expect(page.url()).toContain(`#row=${row}`);
    await page.reload();
    await expect(page.getByTestId("tile")).toHaveAttribute("data-row", row!);
  });

  test("Esc goes back from the tile to the board", async ({ page }) => {
    await openGate(page);
    await openGroup(page, log4jGroup(page));
    await expect(page.getByTestId("board")).toBeHidden();
    await page.keyboard.press("Escape");
    await expect(page.getByTestId("board")).toBeVisible();
    await expect(page.getByTestId("tile-view")).toBeHidden();
    expect(new URL(page.url()).pathname).toBe("/ui/map/gates/deb-java/");
  });

  test("the breadcrumb goes back to the board, and to the check's panel", async ({ page }) => {
    await openGate(page);
    await openGroup(page, log4jGroup(page));
    const crumbs = page.getByTestId("breadcrumb").getByTestId("crumb");
    await expect(crumbs).toHaveCount(3);
    await expect(crumbs.nth(0)).toHaveAttribute("data-kind", "home");
    await expect(crumbs.nth(1)).toHaveAttribute("data-kind", "check");
    await expect(crumbs.nth(1)).toContainText("unjudgedChangesAtMost");
    await expect(crumbs.nth(2)).toHaveAttribute("data-kind", "here");

    await crumbs.nth(0).click();
    await expect(page.getByTestId("board")).toBeVisible();
    await expect(page.getByTestId("tile-view")).toBeHidden();

    await openGroup(page, log4jGroup(page));
    await page.getByTestId("breadcrumb").locator("[data-kind=check]").click();
    await expect(check(page, "unjudgedChangesAtMost")).toBeVisible();
  });

  test("the browser's back button also leaves the tile", async ({ page }) => {
    await openGate(page);
    await openGroup(page, log4jGroup(page));
    await page.goBack();
    await expect(page.getByTestId("board")).toBeVisible();
  });

  test("a failed check's claim opens on the tile to re-examine", async ({ page }) => {
    await openGate(page);
    await page.getByTestId("failing-claim").first().click();
    await expect(page.getByTestId("tile")).toBeVisible();
    await expect(page.getByTestId("tile")).toHaveAttribute("data-verdict", "fp");
    await expect(page.getByTestId("label-effect")).toContainText("fails on this label");
  });

  test("v jumps to another open match that bears on the gate", async ({ page }) => {
    await openGate(page);
    await openGroup(page, log4jGroup(page));
    const first = await page.getByTestId("tile").getAttribute("data-row");
    await page.keyboard.press("v");
    await expect(page.getByTestId("tile")).not.toHaveAttribute("data-row", first!);
  });
});

test.describe("help and theme", () => {
  test("? opens the keyboard help, ? and Esc close it", async ({ page }) => {
    await openGate(page);
    await expect(page.getByTestId("help")).toBeHidden();
    await page.keyboard.press("?");
    await expect(page.getByTestId("help")).toBeVisible();
    await expect(page.getByTestId("help")).toContainText("Keyboard");
    await page.keyboard.press("Escape");
    await expect(page.getByTestId("help")).toBeHidden();
    await page.keyboard.press("?");
    await expect(page.getByTestId("help")).toBeVisible();
    await page.keyboard.press("?");
    await expect(page.getByTestId("help")).toBeHidden();
  });

  test("the help button opens it and a click outside the card closes it", async ({ page }) => {
    await openGate(page);
    await page.getByTestId("help-button").click();
    await expect(page.getByTestId("help")).toBeVisible();
    await page.getByTestId("help").click({ position: { x: 3, y: 3 } });
    await expect(page.getByTestId("help")).toBeHidden();
  });

  test("keys do nothing while the help is open, but ? and Esc", async ({ page }) => {
    await openGate(page);
    await page.keyboard.press("?");
    await page.keyboard.press("D");
    await expect(page.getByTestId("theme-button")).toHaveText("theme: system");
  });

  test("D cycles the theme, and it survives a reload", async ({ page }) => {
    await openGate(page);
    const html = page.locator("html");
    await expect(page.getByTestId("theme-button")).toHaveText("theme: system");
    await expect(html).not.toHaveAttribute("data-theme", /.+/);

    await page.keyboard.press("D");
    await expect(page.getByTestId("theme-button")).toHaveText("theme: light");
    await expect(html).toHaveAttribute("data-theme", "light");
    await page.keyboard.press("D");
    await expect(html).toHaveAttribute("data-theme", "dark");

    await page.reload();
    await expect(html).toHaveAttribute("data-theme", "dark");
    await expect(page.getByTestId("theme-button")).toHaveText("theme: dark");

    await page.getByTestId("theme-button").click();
    await expect(page.getByTestId("theme-button")).toHaveText("theme: system");
    await expect(html).not.toHaveAttribute("data-theme", /.+/);
    await page.reload();
    await expect(html).not.toHaveAttribute("data-theme", /.+/);
  });
});

test.describe("image scope", () => {
  test("1 and 2 scope to an image, 0 to every image", async ({ page }) => {
    await openGate(page);
    const unjudged = check(page, "unjudgedChangesAtMost");
    await expect(page.getByTestId("image-all")).toHaveAttribute("data-active", "true");
    await expect(unjudged.getByTestId("group-row")).toHaveCount(4);

    await page.keyboard.press("2");
    await expect(page.locator("[data-testid=image][data-subject=java]")).toHaveAttribute("data-active", "true");
    await expect(page.getByTestId("image-all")).toHaveAttribute("data-active", "false");
    await expect(page).toHaveURL(/\?image=java/);
    await expect(unjudged.getByTestId("group-row")).toHaveCount(1);
    await expect(log4jGroup(page)).toBeVisible();
    await expect(page.getByTestId("scope-name")).toContainText("java");

    await page.keyboard.press("1");
    await expect(page.locator("[data-testid=image][data-subject=deb]")).toHaveAttribute("data-active", "true");
    await expect(page).toHaveURL(/\?image=deb/);
    await expect(unjudged.getByTestId("group-row")).toHaveCount(3);
    await expect(log4jGroup(page)).toHaveCount(0);
    await expect(causeGroup(page)).toBeVisible();

    await page.keyboard.press("0");
    await expect(page.getByTestId("image-all")).toHaveAttribute("data-active", "true");
    await expect(unjudged.getByTestId("group-row")).toHaveCount(4);
    expect(page.url()).not.toContain("image=");
  });

  test("the image controls scope too, and clicking the active image clears it", async ({ page }) => {
    await openGate(page);
    const java = page.locator("[data-testid=image][data-subject=java]");
    await java.click();
    await expect(java).toHaveAttribute("data-active", "true");
    await expect(page).toHaveURL(/\?image=java/);
    await java.click();
    await expect(page.getByTestId("image-all")).toHaveAttribute("data-active", "true");
    await page.locator("[data-testid=image][data-subject=deb]").click();
    await page.getByTestId("image-all").click();
    await expect(page.getByTestId("image-all")).toHaveAttribute("data-active", "true");
  });

  test("?image= in the URL scopes the page, and an unknown image means every image", async ({ page }) => {
    await page.goto("/ui/map/gates/deb-java/?image=java");
    await expect(page.locator("[data-testid=image][data-subject=java]")).toHaveAttribute("data-active", "true");
    await expect(page.getByTestId("group-row")).toHaveCount(1);
    await page.goto("/ui/map/gates/deb-java/?image=nope");
    await expect(page.getByTestId("image-all")).toHaveAttribute("data-active", "true");
    await expect(page.getByTestId("group-row")).toHaveCount(4);
  });

  test("a scoped tile only walks that image's matches", async ({ page }) => {
    await page.goto("/ui/map/gates/deb-java/?image=java");
    await openGroup(page, log4jGroup(page));
    await expect(page.getByTestId("tile-position")).toHaveAttribute("data-total", "4");
    await expect(page.getByTestId("tile-image")).toContainText("java");
  });
});

test.describe("the delta map", () => {
  test("the toggle switches between the board and the treemap", async ({ page }) => {
    await openGate(page);
    const toggle = page.getByTestId("gate-view-toggle");
    await expect(toggle).toHaveAttribute("data-goes-to", "map");
    await toggle.click();
    await expect(page.getByTestId("treemap")).toBeVisible();
    await expect(page.getByTestId("board")).toBeHidden();
    await expect(page).toHaveURL(/\/delta$/);
    await expect(page.getByTestId("gate-view-toggle")).toHaveAttribute("data-goes-to", "board");
    // off the board the ribbon draws each check's bar
    await expect(page.getByTestId("check-bar")).toHaveCount(4);
    await page.getByTestId("gate-view-toggle").click();
    await expect(page.getByTestId("board")).toBeVisible();
  });

  test("draws added and dropped, with a block per source package", async ({ page }) => {
    await page.goto("/ui/map/gates/deb-java/delta");
    await expect(page.locator("[data-testid=dir-region][data-dir=added]")).toHaveAttribute("data-count", "8");
    await expect(page.locator("[data-testid=dir-region][data-dir=dropped]")).toHaveAttribute("data-count", "4");
    const util = page.locator("[data-testid=block][data-package=util-linux]");
    await expect(util).toHaveAttribute("data-count", "4");
    await expect(util).toHaveAttribute("data-open", "4");
    const log4j = page.locator("[data-testid=block][data-package='org.apache.logging.log4j']");
    await expect(log4j).toHaveAttribute("data-count", "4");
    await expect(log4j).toHaveAttribute("data-unclear", "2");
    await expect(log4j).toHaveAttribute("data-hinted", "4");
    const tar = page.locator("[data-testid=block][data-package=tar]");
    await expect(tar).toHaveAttribute("data-count", "3");
    await expect(tar).toHaveAttribute("data-fp", "1");
    await expect(page.locator("[data-testid=block][data-package=gnutls28]")).toHaveAttribute("data-fp", "1");
    await expect(page.getByTestId("legend")).toBeVisible();
  });

  test("hovering a block says what it holds", async ({ page }) => {
    await page.goto("/ui/map/gates/deb-java/delta");
    await page.locator("[data-testid=block][data-package=util-linux]").hover();
    await expect(page.getByTestId("hover-line")).toContainText("util-linux");
    await expect(page.getByTestId("hover-line")).toContainText("4 lines");
  });

  test("a block opens its cards, a crumb zooms to its reason, and zooming out goes back", async ({ page }) => {
    await page.goto("/ui/map/gates/deb-java/delta");
    await page.locator("[data-testid=block][data-package=util-linux]").click();
    await expect(page.getByTestId("tile")).toBeVisible();
    await expect(page.getByTestId("tile-position")).toHaveAttribute("data-total", "4");
    await expect(page.getByTestId("tile")).toHaveAttribute("data-package", /.+/);

    await page.getByTestId("breadcrumb").locator("[data-kind=reason]").click();
    await expect(page.getByTestId("zoom-title")).toHaveAttribute("data-dir", "added");
    await expect(page.getByTestId("treemap")).toBeVisible();
    // zoomed to the added direction: dropped is gone
    await expect(page.getByTestId("dir-region")).toHaveCount(0);
    await expect(page.locator("[data-testid=block]")).toHaveCount(2);

    await page.getByTestId("zoom-out").click();
    await expect(page.getByTestId("zoom-title")).toHaveCount(0);
    await expect(page.locator("[data-testid=dir-region]")).toHaveCount(2);
  });

  test("Esc zooms out and then leaves the map", async ({ page }) => {
    await page.goto("/ui/map/gates/deb-java/delta/added/" + encodeURIComponent("unexplained||"));
    await expect(page.getByTestId("zoom-title")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByTestId("zoom-title")).toHaveCount(0);
    await expect(page.getByTestId("treemap")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByTestId("board")).toBeVisible();
  });

  test("label all as cards opens every match of the reason", async ({ page }) => {
    await page.goto("/ui/map/gates/deb-java/delta/added/" + encodeURIComponent("unexplained||"));
    await page.getByTestId("label-all-cards").click();
    await expect(page.getByTestId("tile")).toBeVisible();
    await expect(page.getByTestId("tile-position")).toHaveAttribute("data-total", "8");
  });

  test("labeling on a delta card moves the block's bar", async ({ page }) => {
    await page.goto("/ui/map/gates/deb-java/delta");
    const util = page.locator("[data-testid=block][data-package=util-linux]");
    await util.click();
    await page.keyboard.press("t");
    await expect(page.getByTestId("receipt")).toBeVisible();
    await page.getByTestId("breadcrumb").locator("[data-kind=home]").click();
    await expect(util).toHaveAttribute("data-tp", "1");
    await expect(util).toHaveAttribute("data-open", "3");
  });
});
