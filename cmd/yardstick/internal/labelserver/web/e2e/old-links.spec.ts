import { expect, test } from "./fixtures";
import { images, railImage, tableRows } from "./helpers";

// the old map UI's URLs (server.go redirectOldMap). navigation.spec.ts loads the common ones in the
// page; this checks each shape's answer, with maxRedirects 0 so the 302 and its location are seen.
const old = "/ui/map/gates/", jfh = "GHSA-jfh8-c2jp-5v3q";

const redirects: [string, string][] = [
  [`${old}`, "/ui/gates/"],
  [`${old}deb-java/`, "/ui/gates/deb-java/"],
  [`${old}deb-java/delta/added/unexplained`, "/ui/gates/deb-java/map"],
  [`${old}deb-java/delta/added/unexplained/all`, "/ui/gates/deb-java/map"],
  // a package block goes to the findings tab filtered to it: the image stays, other params go
  [`${old}deb-java/delta/dropped/unexplained/tar?image=x&foo=1`, "/ui/gates/deb-java/findings?image=x&pkg=tar"],
  [`${old}deb-npm/delta/dropped/unexplained/%40babel%2Ftraverse`, "/ui/gates/deb-npm/findings?pkg=%40babel%2Ftraverse"],
  [`${old}deb-java/check/f1NotWorse/cause/${jfh}`, "/ui/gates/deb-java/checks/f1NotWorse"],
  [`${old}deb-java/check/noNewFalsePositives/tier/1/added/util-linux`, "/ui/gates/deb-java/checks/noNewFalsePositives"],
  [`${old}deb-java/check/`, "/ui/gates/deb-java/"],
  [`${old}deb-java/unknown/x`, "/ui/gates/deb-java/"],
  [`${old}?gate=deb-java&image=y`, "/ui/gates/deb-java/?image=y"],
  [`${old}nope/`, "/ui/gates/nope/"],
];

test.describe("old /ui/map/ URLs", () => {
  for (const [from, to] of redirects) {
    test(`${from} redirects to ${to}`, async ({ request }) => {
      const res = await request.get(from, { maxRedirects: 0 });
      expect(res.status()).toBe(302);
      expect(res.headers()["location"]).toBe(to);
    });
  }

  test("a gate that was never scanned answers 404", async ({ request }) => {
    // a request and not a page, since a 404 page load is a console error
    const res = await request.get("/ui/gates/nope/", { maxRedirects: 0 });
    expect(res.status()).toBe(404);
    expect(await res.text()).toContain("no gate nope has been scanned");
  });

  test("a package block lands on the findings tab filtered to the package", async ({ page }) => {
    await page.goto(`${old}deb-java/delta/dropped/unexplained/tar`);
    await expect(page).toHaveURL(/\/ui\/gates\/deb-java\/findings\?pkg=tar$/);
    await expect(page.getByTestId("package-chip")).toBeVisible();
    await expect(tableRows(page, "findings-table")).toHaveCount(3);
  });

  test("a package name with an escaped slash survives the redirect", async ({ page }) => {
    await page.goto(`${old}deb-npm/delta/dropped/unexplained/%40babel%2Ftraverse`);
    await expect(page).toHaveURL(/\/ui\/gates\/deb-npm\/findings\?pkg=%40babel%2Ftraverse$/);
    await expect(page.getByTestId("package-chip")).toContainText("package: @babel/traverse");
    await expect(tableRows(page, "findings-table")).toHaveCount(1);
  });

  test("?gate= and ?image= open that gate scoped to the image", async ({ page }) => {
    await page.goto(`${old}?gate=deb-java&image=${images.java.slug}`);
    await expect(page).toHaveURL(new RegExp(`/ui/gates/deb-java/\\?image=${images.java.slug}$`));
    await expect(railImage(page, "java")).toHaveAttribute("aria-pressed", "true");
    await expect(railImage(page, "deb")).toHaveAttribute("aria-pressed", "false");
  });
});
