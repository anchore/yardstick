import { expect, test } from "./fixtures";
import { gatesPage, labelsOf, rows } from "./helpers";
import type { Page } from "@playwright/test";

const card = (page: Page, gate: string) => page.locator(`[data-testid=gate-card][data-gate=${gate}]`);
const fgroup = (page: Page, key: string) => page.locator(`[data-testid=finding-group][data-group="${key}"]`);
const finding = (page: Page, row: string, gate?: string) =>
  page.locator(`[data-testid=finding][data-row="${row}"]${gate ? `[data-gate="${gate}"]` : ""}`);

async function openGates(page: Page) {
  await page.goto(gatesPage);
  await expect(page.getByTestId("gate-card")).toHaveCount(2);
}

test.describe("every gate", () => {
  test("shows both gates with their outcomes and open counts", async ({ page }) => {
    await openGates(page);
    await expect(card(page, "deb-java")).toHaveAttribute("data-state", "fail");
    await expect(card(page, "deb-java")).toHaveAttribute("data-open", "10");
    await expect(card(page, "deb-java").getByTestId("gate-outcome")).toHaveAttribute("data-state", "fail");
    await expect(card(page, "deb-npm")).toHaveAttribute("data-state", "undecided");
    await expect(card(page, "deb-npm")).toHaveAttribute("data-open", "3");
    await expect(card(page, "deb-npm").getByTestId("gate-outcome")).toHaveAttribute("data-state", "undecided");
  });

  test("each card lists its checks with their states", async ({ page }) => {
    await openGates(page);
    const java = card(page, "deb-java").getByTestId("gate-check");
    await expect(java).toHaveCount(4);
    await expect(card(page, "deb-java").locator("[data-testid=gate-check][data-check=f1NotWorse]")).toHaveAttribute("data-state", "fail");
    await expect(card(page, "deb-java").locator("[data-testid=gate-check][data-check=unjudgedChangesAtMost]")).toHaveAttribute("data-state", "undecided");
    await expect(card(page, "deb-npm").getByTestId("gate-check")).toHaveCount(1);
    await expect(card(page, "deb-npm").getByTestId("gate-check")).toHaveAttribute("data-state", "undecided");
  });

  test("a board link goes into the gate", async ({ page }) => {
    await openGates(page);
    const link = page.locator("[data-testid=gate-board-link][data-gate=deb-npm]");
    await expect(link).toHaveAttribute("href", /\/ui\/map\/gates\/deb-npm\/$/);
    await link.click();
    await expect(page).toHaveURL(/\/ui\/map\/gates\/deb-npm\/$/);
    await expect(page.getByTestId("board")).toBeVisible();
    await expect(page.getByTestId("gate-outcome")).toHaveAttribute("data-state", "undecided");
  });

  test("lists the ten open findings in groups, by how many gates one label decides", async ({ page }) => {
    await openGates(page);
    await expect(page.getByTestId("list-head")).toHaveAttribute("data-gate", "");
    const counts = await page.getByTestId("finding-group").evaluateAll((els) => els.map((e) => Number(e.getAttribute("data-count"))));
    expect(counts.reduce((a, b) => a + b, 0)).toBe(10);
    await expect(page.locator("[data-testid=finding-group][data-package=util-linux]")).toHaveAttribute("data-count", "4");

    // the tar finding that is in both gates comes first: it is the one that flips deb-npm
    const tar = fgroup(page, "p:deb|tar");
    await expect(tar).toHaveAttribute("data-count", "2");
    await expect(tar.locator("[data-testid=gate-chip][data-gate=deb-java]")).toHaveAttribute("data-bears", "2");
    await expect(tar.locator("[data-testid=gate-chip][data-gate=deb-npm]")).toHaveAttribute("data-bears", "1");
    await expect(tar.locator("[data-testid=gate-chip][data-gate=deb-npm]")).toHaveAttribute("data-flips", "1");
  });

  test("an open group shows its findings with what a label would do to each gate", async ({ page }) => {
    await openGates(page);
    const tar = fgroup(page, "p:deb|tar");
    await tar.getByTestId("group-head").click();
    await expect(tar).toHaveAttribute("data-open", "true");
    await expect(tar.getByTestId("finding")).toHaveCount(2);

    const shared = finding(page, rows.tarDropped, "deb-java");
    await expect(shared).toHaveAttribute("data-vulnerability", "CVE-2005-2541");
    await expect(shared).toHaveAttribute("data-image", "deb");
    await expect(shared.getByTestId("hint-chip")).toHaveAttribute("data-verdict", "fp");
    // labeling it ends deb-npm either way, and does nothing to deb-java
    const npm = shared.locator("[data-testid=gate-effect][data-gate=deb-npm]");
    await expect(npm).toHaveAttribute("data-if-tp", "pass");
    await expect(npm).toHaveAttribute("data-if-fp", "pass");
    await expect(shared.locator("[data-testid=gate-effect][data-gate=deb-java]")).toHaveAttribute("data-if-tp", "fail");
    await expect(finding(page, rows.tarHand).getByTestId("hint-chip")).toHaveCount(0);
  });

  test("a gate card filters the findings to that gate, and every gate clears it", async ({ page }) => {
    await openGates(page);
    await card(page, "deb-npm").click();
    await expect(card(page, "deb-npm")).toHaveAttribute("data-active", "true");
    await expect(page.getByTestId("list-head")).toHaveAttribute("data-gate", "deb-npm");
    await expect(page).toHaveURL(/gate=deb-npm/);
    const counts = await page.getByTestId("finding-group").evaluateAll((els) => els.map((e) => Number(e.getAttribute("data-count"))));
    expect(counts.reduce((a, b) => a + b, 0)).toBe(3);
    await expect(page.locator("[data-testid=finding-group][data-package=util-linux]")).toHaveCount(0);

    await page.getByTestId("clear-gate-filter").click();
    await expect(page.getByTestId("list-head")).toHaveAttribute("data-gate", "");
    await expect(card(page, "deb-npm")).toHaveAttribute("data-active", "false");
  });

  test("?gate= in the URL filters the page", async ({ page }) => {
    await page.goto(`${gatesPage}?gate=deb-java`);
    await expect(page.getByTestId("list-head")).toHaveAttribute("data-gate", "deb-java");
    await expect(page.locator("[data-testid=finding-group][data-package=util-linux]")).toBeVisible();
  });
});

test.describe("labeling from every gate", () => {
  test("accepting the tar hint labels it and decides deb-npm without touching deb-java's outcome", async ({ page }) => {
    await openGates(page);
    const tar = fgroup(page, "p:deb|tar");
    await tar.getByTestId("group-head").click();
    await finding(page, rows.tarDropped, "deb-java").getByTestId("accept-button").click();

    await expect.poll(() => labelsOf("CVE-2005-2541").length).toBe(1);
    expect(labelsOf("CVE-2005-2541")[0]).toMatchObject({ subject: "deb", package: "pkg:deb/debian/tar", verdict: "fp", justification: "fix-installed" });
    // deb has gzip left and npm has babel, one each, which is what deb-npm allows
    await expect(card(page, "deb-npm")).toHaveAttribute("data-state", "pass");
    await expect(card(page, "deb-java")).toHaveAttribute("data-open", "9");
    await expect(card(page, "deb-java")).toHaveAttribute("data-state", "fail");
  });

  test("TP on one finding writes a tp label", async ({ page }) => {
    await openGates(page);
    const cause = page.locator("[data-testid=finding-group][data-package=util-linux]");
    await cause.getByTestId("group-head").click();
    await finding(page, rows.utilLinux[0]).getByTestId("label-button").click();
    await expect.poll(() => labelsOf("CVE-2026-3184").length).toBe(1);
    expect(labelsOf("CVE-2026-3184")[0]).toMatchObject({ subject: "deb", verdict: "tp" });
  });

  test("FP with a reason on a group labels all its findings", async ({ page }) => {
    await openGates(page);
    const tar = fgroup(page, "p:deb|tar");
    await tar.getByTestId("group-head").click();
    await tar.locator("[data-testid=actions][data-scope=group] [data-testid=label-select][data-verdict=fp]").selectOption({ value: "fix-installed" });
    await expect.poll(() => labelsOf("CVE-2026-18508").length).toBe(1);
    await expect.poll(() => labelsOf("CVE-2005-2541").length).toBe(1);
    for (const v of ["CVE-2026-18508", "CVE-2005-2541"]) expect(labelsOf(v)[0]).toMatchObject({ verdict: "fp", justification: "fix-installed" });
  });

  test("TP on the util-linux group labels its four findings", async ({ page }) => {
    await openGates(page);
    const cause = page.locator("[data-testid=finding-group][data-package=util-linux]");
    await cause.locator("[data-testid=actions][data-scope=group] [data-testid=label-button]").click();
    await expect.poll(() => labelsOf("CVE-2026-3184").length).toBe(4);
    for (const l of labelsOf("CVE-2026-3184")) expect(l).toMatchObject({ subject: "deb", verdict: "tp" });
    await expect(card(page, "deb-java")).toHaveAttribute("data-open", "6");
  });
});
