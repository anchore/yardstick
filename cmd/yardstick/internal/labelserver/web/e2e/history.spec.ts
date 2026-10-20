import type { Page } from "@playwright/test";
import { expect, test } from "./fixtures";
import { label, labelsOf, onFinding, openFinding, rows } from "./helpers";

// /ui/history on the seed's four labels: libgnutls (global fp), libc6 (tp), tar CVE-2026-5704 (fp
// with a note) and log4j's vc5p (unclear with a note). They all carry lastUpdated 2026-10-19T22:24:43Z,
// so the day group depends on the browser's time zone, and they predate the server, so these open
// history with since=all (history-undo.spec.ts covers the default).
test.use({ timezoneId: "UTC" });

const table = (page: Page) => page.getByTestId("history-table");
const lines = (page: Page) => table(page).locator("tbody tr[data-id]");
const chip = (page: Page, v: string) => page.locator(`[data-chip=${v}]`);
const search = (page: Page) => page.getByRole("searchbox", { name: "Filter history" });
const line = (page: Page, vuln: string) => lines(page).filter({ hasText: vuln });

async function openHistory(page: Page, query = "?since=all") {
  await page.goto(`/ui/history${query}`);
  await expect(page.getByTestId("page-info")).toBeVisible();
}

test.describe("filters", () => {
  test("the chips split the four seeded labels by verdict", async ({ page }) => {
    await openHistory(page);
    await expect(lines(page)).toHaveCount(4);
    await expect(page.getByTestId("page-info")).toHaveText("1–4 of 4");
    await expect(chip(page, "all")).toHaveAttribute("aria-pressed", "true");
    for (const [v, n] of [["tp", 1], ["fp", 2], ["unclear", 1]] as const) {
      await chip(page, v).click();
      await expect(chip(page, v)).toHaveAttribute("aria-pressed", "true");
      await expect(lines(page)).toHaveCount(n);
      await expect(page.getByTestId("page-info")).toHaveText(`1–${n} of ${n}`);
    }
    await chip(page, "tp").click();
    await expect(line(page, "CVE-2026-5450")).toHaveCount(1);
  });

  test("the text filter matches notes, images and reasons", async ({ page }) => {
    await openHistory(page);
    const find = search(page);
    // a note
    await find.fill("JNDI");
    await expect(lines(page)).toHaveCount(1);
    await expect(line(page, "GHSA-vc5p-v9hr-52mj")).toHaveCount(1);
    // an image: the deb image holds libc6 and tar, the global label has none
    await find.fill("vulnerabilities-debian");
    await expect(lines(page)).toHaveCount(2);
    // a reason: the two fp labels
    await find.fill("fix-installed");
    await expect(lines(page)).toHaveCount(2);
    // together with a verdict
    await chip(page, "tp").click();
    await expect(lines(page)).toHaveCount(0);
    await chip(page, "fp").click();
    await expect(lines(page)).toHaveCount(2);
    await find.fill("tar");
    await expect(lines(page)).toHaveCount(1);
    await expect(line(page, "CVE-2026-5704")).toHaveCount(1);
  });

  test("no match leaves an empty table and a zero count", async ({ page }) => {
    await openHistory(page);
    await search(page).fill("no-such-label");
    await expect(lines(page)).toHaveCount(0);
    await expect(table(page)).toContainText("No labels match.");
    await expect(page.getByTestId("page-info")).toHaveText("0 labels");
    await expect(page.getByTestId("page-next")).toHaveCount(0);
    await expect(page.getByTestId("page-prev")).toHaveCount(0);
  });

  test("filters ride the URL, so a reload keeps them and refills the box", async ({ page }) => {
    await openHistory(page);
    await chip(page, "fp").click();
    await search(page).fill("fix-installed");
    await expect(page).toHaveURL(/\/ui\/history\?verdict=fp&q=fix-installed&since=all$/);
    await expect(lines(page)).toHaveCount(2);
    await page.reload();
    await expect(page.getByTestId("page-info")).toBeVisible();
    await expect(search(page)).toHaveValue("fix-installed");
    await expect(chip(page, "fp")).toHaveAttribute("aria-pressed", "true");
    await expect(lines(page)).toHaveCount(2);

    await openHistory(page, "?verdict=unclear&q=JNDI&since=all");
    await expect(search(page)).toHaveValue("JNDI");
    await expect(lines(page)).toHaveCount(1);
  });
});

test.describe("links", () => {
  test("the global label shows image global and links into both gates", async ({ page }) => {
    await openHistory(page);
    const gnutls = line(page, "CVE-2011-3389");
    await expect(gnutls).toHaveCount(1);
    await expect(gnutls).toContainText("global");
    await expect(gnutls.getByTestId("history-link")).toHaveCount(2);
    for (const gate of ["deb-java", "deb-npm"]) await expect(gnutls.locator(`[data-testid=history-link][data-gate=${gate}]`)).toHaveCount(1);
  });

  test("a label's link opens its finding", async ({ page }) => {
    await openHistory(page);
    // libc6 matches in both scans unchanged, so its finding page loads
    const link = line(page, "CVE-2026-5450").getByTestId("history-link").first();
    const row = await link.getAttribute("data-row");
    expect(row).toBe("cc14c667e8168d2a");
    await link.click();
    await onFinding(page, "cc14c667e8168d2a");
  });

  test("a label on log4j's two jars links to both rows of the gate", async ({ page }) => {
    // accept the jfh8 hint: one label, on both jars
    await openFinding(page, rows.jfhA);
    await page.keyboard.press("a");
    await expect.poll(() => labelsOf("GHSA-jfh8-c2jp-5v3q").length).toBe(1);
    await openHistory(page);
    const links = line(page, "GHSA-jfh8-c2jp-5v3q").getByTestId("history-link");
    await expect(links).toHaveText(["deb-java", "deb-java #2"]);
    expect(await links.evaluateAll((a) => a.map((x) => x.getAttribute("data-gate")))).toEqual(["deb-java", "deb-java"]);
    expect(new Set(await links.evaluateAll((a) => a.map((x) => x.getAttribute("data-row"))))).toEqual(new Set([rows.jfhA, rows.jfhB]));
  });
});

test.describe("day groups", () => {
  test("the seeded labels sit in one group, and a new label gets a newer one above it", async ({ page }) => {
    await openHistory(page);
    await expect(page.getByTestId("history-day")).toHaveCount(1);
    await expect(page.getByTestId("history-day")).toHaveAttribute("data-day", "2026-10-19");
    await expect(page.getByTestId("history-day")).toContainText("4 labels");

    // a hand label is stamped with the server's clock
    await openFinding(page, rows.tarHand);
    await label(page, "f", "fix-installed");
    await expect.poll(() => labelsOf("CVE-2026-18508").length).toBe(1);
    await openHistory(page);
    const days = page.getByTestId("history-day");
    await expect(days).toHaveCount(2);
    const keys = await days.evaluateAll((d) => d.map((x) => x.getAttribute("data-day")!));
    expect(keys[1]).toBe("2026-10-19");
    expect(keys[0] > keys[1]).toBe(true);
    await expect(lines(page)).toHaveCount(5);
    await expect(line(page, "CVE-2026-18508")).toHaveCount(1);
  });

  test("the day after the seeded one reads Yesterday", async ({ page }) => {
    await page.clock.setFixedTime("2026-10-20T12:00:00Z");
    await openHistory(page);
    await expect(page.getByTestId("history-day")).toHaveText(/^Yesterday/);
    await page.clock.setFixedTime("2026-10-19T23:00:00Z");
    await openHistory(page);
    await expect(page.getByTestId("history-day")).toHaveText(/^Today/);
  });
});

test.describe("paging", () => {
  // /api/history pages by 50 and the seed has 4 labels, so the first request's real answer is
  // cloned into 120 labels (distinct vulnerabilities, so distinct row ids) and served by offset
  async function pageThrough(page: Page) {
    const asked: string[] = [];
    await page.route("**/api/history?*", async (route) => {
      const url = new URL(route.request().url()), asked0 = new URLSearchParams(url.search);
      asked.push(url.search);
      // the seed's own first page is the template, whatever offset was asked
      url.searchParams.set("offset", "0");
      url.searchParams.delete("verdict");
      url.searchParams.delete("q");
      url.searchParams.delete("since");
      try {
        const res = await route.fetch({ url: url.toString() }), body = await res.json();
        const real = body.labels;
        const all = Array.from({ length: 120 }, (_, i) => {
          const l = structuredClone(real[i % real.length]);
          l.label.vulnerability = `CVE-2099-${String(i).padStart(4, "0")}`;
          return l;
        });
        const offset = Number(asked0.get("offset")), limit = Number(asked0.get("limit"));
        await route.fulfill({ response: res, json: { ...body, total: 120, labels: all.slice(offset, offset + limit) } });
      } catch {
        // the app bar's count reads here too, and a goto can leave its read behind: nothing waits on it
      }
    });
    return asked;
  }

  test("pages by 50: next and prev follow the URL and the request offset", async ({ page }) => {
    const asked = await pageThrough(page);
    await page.goto("/ui/history");
    await expect(page.getByTestId("page-info")).toHaveText("1–50 of 120");
    await expect(lines(page)).toHaveCount(50);
    await expect(page.getByTestId("page-prev")).toHaveCount(0);

    await page.getByTestId("page-next").click();
    await expect(page).toHaveURL(/\/ui\/history\?page=2$/);
    await expect(page.getByTestId("page-info")).toHaveText("51–100 of 120");
    await expect(page.getByTestId("page-prev")).toBeVisible();
    await expect(page.getByTestId("page-next")).toBeVisible();
    expect(asked).toContain("?since=start&offset=50&limit=50");

    await page.getByTestId("page-next").click();
    await expect(page).toHaveURL(/\/ui\/history\?page=3$/);
    await expect(page.getByTestId("page-info")).toHaveText("101–120 of 120");
    await expect(lines(page)).toHaveCount(20);
    await expect(page.getByTestId("page-next")).toHaveCount(0);
    expect(asked).toContain("?since=start&offset=100&limit=50");

    await page.getByTestId("page-prev").click();
    await expect(page.getByTestId("page-info")).toHaveText("51–100 of 120");
  });

  test("a chip on page 2 goes back to page 1", async ({ page }) => {
    await pageThrough(page);
    await page.goto("/ui/history?page=2");
    await expect(page.getByTestId("page-info")).toHaveText("51–100 of 120");
    await chip(page, "fp").click();
    await expect(page).toHaveURL(/\/ui\/history\?verdict=fp$/);
    await expect(page.getByTestId("page-info")).toHaveText("1–50 of 120");
  });
});

test("j, k and Enter walk the table and open the label's finding", async ({ page }) => {
  await openHistory(page);
  // the cursor starts above the first row: j lands on it, so the second j and k come back to it
  const first = lines(page).first().getByTestId("history-link").first();
  const [gate, row] = [await first.getAttribute("data-gate"), await first.getAttribute("data-row")];
  await page.keyboard.press("j");
  await page.keyboard.press("j");
  await page.keyboard.press("k");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(new RegExp(`/ui/gates/${gate}/findings/${row}$`));
  await onFinding(page, row!);
});
