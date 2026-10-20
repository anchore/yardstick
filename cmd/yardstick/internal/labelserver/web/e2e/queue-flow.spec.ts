import { test as base, type Page } from "@playwright/test";
import { expect, test } from "./fixtures";
import { checkPage, claimSet, gatePage, gatesPage, images, label, labelsOf, onFinding, openFinding, rows } from "./helpers";

// the queue's edges: entering with no row, the image and check scopes, a row that isn't open, the
// keys that move without writing, why each row is next, and the three cards. queue.spec.ts walks
// the whole seed; these start from a state set up for the one thing they check.

const card = (page: Page) => page.getByTestId("queue-card");
const cardGate = (page: Page, gate: string) => card(page).locator(`[data-testid=card-gate][data-gate=${gate}]`);
const progress = (page: Page) => page.getByTestId("queue-progress");
const toast = (page: Page) => page.getByTestId("toast");
// whyText is "Why this one is next" without its heading
const whyText = (page: Page) => page.getByTestId("why-next").locator("span");
const queueRow = (row: string, scope?: string) => `/ui/queue/${row}${scope ? `?scope=${scope}` : ""}`;

// reviewAccept accepts hints on /ui/hints: every preselected one, vc5p too, and leaves out the
// vulnerabilities named
async function reviewAccept(page: Page, leaveOut: string[] = []) {
  await page.goto("/ui/hints");
  await expect(page.getByTestId("impact")).toBeVisible();
  const box = (vuln: string) => page.getByTestId("hint-item").filter({ hasText: vuln }).getByTestId("hint-check");
  await box("GHSA-vc5p-v9hr-52mj").check();
  for (const v of leaveOut) await box(v).uncheck();
  await page.getByTestId("accept-hints").click();
  await expect(toast(page)).toContainText("written from");
}

test.describe("entering and leaving", () => {
  test("/ui/queue replaces itself with its first row, so back skips it", async ({ page }) => {
    await page.goto(gatesPage);
    await expect(page.getByTestId("gate-row")).toHaveCount(2);
    await page.goto("/ui/queue");
    await onFinding(page, rows.gzip);
    await expect(page).toHaveURL(new RegExp(`/ui/queue/${rows.gzip}$`));
    await page.goBack();
    await expect(page).toHaveURL(/\/ui\/gates\/$/);
  });

  test("the scope select moves to a gate's queue at its first row", async ({ page }) => {
    await page.goto("/ui/queue");
    await onFinding(page, rows.gzip);
    await page.getByTestId("queue-scope").selectOption("gate:deb-java");
    await onFinding(page, rows.jfhA);
    await expect(page).toHaveURL(new RegExp(`/ui/queue/${rows.jfhA}\\?scope=gate%3Adeb-java$`));
  });

  test("Esc and Exit leave a check's queue for that check", async ({ page }) => {
    const entry = "/ui/queue?scope=gate:deb-java&check=unjudgedChangesAtMost";
    await page.goto(entry);
    await expect(page.getByTestId("label-panel")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page).toHaveURL(new RegExp(`${checkPage("unjudgedChangesAtMost")}$`));

    await page.goto(entry);
    await expect(page.getByTestId("label-panel")).toBeVisible();
    await page.getByTestId("queue-exit").click();
    await expect(page).toHaveURL(new RegExp(`${checkPage("unjudgedChangesAtMost")}$`));
  });

  test("a row that isn't open says so and links to the queue's next row; Esc exits", async ({ page }) => {
    const tar5704 = "6d210210168e93db"; // labeled fp in the seed
    await page.goto(queueRow(tar5704));
    await expect(page.getByTestId("placeholder")).toContainText("This match isn't open in this queue.");
    await expect(page.getByTestId("label-panel")).toHaveCount(0);
    await page.getByTestId("placeholder").getByRole("link", { name: "Start the queue from its next match" }).click();
    await onFinding(page, rows.gzip);

    await page.goto(queueRow(tar5704));
    await expect(page.getByTestId("placeholder")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page).toHaveURL(/\/ui\/gates\/$/);
  });
});

test.describe("image queues", () => {
  test("the java image's queue is its 4 rows, and accepting both hints ends it", async ({ page }) => {
    await page.goto(`/ui/queue?scope=image:${images.java.slug}`);
    await onFinding(page, rows.jfhA);
    await expect(progress(page)).toHaveText("0 of 4 done · 4 left");
    await expect(page.getByTestId("queue-scope")).toHaveValue(`image:${images.java.slug}`);
    await expect(page.getByTestId("queue-scope").locator("option:checked")).toHaveText(`Image: ${images.java.slug}`);

    // one jfh8 label covers both jars
    await page.keyboard.press("a");
    await onFinding(page, rows.vc5pA);
    await expect(progress(page)).toHaveText("2 of 4 done · 2 left");
    await page.keyboard.press("a");
    await expect(card(page)).toHaveAttribute("data-card", "end");
    await expect(page.getByTestId("card-session")).toContainText("2 labels written this session, closing 4 matches: 4 from hints.");
    await page.getByTestId("card-back").click();
    await expect(page).toHaveURL(/\/ui\/gates\/$/);
  });

  test("Esc and Exit leave an image's queue for the gates screen", async ({ page }) => {
    // pinned: UI-RULES says Esc leaves the queue "for where it was entered from", but an image scope
    // carries no gate, so exitRoute (queuelist.ts) sends it to the gates screen even when n was
    // pressed on a gate filtered to the image
    const entry = `${gatePage("deb-java")}?image=${images.java.slug}`;
    await page.goto(entry);
    await expect(page.getByTestId("check-row").first()).toBeVisible();
    await page.keyboard.press("n");
    await onFinding(page, rows.jfhA);
    await expect(page).toHaveURL(new RegExp(`scope=image%3A${images.java.slug}$`));
    await page.keyboard.press("Escape");
    await expect(page).toHaveURL(/\/ui\/gates\/$/);

    await page.goto(`/ui/queue?scope=image:${images.java.slug}`);
    await onFinding(page, rows.jfhA);
    await page.getByTestId("queue-exit").click();
    await expect(page).toHaveURL(/\/ui\/gates\/$/);
  });

  test("the npm image's queue is one row: j and n have nowhere to go", async ({ page }) => {
    await page.goto(`/ui/queue?scope=image:${images.npm.slug}`);
    await onFinding(page, rows.babel);
    await expect(progress(page)).toHaveText("0 of 1 done · 1 left");
    await page.keyboard.press("j");
    await expect(toast(page)).toContainText("last one in the queue");
    await page.keyboard.press("n");
    await expect(toast(page)).toContainText("nothing else is open in this queue");
    await onFinding(page, rows.babel);
  });

  test("an image with nothing open shows the end card at once; Enter goes to the gates screen", async ({ page }) => {
    await page.goto("/ui/queue?scope=image:nope");
    await expect(card(page)).toHaveAttribute("data-card", "end");
    await expect(page.getByTestId("title")).toHaveText("Nothing left to label");
    await expect(page.getByTestId("card-session")).toContainText("0 labels written this session.");
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/\/ui\/gates\/$/);
  });
});

test.describe("moving and saving", () => {
  test("n moves on without writing; with Skip labeled on, ⌥k still goes back to a done row", async ({ page }) => {
    const before = claimSet();
    await page.goto(queueRow(rows.jfhA, "gate:deb-java"));
    await onFinding(page, rows.jfhA);
    await page.keyboard.press("n");
    await expect(page.getByTestId("label-panel")).not.toHaveAttribute("data-row", rows.jfhA);
    expect(claimSet()).toEqual(before);

    // accept jfh8 from its row: both jars are done, and the queue goes on past them
    await page.goto(queueRow(rows.jfhA, "gate:deb-java"));
    await onFinding(page, rows.jfhA);
    await page.keyboard.press("a");
    await expect(page.getByTestId("label-panel")).not.toHaveAttribute("data-row", rows.jfhA);
    await expect(page.getByTestId("queue-skip")).toBeChecked();
    await page.keyboard.press("Alt+k");
    await onFinding(page, rows.jfhB);
    await expect(page.getByTestId("queue-pager")).toHaveAttribute("data-index", "0");
  });

  test("t then Enter saves a tp and goes on", async ({ page }) => {
    const util = rows.utilLinux[0];
    await page.goto(queueRow(util, "gate:deb-java"));
    await onFinding(page, util);
    await page.keyboard.press("t");
    await page.keyboard.press("Enter");
    await expect(page.getByTestId("label-panel")).not.toHaveAttribute("data-row", util);
    await expect.poll(() => labelsOf("CVE-2026-3184").map((l) => `${l.package} ${l.verdict}`)).toEqual(["pkg:deb/debian/util-linux tp"]);
  });
});

test.describe("why this one is next", () => {
  test("tar CVE-2026-18508 on the fresh seed moves no outcome on its own", async ({ page }) => {
    await page.goto(queueRow(rows.tarHand));
    await onFinding(page, rows.tarHand);
    await expect(whyText(page)).toHaveText("deb-java fails, with 10 open matches. No label here changes an outcome on its own, but it counts toward unjudgedChangesAtMost.");
  });

  test("tar CVE-2005-2541 in deb-java's queue decides deb-npm", async ({ page }) => {
    await page.goto(queueRow(rows.tarDropped, "gate:deb-java"));
    await onFinding(page, rows.tarDropped);
    await expect(whyText(page)).toHaveText("deb-java fails, with 10 open matches. A label here decides deb-npm: either label passes it.");
  });

  test("pins: tar CVE-2026-18508 says a label decides deb-java while FP leaves it undecided", {
    annotation: { type: "issue", description: "whyNext says \"decides\" when either verdict moves the gate (queuewords.ts changes / whyNext), so the side that doesn't reads \"leaves it undecided\"" },
  }, async ({ page }) => {
    // accept jfh8: deb-java goes undecided, and now only a TP on tar moves it
    await openFinding(page, rows.jfhA, "f1NotWorse");
    await page.keyboard.press("a");
    await expect.poll(() => labelsOf("GHSA-jfh8-c2jp-5v3q").map((l) => l.verdict)).toEqual(["tp"]);

    // the current wording, contradiction and all; a fix rewrites these two lines
    await page.goto(queueRow(rows.tarHand, "gate:deb-java"));
    await onFinding(page, rows.tarHand);
    await expect(whyText(page)).toHaveText("deb-java is undecided, with 8 open matches. A label here decides it: FP leaves it undecided; TP fails noNewFalseNegatives.");
    await expect(page.getByTestId("verdict-outcome")).toHaveText(["TP → new FN · deb-java fails noNewFalseNegatives", "FP → fixed FP · deb-java stays undecided"]);
  });

  test("tar CVE-2026-18508 as deb-java's only open row decides it", async ({ page }) => {
    await reviewAccept(page);
    await page.goto(queueRow(rows.tarHand));
    await onFinding(page, rows.tarHand);
    await expect(whyText(page)).toHaveText("deb-java is undecided and this is its only open match. A label here decides it: FP passes it; TP fails noNewFalseNegatives.");
  });
});

test.describe("cards", () => {
  // stopAt leaves gzip and babel open with both gates passing: every hint but gzip's, and tar
  // CVE-2026-18508 fp by hand
  async function stopAt(page: Page) {
    await reviewAccept(page, ["CVE-2026-41992"]);
    await openFinding(page, rows.tarHand);
    await label(page, "f", "fix-installed");
    await expect.poll(() => labelsOf("CVE-2026-18508").map((l) => l.verdict)).toEqual(["fp"]);
    await page.goto("/ui/queue");
    await expect(card(page)).toHaveAttribute("data-card", "stop");
  }

  test("the stopping point lists the rows that change nothing; Enter keeps labeling and it shows once", async ({ page }) => {
    await stopAt(page);
    await expect(page.getByTestId("title")).toHaveText("Every gate is decided");
    await expect(cardGate(page, "deb-java")).toHaveAttribute("data-state", "pass");
    await expect(cardGate(page, "deb-npm")).toHaveAttribute("data-state", "pass");
    const left = page.getByTestId("card-left").locator("li");
    await expect(left).toHaveCount(2);
    await expect(left.and(page.locator(`[data-row="${rows.gzip}"]`))).toHaveCount(1);
    await expect(left.and(page.locator(`[data-row="${rows.babel}"]`))).toHaveCount(1);
    await expect(card(page)).toContainText("The 2 matches left change no outcome; label them or stop here.");
    // or research them first: babel has no hint, gzip's is pending
    await expect(card(page).getByTestId("scoped-research").locator("small")).toHaveText("the 1 left, 1 job");
    await expect(card(page).getByTestId("scoped-research")).toHaveAttribute("href", "/ui/research?groups=none");

    await page.keyboard.press("Enter");
    await onFinding(page, rows.gzip);
    // labeling one more goes straight on: the card has had its turn this session
    await page.keyboard.press("a");
    await onFinding(page, rows.babel);
  });

  test("the stopping point's Back goes to the gates screen, and so does Esc", async ({ page }) => {
    await stopAt(page);
    await page.getByTestId("card-back").click();
    await expect(page).toHaveURL(/\/ui\/gates\/$/);

    await page.goto("/ui/queue");
    await expect(card(page)).toHaveAttribute("data-card", "stop");
    await page.keyboard.press("Escape");
    await expect(page).toHaveURL(/\/ui\/gates\/$/);
  });

  test("the boundary card's Back goes to the gate just finished", async ({ page }) => {
    await page.goto("/ui/queue");
    await onFinding(page, rows.gzip);
    await page.keyboard.press("a");
    await expect(card(page)).toHaveAttribute("data-card", "boundary");
    await expect(page.getByTestId("card-back")).toHaveText("Back to deb-npm");
    await page.getByTestId("card-back").click();
    await expect(page).toHaveURL(/\/ui\/gates\/deb-npm\/$/);
  });
});

// a scope the server refuses shows the load error. The shared test fails on any console error and
// Chrome logs the 400, so this one uses Playwright's own test, resets itself and expects that line.
base("a bad scope shows the server's error", async ({ page, request }) => {
  expect((await request.post("/__e2e/reset")).status()).toBe(204);
  const errors: string[] = [];
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  await page.goto("/ui/queue?scope=bogus");
  await expect(page.getByTestId("load-error")).toHaveText("Couldn't load this: 400: scope must be all, gate:<name> or image:<slug>");
  expect(errors).toEqual([expect.stringContaining("400")]);
});
