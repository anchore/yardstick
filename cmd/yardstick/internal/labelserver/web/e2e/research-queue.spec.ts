import { rmSync } from "node:fs";
import { join } from "node:path";
import type { Page, Request } from "@playwright/test";
import { expect, test, workspace } from "./fixtures";
import { gatesPage, openFinding, rows } from "./helpers";

// research across gates (/ui/research), the gates banner's research states and a finding's price.
// On the seed every row that can change a gate already has a hint, so tests that need such rows take
// the agent's records away first (noHints): then gzip, tar CVE-2005-2541, jfh8 and vc5p qualify as
// "can change a gate" (4 jobs, 6 rows), and babel, tar CVE-2026-18508 and util-linux change no
// outcome (3 jobs, 6 rows). With no history the estimate is the built-in sonnet numbers ($0.23 a
// job, $0.18 to $0.28); the stand-in reports $0.25 a job.

test.setTimeout(90_000);

const noHints = () => {
  for (const f of ["proposals.jsonl", "causes.jsonl"]) rmSync(join(workspace, ".yardstick", f), { force: true });
};
const banner = (page: Page) => page.getByTestId("work-banner");
const group = (page: Page, id: string) => page.locator(`[data-testid=research-group][data-group=${id}]`);
const toggle = (page: Page, id: string) => group(page, id).getByTestId("research-group-toggle");
const start = (page: Page) => page.getByTestId("research-start");
const gateResearch = (page: Page, gate: string) => page.locator(`[data-testid=gate-row][data-gate=${gate}]`).getByTestId("gate-research");

// a batch partway through, since the stand-in's jobs finish in a second or two
const partway = { id: "b1", started: "2026-10-20T10:00:00Z", model: "sonnet", total: 21, done: 12, running: 2, queued: 7, failed: 0, cancelled: 0,
  spent: 2.71, estimate: 4.83, secondsLeft: 240, hints: { tp: 0, fp: 9, unclear: 3 } };
const fakeRunning = (page: Page) => page.route("**/api/research/batch", (r) => r.fulfill({ json: partway }));

// enterQueue presses n and expects to land on a queue row
async function enterQueue(page: Page) {
  await page.keyboard.press("n");
  await expect(page).toHaveURL(/\/ui\/queue\/[0-9a-f]{16}/);
  await expect(page.getByTestId("label-panel")).toBeVisible();
}

test.describe("labeling by hand never waits on research", () => {
  test("before any research: with no hint pending, research leads, Label what's left stays and n enters the queue", async ({ page }) => {
    noHints();
    await page.goto(gatesPage);
    await expect(banner(page)).toHaveAttribute("data-research", "offered");
    const research = page.getByTestId("research-rows");
    await expect(research).toHaveText(/^Research 6 matches… r$/);
    await expect(research).not.toHaveAttribute("data-variant", /.+/);
    await expect(page.getByTestId("label-left")).toBeVisible();
    await expect(page.getByTestId("label-left")).toHaveAttribute("data-variant", "outline");
    await expect(page.getByTestId("review-hints")).toBeHidden();
    await expect(page.getByTestId("research-price")).toHaveText("about $0.92");
    await expect(page.getByTestId("research-summary")).toHaveText("4 jobs · about 2 min · about 1.3M tokens");
    // the foot is one sentence on what research covers, not every match each gate waits on
    await expect(page.getByTestId("work-foot")).toHaveText("6 matches across 2 gates can still change an outcome. The other 6 change none.");
    // each gate prices the jobs researched under it
    await expect(gateResearch(page, "deb-npm")).toHaveText("research ~$0.46");
    await expect(gateResearch(page, "deb-java")).toHaveText("research ~$0.46");
    await enterQueue(page);
  });

  test("on the seed, with hints pending, review leads and research is offered for the rows that change no outcome", async ({ page }) => {
    await page.goto(gatesPage);
    await expect(page.getByTestId("research-rows")).toHaveText(/^Research 2 matches… ~\$0\.46 r$/);
    await expect(page.getByTestId("research-rows")).toHaveAttribute("data-variant", "ghost");
    await expect(page.getByTestId("review-hints")).not.toHaveAttribute("data-variant", /.+/);
    await expect(page.getByTestId("label-left")).toBeVisible();
    await expect(page.getByTestId("work-outcome")).toHaveCount(2);
    await expect(page.getByTestId("gate-research")).toHaveCount(0);
  });

  test("while a batch runs the banner is its progress, and Label what's left stays", async ({ page }) => {
    await fakeRunning(page);
    await page.goto(gatesPage);
    await expect(banner(page)).toHaveAttribute("data-research", "running");
    await expect(page.getByTestId("research-done")).toHaveText("12");
    await expect(banner(page)).toContainText("of 21 jobs done");
    await expect(page.getByTestId("research-spent")).toHaveText("$2.71");
    await expect(banner(page)).toContainText("spent of about $4.83");
    await expect(page.getByTestId("research-left")).toHaveText("~4 min");
    await expect(page.locator("[data-testid=research-so-far][data-verdict=fp]")).toContainText("9 hints");
    await expect(page.locator("[data-testid=research-so-far][data-verdict=unclear]")).toContainText("3 hints");
    await expect(page.getByTestId("research-cancel")).toHaveText("Cancel 9 jobs");
    await expect(page.getByTestId("research-rows")).toBeHidden();
    // hints are pending on the seed, so review leads; labeling is right there beside it
    await expect(page.getByTestId("review-hints")).not.toHaveAttribute("data-variant", /.+/);
    await expect(page.getByTestId("label-left")).toBeVisible();
    await enterQueue(page);
  });

  test("while a batch runs with no hint pending, Label what's left is the primary", async ({ page }) => {
    noHints();
    await fakeRunning(page);
    await page.goto(gatesPage);
    await expect(banner(page)).toHaveAttribute("data-research", "running");
    await expect(page.getByTestId("label-left")).not.toHaveAttribute("data-variant", /.+/);
    await expect(page.getByTestId("review-hints")).toBeHidden();
    await page.getByTestId("label-left").click();
    await expect(page).toHaveURL(/\/ui\/queue\/[0-9a-f]{16}/);
  });

  test("a batch started from the research page runs, then the banner keeps its real total and the hints it left lead", async ({ page }) => {
    noHints();
    await page.goto("/ui/research");
    await expect(start(page)).toHaveText("Start 4 research jobs");
    await start(page).click();
    await expect(page.getByTestId("toast")).toContainText("4 research jobs started");
    await expect(page).toHaveURL(/\/ui\/gates\/$/);
    await expect(banner(page)).toHaveAttribute("data-research", /running|finished/);
    await expect(banner(page)).toHaveAttribute("data-research", "finished", { timeout: 60_000 });
    await expect(page.getByTestId("work-caps")).toHaveText("Research finished · 4 jobs · $1.00");
    // the stand-in leaves a tp hint on each job's first row
    await expect(page.getByTestId("review-hints")).toHaveText(/^Review 4 hints/);
    await expect(page.getByTestId("review-hints")).not.toHaveAttribute("data-variant", /.+/);
    // the batch's four jobs are now this workspace's own measure of sonnet: $0.25 each
    await expect(page.getByTestId("research-rows")).toHaveText(/^Research 6 more… ~\$0\.75 r$/);
    await expect(page.getByTestId("label-left")).toBeVisible();
    await enterQueue(page);
  });

  test("Cancel stops the rest of the batch", async ({ page }) => {
    await fakeRunning(page);
    let sent: Request | null = null;
    await page.route("**/api/research/batch/cancel", (r) => { sent = r.request(); return r.fulfill({ json: { cancelled: ["a", "b"], notCancelled: [] } }); });
    await page.goto(gatesPage);
    await page.getByTestId("research-cancel").click();
    await expect(page.getByTestId("toast")).toContainText("2 research jobs cancelled");
    expect(sent!.postDataJSON()).toEqual({ id: "b1" });
    expect(sent!.headers()["x-yardstick-token"]).toBeTruthy();
  });
});

test.describe("the research page", () => {
  test("on the seed only the rows that change no outcome qualify, unchecked until chosen", async ({ page }) => {
    await page.goto("/ui/research");
    await expect(group(page, "none")).toBeVisible();
    await expect(group(page, "change")).toBeHidden();
    await expect(group(page, "none").getByTestId("research-job")).toHaveCount(2);
    await expect(toggle(page, "none")).not.toBeChecked();
    await expect(page.getByTestId("research-skipped")).toContainText("0 matches already researched, 10 with an agent hint, 0 queued or running");
    await expect(start(page)).toBeDisabled();
    await expect(start(page)).toHaveText("Select matches to research");
    await toggle(page, "none").check();
    await expect(start(page)).toHaveText("Start 2 research jobs");
    await expect(page.getByTestId("research-cost")).toHaveText("$0.46");
    await expect(page.getByTestId("label-left")).toBeVisible();
  });

  test("the estimate follows the groups, the model and the limit", async ({ page }) => {
    noHints();
    await page.goto("/ui/research");
    await expect(group(page, "change").getByTestId("research-job")).toHaveCount(4);
    await expect(toggle(page, "change")).toBeChecked();
    await expect(start(page)).toHaveText("Start 4 research jobs");
    await expect(page.getByTestId("research-cost")).toHaveText("$0.92");
    await expect(page.getByTestId("research-range")).toHaveText("$0.72 to $1.12");
    await expect(page.getByTestId("research-rows")).toHaveText("6");
    await expect(page.getByTestId("research-tokens")).toHaveText("~1.2M in · ~19k out");
    await expect(page.getByTestId("research-basis")).toContainText("from 23 jobs measured 2026-10-19 on Sonnet");

    // the second group adds its jobs and their price
    await toggle(page, "none").check();
    await expect(start(page)).toHaveText("Start 7 research jobs");
    await expect(page.getByTestId("research-cost")).toHaveText("$1.61");
    await expect(page.getByTestId("research-rows")).toHaveText("12");

    // a model with no finished jobs here has only a job count
    await page.getByTestId("research-model").selectOption("opus");
    await expect(page.getByTestId("research-cost")).toHaveText("not measured");
    await expect(page.getByTestId("research-range")).toHaveText("7 jobs");
    await expect(page.getByTestId("research-unmeasured")).toBeVisible();

    await page.getByTestId("research-limit").fill("2");
    await expect(start(page)).toHaveText("Start 2 research jobs");
  });

  test("r opens it from the gates screen, the palette has it, and n leaves it for the queue in its scope", async ({ page }) => {
    await page.goto(gatesPage);
    await expect(banner(page)).toBeVisible();
    await page.keyboard.press("r");
    await expect(page).toHaveURL(/\/ui\/research$/);
    await expect(page.getByTestId("research-estimate")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page).toHaveURL(/\/ui\/gates\/$/);

    await page.keyboard.press("Control+k");
    await page.getByTestId("palette").locator("[data-testid=palette-item][data-group=Actions][data-id=research]").click();
    await expect(page).toHaveURL(/\/ui\/research$/);

    await page.locator("[data-testid=research-gate-chip][data-gate=deb-java]").click();
    await expect(page).toHaveURL(/\/ui\/research\?scope=gate%3Adeb-java$/);
    await expect(page.getByTestId("research-job")).toHaveCount(1);
    await page.keyboard.press("n");
    await expect(page).toHaveURL(/\/ui\/queue\/[0-9a-f]{16}\?scope=gate%3Adeb-java$/);
  });
});

test.describe("a finding's Research button", () => {
  test("shows the price of its one job and the packages that share it", async ({ page }) => {
    await openFinding(page, rows.tarHand);
    await expect(page.getByTestId("research-price")).toHaveText("~$0.23");
    await expect(page.getByTestId("research-shares")).toHaveText("One job, about a minute.");
    await openFinding(page, rows.utilLinux[0]);
    await expect(page.getByTestId("research-shares")).toContainText("One job, about a minute, shared with ");
  });
});
