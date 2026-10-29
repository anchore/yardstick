import { rmSync } from "node:fs";
import { join } from "node:path";
import type { Page, Request } from "@playwright/test";
import type { CancelResponse, ResearchJob, ResearchJobs, ResearchJobsSummary, ResearchResponse, RowResponse, State, StateRow } from "../src/gen/wire";
import { answersWithError, expect, test, workspace } from "./fixtures";
import { checkPage, gatePage, gatesPage, images, openFinding, rows, startedBatch, tableRow } from "./helpers";

// research wherever labeling is offered: the Agent hint cell's states, a row's and a selection's
// Research, the scoped Research buttons and r, the jobs page, the top bar's chip and hint review's
// strip. The seed's stand-in finishes a job in a second or two, so running and queued states are
// faked by rewriting the gate's state and the jobs list on their way to the page, as
// research-queue.spec.ts fakes a batch.

test.setTimeout(90_000);

const noHints = () => {
  for (const f of ["proposals.jsonl", "causes.jsonl"]) rmSync(join(workspace, ".yardstick", f), { force: true });
};

// fakeState rewrites a gate's state as it reaches the page: edit gets its rows by id
async function fakeState(page: Page, edit: (by: Map<string, StateRow>, st: State) => void, gate = "deb-java") {
  await page.route(`**/api/gates/${gate}/state`, async (r) => {
    const st = (await (await r.fetch()).json()) as State;
    edit(new Map(st.subjects.flatMap((s) => s.rows.map((x) => [x.id, x] as const))), st);
    await r.fulfill({ json: st satisfies State });
  });
}
// uncaused takes rows out of the package hints listing them, so they read as having no hint
const uncaused = (st: State, ...ids: string[]) => { for (const c of st.causes) c.pending = c.pending.filter((id) => !ids.includes(id)); };

const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();
const job = (id: string, rows: string[], vulnerability: string, extra: Partial<ResearchJob>): ResearchJob =>
  ({ id, rows, vulnerability, package: "pkg:deb/debian/tar@1.34", gate: "deb-java", status: "done", command: "", dir: "", queued: ago(600), hints: [], ...extra });
const summary = (extra: Partial<ResearchJobsSummary> = {}): ResearchJobsSummary =>
  ({ total: 0, done: 0, running: 0, queued: 0, failed: 0, cancelled: 0, spent: 0, estimate: 0, secondsLeft: 0, concurrency: 2, hints: { tp: 0, fp: 0, unclear: 0 }, ...extra });
const fakeJobs = (page: Page, jobs: ResearchJob[], s: Partial<ResearchJobsSummary>) =>
  page.route("**/api/research/jobs", (r) => r.fulfill({ json: { jobs, summary: summary(s) } satisfies ResearchJobs }));

const cell = (page: Page, id: string, testid = "findings-table") => tableRow(page, testid, id).getByTestId("research-cell");
const unlabeledFindings = "/ui/gates/deb-java/findings?verdict=unlabeled";

test.describe("the Agent hint cell", () => {
  test("says what research is doing on each row, and the Researching chip filters to the rows with a job", async ({ page }) => {
    await fakeState(page, (by, st) => {
      uncaused(st, ...rows.utilLinux);
      by.get(rows.tarHand)!.research = { job: "j-run", status: "running", started: ago(41), batch: "3f9a21c0aa", model: "sonnet" };
      by.get(rows.jfhA)!.research = { job: "j-q", status: "queued", position: 1, queueLength: 13 };
      by.get(rows.utilLinux[0])!.research = { job: "j-f", status: "failed", error: "exit 1: no hint written" };
      Object.assign(by.get(rows.utilLinux[1])!, { research: { job: "j-d", status: "done" }, researched: true });
    });
    await page.goto(unlabeledFindings);
    await expect(cell(page, rows.tarHand)).toHaveAttribute("data-state", "running");
    await expect(cell(page, rows.tarHand)).toHaveText(/^researching 0:4\d$/);
    await expect(cell(page, rows.tarHand)).toHaveAttribute("href", "/ui/research/jobs#job-j-run");
    await expect(cell(page, rows.tarHand)).toHaveAttribute("title", "batch 3f9a21c0 · Sonnet");
    // a job in flight shows over the hint the row already has
    await expect(cell(page, rows.jfhA)).toHaveText("queued 1st of 13");
    await expect(cell(page, rows.utilLinux[0])).toHaveAttribute("data-state", "failed");
    await expect(cell(page, rows.utilLinux[0])).toHaveAttribute("title", "exit 1: no hint written");
    await expect(cell(page, rows.utilLinux[0]).getByTestId("research-retry")).toBeVisible();
    await expect(cell(page, rows.utilLinux[1])).toHaveText("researched, no hint");
    await expect(cell(page, rows.utilLinux[2])).toHaveText("Research ~$0.23");
    // a hinted row with nothing in flight keeps its hint
    await expect(tableRow(page, "findings-table", rows.jfhB).getByTestId("hint")).toBeVisible();

    const chip = page.locator(".chip[data-chip=researching]");
    await expect(chip.locator("b")).toHaveText("2");
    await chip.click();
    await expect(page).toHaveURL(/hint=researching/);
    await expect(page.getByTestId("findings-table").locator("tbody tr[data-id]")).toHaveCount(2);
  });

  test("with no job in view there is no Researching chip", async ({ page }) => {
    await page.goto(unlabeledFindings);
    await expect(cell(page, rows.tarHand)).toHaveAttribute("data-state", "offer");
    await expect(page.locator(".chip[data-chip=researching]")).toHaveCount(0);
  });

  test("a table drawn from rows read before their job finished reads them again", async ({ page }) => {
    // the first read of the state has a job running on the row, every later one has it finished
    let reads = 0;
    await fakeState(page, (by) => { if (reads++ === 0) by.get(rows.tarHand)!.research = { job: "j-gone", status: "running", started: ago(41) }; });
    const firstJobs = page.waitForResponse("**/api/research/jobs");
    await page.goto("/ui/gates");
    await firstJobs;
    await page.waitForLoadState("networkidle");
    // in the app, so the top bar has already read the jobs (nothing in flight) and won't again
    await page.evaluate((u) => { history.pushState(null, "", u); dispatchEvent(new PopStateEvent("popstate")); }, unlabeledFindings);
    await expect(cell(page, rows.tarHand)).toHaveAttribute("data-state", "offer");
  });

  test("Research on a row starts it from the table, the cell follows the job to its hint, and the top bar says a new hint waits", async ({ page }) => {
    let sent: Request | null = null;
    page.on("request", (q) => { if (q.method() === "POST" && q.url().endsWith("/api/gates/deb-java/research")) sent = q; });
    await page.goto(unlabeledFindings);
    await expect(page.getByTestId("activity")).toBeHidden();
    await cell(page, rows.tarHand).click();
    await expect(page.getByTestId("toast")).toContainText("1 research job started");
    expect(sent!.postDataJSON()).toEqual({ rows: [rows.tarHand], from: "table" });
    // the stand-in leaves a tp hint, and the table shows it without a reload
    await expect(tableRow(page, "findings-table", rows.tarHand).getByTestId("hint")).toHaveText("TP · medium", { timeout: 60_000 });
    await expect(page.getByTestId("activity")).toHaveText("✦ 1 new hint", { timeout: 10_000 });
    await expect(page.getByTestId("activity")).toHaveAttribute("href", "/ui/hints");

    // the jobs page lists it as started from a table, with the hint it left
    await page.goto("/ui/research/jobs");
    const row = page.getByTestId("job-row").first();
    await expect(row).toHaveAttribute("data-state", "done");
    await expect(row).toContainText("matches table");
    await expect(row.getByTestId("hint")).toHaveText("TP · medium");
    await expect(page.getByTestId("jobs-review")).toHaveText(/^Review 1 new hint/);
  });

  test("the Unlabeled tab offers it too, through the research queue", async ({ page }) => {
    let sent: Request | null = null;
    await page.route("**/api/research", (r) => {
      sent = r.request();
      return r.fulfill({ json: startedBatch(["x"], "b") });
    });
    await page.goto("/ui/gates/?tab=unlabeled&q=CVE-2026-18508");
    const c = page.getByTestId("unlabeled-table").locator("tbody tr[data-id]").getByTestId("research-cell");
    await expect(c).toHaveText("Research ~$0.23");
    await c.click();
    await expect(page.getByTestId("toast")).toContainText("1 research job started");
    expect(sent!.postDataJSON()).toEqual({ rows: [rows.tarHand] });
  });
});

test.describe("the bulk bar's Research", () => {
  test("counts what it would research, says what it skips, and starts from the table", async ({ page }) => {
    let sent: Request | null = null;
    await page.route("**/api/gates/deb-java/research", (r) => { sent = r.request(); return r.fulfill({ json: { jobs: ["x"], matches: 1, queued: 1, skipped: 0 } satisfies ResearchResponse }); });
    await page.goto(unlabeledFindings);
    await tableRow(page, "findings-table", rows.tarHand).getByRole("checkbox").check();
    await tableRow(page, "findings-table", rows.jfhA).getByRole("checkbox").check();
    const b = page.getByTestId("bulk-research");
    await expect(b).toHaveText("Research 1 · ~$0.23");
    await expect(b).toHaveAttribute("data-jobs", "1");
    await expect(page.getByTestId("bulk-research-why")).toHaveText("Research skips 1 with a hint. 1 job, about a minute at 2 at a time.");
    await expect(page.getByTestId("bulk-accept")).toHaveText("Accept hints (1)");
    await b.click();
    await expect(page.getByTestId("toast")).toContainText("1 research job started");
    expect(sent!.postDataJSON()).toEqual({ rows: [rows.tarHand], from: "table" });
    await expect(page.getByTestId("bulk-bar")).toBeHidden();
  });

  test("with nothing to research it says why", async ({ page }) => {
    await page.goto(unlabeledFindings);
    await tableRow(page, "findings-table", rows.jfhA).getByRole("checkbox").check();
    await expect(page.getByTestId("bulk-research")).toBeDisabled();
    await expect(page.getByTestId("bulk-research-why")).toHaveText("Nothing to research: 1 with a hint.");
  });

  test("over ten jobs it opens the research page with the rows instead of starting", async ({ page }) => {
    // eleven more open rows with no hint, each its own job
    await fakeState(page, (by, st) => {
      const tar = by.get(rows.tarHand)!;
      st.subjects.find((s) => s.rows.includes(tar))!.rows.push(...Array.from({ length: 11 }, (_, i) => ({ ...tar, id: `f00000000000000${i.toString(16)}`, vulnerability: `CVE-2099-${1000 + i}`, research: undefined, researchShares: [] })));
    });
    await page.goto(`${unlabeledFindings}&q=CVE-2099`);
    await page.getByTestId("findings-table").getByRole("checkbox", { name: "Select every row shown" }).check();
    await expect(page.getByTestId("bulk-research")).toHaveText("Research 11… · ~$2.53");
    await expect(page.getByTestId("bulk-research-why")).toContainText("More than 10, so the research page shows the estimate first.");
    await page.getByTestId("bulk-research").click();
    await expect(page).toHaveURL(/\/ui\/research\?scope=gate%3Adeb-java&rows=f000000000000000%2C/);
    await expect(page.getByTestId("research-rows-chip")).toHaveText(/^11 selected matches/);
  });
});

test.describe("scoped Research buttons", () => {
  const scoped = (page: Page) => page.getByTestId("scoped-research");

  test("a gate offers what changes no outcome when nothing can change it, and r opens the same", async ({ page }) => {
    await page.goto(gatePage());
    await expect(scoped(page)).toBeVisible();
    await expect(scoped(page).locator("small")).toHaveText("1 that changes no outcome");
    await expect(scoped(page)).toHaveAttribute("href", "/ui/research?scope=gate%3Adeb-java&groups=none");
    await page.keyboard.press("r");
    await expect(page).toHaveURL(/\/ui\/research\?scope=gate%3Adeb-java&groups=none$/);
    await expect(page.locator("[data-testid=research-group][data-group=none]").getByTestId("research-group-toggle")).toBeChecked();
  });

  test("with no hints, a gate offers what can change it, and the image filter narrows it", async ({ page }) => {
    noHints();
    await page.goto(gatePage());
    await expect(scoped(page).locator("small")).toHaveText(/^\d+ that can change the gate$/);
    await expect(scoped(page)).toHaveAttribute("href", "/ui/research?scope=gate%3Adeb-java");
    await expect(scoped(page).locator(".costpill")).toHaveText(/^~\$\d+\.\d\d$/);
    await page.goto(`${gatePage()}?image=${images.java.slug}`);
    await expect(scoped(page).locator("small")).toHaveText(new RegExp(`^\\d+ on ${images.java.name}$`));
    await expect(scoped(page)).toHaveAttribute("href", `/ui/research?scope=image%3A${images.java.slug}`);
  });

  test("a check offers its own rows, r opens them, and the research page shows the check", async ({ page }) => {
    await page.goto(checkPage("unlabeledChangesAtMost"));
    await expect(scoped(page)).toBeVisible();
    await expect(scoped(page)).toHaveAttribute("href", /^\/ui\/research\?scope=gate%3Adeb-java&check=unlabeledChangesAtMost/);
    await page.keyboard.press("r");
    await expect(page).toHaveURL(/\/ui\/research\?scope=gate%3Adeb-java&check=unlabeledChangesAtMost/);
    await expect(page.getByTestId("research-check-chip")).toContainText("unlabeledChangesAtMost");
  });

  test("the gates screen's research pill opens research scoped to its gate", async ({ page }) => {
    noHints();
    await page.goto(gatesPage);
    const pill = page.locator("[data-testid=gate-row][data-gate=deb-npm]").getByTestId("gate-research");
    await expect(pill).toHaveAttribute("href", "/ui/research?scope=gate%3Adeb-npm");
    await pill.click();
    await expect(page).toHaveURL(/\/ui\/research\?scope=gate%3Adeb-npm$/);
  });

  test("hint review offers the open matches no agent has looked at", async ({ page }) => {
    await page.goto("/ui/hints");
    const b = page.getByTestId("impact").getByTestId("scoped-research");
    await expect(b.locator("small")).toHaveText(/^the \d+ with no job$/);
    await expect(b).toHaveAttribute("href", "/ui/research?groups=change%2Cnone");
  });

  test("the palette researches the gate and the check on screen, and lists the jobs", async ({ page }) => {
    await page.goto(checkPage("unlabeledChangesAtMost"));
    await page.keyboard.press("Control+k");
    const item = (id: string) => page.getByTestId("palette").locator(`[data-testid=palette-item][data-group=Actions][data-id=${id}]`);
    await expect(item("research-gate")).toHaveAttribute("href", "/ui/research?scope=gate%3Adeb-java");
    await expect(item("research-check")).toHaveAttribute("href", "/ui/research?scope=gate%3Adeb-java&check=unlabeledChangesAtMost");
    await item("jobs").click();
    await expect(page).toHaveURL(/\/ui\/research\/jobs$/);
  });
});

test.describe("the jobs page", () => {
  const jobs = [
    job("j-done", [rows.utilLinux[0]], "CVE-2026-3184", { from: "finding", started: ago(400), finished: ago(342), usage: { costUSD: 0.24, inputTokens: 0, cacheReadTokens: 0, cacheCreationTokens: 0, outputTokens: 0, turns: 0, durationMs: 58_000 }, hints: [{ id: "h1", verdict: "fp", confidence: "medium" }] }),
    job("j-q2", [rows.jfhA, rows.jfhB], "GHSA-jfh8-c2jp-5v3q", { status: "queued", position: 2, from: "table", cancellable: true }),
    job("j-run", [rows.tarHand], "CVE-2026-18508", { status: "running", started: ago(41), from: "research", batch: "3f9a21c0aaaa", cancellable: true }),
    job("j-q1", [rows.vc5pA], "GHSA-vc5p-v9hr-52mj", { status: "queued", position: 1, from: "research", batch: "3f9a21c0aaaa", cancellable: true }),
    job("j-fail", [rows.tarDropped], "CVE-2005-2541", { status: "failed", started: ago(300), finished: ago(291), error: "exit 1: no hint written" }),
    job("j-cancel", [rows.utilLinux[1]], "CVE-2026-3184", { status: "cancelled", finished: ago(200) }),
  ];
  const busy = { total: 6, running: 1, queued: 2, done: 1, failed: 1, cancelled: 1, spent: 0.26, estimate: 1.0, secondsLeft: 180, hints: { tp: 0, fp: 1, unclear: 0 } };

  test("groups running, queued in run order and finished, says where each started, and cancels", async ({ page }) => {
    await fakeJobs(page, jobs, busy);
    const cancels: unknown[] = [];
    await page.route("**/api/gates/deb-java/research/cancel", (r) => { cancels.push(r.request().postDataJSON()); return r.fulfill({ json: { cancelled: ["x"], notCancelled: [] } satisfies CancelResponse }); });
    await page.goto("/ui/research/jobs");
    await expect(page.getByTestId("jobs-group")).toHaveCount(3);
    expect(await page.getByTestId("jobs-group").evaluateAll((gs) => gs.map((g) => (g as HTMLElement).dataset.group))).toEqual(["running", "queued", "finished"]);
    expect(await page.getByTestId("job-row").evaluateAll((rs) => rs.map((r) => (r as HTMLElement).dataset.job))).toEqual(["j-run", "j-q1", "j-q2", "j-cancel", "j-fail", "j-done"]);
    const row = (id: string) => page.locator(`[data-testid=job-row][data-job=${id}]`);
    await expect(row("j-q1")).toContainText("1st");
    await expect(row("j-q2")).toContainText("2nd");
    await expect(row("j-run")).toContainText("research page · batch 3f9a21c0");
    await expect(row("j-q2")).toContainText("matches table · 2 rows");
    await expect(row("j-done")).toContainText("match page");
    await expect(row("j-done").getByTestId("hint")).toHaveText("FP · medium");
    await expect(row("j-done")).toContainText("$0.24");
    await expect(row("j-fail")).toContainText("exit 1: no hint written");
    await expect(row("j-cancel")).toContainText("cancelled before it started");
    await expect(row("j-fail").getByTestId("job-retry")).toBeVisible();
    await expect(page.getByTestId("jobs-running")).toHaveText("1");
    await expect(page.getByTestId("jobs-finished")).toHaveText("3");
    await expect(page.getByTestId("research-toggle").locator("[data-tab=jobs]")).toHaveAttribute("aria-pressed", "true");

    await row("j-run").getByTestId("job-cancel").click();
    await expect(page.getByTestId("toast")).toContainText("1 research job cancelled");
    await page.getByTestId("jobs-cancel-all").click();
    await expect.poll(() => cancels).toEqual([{ rows: [rows.tarHand] }, { rows: [rows.jfhA, rows.tarHand, rows.vc5pA] }]);
  });

  test("the top bar's chip opens it while research is in flight, and a table cell links its job", async ({ page }) => {
    await fakeJobs(page, jobs, busy);
    await page.goto(gatesPage);
    await expect(page.getByTestId("activity")).toHaveText("1 researching · 2 queued");
    await page.getByTestId("activity").click();
    await expect(page).toHaveURL(/\/ui\/research\/jobs$/);
    await page.goto("/ui/research/jobs#job-j-q2");
    await expect(page.locator("[data-testid=job-row][data-job=j-q2]")).toHaveClass(/\bon\b/);
  });

  test("hint review says how many more are on the way and marks the open rows with a job", async ({ page }) => {
    await fakeJobs(page, jobs, { ...busy, running: 2, queued: 13, secondsLeft: 420 });
    await fakeState(page, (by) => { by.get(rows.tarHand)!.research = { job: "j-run", status: "running", started: ago(41) }; });
    await page.goto("/ui/hints");
    const strip = page.getByTestId("hints-on-the-way");
    await expect(strip).toContainText("15 more on the way");
    await expect(strip).toContainText("2 researching, 13 queued · about 7 min");
    await expect(page.getByTestId("impact-left-job").first()).toHaveAttribute("data-state", "running");
    await strip.getByTestId("hints-jobs").click();
    await expect(page).toHaveURL(/\/ui\/research\/jobs$/);
  });

  test("a finding with a queued job says where it is in line and links the job", async ({ page }) => {
    await fakeState(page, (by) => { by.get(rows.tarHand)!.research = { job: "j-q", status: "queued", position: 3, queueLength: 13, cancellable: true }; });
    await openFinding(page, rows.tarHand, null);
    await expect(page.getByTestId("research-status")).toHaveText("queued 3rd of 13");
    await expect(page.getByTestId("research-job-link")).toHaveAttribute("href", "/ui/research/jobs#job-j-q");
    await expect(page.getByTestId("research-cancel-row")).toBeVisible();
  });
});

// research that ran but recorded nothing: CLEANSTART's in the turnup, refused by propose or denied
// its writes, read as "researched, no hint" with no way to see why
test.describe("research that recorded nothing", () => {
  const why = "the agent was refused 5 tool uses: Write .yardstick/research/CVE-2026-18508/tar/REPORT.md";
  const notRecorded = (by: Map<string, StateRow>) => {
    by.get(rows.tarHand)!.research = { job: rows.tarHand, status: "not-recorded", error: why, model: "sonnet", costUSD: 0.27, finished: ago(600) };
    by.get(rows.tarHand)!.researched = true;
  };
  // wrote is the row's detail as it reaches the page, its research having written a proposal or not
  const wrote = (page: Page, proposal: boolean) => page.route(`**/api/gates/deb-java/rows/${rows.tarHand}`, async (r) => {
    const d = (await (await r.fetch()).json()) as RowResponse;
    d.research = { recordable: proposal, summary: "Verdict I would propose: tp, fix-newer, medium.",
      output: { dir: ".yardstick/research/CVE-2026-18508/tar", files: proposal ? ["REPORT.md", "proposal.json"] : ["proposal.json"],
        report: proposal ? "# CVE-2026-18508 on tar\n\ntp, medium confidence" : undefined,
        proposal: proposal ? { verdict: "tp", justification: "fix-newer", confidence: "medium", openQuestions: ["Was the fix backported?"] } : undefined } };
    await r.fulfill({ json: d satisfies RowResponse });
  });

  test("the cell says it wasn't recorded, and why on hover", async ({ page }) => {
    await fakeState(page, notRecorded);
    await page.goto(unlabeledFindings);
    await expect(cell(page, rows.tarHand)).toHaveAttribute("data-state", "notrecorded");
    await expect(cell(page, rows.tarHand)).toHaveText("researched, not recorded");
    await expect(cell(page, rows.tarHand)).toHaveAttribute("title", why);
  });

  test("the finding says what it found, records it as a hint, and keeps a refusal in place", async ({ page }) => {
    await fakeState(page, notRecorded);
    await wrote(page, true);
    await page.route(`**/api/gates/deb-java/research/record`, async (r) => {
      answersWithError(page, r.request().url());
      await r.fulfill({ status: 400, contentType: "text/plain", body: "propose refused it: justification \"fix-newer\" is not listed under tp in vocabulary.yaml" });
    });
    await openFinding(page, rows.tarHand, null);
    const section = page.getByTestId("research-outcome");
    await expect(section).toHaveAttribute("data-outcome", "notrecorded");
    await expect(section.getByTestId("research-head")).toContainText("· Sonnet · $0.27");
    await expect(section.getByTestId("research-outcome-text")).toHaveText(`Research concluded tp · fix-newer · medium but it wasn't recorded: ${why}`);
    await expect(section.getByTestId("research-questions")).toContainText("Was the fix backported?");
    await expect(section.getByTestId("research-report")).toContainText("tp, medium confidence");
    await section.getByTestId("research-record").click();
    // a refusal stays, unlike a toast
    await page.waitForTimeout(3000);
    await expect(section.getByTestId("research-record-error")).toHaveText('propose refused it: justification "fix-newer" is not listed under tp in vocabulary.yaml');
  });

  test("research that wrote nothing says so, with the agent's last message", async ({ page }) => {
    await fakeState(page, notRecorded);
    await wrote(page, false);
    await openFinding(page, rows.tarHand, null);
    const section = page.getByTestId("research-outcome");
    await expect(section).toHaveAttribute("data-outcome", "nothing");
    await expect(section.getByTestId("research-outcome-text")).toHaveText(`Research ran but wrote no result: ${why}`);
    await expect(section.getByTestId("research-record")).toHaveCount(0);
    await section.getByTestId("research-summary").locator("summary").click();
    await expect(section.getByTestId("research-summary")).toContainText("Verdict I would propose: tp, fix-newer, medium.");
  });
});
