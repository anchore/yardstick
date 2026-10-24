import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { expect, type Locator, type Page } from "@playwright/test";
import type { ResearchQueueResponse } from "../src/gen/wire";
import { workspace } from "./fixtures";

// package is the purl without version and qualifiers: the UI writes the row's own, the seed the bare name
export interface DiskLabel {
  file: string;
  subject: string;
  package: string;
  vulnerability: string;
  verdict: string;
  justification?: string;
  notes: string[];
}

// diskLabels is every label in the workspace's claims, as written by the UI or seeded
export function diskLabels(): DiskLabel[] {
  const claims = join(workspace, "claims");
  const out: DiskLabel[] = [];
  for (const f of readdirSync(claims, { recursive: true, encoding: "utf8" })) {
    if (!f.endsWith(".json") || f.endsWith("sbom.json")) continue;
    const doc = JSON.parse(readFileSync(join(claims, f), "utf8"));
    for (const l of doc.labels ?? []) {
      out.push({
        file: f, subject: doc.subject?.image?.replace(/@.*/, "").replace(/.*\//, "") ?? "global",
        package: l.package.replace(/[@?].*/, ""), vulnerability: l.vulnerability, verdict: l.verdict, justification: l.justification,
        notes: (l.notes ?? []).map((n: { text: string }) => n.text),
      });
    }
  }
  return out;
}

// labelsOf is the on-disk labels for a vulnerability, without files and notes
export const labelsOf = (vuln: string) => diskLabels().filter((l) => l.vulnerability === vuln);

// claimSet is the comparable form of the labels: no timestamps, authors or files
export const claimSet = () =>
  diskLabels().map((l) => `${l.subject} ${l.package} ${l.vulnerability} ${l.verdict} ${l.justification ?? ""}`).sort();

// startedBatch is POST /api/research's answer to a start, for a test that fakes one: the jobs it
// queued under one batch, and no plan
export const startedBatch = (jobs: string[], batch: string): ResearchQueueResponse => ({
  groups: [], skipped: { researched: 0, hinted: 0, active: 0 }, concurrency: 2, jobs, batch,
  estimate: { jobs: 0, rows: 0, low: 0, mean: 0, high: 0, tokensIn: 0, tokensOut: 0, seconds: 0,
    basis: { model: "sonnet", measured: false, n: 0, min: 0, mean: 0, max: 0, tokensIn: 0, tokensOut: 0, seconds: 0 } },
});

// row ids from SCENARIO.md
export const rows = {
  tarDropped: "0fe9fc814bcd060a", // CVE-2005-2541, in both gates
  tarHand: "e3bfd3b0b0c30ee6", // CVE-2026-18508, no hint
  utilLinux: ["9f5eb52729c83cc1", "d2572e8f87a44f74", "781d813b74ed9e10", "12fab8dbf4fcf9e8"],
  jfhA: "e1af7851f0e60bb4", jfhB: "783bbb63489d81a6",
  vc5pA: "42c45bf99e4f741b", vc5pB: "a88b3bd584c62516",
  gzip: "5e50fe5b2007001a", babel: "24160b879ac36bf5",
};

// the images as the UI names them (repository base and tag, which diskLabels also gives) and as
// ?image= spells them
export const images = {
  deb: { name: "vulnerabilities-debian-12-tar-util-linux:617d48d", slug: "vulnerabilities-debian-12-tar-util-linux-617d48d" },
  java: { name: "grype-quality-java-log4j-two-jars:e363e44", slug: "grype-quality-java-log4j-two-jars-e363e44" },
  npm: { name: "grype-quality-npm-babel:8e253b5", slug: "grype-quality-npm-babel-8e253b5" },
};

export const gatesPage = "/ui/gates/";
export const gatePage = (gate = "deb-java") => `/ui/gates/${gate}/`;
export const checkPage = (check: string, gate = "deb-java") => `/ui/gates/${gate}/checks/${check}`;
// findingPage is a finding reached from a check, or from the gate's Findings tab with no check
export const findingPage = (row: string, check: string | null = "unlabeledChangesAtMost", gate = "deb-java") =>
  check ? `${checkPage(check, gate)}/${row}` : `/ui/gates/${gate}/findings/${row}`;

// outcome is the status badge in the title row: a gate's outcome on a gate screen, a check's state
// on a check screen
export const outcome = (page: Page): Locator => page.getByTestId("title-row").getByTestId("status");

// checkRow is a check's row on its gate's Checks tab
export const checkRow = (page: Page, name: string): Locator => page.locator(`[data-testid=check-row][data-check=${name}]`);

// checkStates expects each check's state on a gate's Checks tab
export async function checkStates(page: Page, want: Record<string, string>) {
  for (const [name, state] of Object.entries(want)) await expect(checkRow(page, name), name).toHaveAttribute("data-state", state);
}

// railImage is an image's row in the image rail
export const railImage = (page: Page, image: keyof typeof images): Locator =>
  page.getByTestId("image-rail").locator(`[data-testid=rail-image][data-slug="${images[image].slug}"]`);

// tableRow is a row of a findings or labels table by its row id
export const tableRow = (page: Page, testid: string, id: string): Locator => page.getByTestId(testid).locator(`tbody tr[data-id="${id}"]`);
export const tableRows = (page: Page, testid: string): Locator => page.getByTestId(testid).locator("tbody tr[data-id]");

// openFinding loads a finding page and waits for its label panel
export async function openFinding(page: Page, row: string, check: string | null = "unlabeledChangesAtMost", gate = "deb-java") {
  await page.goto(findingPage(row, check, gate));
  await expect(page.getByTestId("label-panel")).toHaveAttribute("data-row", row);
}

// onFinding expects the finding page to be on row, reached from check
export const onFinding = (page: Page, row: string) => expect(page.getByTestId("label-panel")).toHaveAttribute("data-row", row);

export const verdictButton = (page: Page, v: string): Locator => page.locator(`[data-testid=verdict-button][data-verdict=${v}]`);

// setPref sets a checkbox in the app bar's settings cog and closes the cog again with Esc, as a
// reader would, so the page's keys work after it
export async function setPref(page: Page, testid: "advance-checkbox" | "queue-skip", on: boolean) {
  await page.getByTestId("settings-button").click();
  await page.getByTestId(testid).setChecked(on);
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("settings-panel")).toBeHidden();
}

// label picks a verdict by key on a finding page, a reason for fp and unclear, and saves
export async function label(page: Page, key: "t" | "f" | "u", reason?: string) {
  await page.keyboard.press(key);
  if (reason) await page.getByTestId("reason-picker").selectOption(reason);
  await page.getByTestId("save-label").click();
}

// screenText is what a write can change on a screen: the title row, the tab counts, the verdict bar,
// the rail's counts, the label panel and the table rows
const screenText = (page: Page) => page.evaluate(() => {
  const text = (s: string) => [...document.querySelectorAll<HTMLElement>(s)].map((e) => e.innerText.replace(/\s+/g, " ").trim());
  return {
    title: text("[data-testid=title-row]"), tabs: text("[data-testid=tabs] [role=tab]"), verdicts: text("[data-testid=verdict-bar]"),
    rail: text("[data-testid=rail-image]"), panel: text("[data-testid=label-panel]"), rows: text("tbody tr[data-id]"),
  };
});

// expectFreshLoad expects the screen, refreshed in place after a write, to show what a fresh
// navigation to its URL shows, so a region the refresh missed fails here whatever the screen
export async function expectFreshLoad(page: Page) {
  const fresh = await page.context().newPage();
  await fresh.goto(page.url(), { waitUntil: "networkidle" });
  const want = await screenText(fresh);
  await fresh.close();
  await expect.poll(() => screenText(page), { message: "the screen matches a fresh load of its URL" }).toEqual(want);
}

// keeps marks an element before a write and starts watching for a loading frame; the check it
// returns expects the very same element still on screen, not a copy, and no loading frame shown
export async function keeps(page: Page, kept: Locator) {
  await kept.evaluate((e) => { (window as unknown as { kept: Element }).kept = e; });
  await page.evaluate(() => {
    const w = window as unknown as { flashed: boolean };
    w.flashed = false;
    new MutationObserver(() => { if (document.querySelector("[data-testid=loading]")) w.flashed = true; })
      .observe(document.body, { childList: true, subtree: true });
  });
  return async () => {
    expect(await page.evaluate(() => (window as unknown as { flashed: boolean }).flashed), "a loading frame showed").toBe(false);
    expect(await kept.evaluate((e) => e === (window as unknown as { kept: Element }).kept), "the same element is on screen").toBe(true);
  };
}
