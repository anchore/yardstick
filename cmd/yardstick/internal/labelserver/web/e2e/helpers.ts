import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { expect, type Locator, type Page } from "@playwright/test";
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
        file: f, subject: doc.subject?.image?.replace(/^docker.io\/anchore\/yardstick-fixture-/, "").replace(/@.*/, "") ?? "global",
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

// row ids from SCENARIO.md
export const rows = {
  tarDropped: "f6c84232c44b2e7c", // CVE-2005-2541, in both gates
  tarHand: "f9df921776ca876d", // CVE-2026-18508, no hint
  utilLinux: ["2817af9158bb4920", "7686e908f573f7b7", "f3639433e8dd7e25", "497821ed48240b13"],
  jfhA: "92028af2aa075929", jfhB: "db296d8425f164e0",
  vc5pA: "95d913cf49b90d65", vc5pB: "b5049885e0df8561",
  gzip: "e49d34ea0fd16e94", babel: "d19a1ab46b67fd84",
};

export const javaGate = "/ui/map/gates/deb-java/";
export const npmGate = "/ui/map/gates/deb-npm/";
export const gatesPage = "/ui/map/gates/";

// openGate loads a gate's board and waits for it to draw
export async function openGate(page: Page, gate = "deb-java") {
  await page.goto(`/ui/map/gates/${gate}/`);
  await expect(page.getByTestId("board")).toBeVisible();
}

// openGroup opens a board group on the tile
export async function openGroup(page: Page, g: Locator) {
  await g.getByTestId("group-open").click();
  await expect(page.getByTestId("tile")).toBeVisible();
}

// causeGroup is the board group of an agent cause; its key carries a generated id
export const causeGroup = (page: Page): Locator => page.locator('[data-testid=group-row][data-group^="c|"]');

// openRow opens the group on the board and selects a row of it
export async function openRow(page: Page, row: string, g: Locator, gate = "deb-java") {
  await openGate(page, gate);
  await openGroup(page, g);
  await page.goto(page.url().replace(/#.*/, "") + `#row=${row}`);
  await expect(page.getByTestId("tile")).toHaveAttribute("data-row", row);
}

export const group = (page: Page, key: string): Locator => page.locator(`[data-testid=group-row][data-group="${key}"]`);
// groups by what they hold, since the tier in a key moves as labels land: log4j's, and the tar
// groups with and without a hint (CVE-2005-2541 and CVE-2026-18508 at the start)
export const log4jGroup = (page: Page): Locator => page.locator("[data-testid=group-row][data-package='org.apache.logging.log4j']");
export const tarGroup = (page: Page, hinted: boolean): Locator =>
  page.locator(`[data-testid=group-row][data-package=tar][data-hinted='${hinted ? 1 : 0}']`);
export const check = (page: Page, name: string): Locator => page.locator(`[data-testid=check-panel][data-check=${name}]`);
export const verdictButton = (page: Page, v: string): Locator => page.locator(`[data-testid=verdict-button][data-verdict=${v}]`);

// pick chooses a justification in the tile's picker by its value, <verdict>:<justification>
export const pick = (page: Page, value: string) => page.getByTestId("justification-picker").selectOption(value);
