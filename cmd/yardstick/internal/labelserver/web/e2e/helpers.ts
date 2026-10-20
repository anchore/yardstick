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

// imageTile is an image's small multiple in a board's header
export const imageTile = (page: Page, image: keyof typeof images) =>
  page.locator(`[data-testid=image][data-subject="${images[image].name}"]`);

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
