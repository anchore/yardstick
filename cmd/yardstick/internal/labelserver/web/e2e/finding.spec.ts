import { expect, test } from "./fixtures";
import { images, labelsOf, rows } from "./helpers";

// the finding page (level 3) on the seed: /ui/gates/<gate>/checks/<check>/<row>. The check lists
// come from GET checks/{check}/findings in its order; SCENARIO.md has the rows.
const unjudged = "/ui/gates/deb-java/checks/unjudgedChangesAtMost";
const f1 = "/ui/gates/deb-java/checks/f1NotWorse";
// unjudgedChangesAtMost's open rows in the check's order: the three util-linux binaries, both tar,
// util-linux itself, then log4j's four (jfh8 twice, vc5p twice, which carry an unclear label)
const libgnutls = "c54934489d4ac861"; // CVE-2011-3389, the global fp label

test("a finding opened by URL shows its title, subtitle, tabs and the hint", async ({ page }) => {
  await page.goto(`${unjudged}/${rows.tarDropped}`);
  await expect(page.getByTestId("title")).toHaveText("CVE-2005-2541");
  await expect(page.getByTestId("breadcrumb")).toHaveText(/^Gates\s*›\s*deb-java\s*›\s*unjudgedChangesAtMost\s*›\s*CVE-2005-2541$/);
  await expect(page.locator(".titlerow [data-testid=verdict]")).toHaveText("unlabeled");
  await expect(page.getByTestId("finding-package")).toHaveText("tar 1.34+dfsg-1.2+deb12u1");
  await expect(page.getByTestId("finding-image")).toHaveText(images.deb.name);
  await expect(page.getByTestId("finding-image")).toHaveAttribute("title", /^ghcr\.io\/anchore\/test-images\/vulnerabilities-debian-12-tar-util-linux:617d48d@sha256:617d48dd/);
  await expect(page.getByTestId("finding-direction")).toHaveText("− dropped by candidate");
  await expect(page.getByTestId("pager")).toHaveAttribute("data-index", "4");
  await expect(page.getByTestId("pager")).toHaveAttribute("data-total", "10");

  const tabs = page.getByTestId("finding-tabs").getByRole("tab");
  await expect(tabs).toHaveText(["Why it differs", "Evidence", "Raw match", "Labels on file (0)"]);
  await expect(page.getByTestId("match-lanes")).toBeVisible();
  await expect(page.getByTestId("finding-ref")).toContainText("vulnerabilities-debian-12-tar-util-linux:617d48d@sha256:");

  const hint = page.getByTestId("hint-card");
  await expect(hint).toHaveAttribute("data-verdict", "fp");
  await expect(hint).toHaveAttribute("data-confidence", "medium");
  await expect(page.getByTestId("label-meaning")).toHaveText("TP: the candidate introduced a false negative. FP: it fixed a false positive.");

  await page.getByRole("tab", { name: "Evidence" }).click();
  await expect(page.getByTestId("evidence-links").getByRole("link").first()).toBeVisible();

  // the tab is the reader's standing choice
  await page.getByRole("tab", { name: "Raw match" }).click();
  await expect(page.getByTestId("raw-candidate")).toHaveText("no match on the candidate's side");
  await expect(page.getByTestId("raw-reference")).toContainText("CVE-2005-2541");
  // the artifact comes from the SBOM cache, which a reset can leave pointing at the last server's
  await expect(page.getByTestId("raw-artifact")).toHaveText(/"name": "tar"|^SBOM not found: /);
  await page.reload();
  await expect(page.getByRole("tab", { name: "Raw match" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByTestId("raw-reference")).toBeVisible();
});

test("a accepts the agent hint, writes it to disk and moves to the next open finding", async ({ page }) => {
  await page.goto(`${unjudged}/${rows.tarDropped}`);
  await expect(page.getByTestId("hint-card")).toBeVisible();
  await page.keyboard.press("a");
  await expect.poll(() => labelsOf("CVE-2005-2541").map((l) => `${l.verdict} ${l.justification}`)).toEqual(["fp fix-installed"]);
  await expect(page).toHaveURL(new RegExp(`${unjudged}/${rows.tarHand}$`));
  await expect(page.getByTestId("title")).toHaveText("CVE-2026-18508");
});

test("t, f and u pick the verdict, and a reason and a note save the label", async ({ page }) => {
  await page.goto(`${unjudged}/${rows.tarHand}`);
  await expect(page.getByTestId("label-panel")).toBeVisible();
  await expect(page.getByTestId("hint-card")).toHaveCount(0);
  const seg = (v: string) => page.locator(`[data-testid=verdict-button][data-verdict=${v}]`);

  await page.keyboard.press("t");
  await expect(seg("tp")).toHaveAttribute("aria-pressed", "true");
  await page.keyboard.press("u");
  await expect(seg("unclear")).toHaveAttribute("aria-pressed", "true");
  await expect(seg("tp")).toHaveAttribute("aria-pressed", "false");
  // u and f put the focus on the reason they need; Esc gives the keys back
  await expect(page.getByTestId("reason-picker")).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(page).toHaveURL(new RegExp(`${rows.tarHand}$`));
  await page.keyboard.press("f");
  await expect(seg("fp")).toHaveAttribute("aria-pressed", "true");

  // fp needs a reason: saving without one says so and writes nothing
  await page.getByTestId("save-label").click();
  await expect(page.getByTestId("toast")).toContainText("FP needs a reason");
  expect(labelsOf("CVE-2026-18508")).toEqual([]);

  await page.getByTestId("reason-picker").selectOption("fix-installed");
  await page.getByTestId("note-input").fill("fixed in the installed build");
  await page.getByTestId("save-label").click();
  await expect.poll(() => labelsOf("CVE-2026-18508").map((l) => `${l.verdict} ${l.justification} ${l.notes.join("|")}`))
    .toEqual(["fp fix-installed fixed in the installed build"]);
});

test("Save and next lands on the next unlabeled finding of the filtered list", async ({ page }) => {
  await page.goto(`${unjudged}/${rows.tarHand}?verdict=unlabeled`);
  // unclear vc5p rows are filtered out: 8 unlabeled, tar CVE-2026-18508 the fifth
  await expect(page.getByTestId("pager")).toHaveAttribute("data-index", "5");
  await expect(page.getByTestId("pager")).toHaveAttribute("data-total", "8");
  await page.keyboard.press("f");
  await page.getByTestId("reason-picker").selectOption("fix-installed");
  await expect(page.getByTestId("save-label")).toHaveText("Save and next");
  await page.getByTestId("save-label").click();
  await expect(page).toHaveURL(new RegExp(`${unjudged}/${rows.utilLinux[0]}\\?verdict=unlabeled$`));
  await expect(page.getByTestId("title")).toHaveText("CVE-2026-3184");
  // the labeled row left the list
  await expect(page.getByTestId("pager")).toHaveAttribute("data-index", "5");
  await expect(page.getByTestId("pager")).toHaveAttribute("data-total", "7");
  expect(labelsOf("CVE-2026-18508").map((l) => l.verdict)).toEqual(["fp"]);
});

test("j and k walk the check's list, and the gate's Findings list off a gate route", async ({ page }) => {
  await page.goto(`${f1}/${rows.jfhA}`);
  const pager = page.getByTestId("pager");
  await expect(pager).toHaveText(/1 of 12/);
  await page.keyboard.press("j");
  await expect(page).toHaveURL(new RegExp(`${f1}/${rows.jfhB}$`));
  await expect(pager).toHaveText(/2 of 12/);
  await page.getByTestId("pager-next").click();
  await expect(page).toHaveURL(new RegExp(`${f1}/${rows.vc5pA}$`));
  await page.keyboard.press("k");
  await page.keyboard.press("k");
  await expect(page).toHaveURL(new RegExp(`${f1}/${rows.jfhA}$`));
  await page.keyboard.press("k");
  await expect(page.getByTestId("toast")).toContainText("first one in this list");

  // from the gate's Findings tab, the list is every changed row in report order
  await page.goto(`/ui/gates/deb-java/findings/${rows.jfhA}?image=${images.java.slug}`);
  await expect(page.getByTestId("breadcrumb")).toHaveText(/^Gates\s*›\s*deb-java\s*›\s*GHSA-jfh8-c2jp-5v3q$/);
  await expect(pager).toHaveText(/1 of 4/);
  await page.keyboard.press("j");
  await expect(page).toHaveURL(new RegExp(`/findings/${rows.jfhB}\\?image=${images.java.slug}$`));
});

test("Esc goes back to the check with the filters it came with", async ({ page }) => {
  await page.goto(`${f1}/${rows.jfhA}?image=${images.java.slug}&verdict=unlabeled`);
  await expect(page.getByTestId("pager")).toHaveText(/1 of 2/);
  await page.keyboard.press("Escape");
  await expect(page).toHaveURL(new RegExp(`${f1}\\?image=${images.java.slug}&verdict=unlabeled$`));
});

test("a labeled finding shows the label on file and every source, and can be relabeled", async ({ page }) => {
  await page.goto(`${f1}/${libgnutls}`);
  await expect(page.getByTestId("title")).toHaveText("CVE-2011-3389");
  await expect(page.locator(".titlerow [data-testid=verdict]")).toHaveText("FP");
  const onFile = page.getByTestId("label-on-file");
  await expect(onFile).toHaveAttribute("data-verdict", "fp");
  await expect(onFile.getByTestId("reason")).not.toHaveText("no reason");
  await expect(onFile.getByTestId("label-source")).toHaveText("claims · global");
  // the relabel form starts from the label on file
  await expect(page.locator("[data-testid=verdict-button][data-verdict=fp]")).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByTestId("reason-picker")).toHaveValue("fix-installed");

  await page.getByRole("tab", { name: "Labels on file (1)" }).click();
  await expect(page.getByTestId("label-record")).toHaveAttribute("data-author", "e2e");
  await expect(page.getByTestId("label-note")).toContainText("the BEAST attack");
  await expect(page.getByTestId("label-sources").locator("li")).toHaveCount(1);

  // stay on the match after labeling: the switch is kept in this browser
  await page.getByTestId("advance-checkbox").uncheck();
  await expect(page.getByTestId("save-label")).toHaveText("Save");
  await page.keyboard.press("u");
  await page.getByTestId("reason-picker").selectOption("not-assessed");
  await page.getByTestId("note-input").fill("the global label doesn't hold for this image");
  await page.getByTestId("note-input").press("Enter");
  await expect.poll(() => labelsOf("CVE-2011-3389").map((l) => l.verdict).sort()).toEqual(["fp", "unclear"]);
  await expect(page).toHaveURL(new RegExp(`${f1}/${libgnutls}$`));
  await expect(onFile).toHaveAttribute("data-verdict", "unclear");

  await page.reload();
  await expect(page.getByTestId("advance-checkbox")).not.toBeChecked();
});

test("the cause card accepts the package hint for all four util-linux rows", async ({ page }) => {
  await page.goto(`${unjudged}/${rows.utilLinux[0]}`);
  const card = page.getByTestId("cause-card");
  await expect(card).toHaveAttribute("data-count", "4");
  await expect(card).toContainText("CVE-2026-3184 on util-linux");
  await expect(page.getByTestId("hint-card")).toHaveCount(0);
  await card.getByTestId("accept-all").click();
  await expect.poll(() => labelsOf("CVE-2026-3184").map((l) => `${l.package.replace(/.*\//, "")} ${l.verdict}`).sort())
    .toEqual(["libblkid1 tp", "libmount1 tp", "mount tp", "util-linux tp"]);
});

test("research started on a finding leaves a researched hint that can be accepted", async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto(`${unjudged}/${rows.tarHand}`);
  await expect(page.getByTestId("label-panel")).toBeVisible();
  await expect(page.getByTestId("hint-card")).toHaveCount(0);
  await expect(page.getByTestId("research-button")).toHaveAttribute("data-researched", "false");
  await page.keyboard.press("R");
  await expect(page.getByTestId("toast")).toContainText("research started");

  const hint = page.getByTestId("hint-card");
  await expect(hint).toHaveAttribute("data-verdict", "tp", { timeout: 60_000 });
  await expect(hint.getByTestId("researched-mark")).toBeVisible();
  await expect(page.getByTestId("research-button")).toHaveAttribute("data-researched", "true");
  await hint.getByTestId("hint-facts").locator("summary").click();
  await expect(hint.getByTestId("hint-note")).toContainText("e2e research stand-in");

  await page.keyboard.press("a");
  await expect.poll(() => labelsOf("CVE-2026-18508").map((l) => l.verdict)).toEqual(["tp"]);
});
