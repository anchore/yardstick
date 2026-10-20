// kit.ts is /ui/gates/_kit: every shell component on sample data from the grype-upgrade mockup (real
// image names, packages and IDs; made-up counts), wired together the way the gate and check
// screens will be. Nothing links here; it's for building and reviewing the components.
import { el, fill, type Child } from "../shared/dom";
import { columnHelp } from "../shared/words";
import { noCounts, sumCounts, type RailImage } from "./images";
import { imageRail } from "./rail";
import { withFilters, type Route, type VerdictFilter } from "./route";
import { renderShell, type Nav, type View } from "./shell";
import { countBy, filterRows } from "./table";
import { dataTable, type Column } from "./tableview";
import { outcome as outcomeOf, outcomeRank } from "../shared/rows";
import { couldMove, hint, imageName, kbd, meter, outcome, status, verdict, verdictBar, type Verdict } from "./ui";

// name, reference, then tp, fp, unclear, hinted, unlabeled without a hint
const sample: [string, string, number, number, number, number, number][] = [
  ["wolfi-base", "cgr.dev/chainguard/wolfi-base@sha256:be3834598c3c4b76ace6a866edcbbe1fa18086f9ee238b57769e4d230cd7d507", 1, 1, 0, 1, 0],
  ["java:56d52bc", "ghcr.io/anchore/test-images/java:56d52bc@sha256:10008791acbc5866de04108746a02a0c4029ce3a4400a9b3dad45d7f2245f9da", 2, 1, 1, 1, 1],
  ["grype-quality-ruby:d89207b", "ghcr.io/anchore/test-images/grype-quality-ruby:d89207b@sha256:1a5a5f870924e88a6f0f2b8089cf276ef0a79b5244a052cdfe4a47bb9e5a2c10", 0, 0, 0, 0, 0],
  ["vulnerabilities-alpine-3.6:d5be50d", "ghcr.io/anchore/test-images/vulnerabilities-alpine-3.6:d5be50d@sha256:58637f273108e3e9eb4df4d73f7b6b1da303cbbf64f65e65fb7762482f2de63d", 1, 1, 0, 0, 0],
  ["grype-quality-golang:d89207b", "ghcr.io/anchore/test-images/grype-quality-golang:d89207b@sha256:7536ee345532f674ec9e448e3768db4e546c48220ba2b6ec9bc9cfbfb3b7b74a", 2, 2, 0, 3, 2],
  ["vulnerabilities-package-name-normalization:984794b", "ghcr.io/anchore/test-images/vulnerabilities-package-name-normalization:984794b@sha256:92f1981518e92bf3712ff95cf342f7f4d5fc83fb93a30a36d7d1204e64342199", 0, 0, 0, 1, 0],
  ["grype-quality-java:d89207b", "ghcr.io/anchore/test-images/grype-quality-java:d89207b@sha256:b3534fc2e37943136d5b54e3a58b55d4ccd4363d926cf7aa5bf55a524cf8275b", 3, 5, 0, 4, 2],
  ["grype-quality-node:d89207b", "ghcr.io/anchore/test-images/grype-quality-node:d89207b@sha256:f56164678054e5eb59ab838367373a49df723b324617b1ba6de775749d7f91d4", 2, 5, 0, 3, 1],
  ["alpine", "docker.io/library/alpine@sha256:ddac200f3ebc9902fb8cfcd599f41feb2151f1118929da21bcef57dc276975f9", 0, 0, 0, 0, 0],
  ["ubuntu", "docker.io/library/ubuntu@sha256:c95b7b93ccd48c3bfd97f8cac6d5ca8053ced584c9e8e6431861ca30b0d73114", 0, 0, 1, 1, 0],
  ["python3-debian11", "gcr.io/distroless/python3-debian11@sha256:69ae7f133d33faab720af28e78fb45707b623bcbc94ae02a07c633bf053f4b40", 1, 1, 0, 1, 1],
  ["scanner-test", "ghcr.io/chainguard-images/scanner-test@sha256:59bddc101fba0c45d5c093575c6bc5bfee7f0e46ff127e6bb4e5acaaafb525f9", 1, 0, 0, 0, 0],
  ["core", "mcr.microsoft.com/cbl-mariner/base/core@sha256:51101e635f56032d5afd3fb56d66c7b93b34d5a39ddac01695d62b94473cc34e", 0, 0, 0, 2, 1],
  ["grype-test", "registry.replicated.com/library/grype-test@sha256:3339bcd874d21fa3ca5bd20636e793c0c33bd71ace3a18a9a3b3d147b91dd000", 0, 0, 0, 0, 2],
];
const images: RailImage[] = sample.map(([name, ref, tp, fp, unclear, hinted, plain]) => ({
  name, ref, slug: name.replace(":", "-"),
  counts: { ...noCounts, tp, fp, unclear, hinted, open: hinted + plain, total: tp + fp + unclear + hinted + plain },
}));
const byName = new Map(images.map((i) => [i.name, i]));

interface Finding { id: string; label: Verdict; vuln: string; pkg: string; version: string; purl: string; image: string; change: "added" | "dropped"; hint?: string; effect: "decides" | "could move" | "counted" }
const f = (id: string, label: Verdict, vuln: string, pkg: string, version: string, purl: string, image: string, change: Finding["change"], effect: Finding["effect"], h?: string): Finding =>
  ({ id, label, vuln, pkg, version, purl, image, change, effect, hint: h });
const findings: Finding[] = [
  f("3e91c0a7d2b4f816", "fp", "CVE-2019-13139", "docker", "v17.12.0-ce-rc1.0.20200309214505-aa6a9891b09c+incompatible", "github.com/docker/docker", "grype-quality-golang:d89207b", "added", "decides"),
  f("5b0e3c2d9a417f60", "fp", "GHSA-qq97-vm5h-rrhg", "distribution", "v2.7.1+incompatible", "github.com/docker/distribution", "grype-quality-golang:d89207b", "added", "decides"),
  f("8c41d2e07f9a3b15", "tp", "GHSA-vp35-85q5-9f25", "docker", "v20.10.17+incompatible", "github.com/docker/docker", "grype-quality-golang:d89207b", "dropped", "decides"),
  f("1f7a9e3c5d2b8064", "fp", "CVE-2016-7132", "php-checks", "3.17.0.7439", "org.sonarsource.php:php-checks", "grype-quality-java:d89207b", "added", "decides"),
  f("a2d6f80b3e1c9475", "fp", "CVE-2019-1010022", "glibc-2.42", "2.42-r4", "glibc-2.42", "grype-test", "dropped", "counted"),
  f("c7e05b9d1a3f2864", "unclear", "CVE-2002-2439", "libgcc1", "1:4.6.3-1ubuntu5", "libgcc1", "ubuntu", "dropped", "could move", "TP · medium"),
  f("d93a1c6e0b7f4258", "unlabeled", "CVE-2023-38545", "curl", "7.84.0-1.cm2", "curl", "core", "dropped", "could move", "TP · high"),
  f("e4b8027c6d1a9f35", "unlabeled", "CVE-2023-0286", "openssl", "1.1.1n-0+deb11u5", "openssl", "python3-debian11", "added", "could move", "TP · medium"),
  f("f05c3a9e8b2d7146", "unlabeled", "CVE-2020-1747", "pyyaml", "5.1", "pyyaml", "vulnerabilities-package-name-normalization:984794b", "added", "counted", "TP · medium"),
  f("0a6d4f1b9c8e2735", "unlabeled", "CVE-2022-22965", "spring-core", "2.5", "org.springframework:spring-core", "java:56d52bc", "added", "counted"),
  f("16e9b3d07a5c4f82", "unlabeled", "CVE-2023-3696", "mongoose", "6.5.1", "mongoose", "grype-quality-node:d89207b", "added", "counted", "TP · medium"),
  f("2b7f5e8c4d0a1963", "unlabeled", "CVE-2022-48174", "busybox", "1.35.0-r2", "busybox", "wolfi-base", "added", "counted", "TP · low"),
];

const columns: Column<Finding>[] = [
  { key: "label", label: "Label", cell: (r) => verdict(r.label), sort: (r) => r.label, help: columnHelp.label },
  { key: "vuln", label: "Vulnerability", cell: (r) => el("span", { class: "strong" }, r.vuln), sort: (r) => r.vuln },
  { key: "package", label: "Package", cell: (r) => el("span", { class: "mono" }, r.pkg, " ", el("small", {}, r.version)), sort: (r) => r.pkg, title: (r) => `${r.purl} ${r.version}`, truncate: true },
  { key: "image", label: "Image", cell: (r) => imageName(r.image, byName.get(r.image)?.ref), sort: (r) => r.image, title: (r) => byName.get(r.image)?.ref ?? r.image, truncate: true },
  { key: "outcome", label: "Outcome", cell: (r) => outcome(r.change, r.label), sort: (r) => outcomeRank(outcomeOf(r.change, r.label)), help: columnHelp.outcome },
  { key: "hint", label: "Agent hint", cell: (r) => (r.hint ? hint(r.hint) : el("span", { class: "muted" }, "–")), sort: (r) => r.hint, help: columnHelp.hint },
  { key: "effect", label: "Effect", cell: (r) => (r.effect === "could move" ? couldMove() : r.effect), sort: (r) => r.effect, help: columnHelp.effect },
];

type Chip = VerdictFilter | "all" | "hint";
const chipWords: Record<Chip, string> = { all: "All", unlabeled: "Unlabeled", tp: "TP", fp: "FP", unclear: "Unclear", hint: "Has hint" };
const chipOf = (r: Route): Chip => (r.filters.hint === "yes" ? "hint" : r.filters.verdict ?? "all");
const inChip = (row: Finding, c: Chip) => c === "all" || (c === "hint" ? !!row.hint : row.label === c);

export function kitView(host: HTMLElement, r0: Route, nav: Nav): View {
  let r = r0;
  const rail = imageRail({ images, selected: r.filters.image ?? null, onSelect: (slug) => nav(withFilters(r, { image: slug ?? undefined })) });
  const search: HTMLInputElement = el("input", { class: "input search", type: "search", placeholder: "Filter by CVE, package, image…", "aria-label": "Filter matches", value: r.filters.q ?? "",
    oninput: () => { nav(withFilters(r, { q: search.value }), true); } });
  const chips = el("div", { class: "chips", role: "group", "aria-label": "Filter by label" });
  const table = dataTable<Finding>({
    columns, rows: findings, id: (x) => x.id, sort: null,
    select: { bulk: (ids, clear) => [
      el("button", { type: "button", class: "btn", "data-variant": "outline", "data-size": "sm", onclick: clear }, `Accept hints (${ids.length})`),
      el("button", { type: "button", class: "btn", "data-variant": "outline", "data-size": "sm", onclick: clear }, "Label as…"),
    ] },
    foot: (shown) => `${shown.length} ${shown.length === 1 ? "match" : "matches"} · Group by: none · Sort: click a column`,
    testid: "kit-table",
  });

  const imageOf = (s: string | undefined) => images.find((i) => i.slug === s);
  const shell = renderShell(host, r, {
    title: "Component kit",
    status: status("fail", true),
    sub: "Each shell component on sample data from the grype-upgrade mockup. Nothing links here.",
    actions: el("button", { type: "button", class: "btn", "data-testid": "primary" }, "Label next ", kbd("n")),
    above: verdictBar(sumCounts(images.map((i) => i.counts))),
    rail,
    meta: "grype-upgrade.yaml",
    body: [
      el("section", { class: "kit", "data-testid": "kit-gallery" },
        line("Status", status("pass"), status("fail"), status("undecided")),
        line("Verdict", verdict("tp"), verdict("fp"), verdict("unclear"), verdict("unlabeled"), hint("TP · medium"), couldMove()),
        line("Outcome", outcome("added", "tp"), outcome("added", "fp"), outcome("dropped", "tp"), outcome("dropped", "fp"), outcome("added", undefined), outcome("dropped", undefined), outcome("dropped", "fp", true)),
        line("Buttons", el("button", { type: "button", class: "btn" }, "Accept hint ", kbd("a")),
          el("button", { type: "button", class: "btn", "data-variant": "outline" }, "Skip ", kbd("j")),
          el("button", { type: "button", class: "btn", "data-variant": "ghost" }, "Open")),
        line("Tabs", el("div", { class: "tabs" }, el("div", { role: "tablist" },
          el("button", { type: "button", role: "tab", "aria-selected": "true" }, "Checks ", el("span", { class: "ct" }, "4")),
          el("button", { type: "button", role: "tab", "aria-selected": "false" }, "Matches ", el("span", { class: "ct" }, "58")),
          el("button", { type: "button", role: "tab", "aria-selected": "false" }, "Labels ", el("span", { class: "ct" }, "2,466"))))),
        line("Meter",
          meter({ value: 0.5, limit: 0, state: "fail", caption: [el("b", {}, "0.500"), " worse · limit 0"] }),
          meter({ value: 0, limit: 0, state: "pass", caption: [el("b", {}, "0"), " new · limit 0"] }),
          meter({ value: 27, limit: 30, state: "undecided", caption: [el("b", {}, "27"), " unlabeled · limit 30"] })),
        line("Image names", ...["vulnerabilities-package-name-normalization:984794b", "grype-quality-golang:d89207b", "core"].map((n) => el("span", { class: "namebox" }, imageName(n, byName.get(n)?.ref))))),
      el("div", { class: "filters" }, chips, search),
      table.el,
    ],
  });

  function update(next: Route) {
    r = next;
    const img = imageOf(r.filters.image);
    rail.select(img?.slug ?? null);
    shell.scope(img ? imageName(img.name, img.ref) : null, () => nav(withFilters(r, { image: undefined })));
    if (search.value !== (r.filters.q ?? "")) search.value = r.filters.q ?? "";
    // the chips count what the image and the search leave, so they follow the rail
    const scoped = filterRows(findings.filter((x) => !img || x.image === img.name), r.filters.q ?? "", (x) => `${x.vuln} ${x.pkg} ${x.version} ${x.image}`);
    const n = countBy(scoped, (x) => x.label), hinted = scoped.filter((x) => x.hint).length, on = chipOf(r);
    fill(chips, (Object.keys(chipWords) as Chip[]).map((c) =>
      el("button", { type: "button", class: "chip", "aria-pressed": String(c === on), "data-chip": c,
        onclick: () => nav(withFilters(r, c === "hint" ? { hint: "yes", verdict: undefined } : { verdict: c === "all" ? undefined : c, hint: undefined })) },
      chipWords[c], " ", el("b", {}, String(c === "all" ? scoped.length : c === "hint" ? hinted : n[c] ?? 0)))));
    table.update(scoped.filter((x) => inChip(x, on)), img ? ["image"] : []);
    return true;
  }
  update(r);
  return { key: rail.key, update };
}

function line(caption: string, ...children: Child[]) {
  return el("div", { class: "kit-line" }, el("span", { class: "kit-cap" }, caption), el("div", { class: "kit-items" }, children));
}
