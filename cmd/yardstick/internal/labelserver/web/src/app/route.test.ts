import { describe, expect, test } from "bun:test";
import { crumbs, formatRoute, inGate, parseRoute, up, withFilters, type Route } from "./route";

// parse splits a URL the way location does
function parse(url: string) {
  const u = new URL(url, "http://localhost");
  return parseRoute(u.pathname, u.search);
}

const routes: Route[] = [
  { level: "gates", tab: "gates", filters: {} },
  { level: "gates", tab: "unlabeled", filters: { image: "core" } },
  { level: "gates", tab: "labels", filters: { verdict: "fp", page: 3 } },
  { level: "kit", filters: {} },
  { level: "gate", gate: "grype-upgrade", tab: "checks", filters: {} },
  { level: "gate", gate: "grype-upgrade", tab: "findings", filters: { image: "grype-quality-golang-d89207b", verdict: "unlabeled" } },
  { level: "gate", gate: "grype-upgrade", tab: "labels", filters: { q: "log4j core", page: 2 } },
  { level: "gate", gate: "my gate/x", tab: "map", filters: {} },
  { level: "check", gate: "grype-upgrade", check: "f1NotWorse", filters: { hint: "yes" } },
  { level: "finding", gate: "grype-upgrade", check: "f1NotWorse", row: "3e91c0a7d2b4f816", filters: { image: "core", verdict: "tp" } },
  { level: "finding", gate: "grype-upgrade", check: null, row: "3e91c0a7d2b4f816", filters: {} },
  { level: "gate", gate: "deb-java", tab: "findings", filters: { pkg: "org.apache.logging.log4j" } },
  { level: "research", filters: {} },
  { level: "research", scope: "gate:deb-java", filters: {} },
  { level: "research", scope: "gate:deb-java", check: "f1NotWorse", filters: {} },
  { level: "research", scope: "gate:deb-java", rows: ["e3bfd3b0b0c30ee6", "0fe9fc814bcd060a"], filters: {} },
  { level: "research", groups: ["change", "none"], filters: {} },
  { level: "jobs", filters: {} },
  { level: "hints", filters: {} },
  { level: "queue", filters: {} },
  { level: "queue", row: "e1af7851f0e60bb4", filters: { image: "core" } },
  { level: "history", filters: {} },
];

describe("formatRoute", () => {
  test("each level has its documented path", () => {
    expect(formatRoute(routes[0])).toBe("/ui/gates/");
    expect(formatRoute(routes[1])).toBe("/ui/gates/?tab=unlabeled&image=core");
    expect(formatRoute(routes[3])).toBe("/ui/gates/_kit");
    expect(formatRoute(routes[4])).toBe("/ui/gates/grype-upgrade/");
    expect(formatRoute(routes[5])).toBe("/ui/gates/grype-upgrade/findings?image=grype-quality-golang-d89207b&verdict=unlabeled");
    expect(formatRoute(routes[7])).toBe("/ui/gates/my%20gate%2Fx/map");
    expect(formatRoute(routes[8])).toBe("/ui/gates/grype-upgrade/checks/f1NotWorse?hint=yes");
    expect(formatRoute(routes[9])).toBe("/ui/gates/grype-upgrade/checks/f1NotWorse/3e91c0a7d2b4f816?image=core&verdict=tp");
    expect(formatRoute(routes[10])).toBe("/ui/gates/grype-upgrade/findings/3e91c0a7d2b4f816");
  });
  test("the labeling flow's screens sit beside /ui/gates/", () => {
    expect(routes.slice(-4).map(formatRoute)).toEqual(["/ui/hints", "/ui/queue", "/ui/queue/e1af7851f0e60bb4?image=core", "/ui/history"]);
  });
  test("history's since rides the query: all or a time, anything else is the server start", () => {
    for (const since of ["all", "2026-10-20T09:30:00.000Z"]) {
      const h: Route = { level: "history", filters: { verdict: "fp", since } };
      expect(parse(formatRoute(h))).toEqual(h);
    }
    expect(formatRoute({ level: "history", filters: { since: "all" } })).toBe("/ui/history?since=all");
    expect(parse("/ui/history?since=yesterday")).toEqual({ level: "history", filters: {} });
  });
  test("a queue keeps its scope, check and low in the query; all is the default", () => {
    const q: Route = { level: "queue", row: "e3bfd3b0b0c30ee6", scope: "gate:deb-java", check: "f1NotWorse", low: true, filters: {} };
    expect(formatRoute(q)).toBe("/ui/queue/e3bfd3b0b0c30ee6?scope=gate%3Adeb-java&check=f1NotWorse&low=1");
    expect(parse(formatRoute(q))).toEqual(q);
    expect(formatRoute({ level: "queue", scope: "all", filters: {} })).toBe("/ui/queue");
  });
  test("research keeps its scope in the query; all is the default", () => {
    expect(formatRoute({ level: "research", scope: "gate:deb-java", filters: {} })).toBe("/ui/research?scope=gate%3Adeb-java");
    expect(formatRoute({ level: "research", scope: "all", filters: {} })).toBe("/ui/research");
    expect(crumbs({ level: "research", filters: {} }).map((c) => c.label)).toEqual(["Gates", "Research"]);
    expect(formatRoute({ level: "research", scope: "gate:deb-java", check: "f1NotWorse", rows: ["a", "b"], groups: ["none"], filters: {} }))
      .toBe("/ui/research?scope=gate%3Adeb-java&check=f1NotWorse&rows=a%2Cb&groups=none");
  });
  test("the jobs page sits under research", () => {
    expect(formatRoute({ level: "jobs", filters: {} })).toBe("/ui/research/jobs");
    expect(crumbs({ level: "jobs", filters: {} }).map((c) => c.label)).toEqual(["Gates", "Research", "Jobs"]);
  });
  test("page 1 stays out of the URL", () => {
    expect(formatRoute({ level: "gate", gate: "g", tab: "labels", filters: { page: 1 } })).toBe("/ui/gates/g/labels");
  });
});

describe("parseRoute", () => {
  test("routes round-trip", () => {
    for (const r of routes) expect(parse(formatRoute(r))).toEqual(r);
  });
  test("the gate path parses with or without its trailing slash", () => {
    expect(parse("/ui/gates/g")).toEqual({ level: "gate", gate: "g", tab: "checks", filters: {} });
    expect(parse("/ui/gates/g/checks/c/")).toEqual({ level: "check", gate: "g", check: "c", filters: {} });
  });
  test("unknown filters, tabs and verdicts are dropped", () => {
    expect(parse("/ui/gates/?tab=nope&verdict=maybe&page=x&foo=1")).toEqual({ level: "gates", tab: "gates", filters: {} });
  });
  test("paths outside the app are null", () => {
    for (const p of ["/ui/map/gates/", "/ui/hints/x", "/ui/queue/a/b", "/ui/historyx", "/ui/gates/g/nope", "/ui/gates/g/checks", "/ui/gates/g/checks/c/r/extra", "/ui/gates/g/findings/r/x", "/ui/gates/%E0%A4%A/"]) {
      expect(parse(p)).toBeNull();
    }
  });
});

describe("up and crumbs", () => {
  test("Esc walks one level at a time to the top", () => {
    const chain: string[] = [];
    for (let r: Route | null = routes[9]; r; r = up(r)) chain.push(formatRoute(r));
    expect(chain).toEqual([
      "/ui/gates/grype-upgrade/checks/f1NotWorse/3e91c0a7d2b4f816?image=core&verdict=tp",
      "/ui/gates/grype-upgrade/checks/f1NotWorse?image=core&verdict=tp",
      "/ui/gates/grype-upgrade/?image=core",
      "/ui/gates/",
    ]);
  });
  test("a finding from the Findings tab goes back to that tab", () => {
    expect(formatRoute(up(routes[10])!)).toBe("/ui/gates/grype-upgrade/findings");
  });
  test("crumbs are nouns, top first, the finding named when known", () => {
    expect(crumbs(routes[9], "CVE-2019-13139").map((c) => c.label)).toEqual(["Gates", "grype-upgrade", "f1NotWorse", "CVE-2019-13139"]);
    expect(crumbs(routes[10]).map((c) => c.label)).toEqual(["Gates", "grype-upgrade", "3e91c0a7d2b4f816"]);
    expect(crumbs(routes[0])).toEqual([{ label: "Gates", href: "/ui/gates/" }]);
  });
});

describe("inGate", () => {
  test("a gate screen keeps its tab in the other gate, anything else goes to its Checks", () => {
    expect(formatRoute(inGate(routes[6], "deb-npm"))).toBe("/ui/gates/deb-npm/labels");
    for (const r of [routes[0], routes[8], routes[9], routes.at(-1)!]) expect(formatRoute(inGate(r, "deb-npm"))).toBe("/ui/gates/deb-npm/");
  });
  test("the gate crumb names its gate, and the flow's screens sit under Gates", () => {
    expect(crumbs(routes[9]).map((c) => c.gate ?? "-")).toEqual(["-", "grype-upgrade", "-", "-"]);
    expect(crumbs(routes.at(-1)!).map((c) => c.label)).toEqual(["Gates", "History"]);
  });
});

describe("withFilters", () => {
  test("sets and drops filters, and resets the page unless it is the change", () => {
    const r: Route = { level: "check", gate: "g", check: "c", filters: { image: "a", page: 4 } };
    expect(withFilters(r, { image: undefined, verdict: "tp" }).filters).toEqual({ verdict: "tp" });
    expect(withFilters(r, { page: 5 }).filters).toEqual({ image: "a", page: 5 });
    expect(withFilters(r, { q: "" }).filters).toEqual({ image: "a" });
  });
});
