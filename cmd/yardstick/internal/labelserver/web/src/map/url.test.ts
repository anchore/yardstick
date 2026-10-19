import { describe, expect, test } from "bun:test";
import type { SubjectInfo } from "../gen/wire";
import { parseURL, urlFor, type View } from "./url";

const base = "/ui/map/gates/my%20gate/";
const subjects: SubjectInfo[] = [{ name: "alpine", slug: "alpine-3.20" }, { name: "debian", slug: "debian-12" }];
const none: View = { si: null, delta: false, zoom: null, cardsSpec: null, selected: null, evidence: false };

// where splits a URL the way location does
function where(url: string) {
  const u = new URL(url, "http://localhost");
  return { pathname: u.pathname, search: u.search, hash: u.hash };
}
const roundTrip = (v: View) => parseURL(base, where(urlFor(base, v, subjects)), subjects);

describe("urlFor", () => {
  test("the board is the gate's page path", () => {
    expect(urlFor(base, none, subjects)).toBe(base);
  });
  test("each view has its documented path", () => {
    expect(urlFor(base, { ...none, delta: true }, subjects)).toBe(`${base}delta`);
    expect(urlFor(base, { ...none, delta: true, zoom: { dir: "added", why: "none" } }, subjects)).toBe(`${base}delta/added/none`);
    expect(urlFor(base, { ...none, cardsSpec: { kind: "delta", dir: "added", why: "none", pkg: null } }, subjects)).toBe(`${base}delta/added/none/all`);
    expect(urlFor(base, { ...none, cardsSpec: { kind: "tier", check: "f1", tier: 2, dir: "dropped", pkg: "openssl" } }, subjects)).toBe(`${base}check/f1/tier/2/dropped/openssl`);
    expect(urlFor(base, { ...none, cardsSpec: { kind: "fails", check: "f1", vuln: null, pkg: null } }, subjects)).toBe(`${base}check/f1/fails`);
  });
  test("segments are escaped, the image is its slug, and the card goes in the hash", () => {
    const v: View = { ...none, si: 1, cardsSpec: { kind: "cause", check: "no new FNs", cause: "a/b" }, selected: "0123456789abcdef", evidence: true };
    expect(urlFor(base, v, subjects)).toBe(`${base}check/no%20new%20FNs/cause/a%2Fb?image=debian-12#row=0123456789abcdef&evidence`);
  });
  test("a selected row stays out of the URL without open cards", () => {
    expect(urlFor(base, { ...none, delta: true, selected: "0123456789abcdef" }, subjects)).toBe(`${base}delta`);
  });
  test("an image with no known slug is its index", () => {
    expect(urlFor(base, { ...none, si: 1 }, undefined)).toBe(`${base}?image=1`);
  });
});

describe("parseURL", () => {
  test("views round-trip", () => {
    const views: View[] = [
      none,
      { ...none, delta: true },
      { ...none, si: 0 },
      { ...none, delta: true, zoom: { dir: "dropped", why: "record/absent-in-candidate|ubuntu:distro:ubuntu:24.04|" } },
      { ...none, delta: true, zoom: { dir: "added", why: "none" }, cardsSpec: { kind: "delta", dir: "added", why: "none", pkg: null } },
      { ...none, delta: true, zoom: { dir: "added", why: "none" }, cardsSpec: { kind: "delta", dir: "added", why: "none", pkg: "@scope/pkg" }, selected: "00000000deadbeef" },
      { ...none, si: 1, cardsSpec: { kind: "cause", check: "f1NotWorse", cause: "c-1" }, selected: "0123456789abcdef", evidence: true },
      { ...none, cardsSpec: { kind: "tier", check: "noNewFalseNegatives", tier: 1, dir: "dropped", pkg: "glibc" } },
      { ...none, cardsSpec: { kind: "fails", check: "f1NotWorse", vuln: null, pkg: null } },
      { ...none, cardsSpec: { kind: "fails", check: "f1NotWorse", vuln: "CVE-2024-1", pkg: "zlib" } },
    ];
    for (const v of views) expect(roundTrip(v)).toEqual(v);
  });
  test("an image matches by slug, else by an index in range, else every image", () => {
    expect(parseURL(base, where(`${base}?image=debian-12`), subjects).si).toBe(1);
    expect(parseURL(base, where(`${base}?image=0`), subjects).si).toBe(0);
    expect(parseURL(base, where(`${base}?image=2`), subjects).si).toBeNull();
    expect(parseURL(base, where(`${base}?image=nope`), subjects).si).toBeNull();
  });
  test("a hash that is not a row id selects nothing", () => {
    const v = parseURL(base, where(`${base}check/f1/cause/c#row=xyz`), subjects);
    expect(v.selected).toBeNull();
    expect(v.evidence).toBe(false);
  });
  test("an incomplete check path opens no cards", () => {
    expect(parseURL(base, where(`${base}check/f1/tier/2/added`), subjects).cardsSpec).toBeNull();
    expect(parseURL(base, where(`${base}check/f1/cause`), subjects).cardsSpec).toBeNull();
  });
});
