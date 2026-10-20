// names.ts turns grype's namespaces and an image's distro into the names people read. Pure: no DOM,
// no page state.
import { detail, type Row } from "./rows";

const distroNames: Record<string, string> = { ubuntu: "Ubuntu", debian: "Debian", redhat: "RHEL", rhel: "RHEL", centos: "CentOS", fedora: "Fedora", alpine: "Alpine", amazonlinux: "Amazon Linux", amazon: "Amazon Linux",
  oraclelinux: "Oracle Linux", ol: "Oracle Linux", sles: "SLES", opensuse: "openSUSE", wolfi: "Wolfi", chainguard: "Chainguard", mariner: "Mariner", azurelinux: "Azure Linux", rocky: "Rocky", almalinux: "Alma",
  photon: "Photon", echo: "Echo", minimos: "MinimOS", secureos: "SecureOS", gentoo: "Gentoo", busybox: "BusyBox" };
const codenames: Record<string, Record<string, string>> = {
  ubuntu: { "12.04": "precise", "14.04": "trusty", "16.04": "xenial", "18.04": "bionic", "20.04": "focal", "22.04": "jammy", "24.04": "noble", "24.10": "oracular", "25.04": "plucky", "25.10": "questing", "26.04": "resolute",
    "20.10": "groovy", "21.04": "hirsute", "21.10": "impish", "22.10": "kinetic", "23.04": "lunar", "23.10": "mantic", "19.10": "eoan", "19.04": "disco", "18.10": "cosmic", "17.10": "artful" },
  debian: { 7: "wheezy", 8: "jessie", 9: "stretch", 10: "buster", 11: "bullseye", 12: "bookworm", 13: "trixie", 14: "forky", unstable: "sid" },
};

export type Namespace =
  | { kind: "distro"; provider: string; distro: string; version: string; esm: boolean }
  | { kind: "language"; provider: string; lang: string }
  | { kind: "cpe"; provider: string }
  | { kind: "other"; provider: string };

export interface Release { distro: string; version: string }

// nsParse reads a grype namespace: provider:distro:name:version, provider:language:lang, nvd:cpe
export function nsParse(ns: string | undefined): Namespace {
  const p = (ns || "").split(":");
  if (p[1] === "distro" && p.length >= 4) {
    let version = p.slice(3).join(":"), esm = false;
    if (/\+esm$/.test(version)) { esm = true; version = version.replace(/\+esm$/, ""); }
    if (p[2] === "ubuntu") version = version.replace(/^(\d\d)\.(\d)$/, "$1.0$2"); // 24.4 → 24.04
    return { kind: "distro", provider: p[0], distro: p[2], version, esm };
  }
  if (p[1] === "language") return { kind: "language", provider: p[0], lang: p[2] };
  if (p[0] === "nvd" && p[1] === "cpe") return { kind: "cpe", provider: "nvd" };
  return { kind: "other", provider: p[0] };
}
// nsHuman: "ubuntu:distro:ubuntu:24.04" → "Ubuntu 24.04 (noble)"; the raw namespace goes in the title
export function nsHuman(ns: string | undefined) {
  const n = nsParse(ns);
  if (n.kind === "distro") {
    const name = distroNames[n.distro] || n.distro, code = codenames[n.distro]?.[n.version];
    return `${name} ${n.version}${code ? ` (${code})` : ""}${n.esm ? " ESM" : ""}${n.provider !== n.distro && !(n.provider === "redhat" && n.distro === "rhel") ? ` · ${n.provider} data` : ""}`;
  }
  if (n.kind === "language") return `${n.provider === "github" ? "GitHub advisories" : n.provider} · ${n.lang}`;
  if (n.kind === "cpe") return "NVD (CPE)";
  return ns || "";
}
// imageRelease is the distro the image is, from grype's view of it or the purl's distro qualifier
export function imageRelease(r: Row): Release | null {
  const d = detail(r)?.distro || "";
  let m = d.match(/^(\S+)\s+(\S+)$/);
  if (!m) { const q = (r.package.ref || "").match(/[?&]distro=([^&#]+)/); if (q) m = decodeURIComponent(q[1]).match(/^(.+?)-(.+)$/); }
  if (!m) return null;
  return { distro: m[1].toLowerCase().replace(/^rhel$/, "redhat"), version: m[2] };
}
// releaseName is a release as people say it: "Debian 11 (bullseye)", "SecureOS 2025.09.09"
export const releaseName = (r: Release) => nsHuman(`${r.distro}:distro:${r.distro}:${r.version}`);
// sameRelease is true when a namespace is the image's own distro release (ESM counts)
export function sameRelease(ns: string | undefined, rel: Release | null) {
  if (!rel) return false;
  const n = nsParse(ns);
  if (n.kind !== "distro") return false;
  const a = (n.distro === "rhel" ? "redhat" : n.distro), b = rel.distro;
  const major = (v: string) => String(v).split(".")[0];
  // Red Hat namespaces carry the major only (redhat:distro:redhat:8); an image says 8.6
  return a === b && (n.version === rel.version || (a === "redhat" && major(n.version) === major(rel.version)));
}
