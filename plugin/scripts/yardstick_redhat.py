"""Red Hat's security data as evidence for rpm matches: the CSAF VEX per CVE (per-binary-RPM status,
fixed NEVRAs per stream, not-affected justification flags) and the Hydra API (per-product fix_state
for unfixed packages, the analyst statement).

    vex = yardstick_redhat.vex("CVE-2024-38477")
    yardstick_redhat.binary_status(vex, major="8", binary="httpd-tools", installed="2.4.37-43.module+el8...")

Sources:
  https://security.access.redhat.com/data/csaf/v2/vex/<year>/cve-<id-lowercase>.json
  https://access.redhat.com/hydra/rest/securitydata/cve/<CVE>.json
"""
from __future__ import annotations

import re

import yardstick_common as dc

STREAM_RE = re.compile(r"^(?P<repo>[A-Za-z0-9_-]+?)-(?P<major>\d+)(?:\.(?P<minor>\d+))?(?:\.\d+)?(?:\.Z)?(?P<rest>.*)$")


def vex(cve: str) -> dict | None:
    year = cve.split("-")[1]
    return dc.fetch_json(f"https://security.access.redhat.com/data/csaf/v2/vex/{year}/{cve.lower()}.json")


def hydra(cve: str) -> dict | None:
    return dc.fetch_json(f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json")


def _stream_major(stream: str) -> tuple[str | None, str | None]:
    """'AppStream-8.8.0.Z.MAIN.EUS' -> ('8', '8.8'); 'red_hat_enterprise_linux_8' -> ('8', None); '7Server-7.7.AUS' -> ('7', '7.7')."""
    m = re.match(r"^red_hat_enterprise_linux_(\d+)", stream)
    if m:
        return m.group(1), None
    m = re.match(r"^(?:[A-Za-z0-9_-]+?)-(\d+)\.(\d+)", stream)
    if m:
        return m.group(1), f"{m.group(1)}.{m.group(2)}"
    m = re.match(r"^(\d+)(?:Server|Client|Workstation|ComputeNode|Base)", stream)
    if m:
        return m.group(1), None
    m = re.match(r"^(?:[A-Za-z0-9_-]+?)-(\d+)(?:$|[^.\d])", stream)
    if m:
        return m.group(1), None
    return None, None


def binary_status(doc: dict | None, major: str, binary: str, installed: str, source: str | None = None) -> dict:
    """What Red Hat's VEX says about one binary RPM on one RHEL major.

    Returns {status, flags, fixed: [(stream, nevra)], applicable_fix, comparison, advisories, statement_ids}
    status: 'fixed' | 'known_not_affected' | 'known_affected' | 'under_investigation' | 'not-listed'
    """
    out = {"status": "not-listed", "flags": [], "fixed": [], "applicable_fix": None, "comparison": None, "advisories": []}
    if not doc:
        return out
    v = (doc.get("vulnerabilities") or [{}])[0]
    ps = v.get("product_status") or {}
    flags = {}
    for f in v.get("flags") or []:
        for pid in f.get("product_ids", []):
            flags.setdefault(pid, []).append(f.get("label"))
    remed = {}
    for r in v.get("remediations") or []:
        if r.get("category") == "vendor_fix":
            for pid in r.get("product_ids", []):
                remed[pid] = r.get("url")

    def matches(pid: str) -> tuple[bool, str | None, str | None]:
        stream, _, comp = pid.partition(":")
        mj, minor = _stream_major(stream)
        if mj != major:
            return False, None, None
        n = dc.rpm_nevra(comp)
        name = n["name"] if n else comp.removesuffix(".src")
        if name == binary or (source and name == source and comp.endswith(".src")):
            return True, minor, (f"{n['epoch']}:{n['version']}-{n['release']}" if n and n.get("release") else None)
        return False, None, None

    # Red Hat's VEX has two shapes of product id. Unversioned ("red_hat_enterprise_linux_8:krb5-libs") is a statement
    # about the component on that product. Versioned ("BaseOS-8.10.0.Z.MAIN.EUS:vim-minimal-2:8.0.1763-22.el8_10.1.x86_64")
    # names one build: under `fixed` it is the fix, and under `known_not_affected` it means "not affected at this build",
    # i.e. also a fix. Only the unversioned form is a verdict about the package as such.
    for status in ("known_not_affected", "known_affected", "under_investigation", "fixed"):
        for pid in ps.get(status, []):
            ok, minor, evr = matches(pid)
            if not ok:
                continue
            if evr and status in ("fixed", "known_not_affected"):
                out["fixed"].append((minor, evr, remed.get(pid)))
                if out["status"] == "not-listed":
                    out["status"] = "fixed"
                continue
            if status != "fixed" and out["status"] in ("not-listed", "fixed"):
                out["status"] = status
            out["flags"] += flags.get(pid, [])
    out["flags"] = sorted(set(out["flags"]))
    if out["fixed"]:
        inst_minor = dc.rpm_dist_minor(dc.rpm_evr(installed)[2]) if installed else None
        # the stream the package came from (EUS minors fix at their own versions); otherwise the newest stream,
        # which is where a non-EUS package would be updated
        same = [f for f in out["fixed"] if f[0] == inst_minor]
        if not same:
            newest = max((f[0] for f in out["fixed"] if f[0]), key=lambda m: [int(x) for x in m.split(".")], default=None)
            same = [f for f in out["fixed"] if f[0] == newest] or out["fixed"]
        fix = min(same, key=lambda f: (dc.rpm_evr(f[1])[0], dc.rpm_evr(f[1])[1], dc.rpm_evr(f[1])[2]))
        out["applicable_fix"] = fix
        out["comparison"] = dc.rpm_compare(installed, fix[1]) if installed else None
        out["advisories"] = sorted({f[2] for f in out["fixed"] if f[2]})
    return out


def hydra_state(doc: dict | None, major: str, source: str | None) -> dict | None:
    """Hydra's package_state for the source package on this RHEL major: {fix_state, product_name}; plus the statement."""
    if not doc:
        return None
    for p in doc.get("package_state") or []:
        if p.get("product_name", "").endswith(f"Linux {major}") and (not source or p.get("package_name") == source):
            return {"fix_state": p.get("fix_state"), "product_name": p.get("product_name"), "package_name": p.get("package_name"), "statement": doc.get("statement")}
    return {"fix_state": None, "statement": doc.get("statement")} if doc.get("statement") else None


def components_named(text: str) -> list[str]:
    """Apache modules, shared objects and executables a vendor statement names: 'mod_proxy', 'libxml2.so.2', 'mod_http2'."""
    found = re.findall(r"\b(mod_[a-z0-9_]+)\b", text or "")
    found += re.findall(r"\b([a-zA-Z0-9_+.-]+\.so(?:\.\d+)*)\b", text or "")
    return list(dict.fromkeys(found))


def files_contain(files: list[str], component: str) -> bool:
    c = component.lower()
    return any(c in f.lower().rsplit("/", 1)[-1] for f in files)
