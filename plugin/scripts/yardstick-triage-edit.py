#!/usr/bin/env python3
"""Adjust drafted triage proposals by group number, then rewrite proposals.md.

    yardstick-triage-edit.py <triage-dir> <groups...> [--name PKG ...] [--verdict V] [--confidence C] [--note TEXT]
                         [--rule R] [--evidence KIND[:TEXT]] [--question Q ...] [--drop]

Groups are the numbers in evidence.md / proposals.md ("3", "7-9"); a token "row:<id>" selects one row.
--name limits the edit to rows for those binary packages within the groups (libssl1.1 fp while
libcrypto1.1 stays tp). --drop removes the group's lines
from proposals.jsonl so nothing is proposed for it. A note you write replaces the rule's note; keep
the deciding line first, the UI shows it. Changing the verdict without a rule leaves evidence[].rule empty
(a judgement call) unless you pass --rule. --evidence sets the proposal's justification (from justifications:
in the corpus's vocabulary.yaml, `yardstick claims policy`; the UI's headline), plus the specific after a colon,
which becomes the evidence's interpretation: `--evidence introduced-later:"pdfi, added in 9.55.0"`. A rule with a
known justification fills it in when you give none.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import importlib  # noqa: E402

import yardstick_common as dc  # noqa: E402

evidence = importlib.import_module("yardstick-triage-evidence")


def expand(specs: list[str]) -> set[int]:
    out = set()
    for s in specs:
        if not s:
            continue
        for part in s.replace(",", " ").split():
            if "-" in part:
                a, b = part.split("-", 1)
                out.update(range(int(a), int(b) + 1))
            else:
                out.add(int(part))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir")
    ap.add_argument("groups", nargs="+", help="group numbers, ranges, or row:<id>")
    ap.add_argument("--name", action="append", help="only rows for this binary package (repeatable)")
    ap.add_argument("--verdict", choices=["tp", "fp", "unclear"])
    ap.add_argument("--confidence", choices=["high", "medium", "low"])
    ap.add_argument("--note")
    ap.add_argument("--rule")
    ap.add_argument("--evidence", dest="why", help="JUSTIFICATION[:TEXT]; justifications are listed by `yardstick claims policy`")
    ap.add_argument("--question", action="append")
    ap.add_argument("--drop", action="store_true")
    args = ap.parse_args()

    d = Path(args.dir)
    groups = json.loads((d / "groups.json").read_text())
    store = Path(json.loads((d / "evidence.json").read_text())["store"])
    evidence.set_policy(dc.load_policy(dc.find_yardstick(store), store))
    row_tokens = [g[4:] for g in args.groups if g.startswith("row:")]
    wanted = {rid for n in expand([g for g in args.groups if not g.startswith("row:")]) for rid in groups.get(str(n), [])} | set(row_tokens)
    if args.name:
        ev = json.loads((d / "evidence.json").read_text())["rows"]
        names = set(args.name)
        wanted = {r["row_id"] for r in ev if r["row_id"] in wanted and r["name"] in names}
    if not wanted:
        sys.exit("no rows for those groups")
    lines = [json.loads(l) for l in (d / "proposals.jsonl").read_text().splitlines() if l.strip()]
    kept, touched = [], 0
    for p in lines:
        if p["row"] not in wanted:
            kept.append(p)
            continue
        touched += 1
        if args.drop:
            continue
        ev = (p.get("evidence") or [{"facts": []}])[0]
        if args.verdict and args.verdict != p["verdict"]:
            p["verdict"] = args.verdict
            ev["rule"] = args.rule or ""
        if args.rule:
            ev["rule"] = args.rule
        if args.confidence:
            p["confidence"] = args.confidence
        rule = ev.get("rule", "")
        r = evidence.POLICY.get(rule) or {}
        pv, ceiling = r.get("verdict", "any"), r.get("ceiling", "medium")
        if pv not in ("any", p["verdict"]):
            sys.exit(f"rule {rule} proposes {pv} per the policy (yardstick claims policy), not {p['verdict']}")
        if args.why or args.verdict or args.rule:
            kind, _, text = (args.why or "").partition(":")
            old = p.get("justification")
            if not kind and old in evidence.REASONS and evidence.REASONS[old][0] == p["verdict"]:
                kind, text = old, ev.get("interpretation", "")  # the earlier justification still fits
            try:
                why = evidence.why_for(rule, p["verdict"], kind or None, text)
            except ValueError as e:
                sys.exit(str(e))
            if why:
                p["justification"] = why["kind"]
            else:
                p.pop("justification", None)
            if why and why.get("text"):
                ev["interpretation"] = why["text"]
            else:
                ev.pop("interpretation", None)
        if p["verdict"] != "tp" and not p.get("justification"):
            allowed = sorted(k for k, (v, _) in evidence.REASONS.items() if v == p["verdict"])
            sys.exit(f"{p['verdict']} needs a justification: pass --evidence <one of {', '.join(allowed)}>[:TEXT]")
        if not ev.get("rule"):
            ev.pop("rule", None)
        if ev["facts"]:
            p["evidence"] = [ev] + (p.get("evidence") or [])[1:]
        else:
            p.pop("evidence", None)  # an evidence entry needs a fact, so a rule nothing observed for is dropped
        if evidence.CONF_RANK[p.get("confidence", "low")] > evidence.CONF_RANK[ceiling]:
            print(f"group {args.groups}: confidence clamped to {ceiling}, the ceiling for {rule or 'a rule-less judgement'} in the policy")
            p["confidence"] = ceiling
        if args.note:
            p["note"] = args.note
        if args.question:
            p["openQuestions"] = args.question
        if p["verdict"] != "unclear":
            p.pop("openQuestions", None) if not args.question else None
        kept.append(p)
    (d / "proposals.jsonl").write_text("".join(json.dumps(p) + "\n" for p in kept))
    ev = json.loads((d / "evidence.json").read_text())
    rows = ev["rows"]
    import collections
    gs: dict = collections.OrderedDict()
    for r in rows:
        gs.setdefault((r["side"], r["vulnerability"], r["source_pkg"]), []).append(r)
    evidence.write_proposals_md(d, rows, gs)
    model = next((p.get("author", {}).get("model") for p in kept if p.get("author")), "unknown")
    n = evidence.write_causes(d, rows, {p["row"]: p for p in kept}, model)
    print(f"{n} causes rewritten in causes.jsonl")
    print(f"{'dropped' if args.drop else 'updated'} {touched} proposal(s); {len(kept)} remain in {d / 'proposals.jsonl'}")


if __name__ == "__main__":
    main()
