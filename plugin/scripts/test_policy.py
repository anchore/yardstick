#!/usr/bin/env python3
"""Fail when the triage scripts drift from the policy in the claims corpus's vocabulary.yaml.

    python3 -I plugin/scripts/test_policy.py        (set YARDSTICK_BIN to skip building yardstick)

Reads the policy through `yardstick claims policy -o json` in the checkout and checks that
every rule id the evidence script can emit is a listed rule whose verdict matches, that every rule names
a decision in claims/labeling-policy.md and says what it rests on, that every rule's justification is
listed under its verdict, that the justifications why_from_text derives are fp ones, and that every fact
source the scripts write is listed under fact-sources.
"""
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import importlib  # noqa: E402

import yardstick_common as dc  # noqa: E402

ev = importlib.import_module("yardstick-triage-evidence")

policy = dc.checkout_policy()
ev.set_policy(policy)
rules, reasons = ev.POLICY, ev.REASONS
# labeling-policy.md did not come along when the corpus moved to anchore/match-claims, so the decisions
# check runs only against a copy given in $LABELING_POLICY
doc_path = os.environ.get("LABELING_POLICY")
decisions = set(re.findall(r"^\| (P-\d+) \|", Path(doc_path).read_text(), re.M)) if doc_path else None
if decisions is None:
    print("skipped: the decisions check (set LABELING_POLICY to a labeling-policy.md)")
src = Path(ev.__file__).read_text()
emitted = set(re.findall(r"Verdict\(\s*\"(tp|fp|unclear)\",\s*\"(?:high|medium|low)\",\s*\"([a-z]+/[a-z0-9-]+)\"", src, re.S))

errors = []
for verdict, rule in emitted:
    if rule not in rules:
        errors.append(f"rule {rule} is emitted by the script but missing from rules: in vocabulary.yaml")
    elif rules[rule]["verdict"] not in ("any", verdict):
        errors.append(f"rule {rule} emits {verdict} but vocabulary.yaml says {rules[rule]['verdict']}")
NO_JUSTIFICATION_YET = {"judgement/prior-claims-pattern"}  # proposes either verdict; the reviewer states the justification
for rule, r in rules.items():
    verdict, why = r.get("verdict"), r.get("justification", "")
    if decisions is not None and r.get("decision") not in decisions:
        errors.append(f"rule {rule} cites {r.get('decision')}, which is not in the Decisions table of claims/labeling-policy.md")
    if not r.get("basis"):
        errors.append(f"rule {rule} has no basis")
    if why in ("", ev.PER_LABEL):
        if not why and rule not in NO_JUSTIFICATION_YET:
            errors.append(f"rule {rule} has no justification")
    elif why not in reasons:
        errors.append(f"rule {rule} has justification {why}, which is not listed under justifications:")
    elif verdict != "any" and reasons[why][0] != verdict:
        errors.append(f"rule {rule} proposes {verdict} but its justification {why} supports {reasons[why][0]}")
    if r.get("ceiling") not in ev.CONF_RANK or verdict not in ("tp", "fp", "unclear", "any"):
        errors.append(f"rule {rule} has a bad verdict/ceiling: {verdict}/{r.get('ceiling')}")
    if verdict == "unclear" and r.get("ceiling") != "low":
        errors.append(f"rule {rule}: unclear must have ceiling low")
for text in ("code not built", "only affects Windows", "vulnerable code introduced later", "fixed in 1.2", "rejected", "whatever"):
    kind = ev.why_from_text(text)
    if kind not in policy["justifications"]["fp"]:
        errors.append(f"why_from_text({text!r}) gives {kind}, which is not an fp justification")
sources = set(policy.get("factSources") or [])
for f in HERE.glob("yardstick*.py"):
    for s in set(re.findall(r"\bfact\(\s*\"([a-z][a-z0-9.-]*)\"", f.read_text())):
        if s not in sources and f.name != "yardstick-explain-evidence.py":  # explanations' facts are not label evidence
            errors.append(f"{f.name} writes fact source {s}, which is not listed under fact-sources: in vocabulary.yaml")
if errors:
    print("\n".join(errors))
    sys.exit(1)
print(f"ok: {len(emitted)} emitted rules, {len(rules)} policy rules, {len(decisions or ())} decisions, {len(reasons)} justifications")
