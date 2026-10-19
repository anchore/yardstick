// tile.ts is the Focus tile: everything that renders one finding, ported from delta. The page keeps its own layout, ordering, URLs and
// keys and calls render(container, ctx). ctx carries the run's state, the row,
// the check being worked on, the page's toggles and caches, and the actions the buttons call.
//
// ctx: { state, run, get, r, si, dir, check, reexamine, tierName, counter, receipt, backKey,
//        canStay, why, more, note, matches: Map, details: Map, subjectName(si),
//        on: { label(verdict, justification), accept(rows), acceptCause(cause), research(rows),
//              toggleWhy(), toggleMore(), note(text), skip() } }
//
// receipt is { text, plain?, from? }: set it once per label and keep the same object across
// re-renders. canStay says the page honours autoAdvance() (false: stay on the labeled
// match after a label), and shows the switch for it.
const tile = (() => {
  const $ = (s) => document.querySelector(s);

  const labels = {
    tp: { glyph: "●", word: "TP", long: "real match" },
    fp: { glyph: "○", word: "FP", long: "false match" },
    unclear: { glyph: "◐", word: "unclear", long: "unclear" },
  };
  const dots = { high: "•••", medium: "••◦", low: "•◦◦" };
  const marks = { added: "+", dropped: "−", both: "=", neither: "∅" };
  const dirWords = { added: "the candidate added this", dropped: "the candidate dropped this", both: "both sides found this", neither: "neither side found this" };

  function el(tag, attrs = {}, ...children) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === "class") n.className = v;
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? "" : v);
    }
    n.append(...children.flat(Infinity).filter((c) => c != null && c !== false));
    return n;
  }
  const plural = (n, w, many = `${w}s`) => `${n} ${n === 1 ? w : many}`;
  const fmt = (x) => (Number.isInteger(x) ? String(x) : Math.abs(x) < 10 ? x.toFixed(3) : x.toFixed(1));
  const signed = (x) => (x > 0 ? `+${fmt(x)}` : fmt(x));
  let toastTimer;
  function toast(msg, error = false) {
    const t = $("#toast");
    if (!t) return;
    t.textContent = msg; t.className = `toast${error ? " error" : ""}`; t.hidden = false;
    clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.hidden = true), error ? 6000 : 2500);
  }
  function direction(r) {
    if (r.inCandidate && !r.inReference) return "added";
    if (!r.inCandidate && r.inReference) return "dropped";
    return r.inCandidate ? "both" : "neither";
  }
  function pkgOf(ref) {
    const m = (ref || "").match(/^pkg:([^/]+)\/(?:.*\/)?([^@?#]+)(?:@([^?#]+))?/);
    return { type: m?.[1] || "", name: decodeURIComponent(m?.[2] || ref || ""), version: decodeURIComponent(m?.[3] || "") };
  }
  const detail = (r) => r.candidate || r.reference;
  const otherRecords = (r) => (direction(r) === "added" ? r.referenceRecords : r.candidateRecords) || [];
  const isOpen = (r) => r.verdict === "unlabeled" || r.verdict === "unclear" || !!r.conflict;
  const hinted = (r) => r.hint?.status === "pending" && isOpen(r);

  function whyText(w, dir) {
    if (!w) return "";
    const other = dir === "added" ? "reference" : "candidate";
    switch (w.key) {
      case "record/rejected-in-candidate": return "the candidate's DB marks this vulnerability rejected";
      case "record/rejected-in-reference": return "the reference DB marks this vulnerability rejected";
      case "record/absent-in-reference": return `the reference DB has no record of this vulnerability under any alias${w.to ? `; the candidate's has one in ${w.to}` : ""}`;
      case "record/absent-in-candidate": return `the candidate's DB has no record of this vulnerability under any alias${w.from ? `; the reference's had one in ${w.from}` : ""}`;
      case "package/absent-in-reference": return "the reference DB knows the vulnerability but has no record for this package or its source package";
      case "package/absent-in-candidate": return "the candidate's DB knows the vulnerability but has no record for this package or its source package";
      case "namespace/changed": return `the other DB's record is in another namespace: ${w.from} → ${w.to}`;
      case "fix-state/changed": return `the fix state changed: ${w.from} → ${w.to}`;
      case "constraint/changed": return "the version constraint changed between the two DBs";
      case "record/same-but-unmatched": return `the ${other} DB has the same record and its grype still didn't match: a matcher or config difference`;
      case "match-type/cpe-only": return "the reporting side matched by CPE only";
      case "matcher/changed": return "the matcher changed";
      case "unexplained": return "unexplained by the data on the row";
      default: return w.key;
    }
  }
  // justWords is a justification's description from the claims vocabulary, else the value itself
  const justWords = (state, verdict, j) => (j ? state?.vocabulary?.justifications?.[verdict]?.[j] || j : "");
  // ruleWords turns a rule id into words: "sbom/code-not-in-binary" → "sbom: code not in binary"
  const ruleWords = (rule) => (rule ? rule.replace("/", ": ").replace(/-/g, " ") : "");
  // firstSentence is the note's first sentence, cut at about 110 characters
  function firstSentence(text) {
    const m = (text || "").match(/^.*?[.;](\s|$)/);
    let t = (m ? m[0] : text || "").trim().replace(/[.;]$/, "");
    if (t.length > 110) t = `${t.slice(0, 108).replace(/\s+\S*$/, "")}…`;
    return t;
  }

  // ---------- names people read ----------

  const distroNames = { ubuntu: "Ubuntu", debian: "Debian", redhat: "RHEL", rhel: "RHEL", centos: "CentOS", fedora: "Fedora", alpine: "Alpine", amazonlinux: "Amazon Linux", amazon: "Amazon Linux",
    oraclelinux: "Oracle Linux", ol: "Oracle Linux", sles: "SLES", opensuse: "openSUSE", wolfi: "Wolfi", chainguard: "Chainguard", mariner: "Mariner", azurelinux: "Azure Linux", rocky: "Rocky", almalinux: "Alma",
    photon: "Photon", echo: "Echo", minimos: "MinimOS", gentoo: "Gentoo", busybox: "BusyBox" };
  const codenames = {
    ubuntu: { "12.04": "precise", "14.04": "trusty", "16.04": "xenial", "18.04": "bionic", "20.04": "focal", "22.04": "jammy", "24.04": "noble", "24.10": "oracular", "25.04": "plucky", "25.10": "questing", "26.04": "resolute",
      "20.10": "groovy", "21.04": "hirsute", "21.10": "impish", "22.10": "kinetic", "23.04": "lunar", "23.10": "mantic", "19.10": "eoan", "19.04": "disco", "18.10": "cosmic", "17.10": "artful" },
    debian: { 7: "wheezy", 8: "jessie", 9: "stretch", 10: "buster", 11: "bullseye", 12: "bookworm", 13: "trixie", 14: "forky", unstable: "sid" },
  };
  // nsParse reads a grype namespace: provider:distro:name:version, provider:language:lang, nvd:cpe
  function nsParse(ns) {
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
  function nsHuman(ns) {
    const n = nsParse(ns);
    if (n.kind === "distro") {
      const name = distroNames[n.distro] || n.distro, code = codenames[n.distro]?.[n.version];
      return `${name} ${n.version}${code ? ` (${code})` : ""}${n.esm ? " ESM" : ""}${n.provider !== n.distro && !(n.provider === "redhat" && n.distro === "rhel") ? ` · ${n.provider} data` : ""}`;
    }
    if (n.kind === "language") return `${n.provider === "github" ? "GitHub advisories" : n.provider} · ${n.lang}`;
    if (n.kind === "cpe") return "NVD (CPE)";
    return ns || "";
  }
  const nsChip = (ns, cls = "") => el("span", { class: `ns ${cls}`, title: ns }, nsHuman(ns));
  // imageRelease is the distro the image is, from grype's view of it or the purl's distro qualifier
  function imageRelease(r) {
    const d = detail(r)?.distro || "";
    let m = d.match(/^(\S+)\s+(\S+)$/);
    if (!m) { const q = (r.package.ref || "").match(/[?&]distro=([^&#]+)/); if (q) m = decodeURIComponent(q[1]).match(/^(.+?)-(.+)$/); }
    if (!m) return null;
    return { distro: m[1].toLowerCase().replace(/^rhel$/, "redhat"), version: m[2] };
  }
  // sameRelease is true when a namespace is the image's own distro release (ESM counts)
  function sameRelease(ns, rel) {
    if (!rel) return false;
    const n = nsParse(ns);
    if (n.kind !== "distro") return false;
    const a = (n.distro === "rhel" ? "redhat" : n.distro), b = rel.distro;
    const major = (v) => String(v).split(".")[0];
    // Red Hat namespaces carry the major only (redhat:distro:redhat:8); an image says 8.6
    return a === b && (n.version === rel.version || (a === "redhat" && major(n.version) === major(rel.version)));
  }
  function releaseHuman(rel) {
    if (!rel) return "";
    const name = distroNames[rel.distro] || rel.distro, code = codenames[rel.distro]?.[rel.version];
    return `${name} ${rel.version}${code ? ` (${code})` : ""}`;
  }

  // ---------- the match path: how grype got from the package to the match, one lane per side ----------

  // steps reads grype's matchDetails (from the raw match) into the steps of the path. Without a
  // match, the lane stops where the row's data says it diverged.
  function steps(r, dir, side, raw, rel) {
    const pk = pkgOf(r.package.ref), d = side === "candidate" ? r.candidate : r.reference;
    const out: any[] = [{ k: "package", t: `${pk.name} ${pk.version}`, sub: pk.type || "" }];
    const md = raw?.matchDetails?.[0];
    if (d) {
      const sb = md?.searchedBy || {}, fd = md?.found || {};
      const viaName = sb.package?.name && sb.package.name !== pk.name ? sb.package.name : (d.matchTypes || []).includes("exact-indirect-match") && (d.upstreams || [])[0] ? d.upstreams[0] : null;
      if (sb.cpes?.length || (d.matchTypes || []).includes("cpe-match")) out.push({ k: "via", t: "as CPE", sub: (sb.cpes || d.cpes || [])[0] || "", title: (sb.cpes || d.cpes || []).join("\n") });
      else if (viaName) out.push({ k: "via", t: `via source package ${viaName}`, sub: sb.package?.version && sb.package.version !== pk.version ? sb.package.version : "" });
      out.push({ k: "searched", t: nsHuman(sb.namespace || d.namespace), sub: (md?.matcher || (d.matchers || [])[0] || "").replace(/-matcher$/, " matcher"), title: sb.namespace || d.namespace, same: sameRelease(sb.namespace || d.namespace, rel) });
      const cons = fd.versionConstraint || (d.constraints || [])[0] || "";
      out.push({ k: "record", t: `${fd.vulnerabilityID || r.vulnerability}`, sub: `affected ${cons && cons !== "none" ? cons.replace(/\s*\((\w[\w-]*)\)$/, "") : "every version"}${d.fixState === "fixed" && d.fixVersions?.length ? ` · fixed in ${d.fixVersions[0]}` : d.fixState ? ` · ${d.fixState.replace(/-/g, " ")}` : ""}`, title: cons });
      out.push({ k: "result", t: "matched", sub: (md?.type || (d.matchTypes || [])[0] || "").replace(/-match$/, ""), ok: true });
      return out;
    }
    // no match on this side: where did it stop?
    const w = r.why?.key || "", status = side === "candidate" ? r.candidateStatus : r.referenceStatus;
    const recs = side === "candidate" ? r.candidateRecords : r.referenceRecords;
    const other = side === "candidate" ? r.reference : r.candidate;
    const otherNs = other?.namespace;
    const mine = (recs || []).find((x) => sameRelease(x.namespace, rel)) || (recs || [])[0];
    if (status === "rejected") { out.push({ k: "searched", t: nsHuman(otherNs), title: otherNs }, { k: "record", t: r.vulnerability, sub: "rejected", miss: true }, { k: "result", t: "no match", miss: true }); return out; }
    if (status === "not-in-db" || /^record\/absent/.test(w)) { out.push({ k: "searched", t: "every namespace", sub: "all aliases" }, { k: "record", t: "no record", sub: `${r.vulnerability} is not in this DB`, miss: true }, { k: "result", t: "no match", miss: true }); return out; }
    if (/^package\/absent/.test(w)) {
      out.push({ k: "searched", t: nsHuman(otherNs), title: otherNs, same: sameRelease(otherNs, rel) });
      out.push({ k: "record", t: "no record for this package", sub: mine ? `the DB has it under ${nsHuman(mine.namespace)}` : `${r.vulnerability} is known, ${pk.name}${r.sourcePackage && r.sourcePackage !== pk.name ? ` / ${r.sourcePackage}` : ""} isn't listed`, miss: true, title: mine?.namespace });
      out.push({ k: "result", t: "no match", miss: true });
      return out;
    }
    if (mine) {
      const c = (mine.constraints || [])[0] || "";
      const changed = /^(constraint|fix-state|namespace)\/changed$/.test(w);
      out.push({ k: "searched", t: nsHuman(mine.namespace), title: mine.namespace, same: sameRelease(mine.namespace, rel), diff: w === "namespace/changed" });
      out.push({ k: "record", t: mine.vulnerability || r.vulnerability, sub: `affected ${c && c !== "none" ? c.replace(/\s*\((\w[\w-]*)\)$/, "") : "every version"}${mine.fixVersions?.length ? ` · fixed in ${mine.fixVersions[0]}` : mine.fixStates?.length ? ` · ${mine.fixStates.join("/").replace(/-/g, " ")}` : ""}`, title: (mine.constraints || []).join(" || "), diff: changed });
      out.push({ k: "result", t: "no match", sub: w === "record/same-but-unmatched" ? "same record: the matcher or its config differs" : changed ? "the record differs" : "", miss: true });
      return out;
    }
    out.push({ k: "result", t: "no match", sub: w === "unexplained" ? "unexplained by the row's data" : "", miss: true });
    return out;
  }

  // the kinds of step, in path order: a lane puts each step in its kind's column, so equivalent steps
  // (namespace and namespace, record and record) line up, and a kind one side lacks is an empty slot
  const stepKinds = ["package", "via", "searched", "record", "result"];

  function matchPath(r, dir, m, rel) {
    const lanes = [["candidate", m?.candidate?.[0]], ["reference", m?.reference?.[0]]].map(([side, raw]) => ({ side, steps: steps(r, dir, side, raw, rel) }));
    // a step differs when the other lane has no step of that kind, or its text differs
    const byKind = (l, k) => l.steps.find((s) => s.k === k);
    for (const l of lanes) for (const s of l.steps) {
      const o = byKind(lanes.find((x) => x !== l), s.k);
      // the record's constraint and fix are part of what it is; a step's matcher or match type isn't
      if (!o || o.t !== s.t || (s.k === "record" && (o.sub || "") !== (s.sub || ""))) s.diff = true;
    }
    const chip = (s) => el("span", { class: `step ${s.k}${s.diff ? " diff" : ""}${s.miss ? " miss" : ""}${s.ok ? " ok" : ""}${s.same ? " same" : ""}`, title: s.title || "" },
      el("span", { class: "t" }, s.t), s.sub ? el("span", { class: "sub" }, s.sub) : null, s.same ? el("span", { class: "mine" }, "this image's release") : null);
    const kinds = stepKinds.filter((k) => lanes.some((l) => byKind(l, k)));
    // one grid row per lane: the side's name, then a cell per kind with an arrow before it
    return el("div", { class: `path k${kinds.length}` }, lanes.flatMap((l) => [
      el("span", { class: "lane-k" }, l.side),
      kinds.flatMap((k, i) => { const s = byKind(l, k);
        return [i ? el("span", { class: `arrow${s ? "" : " none"}` }, s ? "→" : "") : null, s ? chip(s) : el("span", { class: "slot", title: `no ${k} step on the ${l.side} side` })]; }),
    ]));
  }

  // records lists what the other DB has for the package in other releases, the image's own release
  // first and bold, the rest dimmed
  function records(r, dir, rel) {
    const recs = otherRecords(r);
    if (!recs.length) return null;
    const sorted = [...recs].sort((a, b) => Number(sameRelease(b.namespace, rel)) - Number(sameRelease(a.namespace, rel)));
    const cons = (list) => (list || []).map((c) => c.replace(/\s*\((\w[\w-]*)\)$/, "")).join(" ‖ ");
    return el("div", { class: "records" }, el("span", { class: "k" }, `the ${dir === "added" ? "reference" : "candidate"} DB also has, for ${r.sourcePackage || pkgOf(r.package.ref).name}:`),
      sorted.map((rec) => el("div", { class: `rec${sameRelease(rec.namespace, rel) ? " same" : " other"}` }, nsChip(rec.namespace),
        ` · ${rec.constraints?.length ? `affected ${cons(rec.constraints)}` : "every version"}${rec.fixVersions?.length ? ` · fixed in ${rec.fixVersions.join(", ")}` : rec.fixStates?.length ? ` · ${rec.fixStates.join("/").replace(/-/g, " ")}` : ""}`)));
  }

  // ---------- the gate, as the tile reads it ----------

  const checksOf = (state) => state.gate?.result?.checks || [];
  const outcomeNow = (state) => state.gate?.result?.outcome;
  // endsGate: one label on this row would change the gate's outcome now
  const endsGate = (state, r) => { const now = outcomeNow(state); return !!r.gate && !!now && (r.gate.ifTP?.outcome !== now || r.gate.ifFP?.outcome !== now); };
  // regressionRisk: a dropped row while a check counting false negatives is open (one TP fails it)
  const regressionRisk = (state, dir) => dir === "dropped" && checksOf(state).some((c) => c.counts === "fn" && c.state === "undecided");

  // ---------- what a label does ----------

  // effects is the glossary's fixed/introduced table: what a TP or FP label on a delta says about
  // the candidate. A match both scans report has no entry: its label fixes or introduces nothing.
  const effects = {
    added: { tp: "fixed a false negative", fp: "introduced a false positive" },
    dropped: { tp: "introduced a false negative", fp: "fixed a false positive" },
  };

  // effect is the first line of the label box: a fact about the candidate, not about the gate. A
  // TP or FP label states the one that applies; otherwise it says what each label would mean.
  function effect(ctx) {
    const { r, dir, check: c } = ctx, e = effects[dir];
    if (!e) return null;
    if ((r.verdict === "tp" || r.verdict === "fp") && !r.conflict) {
      return el("div", { class: "effect fact" }, el("b", {}, `The candidate ${e[r.verdict]}`),
        ctx.reexamine && c ? el("span", { class: "muted" }, ` · ${c.name} fails on this label; relabel it if it's wrong`) : null);
    }
    const half = (v, lead) => el("span", { class: "eff", id: `eff-${v}` }, "If ", el("span", { class: `v-${v}` }, `${labels[v].glyph} ${labels[v].word}`), `: ${lead} ${e[v]}`);
    return el("div", { class: "effect" }, half("tp", "the candidate"), el("span", { class: "muted" }, " · "), half("fp", "it"));
  }
  // preview lights the half of the effect line that the hovered or focused button would make true
  function preview(v) {
    for (const k of ["tp", "fp"]) $(`#eff-${k}`)?.classList.toggle("lit", k === v);
  }

  // ---------- what an agent said ----------

  const hintStatus = { accepted: "the label came from it", agrees: "the label agrees", disagrees: "⚠ the label disagrees" };

  // isResearched is the one place that decides whether a match counts as researched: the server's
  // row.researched, true when research-vuln output exists for it, however it was started (label UI,
  // `delta research`, a hand-run session): a research-vuln hint or a finished research job, with or
  // without a hint. A triage-deltas hint alone is the middle level (Will, 2026-10-13).
  const isResearched = (r) => !!r.researched;

  // researchLevel is "" (no agent hint, no research-vuln output), "triaged" (a triage-deltas hint, no
  // research-vuln output) or "researched". The tile shows only "researched": next to the hint chip
  // "triaged" is redundant; Map's lists, which hide the hints, show both.
  const researchLevel = (r) => (isResearched(r) ? "researched" : r.researchLevel || "");

  // provenance says where a hint came from: the skill, and who started the research that left it
  const originWords = { "label-ui": "requested in the label UI", cli: "requested with yardstick", "research-job": "requester not recorded" };
  function provenance(h) {
    const skill = h.skill || "an agent";
    return `✦ ${skill}${h.origin && h.origin !== "skill-run" && originWords[h.origin] ? ` · ${originWords[h.origin]}` : ""}`;
  }

  // researchLine says where the row's newest research job is when the "✦ researched" mark doesn't
  // already: running, failed, or done after the hint shown without leaving a new one
  function researchLine(r) {
    const j = r.research;
    if (!j) return "";
    if (j.status === "queued" || j.status === "running") return `⧗ research ${j.status}`;
    if (j.status === "cancelled") return "research cancelled";
    if (j.status !== "done") return `research ${j.status}${j.error ? `: ${j.error}` : ""}`;
    if (!r.hint) return "";
    const fresh = r.hint.written && j.started && new Date(r.hint.written) >= new Date(j.started);
    const when = j.finished ? ` ${new Date(j.finished).toLocaleDateString()}` : "";
    return fresh ? "" : `research${when} left no new agent hint; the one here is older`;
  }

  // agent is the agent hint for the row, open or already labeled, and the row's research. The
  // verdict and confidence are the button that opens the hint's note, facts and rule (w).
  function agent(ctx, h, cause) {
    const { r, on } = ctx, pending = h?.status === "pending" && isOpen(r);
    const line = researchLine(r);
    const off = ctx.state?.research && !ctx.state.research.available ? ctx.state.research : null;
    const foot = el("div", { class: "foot" }, line || null, el("button", { class: "ghost", onclick: () => on.research([r.id]), disabled: !!off, title: off ? `research disabled: ${off.reason}${off.command ? `; run ${off.command}` : ""}` : null }, isResearched(r) ? "research again" : "research"), el("kbd", {}, "R"));
    if (!h) {
      return el("div", { class: "agent none" }, isResearched(r) ? el("span", { class: "researched" }, "✦ researched, no hint") : el("span", {}, "✦ no agent hint"), foot);
    }
    return el("div", { class: `agent${pending ? "" : " settled"}${ctx.why ? " open" : ""}` },
      el("h2", {}, "Agent hint"),
      el("div", { class: "head" },
        el("button", { class: "verdict", "aria-expanded": ctx.why ? "true" : "false", title: ctx.why ? "hide the note and facts (w)" : "show the note and facts (w)", onclick: () => on.toggleWhy() },
          el("span", { class: "star" }, "✦"), el("span", { class: `v-${h.verdict} big` }, `${labels[h.verdict].glyph} ${labels[h.verdict].word}`),
          el("span", { class: "conf" }, `${h.confidence} ${dots[h.confidence] || ""}`), el("span", { class: "caret" }, ctx.why ? "▾" : "▸")),
        el("span", { class: "reason", id: "hint-reason", title: h.rule ? `rule ${h.rule}${h.decision ? ` · policy ${h.decision}` : ""}` : "" }, h.title || justWords(ctx.state, h.verdict, h.justification) || ruleWords(h.rule)),
        pending ? null : el("span", { class: `status ${h.status}` }, hintStatus[h.status] || h.status)),
      el("div", { class: "from", title: [h.model ? `model ${h.model}` : "", h.researchJob ? `research job ${h.researchJob}` : ""].filter(Boolean).join(" · ") },
        el("span", { class: "skill" }, provenance(h)),
        h.written ? el("span", {}, new Date(h.written).toLocaleDateString()) : null,
        isResearched(r) ? el("span", { class: "researched" }, "✦ researched") : null),
      ctx.why ? el("div", { class: "note", id: "hint-note" }, "…") : null,
      ctx.why ? el("ul", { class: "facts", id: "hint-facts" }) : null,
      ctx.why ? el("div", { class: "rule", id: "hint-rule" }, h.rule ? `rule: ${ruleWords(h.rule)}${h.decision ? ` · policy ${h.decision}` : ""}` : "") : null,
      pending && cause ? el("div", { class: "group" }, `✦ same reasoning on ${plural(cause.pending.length, "unlabeled match", "unlabeled matches")} (${cause.sourcePackage}): `, el("button", { class: "ghost", onclick: () => on.acceptCause(cause) }, `accept all ${cause.pending.length} as ${labels[cause.verdict].glyph} ${labels[cause.verdict].word}`), " ", el("kbd", {}, "A")) : null,
      foot);
  }

  // ---------- the tile ----------

  let shown = null; // the row id on screen, so late fetches don't paint over the next finding

  // ---------- after labeling: the receipt and whether to move on ----------

  // autoAdvance is the reader's standing choice, kept in localStorage: after a label, move to the
  // next match (the default) or stay on the one just labeled. Pages that honour it pass canStay.
  const advanceKey = "yardstick.autoAdvance";
  const autoAdvance = () => localStorage.getItem(advanceKey) !== "off";
  const setAutoAdvance = (on) => (on ? localStorage.removeItem(advanceKey) : localStorage.setItem(advanceKey, "off"));

  // A page sets ctx.receipt = { text } once per label and keeps that object while it re-renders.
  // The tile remembers which row was on screen when a receipt's page moved to another, so the
  // receipt can name both the match labeled and the one now shown, for as long as it stands.
  let shownRow = null;
  const receiptFrom = new WeakMap();
  const matchName = (x) => `${x.vulnerability} ${pkgOf(x.package.ref).name}`;
  function receipt(ctx, prev) {
    const { r, receipt: rc } = ctx;
    const counter = el("div", { class: "receipt muted" }, ctx.counter || "", ctx.tierName ? ` · ${ctx.tierName}` : "");
    if (!rc) return counter;
    if (rc.from == null && !receiptFrom.has(rc) && prev && prev.id !== r.id) receiptFrom.set(rc, prev);
    const from = rc.from || receiptFrom.get(rc);
    const what = rc.text.replace(/ recorded\b/, "");
    const bar = rc.plain ? el("div", { class: "receipt bar", role: "status" }, el("b", {}, rc.text))
      : from ? el("div", { class: "receipt bar moved", role: "status" }, "Labeled ", el("b", {}, matchName(from)), `: ${what}`, el("span", { class: "sep" }, " · "), "now on ", el("b", {}, matchName(r)),
        ctx.backKey ? [el("span", { class: "sep" }, " · "), "back ", el("kbd", {}, ctx.backKey)] : null)
        : el("div", { class: "receipt bar", role: "status" }, "Labeled ", el("b", {}, matchName(r)), `: ${what}`, ctx.on.skip ? [el("span", { class: "sep" }, " · "), "next ", el("kbd", {}, "j")] : null);
    return [bar, counter];
  }
  // advanceToggle is the standing "after labeling, go to the next match" switch
  const advanceToggle = (ctx) => (ctx.canStay ? el("label", { class: "advance", title: "kept in this browser" },
    el("input", { type: "checkbox", checked: autoAdvance(), onchange: (e) => { setAutoAdvance(e.target.checked); e.target.blur(); } }),
    " after labeling, go to the next match") : null);

  function render(container, ctx) {
    const { state, r, dir, on } = ctx;
    shown = r.id;
    const prev = shownRow;
    shownRow = r;
    const pk = pkgOf(r.package.ref);
    const h = hinted(r) ? r.hint : null;
    const rel = imageRelease(r);
    const cause = (r.causes || []).map((id) => (state.causes || []).find((k) => k.id === id)).find((k) => k && k.pending?.length > 1);
    const btn = (v, key) => el("button", {
      class: `btn ${v}${r.verdict === v && !r.conflict ? " filled" : ""}${h?.verdict === v ? " hinted" : h ? " quiet" : ""}`,
      title: h?.verdict === v ? "the agent hint: accept it (a)" : labels[v].long,
      onclick: () => (h?.verdict === v ? on.accept([r.id]) : on.label(v)),
      onmouseenter: () => preview(v), onmouseleave: () => preview(null), onfocus: () => preview(v), onblur: () => preview(null),
    }, h?.verdict === v ? el("span", { class: "cap" }, "✦ agent hint") : null, el("span", { class: "lbl" }, `${labels[v].glyph} ${labels[v].word}`, el("kbd", {}, key)));
    container.classList.add("tile");
    // replaceChildren turns null into the text "null": the parts that may be absent are dropped first
    container.replaceChildren(...[
      receipt(ctx, prev),
      el("div", { class: "title" },
        el("span", { class: "mark", title: dirWords[dir] }, marks[dir]),
        el("span", { class: "vuln" }, r.vulnerability),
        el("span", { class: "pkg" }, `${pk.name} ${pk.version}`),
        el("span", { class: "img" }, ctx.subjectName(ctx.si), rel ? ` · ${releaseHuman(rel)}` : ""),
        (r.aliases || []).filter((a) => a !== r.vulnerability).map((a) => el("span", { class: "alias" }, a)),
        !ctx.reexamine && endsGate(state, r) ? el("span", { class: "decisive" }, "◆ a label here ends the gate") : null,
        r.conflict ? el("span", { class: "conflict" }, "⚡ people's labels disagree") : null),
      // three sections that look different on purpose: why the scans differ (open, on the page), what
      // the agent thinks (its tinted card), and the label (one solid box: what it does, the
      // controls, who labeled it)
      el("section", { class: "sec sec-why" },
        el("h2", {}, "Why the scans differ"),
        el("div", { class: "why" }, el("b", {}, `${dirWords[dir][0].toUpperCase()}${dirWords[dir].slice(1)}`), r.why ? `: ${whyText(r.why, dir)}` : "", (r.why?.secondary || []).map((s) => ` · ${whyText(s, dir)}`)),
        el("div", { id: "path" }, matchPath(r, dir, ctx.matches.get(r.id), rel)),
        records(r, dir, rel)),
      el("section", { class: "sec sec-agent" }, agent(ctx, h || r.hint, cause)),
      el("section", { class: "sec sec-label" },
        el("h2", {}, "Label"),
        effect(ctx),
        el("div", { class: "buttons" }, btn("tp", "t"), btn("fp", "f"), btn("unclear", "u"), on.skip ? el("button", { class: "btn skip", onclick: () => on.skip() }, "skip", el("kbd", {}, "j")) : null, advanceToggle(ctx)),
        picker(ctx),
        el("input", { class: "note", id: "note", placeholder: "note for the label (n)", value: ctx.note || "", oninput: (e) => on.note(e.target.value), onkeydown: (e) => { if (e.key === "Escape" || e.key === "Enter") { e.target.blur(); e.stopPropagation(); } } }),
        r.label ? el("div", { class: "labeled", id: "labeled" }) : null),
      ctx.more ? more(ctx) : el("div", { class: "muted" }, el("button", { class: "ghost", onclick: () => on.toggleMore() }, "more evidence"), " ", el("kbd", {}, "e"), " links, the label's sources, grype's raw match"),
    ].flat().filter((c) => c != null && c !== false));
    fillDetail(ctx);
    fillPath(ctx, rel);
  }

  // fillPath redraws the match path once grype's raw match details are here
  async function fillPath(ctx, rel) {
    const { r, dir } = ctx;
    if (ctx.matches.has(r.id)) return;
    let m;
    try { m = await ctx.get(ctx.gateName, `/rows/${r.id}/matches`); } catch (e) { toast(e.message, true); return; }
    ctx.matches.set(r.id, m);
    if (shown !== r.id) return;
    $("#path")?.replaceChildren(matchPath(r, dir, m, rel));
  }

  function more(ctx) {
    const { r } = ctx;
    const box = el("div", { class: "more" },
      el("h3", {}, "read more"), el("div", { class: "links", id: "links" }, el("span", { class: "muted" }, "loading…")),
      el("h3", {}, "the label, and every claims source holding it"), el("div", { class: "claims", id: "claims" }, "…"),
      el("h3", {}, "grype's raw match, and the syft artifact"), el("div", { class: "raw" }, el("pre", { id: "raw-c" }, "…"), el("pre", { id: "raw-r" }, "…"), el("pre", { id: "raw-a" }, "…")));
    (async () => {
      let m = ctx.matches.get(r.id);
      if (!m) { try { m = await ctx.get(ctx.gateName, `/rows/${r.id}/matches`); } catch (e) { toast(e.message, true); return; } ctx.matches.set(r.id, m); }
      if (shown !== r.id) return;
      const show = (id, v, none) => { const p = $(id); if (p) p.textContent = v == null || (Array.isArray(v) && !v.length) ? none : JSON.stringify(Array.isArray(v) && v.length === 1 ? v[0] : v, null, 2); };
      show("#raw-c", m.candidate, "candidate: no match"); show("#raw-r", m.reference, "reference: no match"); show("#raw-a", m.artifact, m.sbomMissing ? `SBOM not found: ${m.sbomMissing}` : "no artifact");
    })();
    return box;
  }

  async function fillDetail(ctx) {
    const { r } = ctx;
    let d = ctx.details.get(r.id);
    if (!d) { try { d = await ctx.get(ctx.gateName, `/rows/${r.id}`); } catch (e) { toast(e.message, true); return; } ctx.details.set(r.id, d); }
    if (shown !== r.id) return;
    // who labeled it, when, how, and their note: the quiet last part of the label box
    const lb = $("#labeled");
    if (lb) {
      lb.replaceChildren(...(d.label ? [labelLine(ctx.state, d.label)] : []));
    }
    const hr = $("#hint-reason"), hn = $("#hint-note");
    if (hr && d.hint) {
      const rule = d.hint.policy?.rule, basis = rule?.basis, note = d.hint.proposal?.note || "";
      // the rule's title, then its basis, then the justification, then the note; a headline cut from
      // the note goes away while the whole note shows below it
      const own = rule?.title || (basis ? basis[0].toUpperCase() + basis.slice(1) : "") || justWords(ctx.state, d.hint.proposal?.verdict, d.hint.proposal?.justification);
      hr.textContent = own || (hn ? "" : firstSentence(note) || ruleWords(rule?.rule));
    }
    if (hn && d.hint) {
      const p = d.hint.proposal, pol = d.hint.policy;
      hn.textContent = p.note || "(no note)";
      // one fact per line: where it came from, which field, what it said
      const link = (f) => (/^https?:\/\//.test(f.url || "") ? el("a", { href: f.url, target: "_blank", rel: "noopener noreferrer" }, f.source) : f.source);
      const facts = (p.evidence || []).flatMap((e) => e.facts || []);
      $("#hint-facts")?.replaceChildren(...(facts.length ? facts.map((f) => el("li", {}, el("span", { class: "src" }, link(f)), el("span", { class: "fld" }, f.field || ""), el("span", { class: "val" }, f.value ?? "")))
        : [el("li", { class: "muted" }, "no recorded facts")]));
      const hru = $("#hint-rule");
      if (hru && pol?.rule) hru.textContent = `rule: ${pol.rule.basis || ruleWords(pol.rule.rule)}${pol.rule.decision ? ` · policy ${pol.rule.decision}` : ""}${pol.problems?.length ? ` · ⚠ ${pol.problems.join("; ")}` : ""}`;
    }
    const links = $("#links");
    if (links) {
      const groups = new Map();
      for (const l of d.links || []) { if (!groups.has(l.group)) groups.set(l.group, []); groups.get(l.group).push(l); }
      links.replaceChildren(...(groups.size ? [...groups].map(([g, ls]) => el("div", { class: "lgroup" }, el("span", { class: "grp" }, g + ": "), ls.map((l) => el("a", { href: l.url, target: "_blank", rel: "noopener noreferrer" }, l.label)))) : [el("span", { class: "muted" }, "no links")]));
    }
    const cl = $("#claims");
    if (cl) {
      // a label's history is its corpus's git history; here is where it is now
      cl.replaceChildren(...(d.label ? [labelLine(ctx.state, d.label), el("div", { class: "muted" }, `${d.label.global ? "global · " : ""}${d.label.file}`),
        ...(d.label.sources || []).map((s) => el("div", { class: "muted" }, s))] : [el("span", { class: "muted" }, "no label yet")]));
    }
  }

  // labelLine is a label as its file holds it: verdict, reason, who and when, and its notes. A note
  // says who and when only where that is not the label's own author, or there are several.
  function labelLine(state, lv) {
    const l = lv.label, notes = l.notes || [];
    const whoWhen = (n) => notes.length > 1 || n.author !== l.author ? `${n.author} · ${new Date(n.at).toLocaleDateString()}: ` : "";
    return el("div", { class: "who" },
      el("span", { class: `v-${l.verdict}` }, `${labels[l.verdict]?.glyph || ""} ${labels[l.verdict]?.word || l.verdict}`),
      `${l.justification ? ` · ${justWords(state, l.verdict, l.justification)}` : ""} by ${l.author || "?"} · ${new Date(l.lastUpdated).toLocaleDateString()}${l.evidence?.[0]?.rule ? ` · rule: ${ruleWords(l.evidence[0].rule)}` : ""}`,
      ...notes.map((n) => el("div", { class: "lnote" }, whoWhen(n) + n.text)));
  }

  // picker is the justification picker: FP and unclear need one, from the claims vocabulary, and
  // choosing one labels the match with its verdict. TP's are optional, so they're offered too.
  function picker(ctx) {
    const js = ctx.state.vocabulary?.justifications || {};
    return el("select", { class: "note", id: "justification", title: "the reason for the label: choosing one labels the match",
      onchange: (e) => { const [v, j] = e.target.value.split(":"); if (v) ctx.on.label(v, j); } },
    el("option", { value: "" }, "label with a reason…"),
    ...["fp", "unclear", "tp"].filter((v) => js[v]).map((v) => el("optgroup", { label: `${labels[v].glyph} ${labels[v].word}` },
      ...Object.entries(js[v]).sort().map(([j, desc]) => el("option", { value: `${v}:${j}` }, `${labels[v].word} · ${desc}`)))));
  }

  // the helpers a page may want for its own chrome (names, ordering)
  const h = { el, plural, fmt, signed, toast, direction, pkgOf, detail, otherRecords, isOpen, hinted, labels, dots, marks, dirWords,
    whyText, justWords, ruleWords, firstSentence, isResearched, researchLevel, provenance, nsParse, nsHuman, nsChip, imageRelease, sameRelease, releaseHuman, endsGate, regressionRisk };
  return { render, h, autoAdvance, setAutoAdvance };
})();
export const { render, h, autoAdvance, setAutoAdvance } = tile;
