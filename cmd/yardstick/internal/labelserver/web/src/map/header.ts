// header.ts draws the page's top: what is compared (gate, scan date, grype, DB, config), and the
// images as small multiples, each a bar of its differences by label.
import type { setup } from "../gen/wire";
import { el, must } from "../shared/dom";
import { diffRows, subjectName, type Tally, tally } from "./data";
import { scope } from "./nav";
import { st, ui } from "./state";

export function renderHeader() {
  const s = st(), c: Partial<setup.Prepared> = s.candidate || {}, r: Partial<setup.Prepared> = s.reference || c;
  const field = (k: string, v: Node | (Node | string)[], title: string) => el("span", { class: "field", "data-testid": "compared-field", "data-k": k, title }, v);
  const gv = (p: Partial<setup.Prepared>) => p.grype?.spec?.version || p.grype?.spec?.path;
  const grype = gv(c) === gv(r) ? el("b", {}, gv(c) || "?") : [el("b", {}, gv(r) || "?"), " → ", el("b", {}, gv(c) || "?")];
  const dbName = (db: setup.DB | undefined) => (db?.source || db?.requested || "").split("/").pop()?.replace(/^vulnerability-db_/, "").replace(/\.tar\.zst$/, "") || "?";
  const db = c.db?.checksum && c.db.checksum === r.db?.checksum ? el("b", {}, dbName(c.db)) : [el("b", {}, dbName(r.db)), " → ", el("b", {}, dbName(c.db))];
  const cfgName = (f: setup.File | undefined) => (f ? f.path.split("/").pop() || "" : "default");
  const cfg = (c.config?.sha256 || "") === (r.config?.sha256 || "") ? el("b", {}, cfgName(c.config)) : [el("b", {}, cfgName(r.config)), " → ", el("b", {}, cfgName(c.config))];
  must("#compared").replaceChildren(
    field("gate", el("b", {}, s.gate?.name || s.scans.id), s.gate?.description || ""),
    field("scanned", el("b", {}, new Date(s.scans.created).toLocaleDateString(undefined, { month: "short", day: "numeric" })), `${new Date(s.scans.created).toLocaleString()}: re-scan only when the gate's subjects or setups change; labels count at once`),
    field("grype", grype, `${gv(r)} (reference) vs ${gv(c)} (candidate)`),
    field("DB", db, `${r.db?.checksum || ""} (reference)\n${c.db?.checksum || ""} (candidate)`),
    field("config", cfg, `${r.config?.path || "grype defaults"} (reference)\n${c.config?.path || "grype defaults"} (candidate)`),
  );
}

export function renderImages() {
  const s = st();
  const subs = s.subjects.map((_, si) => ({ si, t: tally(diffRows(s, si)) }));
  must("#images").replaceChildren(
    el("div", { class: `img${ui.si == null ? " on" : ""}`, "data-testid": "image-all", "data-active": ui.si == null, onclick: () => scope(null) }, el("div", { class: "nm" }, "every image"), stack(tally(diffRows(s, null))), nums(tally(diffRows(s, null)))),
    ...subs.map(({ si, t }) => el("div", { class: `img${ui.si === si ? " on" : ""}${t.n ? "" : " quiet"}`, title: `${subjectName(s, si)} (${si + 1})`, "data-testid": "image", "data-subject": subjectName(s, si), "data-index": si, "data-active": ui.si === si, "data-diffs": t.n, "data-open": t.open, onclick: () => scope(si) },
      el("div", { class: "nm" }, `${si + 1} · ${subjectName(s, si)}`), stack(t), nums(t))),
  );
}
function stack(t: Tally) {
  const seg = (k: string, n: number) => (n ? el("span", { class: `seg-${k}`, style: `width:${(n / t.n) * 100}%`, title: `${n} ${k}` }) : null);
  return el("div", { class: "stack" }, t.n ? [seg("tp", t.tp), seg("fp", t.fp), seg("unclear", t.unclear), seg("hint", t.hinted)] : null);
}
function nums(t: Tally) {
  return el("div", { class: "nums" }, el("span", {}, el("b", {}, String(t.n)), " diff"), el("span", {}, el("b", {}, String(t.open)), " open"), t.decisive ? el("span", { class: "decisive", "data-testid": "image-decisive", "aria-label": `${t.decisive} could change the verdict` }, `◆ ${t.decisive}`) : null);
}
