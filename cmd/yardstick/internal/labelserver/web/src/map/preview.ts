// preview.ts shows, while an accept control is hovered, the gate as if its agent hints were
// accepted: where the bars would move. The server evaluates it (POST /preview writes nothing);
// results are cached by their rows until the next load.
import type { claimsv1 } from "../gen/wire";
import * as api from "../shared/api";
import { gateBar, renderGate } from "./ribbon";
import { gate, previews, st, ui } from "./state";

// previewAccept starts a preview: labelsByRow maps row id → the verdict accepting would write
async function previewAccept(labelsByRow: Record<string, claimsv1.Verdict>, what: string) {
  const ids = Object.keys(labelsByRow);
  if (!ids.length || !st().gate?.result) return;
  const key = ids.sort().map((id) => `${id}=${labelsByRow[id]}`).join(",");
  ui.preview = { key, what, result: previews.get(key) || null };
  showPreview();
  if (ui.preview.result) return;
  try {
    const result = await api.preview(gate(), labelsByRow);
    previews.set(key, result);
    if (ui.preview?.key === key) { ui.preview.result = result; showPreview(); }
  } catch {
    if (ui.preview?.key === key) ui.preview = null;
    showPreview();
  }
}
export function endPreview() { if (ui.preview) { ui.preview = null; showPreview(); } }
// showPreview redraws the ribbon and the board's bars in place, leaving the hovered control alone
function showPreview() {
  renderGate();
  const checks = st().gate?.result?.checks || [];
  for (const n of document.querySelectorAll<HTMLElement>(".panel .gcheck[data-check]")) {
    const c = checks.find((k) => k.name === n.dataset.check);
    if (c) n.replaceWith(gateBar(c, { head: false }));
  }
}
// previewOn wires hover and focus on an accept control to the preview
export const previewOn = (labelsOf: () => Record<string, claimsv1.Verdict>, what: string) => ({
  onmouseenter: () => previewAccept(labelsOf(), what), onmouseleave: endPreview,
  onfocus: () => previewAccept(labelsOf(), what), onblur: endPreview,
});
