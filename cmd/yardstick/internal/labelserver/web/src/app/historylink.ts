// historylink.ts is the app bar's way to history, on every screen: "History", and once this server
// has written any labels, how many are in the writable claims source since it started. It reads
// GET /api/history on load and on focus, and data.ts has it read again after every write and every
// removal, so no screen counts on its own.
import * as api from "../shared/api";
import { el } from "../shared/dom";
import { plural } from "../shared/words";
import { shortSource } from "./listing";

let started = false, seq = 0;
const count = el("span", { class: "ct", hidden: true, "data-testid": "history-count" });
const link = el("a", { class: "btn history", href: "/ui/history", "data-variant": "ghost", "data-size": "sm", "data-testid": "history-entry", "data-count": "0",
  title: "Labels written since the server started" }, "History", count);

// historyLink is the link, for the shell to put in each screen's app bar
export function historyLink() {
  if (!started) {
    started = true;
    void recount();
    addEventListener("focus", () => void recount());
  }
  return link;
}

// recount reads how many labels this server has written, after a write or a removal
export async function recount() {
  const mine = ++seq;
  try {
    const h = await api.history("since=start&limit=1");
    // a write's read can land after its Undo's: only the newest read draws
    if (mine !== seq) return;
    const where = h.sources.map(shortSource).join(", ") || "the writable claims source";
    count.hidden = h.total === 0;
    count.textContent = h.total ? h.total.toLocaleString() : "";
    link.dataset.count = String(h.total);
    link.title = `${plural(h.total, "label")} written to ${where} since the server started`;
  } catch {
    // the server gone: the count stays as it was
  }
}
