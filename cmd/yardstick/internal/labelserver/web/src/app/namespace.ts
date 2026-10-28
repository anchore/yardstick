// namespace.ts fixes a namespace the claims vocabulary lacks, which the server refuses research on:
// a dialog that adds it to the gate's writable claims source's vocabulary.yaml and runs the refused
// research again, and an alert a gate shows before anyone starts research there.
import type { UnlistedNamespace, VocabularyList } from "../gen/wire";
import * as api from "../shared/api";
import { el, fill, toast } from "../shared/dom";
import { changed, forget } from "./data";
import { addedWords, namespaceWords, retried } from "./namespacewords";

// unlistedIn is the namespace a research refusal is about, if that is why it was refused
export const unlistedIn = (e: unknown) => (e instanceof api.ApiError ? e.unlisted : undefined);

// adds is the add buttons, the suggested list first and primary; each writes and then runs after,
// showing what went wrong in place of status
function adds(u: UnlistedNamespace, status: HTMLElement, after: (list: VocabularyList, file: string) => Promise<void>) {
  const w = namespaceWords(u);
  const buttons = w.adds.map((a, i) => el("button", { type: "button", class: "btn", "data-variant": i ? "outline" : null, disabled: !w.writable,
    "data-testid": "namespace-add", "data-list": a.list, onclick: () => void go(a.list) }, a.text));
  async function go(list: VocabularyList) {
    for (const b of buttons) b.disabled = true;
    fill(status, "Adding…");
    try {
      const res = await api.addNamespace(u.gate, u.namespace, list);
      forget();
      await after(list, res.file);
    } catch (e) {
      fill(status, el("span", { role: "alert" }, (e as Error).message));
      for (const b of buttons) b.disabled = false;
    }
  }
  return buttons;
}

// unlistedDialog asks to add the namespace, staying until it is added or closed. after runs once it
// is added, the dialog still open, and what it throws shows there. It resolves true once added.
export function unlistedDialog(u: UnlistedNamespace, after: () => Promise<void> = async () => undefined): Promise<boolean> {
  const w = namespaceWords(u);
  return new Promise((resolve) => {
    let added = false;
    const status = el("p", { class: "muted", "data-testid": "namespace-status", "aria-live": "polite" });
    const cancel = el("button", { type: "button", class: "btn", "data-variant": "ghost", "data-testid": "namespace-cancel", onclick: (): void => dialog.close() }, "Cancel");
    const buttons = adds(u, status, async (list, file) => {
      fill(status, `${addedWords(u.namespace, list, file)}. Starting research…`);
      await after();
      added = true;
      toast(addedWords(u.namespace, list, file));
      dialog.close();
    });
    const dialog: HTMLDialogElement = el("dialog", { class: "dialog namespace-dialog", "aria-labelledby": "namespace-title", "aria-describedby": "namespace-body", "data-testid": "namespace-dialog" },
      el("div", {},
        el("header", {}, el("h2", { id: "namespace-title" }, w.title), el("p", { id: "namespace-body" }, w.body)),
        el("section", {}, el("p", { class: "muted", "data-testid": "namespace-file" }, w.small), status),
        el("footer", {}, cancel, ...buttons.slice().reverse())));
    dialog.addEventListener("close", () => { dialog.remove(); resolve(added); });
    document.body.append(dialog);
    dialog.showModal();
    buttons[0].focus();
  });
}

// orFix runs a research start, asking to add a namespace it is refused for and then starting again
// (retried); null when the dialog was closed
export const orFix = <T>(start: () => Promise<T>) => retried(start, unlistedIn, unlistedDialog);

// unlistedAlert is the notice of the namespaces of open rows the vocabulary lacks, each with the
// dialog's words and add buttons, naming its gate when the page covers several; null when none
export function unlistedAlert(list: UnlistedNamespace[] | undefined, gates = false) {
  if (!list?.length) return null;
  return el("div", { class: "alert namespace-alert", role: "status", "data-testid": "unlisted-namespaces" }, list.map((u) => {
    const w = namespaceWords(u), status = el("p", { class: "muted" }, w.small);
    const buttons = adds(u, status, async (list, file) => {
      toast(addedWords(u.namespace, list, file));
      changed();
    });
    return [el("h2", {}, gates ? `${w.title} (gate ${u.gate})` : w.title),
      el("section", { "data-namespace": u.namespace }, el("p", {}, w.body), status, el("div", { class: "acts" }, buttons))];
  }));
}
