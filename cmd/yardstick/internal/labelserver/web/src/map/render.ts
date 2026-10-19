// render.ts loads the gate's state and draws the page from it: the header, the gate ribbon and the
// images, then the tile (a group is open), the gate board, or the scan-delta map.
import * as api from "../shared/api";
import { el, must } from "../shared/dom";
import { renderBoard } from "./board";
import { cardsFor } from "./data";
import { renderHeader, renderImages } from "./header";
import { renderMap } from "./mapview";
import { readURL, replaceURL } from "./nav";
import { countForResearch, researchScope } from "./research";
import { renderGate } from "./ribbon";
import { gate, previews, st, ui } from "./state";
import { renderTile } from "./tileview";

export async function load() {
  try {
    ui.state = await api.state(gate());
  } catch (e) {
    must("#map").replaceChildren(el("div", { class: "empty" }, (e as Error).message));
    return;
  }
  ui.details.clear();
  ui.matches.clear();
  previews.clear(); ui.preview = null;
  document.title = `yardstick · map · ${ui.state.scans.label || ui.gateName}`;
  if (!ui.booted) { ui.booted = true; Object.assign(ui, readURL()); }
  render();
  countForResearch();
}

// cardsTitle is the open group's title when it last had rows
let cardsTitle = "";

export function render() {
  ui.cards = cardsFor(st(), ui.si, ui.cardsSpec);
  // the match labeled last stays in its group (afterWrite), even when its label emptied the group:
  // then the tile says the group is done and offers the next
  if (ui.cardsSpec && ui.pin) {
    if (ui.cards) ui.cards.ids.add(ui.pin);
    else if (cardsTitle) ui.cards = { title: cardsTitle, ids: new Set([ui.pin]) };
  }
  if (ui.cards) cardsTitle = ui.cards.title;
  if (ui.cardsSpec && !ui.cards?.ids.size) { ui.cardsSpec = null; ui.cards = null; replaceURL(); }
  renderHeader();
  renderGate();
  renderImages();
  if (ui.research && ui.research.scope !== researchScope()) countForResearch(); // the image scope changed
  if (ui.cards) renderTile();
  else if (st().gate?.result && !ui.delta) renderBoard();
  else renderMap();
}
