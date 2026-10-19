// state.ts is the map page's state: the gate's /state, the view the URL encodes, and what the page
// keeps between renders. The render modules read it; nav.ts and actions.ts change it.
import type { GateResult, MatchesResponse, RowResponse, State } from "../gen/wire";
import { where } from "../shared/api";
import type { Receipt } from "../shared/tile";
import type { Cards, Item } from "./data";
import type { View } from "./url";

// Preview is the gate if a hovered accept were clicked: result is null until the server answers
export interface Preview { key: string; what: string; result: GateResult | null }
// Research is the research controls' dry-run counts by selection, for one image scope, and the
// research started from them
export interface Research {
  scope: string;
  counts: Record<string, number> | null;
  started?: { matches: number; jobs: string[]; cancelled?: boolean } | null;
}

export interface UI extends View {
  gateName: string | null;
  state: State | null;
  opened: Set<string>;         // board panels whose full group list is unfolded
  cards: Cards | null;         // derived from cardsSpec on each render
  base: string;                // this gate's page path, /ui/map/gates/<gate>/
  pushes: number;              // history entries this page pushed (Esc goes back through them)
  booted: boolean;
  rows: Item[];                // the open group's rows, in order
  why: boolean;                // the tile shows the agent's note and facts
  details: Map<string, RowResponse>;
  matches: Map<string, MatchesResponse>;
  note: string;
  receipt: Receipt | null;
  pin: string | null;          // the match labeled last, kept in its group though it left it (until another view opens)
  preview: Preview | null;
  research: Research | null;
  last: string | null;         // the card labeled last (z goes back to it)
  scrollTo: string | null;     // the board panel to scroll to on the next render, by check name
}

export const ui: UI = {
  gateName: where().gate,
  state: null,
  si: null,
  delta: false,
  opened: new Set(),
  zoom: null,
  cardsSpec: null,
  cards: null,
  base: "",
  pushes: 0,
  booted: false,
  rows: [],
  selected: null,
  evidence: false,
  why: false,
  details: new Map(),
  matches: new Map(),
  note: "",
  receipt: null,
  pin: null,
  preview: null,
  research: null,
  last: null,
  scrollTo: null,
};

// previews caches the server's preview results by their rows until the next load
export const previews = new Map<string, GateResult>();

// st is the loaded state; the render modules run only once load has it
export function st(): State {
  if (!ui.state) throw new Error("the gate's state is not loaded");
  return ui.state;
}
// gate is the gate's name; the page never boots without one
export function gate(): string {
  if (ui.gateName == null) throw new Error("no gate in the URL");
  return ui.gateName;
}
