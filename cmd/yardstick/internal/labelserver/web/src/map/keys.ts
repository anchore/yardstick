// keys.ts maps a key press on the map page to what it does, given what is on screen. Pure: app.ts
// carries the action out.

export type Action =
  | { do: "blur" }            // leave a text field
  | { do: "closeHelp" }
  | { do: "help" }
  | { do: "move"; by: 1 | -1 }  // the next or previous card
  | { do: "label"; verdict: "tp" | "fp" | "unclear" }
  | { do: "accept" }          // the agent hint on the card
  | { do: "acceptAll" }       // its package hint, else every high-confidence hint in the group
  | { do: "toggleWhy" }
  | { do: "toggleEvidence" }
  | { do: "focusNote" }
  | { do: "research" }
  | { do: "openLink" }
  | { do: "nextDecisive" }
  | { do: "back" }
  | { do: "last" }            // back to the card labeled last
  | { do: "theme" }
  | { do: "image"; si: number | null };

export interface KeyPress { key: string; tag: string; meta: boolean; ctrl: boolean; alt: boolean }

// Screen is what the keys depend on
export interface Screen {
  helpOpen: boolean;
  cards: boolean;     // a group is open on the tile
  selected: boolean;  // a card is selected
  row: boolean;       // the selected card is in the group
  away: boolean;      // somewhere Esc goes back from: cards, a zoom, or the delta map
  last: boolean;      // there is a card labeled last
  images: number;
}

export function keyAction(e: KeyPress, s: Screen): Action | null {
  if (["INPUT", "TEXTAREA", "SELECT"].includes(e.tag)) return e.key === "Escape" ? { do: "blur" } : null;
  if (e.meta || e.ctrl || e.alt) return null;
  if (s.helpOpen) return e.key === "Escape" || e.key === "?" ? { do: "closeHelp" } : null;
  switch (e.key) {
    case "j": return { do: "move", by: 1 };
    case "k": return { do: "move", by: -1 };
    case "t": return { do: "label", verdict: "tp" };
    case "f": return { do: "label", verdict: "fp" };
    case "u": return { do: "label", verdict: "unclear" };
    case "a": return { do: "accept" };
    case "A": return { do: "acceptAll" };
    case "w": return s.cards ? { do: "toggleWhy" } : null;
    case "e": case "Enter": return s.cards && s.selected ? { do: "toggleEvidence" } : null;
    case "n": return s.cards ? { do: "focusNote" } : null;
    case "R": return s.row ? { do: "research" } : null;
    case "o": return { do: "openLink" };
    case "v": return { do: "nextDecisive" };
    case "Escape": return s.away ? { do: "back" } : null;
    case "z": return s.last && s.cards ? { do: "last" } : null;
    case "D": return { do: "theme" };
    case "?": return { do: "help" };
    case "0": return { do: "image", si: null };
    default:
      return /^[1-9]$/.test(e.key) && Number(e.key) <= s.images ? { do: "image", si: Number(e.key) - 1 } : null;
  }
}
