import { describe, expect, test } from "bun:test";
import { type Action, keyAction, type KeyPress, type Screen } from "./keys";

const press = (key: string, over: Partial<KeyPress> = {}): KeyPress => ({ key, tag: "BODY", meta: false, ctrl: false, alt: false, ...over });
// onCard is the tile with a card selected
const onCard: Screen = { helpOpen: false, cards: true, selected: true, row: true, away: true, last: true, images: 3 };
const onBoard: Screen = { helpOpen: false, cards: false, selected: false, row: false, away: false, last: false, images: 3 };

describe("keyAction", () => {
  test("on a card, every key does what the help card says", () => {
    const want: Record<string, Action> = {
      j: { do: "move", by: 1 }, k: { do: "move", by: -1 },
      t: { do: "label", verdict: "tp" }, f: { do: "label", verdict: "fp" }, u: { do: "label", verdict: "unclear" },
      a: { do: "accept" }, A: { do: "acceptAll" }, w: { do: "toggleWhy" }, e: { do: "toggleEvidence" }, Enter: { do: "toggleEvidence" },
      n: { do: "focusNote" }, R: { do: "research" }, o: { do: "openLink" }, v: { do: "nextDecisive" }, Escape: { do: "back" },
      z: { do: "last" }, D: { do: "theme" }, "?": { do: "help" }, "0": { do: "image", si: null }, "2": { do: "image", si: 1 },
    };
    for (const [key, action] of Object.entries(want)) expect([key, keyAction(press(key), onCard)]).toEqual([key, action]);
  });
  test("keys about the tile do nothing off it", () => {
    for (const key of ["w", "e", "Enter", "n", "R", "z", "Escape"]) expect([key, keyAction(press(key), onBoard)]).toEqual([key, null]);
  });
  test("keys that report their own problem still act off the tile", () => {
    expect(keyAction(press("t"), onBoard)).toEqual({ do: "label", verdict: "tp" });
    expect(keyAction(press("j"), onBoard)).toEqual({ do: "move", by: 1 });
    expect(keyAction(press("v"), onBoard)).toEqual({ do: "nextDecisive" });
  });
  test("Esc goes back from the delta map or a zoom too", () => {
    expect(keyAction(press("Escape"), { ...onBoard, away: true })).toEqual({ do: "back" });
  });
  test("evidence needs a selected card, research a card in the group, z a card labeled last", () => {
    expect(keyAction(press("e"), { ...onCard, selected: false })).toBeNull();
    expect(keyAction(press("R"), { ...onCard, row: false })).toBeNull();
    expect(keyAction(press("z"), { ...onCard, last: false })).toBeNull();
  });
  test("a digit picks an image only when there is one", () => {
    expect(keyAction(press("3"), onCard)).toEqual({ do: "image", si: 2 });
    expect(keyAction(press("4"), onCard)).toBeNull();
  });
  test("in a text field only Esc does anything, and it leaves the field", () => {
    for (const tag of ["INPUT", "TEXTAREA", "SELECT"]) {
      expect(keyAction(press("t", { tag }), onCard)).toBeNull();
      expect(keyAction(press("Escape", { tag }), onCard)).toEqual({ do: "blur" });
    }
  });
  test("a key with a modifier belongs to the browser", () => {
    expect(keyAction(press("t", { meta: true }), onCard)).toBeNull();
    expect(keyAction(press("t", { ctrl: true }), onCard)).toBeNull();
    expect(keyAction(press("t", { alt: true }), onCard)).toBeNull();
  });
  test("while the help is open, only Esc and ? close it", () => {
    const help = { ...onCard, helpOpen: true };
    expect(keyAction(press("Escape"), help)).toEqual({ do: "closeHelp" });
    expect(keyAction(press("?"), help)).toEqual({ do: "closeHelp" });
    expect(keyAction(press("t"), help)).toBeNull();
  });
  test("an unbound key does nothing", () => {
    expect(keyAction(press("x"), onCard)).toBeNull();
  });
});
