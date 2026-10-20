// images.ts is the image rail's logic: names, order, filtering and keys. Pure: rail.ts draws it.

// Counts are one image's findings by verdict. open is every unlabeled one, hinted the open ones an
// agent left a hint on, so the bar's plain-open part is open - hinted. What the UI calls open is
// openOf: unlabeled or unclear, since unclear doesn't judge a row.
export interface Counts { tp: number; fp: number; unclear: number; hinted: number; open: number; total: number }

export interface RailImage {
  name: string;   // what people call it: repository base and tag, e.g. grype-quality-golang:d89207b
  slug: string;   // the ?image= value
  ref: string;    // the full reference, shown on hover
  counts: Counts;
}

export const noCounts: Counts = { tp: 0, fp: 0, unclear: 0, hinted: 0, open: 0, total: 0 };

// openOf is the open rows of a tally: unlabeled, and unclear, which doesn't judge a row
export const openOf = (c: Counts | undefined) => (c?.open ?? 0) + (c?.unclear ?? 0);

// splitName splits a name before its tag, so the repository part can truncate and the tag never
// does: "grype-quality-golang:d89207b" → ["grype-quality-golang", ":d89207b"]
export function splitName(name: string): [string, string] {
  const i = name.lastIndexOf(":");
  // a colon before the last slash is a registry port, not a tag
  if (i <= 0 || i < name.lastIndexOf("/")) return [name, ""];
  return [name.slice(0, i), name.slice(i)];
}

// sumCounts is the "all images" row
export function sumCounts(cs: Counts[]): Counts {
  const s = { ...noCounts };
  for (const c of cs) for (const k of Object.keys(s) as (keyof Counts)[]) s[k] += c[k];
  return s;
}

export type RailSort = "gate" | "open";

// order is the image indices in display order: the gate's, or most open first (ties keep gate
// order). Number keys stay with the gate order whichever is shown.
export function order(images: RailImage[], by: RailSort): number[] {
  const ix = images.map((_, i) => i);
  return by === "open" ? ix.sort((a, b) => openOf(images[b].counts) - openOf(images[a].counts) || a - b) : ix;
}

// matches says whether an image passes the rail's filter text: every word in its name or reference
export function matches(img: RailImage, q: string): boolean {
  const hay = `${img.name} ${img.ref}`.toLowerCase();
  return q.toLowerCase().split(/\s+/).filter(Boolean).every((w) => hay.includes(w));
}

// railKey is the position a key press picks, or null when the key isn't the rail's. Positions are 0
// for every image and i+1 for images[i]. Digits name positions directly; [ and ] step through the
// positions on screen (shown, in display order), from cur.
export function railKey(key: string, count: number, cur: number, shown: number[]): number | null {
  if (/^[0-9]$/.test(key)) {
    const p = Number(key);
    return p <= count ? p : null;
  }
  if (key !== "[" && key !== "]") return null;
  if (!shown.length) return null;
  const at = shown.indexOf(cur);
  if (at < 0) return shown[key === "]" ? 0 : shown.length - 1];
  return shown[Math.max(0, Math.min(shown.length - 1, at + (key === "]" ? 1 : -1)))];
}
