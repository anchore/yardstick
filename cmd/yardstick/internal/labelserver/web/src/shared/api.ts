// api.ts is what the map pages share: the write token, where the page is (which gate), and the
// API calls. Ported from delta, where it was shared by several UIs.
export const token = document.querySelector<HTMLMetaElement>('meta[name="yardstick-token"]').content;

// where: the UI and gate from the path, /ui/<name>/gates/<gate>/<rest>
export function where() {
  const m = location.pathname.match(/^\/ui\/([^/]+)\/gates\/([^/]+)\/?(.*)$/);
  const ui = m?.[1] || location.pathname.match(/^\/ui\/([^/]+)\//)?.[1] || "queue";
  return { ui, gate: m ? decodeURIComponent(m[2]) : null, rest: m?.[3] || "" };
}

export async function call(path, init?) {
  const r = await fetch(path, init);
  if (!r.ok) throw new Error(`${r.status}: ${(await r.text()).trim() || r.statusText}`);
  return r.json();
}
const gatePath = (gate, path) => `/api/gates/${encodeURIComponent(gate)}${path}`;
export const get = (gate, path) => call(gatePath(gate, path));
export const post = (gate, path, body) => call(gatePath(gate, path), {
  method: "POST",
  headers: { "Content-Type": "application/json", "X-Yardstick-Token": token },
  body: JSON.stringify(body),
});
