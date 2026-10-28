// namespacewords.ts is what the UI says about a namespace the claims vocabulary lacks: why nothing
// on its rows can be recorded, which list the gate's scan suggests, the buttons that add it to each
// list (the suggested one first), and the file an add writes.
import type { UnlistedNamespace, VocabularyList } from "../gen/wire";

export interface NamespaceAdd { list: VocabularyList; text: string }
export interface NamespaceWords { title: string; body: string; adds: [NamespaceAdd, NamespaceAdd]; small: string; writable: boolean }

const kinds: Record<VocabularyList, string> = { "vulnerability-namespaces": "disclosure", "advisory-ids": "advisory" };
const other = (l: VocabularyList): VocabularyList => (l === "advisory-ids" ? "vulnerability-namespaces" : "advisory-ids");

// shows is what the scan's example id names: "X → A, B", or "X names none"
function shows(u: UnlistedNamespace) {
  const x = u.example;
  if (!x) return "";
  return x.names.length ? `${x.id} → ${x.names.join(", ")}` : `${x.id} names none`;
}

// judged says what the scan's ids show and the kind of namespace that makes it
function judged(u: UnlistedNamespace) {
  const ns = u.namespace, one = u.checked === 1;
  if (!u.suggest) return `This scan has no ${ns} id to judge it by: a disclosure namespace's ids each name one vulnerability, an advisory's can name several.`;
  const kind = kinds[u.suggest];
  if (u.suggest === "advisory-ids") {
    return one
      ? `The one ${ns} id in this scan names several vulnerabilities (${shows(u)}), so it looks like an ${kind} namespace.`
      : `Some ${ns} ids in this scan name several vulnerabilities (e.g. ${shows(u)}), so it looks like an ${kind} namespace.`;
  }
  return one
    ? `The one ${ns} id in this scan names one vulnerability (${shows(u)}), so it looks like a ${kind} namespace.`
    : `Each ${ns} id in this scan names one vulnerability at most (e.g. ${shows(u)}), so it looks like a ${kind} namespace.`;
}

export function namespaceWords(u: UnlistedNamespace): NamespaceWords {
  const first = u.suggest ?? "vulnerability-namespaces";
  const add = (list: VocabularyList): NamespaceAdd => ({ list, text: `Add as ${kinds[list]}` });
  return {
    title: `${u.namespace} isn't in the claims vocabulary`,
    body: `Research and labels on its rows can't be recorded until it is. ${judged(u)}`,
    adds: [add(first), add(other(first))],
    small: u.file ? `Writes ${u.file}; your PR will show the change.` : "This gate has no local claims source to write to: serve it with --claims <dir> to add one.",
    writable: !!u.file,
  };
}

// addedWords is the confirmation once a namespace is added
export const addedWords = (namespace: string, list: VocabularyList, file: string) => `${namespace} added as a ${kinds[list]} namespace in ${file}`;

// retried runs a research start. Refused for a namespace the vocabulary lacks (unlisted says which),
// it has ask add it, and once added runs the start again inside ask, so ask can show what goes
// wrong; refused then for another namespace, it asks again. It resolves with the start's answer, or
// null when ask was declined; any other refusal throws, as the start's own would.
export async function retried<T>(start: () => Promise<T>, unlisted: (e: unknown) => UnlistedNamespace | undefined,
  ask: (u: UnlistedNamespace, after: () => Promise<void>) => Promise<boolean>): Promise<T | null> {
  let u: UnlistedNamespace | undefined;
  try {
    return await start();
  } catch (e) {
    u = unlisted(e);
    if (!u) throw e;
  }
  let out: { v: T } | null = null;
  const added = await ask(u, async () => {
    try {
      out = { v: await start() };
    } catch (e) {
      if (!unlisted(e)) throw e;
    }
  });
  if (!added) return null;
  const done = out as { v: T } | null;
  return done ? done.v : retried(start, unlisted, ask);
}
