// verify-answer: one call that pulls the URLs, DOIs, arXiv ids and PubMed ids out of an AI answer
// (or takes them explicitly), checks every link, verifies every citation, and looks up a Wayback
// snapshot for links that look dead. Reuses linkcheck.ts, citations.ts and archive.ts.
import { MAX_URLS, parseItems, check, type Item } from "./linkcheck";
import { MAX_CITATIONS, parseCitations, verifyCitation, mapLimit, type CitationInput } from "./citations";
import { findArchive } from "./archive";
import { parsePublicHttpUrl } from "./urlguard";

export const PRICE_ANSWER = "0.015";
export const MAX_ANSWER_CHARS = 50_000;
export const MAX_ANSWER_LINKS = MAX_URLS; // 10
export const MAX_ANSWER_CITATIONS = MAX_CITATIONS; // 10
export const MAX_ARCHIVE_LOOKUPS = 5;
const PROBLEM_VERDICTS = new Set(["dead", "soft_404", "parked", "unreachable"]);

export type AnswerInput = { links: Item[]; citations: CitationInput[]; archive: boolean; skipped: { value: string; reason: string }[]; extracted: { urls: number; citations: number } };

function trimTrailing(s: string): string {
  // Drop trailing punctuation and closing brackets that are not balanced inside the token (markdown links, sentences).
  let out = s;
  for (;;) {
    const before = out;
    out = out.replace(/[.,;:!?'"*_>~`]+$/, "");
    for (const [o, c] of [["(", ")"], ["[", "]"], ["{", "}"]] as const) {
      if (out.endsWith(c) && out.split(o).length < out.split(c).length) out = out.slice(0, -1);
    }
    if (out === before) return out;
  }
}

export function extractFromText(text: string): { urls: string[]; citations: string[] } {
  const urls: string[] = [];
  const cites: string[] = [];
  const seenU = new Set<string>(), seenC = new Set<string>();
  const addU = (u: string) => { if (!seenU.has(u)) { seenU.add(u); urls.push(u); } };
  const addC = (c: string) => { const k = c.toLowerCase(); if (!seenC.has(k)) { seenC.add(k); cites.push(c); } };
  for (const m of text.matchAll(/https?:\/\/[^\s<>"'`]+/gi)) {
    const u = trimTrailing(m[0]);
    if (u.length > 10) addU(u);
  }
  for (const m of text.matchAll(/\b10\.\d{4,9}\/[^\s"<>]+/g)) {
    const d = trimTrailing(m[0]).replace(/\.(pdf|html?)$/i, "");
    if (d.length > 8) addC(d);
  }
  for (const m of text.matchAll(/arxiv(?:\.org\/(?:abs|pdf)\/|:\s*|\s+)(\d{4}\.\d{4,5})(v\d+)?/gi)) addC(`arXiv:${m[1]}`);
  for (const m of text.matchAll(/\b(?:PMID|PubMed(?: ID)?)[:\s#]*(\d{4,9})\b/gi)) addC(`PMID: ${m[1]}`);
  for (const m of text.matchAll(/pubmed\.ncbi\.nlm\.nih\.gov\/(\d{4,9})/gi)) addC(`PMID: ${m[1]}`);
  return { urls, citations: cites };
}

export function parseAnswerInput(body: any): { item?: AnswerInput; error?: string } {
  if (!body || typeof body !== "object") return { error: 'Body must be JSON: {"text": "...answer with links and references..."}' };
  const { text, urls, citations } = body;
  if (text !== undefined && typeof text !== "string") return { error: "`text` must be a string" };
  if (typeof text === "string" && text.length > MAX_ANSWER_CHARS) return { error: `\`text\` is limited to ${MAX_ANSWER_CHARS} characters` };
  if (urls !== undefined && !Array.isArray(urls)) return { error: "`urls` must be an array" };
  if (citations !== undefined && !Array.isArray(citations)) return { error: "`citations` must be an array" };
  if (!text && !urls?.length && !citations?.length) return { error: "Send `text` (an AI answer), and/or `urls` / `citations` arrays" };

  const skipped: { value: string; reason: string }[] = [];
  const links: Item[] = [];
  const seen = new Set<string>();
  if (urls?.length) {
    if (urls.length > MAX_ANSWER_LINKS) return { error: `At most ${MAX_ANSWER_LINKS} explicit urls per call` };
    const p = parseItems({ urls });
    if (p.error) return { error: p.error };
    for (const it of p.items!) { if (!seen.has(it.url)) { seen.add(it.url); links.push(it); } }
  }
  const cites: CitationInput[] = [];
  if (citations?.length) {
    if (citations.length > MAX_ANSWER_CITATIONS) return { error: `At most ${MAX_ANSWER_CITATIONS} explicit citations per call` };
    const p = parseCitations({ citations });
    if (p.error) return { error: p.error };
    cites.push(...p.items!);
  }
  const ex = typeof text === "string" && text ? extractFromText(text) : { urls: [], citations: [] };
  for (const u of ex.urls) {
    if (seen.has(u)) continue;
    const g = parsePublicHttpUrl(u);
    if (g.error) { skipped.push({ value: u.slice(0, 300), reason: g.error }); continue; }
    if (links.length >= MAX_ANSWER_LINKS) { skipped.push({ value: u.slice(0, 300), reason: `link limit (${MAX_ANSWER_LINKS}) reached` }); continue; }
    seen.add(u); links.push({ url: u });
  }
  const citeKeys = new Set(cites.map((c) => (c.raw || c.doi || c.arxiv || c.pmid || c.title || "").toLowerCase()));
  for (const c of ex.citations) {
    if (citeKeys.has(c.toLowerCase())) continue;
    if (cites.length >= MAX_ANSWER_CITATIONS) { skipped.push({ value: c, reason: `citation limit (${MAX_ANSWER_CITATIONS}) reached` }); continue; }
    const p = parseCitations({ citations: [c] });
    if (p.error) { skipped.push({ value: c, reason: p.error }); continue; }
    citeKeys.add(c.toLowerCase()); cites.push(p.items![0]);
  }
  if (!links.length && !cites.length) return { error: "No checkable URLs, DOIs, arXiv ids or PubMed ids found. Pass free-text references in `citations`." };
  return { item: { links, citations: cites, archive: body.archive_dead_links !== false, skipped, extracted: { urls: ex.urls.length, citations: ex.citations.length } } };
}

export async function verifyAnswer(input: AnswerInput, ua: string, mailto: string) {
  const [links, cites] = await Promise.all([
    Promise.all(input.links.map(check)) as Promise<any[]>,
    mapLimit(input.citations, 3, (it) => verifyCitation(it, ua, mailto)) as Promise<any[]>,
  ]);
  let archivedFound = 0;
  if (input.archive) {
    const bad = links.filter((r) => PROBLEM_VERDICTS.has(r.verdict)).slice(0, MAX_ARCHIVE_LOOKUPS);
    await mapLimit(bad, 3, async (r: any) => {
      try {
        const a: any = await findArchive({ url: r.url }, ua);
        r.archive = a.found ? { found: true, snapshot_url: a.snapshot_url, captured_at: a.captured_at } : { found: a.found ?? null };
        if (a.found) archivedFound++;
      } catch { r.archive = { found: null }; }
    });
  }
  const live = links.filter((r) => r.verdict === "live").length;
  const count = (v: string) => cites.filter((r) => r.verdict === v).length;
  const problems = (links.length - live) + count("mismatch") + count("not_found");
  return {
    summary: {
      overall: problems ? "problems_found" : (count("error") ? "partial" : "all_ok"),
      links: { total: links.length, live, problems: links.length - live, archived_copies_found: archivedFound },
      citations: { total: cites.length, verified: count("verified"), mismatch: count("mismatch"), not_found: count("not_found"), error: count("error") },
      extracted_from_text: input.extracted,
    },
    links,
    citations: cites,
    skipped: input.skipped,
    sources: "Live HTTP fetch; Crossref, DataCite, arXiv, NCBI PubMed; Internet Archive Wayback Machine",
    checked_at: new Date().toISOString(),
  };
}
