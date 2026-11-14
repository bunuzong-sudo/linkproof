// Citation verification against free public registries: Crossref (+DataCite fallback), arXiv, NCBI PubMed (E-utilities), OpenAlex.
export const MAX_CITATIONS = 10;
const TIMEOUT_MS = 8000;

export type CitationInput = { raw?: string; doi?: string; arxiv?: string; pmid?: string; title?: string; authors?: string[]; year?: number };
type Meta = { source: string; id: string; title: string | null; authors: string[]; year: number | null; venue: string | null; url: string | null };

const DOI_RE = /\b(10\.\d{4,9}\/[^\s"<>]+)/i;
const ARXIV_NEW_RE = /(?:arxiv[:\s/]*|abs\/|pdf\/)?\b(\d{4}\.\d{4,5})(v\d+)?\b/i;
const ARXIV_OLD_RE = /\b(?:arxiv[:\s]*)?([a-z\-]+(?:\.[A-Z]{2})?\/\d{7})(v\d+)?\b/i;
const PMID_RE = /\b(?:pmid|pubmed)[:\s#]*(\d{1,9})\b/i;

function clean(s: unknown, max = 500) { return typeof s === "string" ? s.trim().slice(0, max) : undefined; }

export function parseCitations(body: any): { items?: CitationInput[]; error?: string } {
  if (!body || typeof body !== "object") return { error: 'Body must be JSON: {"citations": [...]}' };
  const raw = body.citations;
  if (!Array.isArray(raw) || raw.length === 0) return { error: "`citations` must be a non-empty array" };
  if (raw.length > MAX_CITATIONS) return { error: `At most ${MAX_CITATIONS} citations per call` };
  const items: CitationInput[] = [];
  for (const r of raw) {
    if (typeof r === "string") {
      if (!r.trim() || r.length > 1000) return { error: "Each citation string must be 1-1000 chars" };
      items.push(fromString(r));
      continue;
    }
    if (!r || typeof r !== "object") return { error: "Each citation must be a string or an object" };
    let authors: string[] | undefined;
    if (Array.isArray(r.authors)) authors = r.authors.filter((a: unknown) => typeof a === "string").map((a: string) => a.slice(0, 120)).slice(0, 30);
    else if (typeof r.authors === "string") authors = r.authors.split(/;|,(?![^,]*,)| and /i).map((a: string) => a.trim()).filter(Boolean).slice(0, 30);
    const year = r.year === undefined ? undefined : Number(r.year);
    if (year !== undefined && !(year > 1500 && year < 2200)) return { error: "`year` must be a 4-digit year" };
    const it: CitationInput = { doi: clean(r.doi, 200), arxiv: clean(r.arxiv, 50), pmid: clean(String(r.pmid ?? ""), 12) || undefined, title: clean(r.title), authors, year };
    if (it.doi) { const m = it.doi.match(DOI_RE); if (!m) return { error: `Invalid DOI: ${it.doi}` }; it.doi = m[1]; }
    if (it.pmid && !/^\d{1,9}$/.test(it.pmid)) return { error: `Invalid PMID: ${it.pmid}` };
    if (!it.doi && !it.arxiv && !it.pmid && !it.title) return { error: "Each citation object needs doi, arxiv, pmid or title" };
    items.push(it);
  }
  return { items };
}

function fromString(s: string): CitationInput {
  const it: CitationInput = { raw: s.trim() };
  const d = s.match(DOI_RE); if (d) it.doi = d[1].replace(/[.,;)\]]+$/, "");
  const p = s.match(PMID_RE); if (p) it.pmid = p[1];
  if (!it.doi && !it.pmid) {
    const a = s.match(ARXIV_NEW_RE); const o = s.match(ARXIV_OLD_RE);
    if (a && (/arxiv/i.test(s) || /^\s*\d{4}\.\d{4,5}(v\d+)?\s*$/.test(s))) it.arxiv = a[1];
    else if (o && /arxiv/i.test(s)) it.arxiv = o[1];
  }
  const y = s.match(/\((\d{4})\)|\b(19\d{2}|20\d{2})\b/); if (y) it.year = Number(y[1] || y[2]);
  return it;
}

async function getJson(url: string, ua: string) {
  let r = await fetch(url, { headers: { "user-agent": ua, accept: "application/json" }, signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (r.status === 429 || r.status === 503) {
    await new Promise((res) => setTimeout(res, 1200));
    r = await fetch(url, { headers: { "user-agent": ua, accept: "application/json" }, signal: AbortSignal.timeout(TIMEOUT_MS) });
  }
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`upstream ${new URL(url).host} HTTP ${r.status}`);
  return r.json<any>();
}

function crossrefMeta(w: any): Meta {
  const y = w?.issued?.["date-parts"]?.[0]?.[0] ?? w?.published?.["date-parts"]?.[0]?.[0] ?? null;
  return { source: "crossref", id: w.DOI, title: w.title?.[0] ?? null, authors: (w.author || []).map((a: any) => a.family || a.name).filter(Boolean),
    year: y ? Number(y) : null, venue: w["container-title"]?.[0] ?? w.publisher ?? null, url: w.URL ?? `https://doi.org/${w.DOI}` };
}

async function byDoi(doi: string, ua: string, mailto: string): Promise<Meta | null> {
  const w = await getJson(`https://api.crossref.org/works/${encodeURIComponent(doi)}?mailto=${encodeURIComponent(mailto)}`, ua);
  if (w?.message) return crossrefMeta(w.message);
  const d = await getJson(`https://api.datacite.org/dois/${encodeURIComponent(doi)}`, ua);
  const a = d?.data?.attributes;
  if (!a) return null;
  return { source: "datacite", id: a.doi, title: a.titles?.[0]?.title ?? null, authors: (a.creators || []).map((c: any) => c.familyName || c.name).filter(Boolean),
    year: a.publicationYear ? Number(a.publicationYear) : null, venue: a.publisher?.name ?? a.publisher ?? null, url: a.url ?? `https://doi.org/${a.doi}` };
}

function xmlText(s: string | undefined) { return s ? s.replace(/<!\[CDATA\[|\]\]>/g, "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/\s+/g, " ").trim() : null; }

async function byArxiv(id: string, ua: string): Promise<Meta | null> {
  const r = await fetch(`https://export.arxiv.org/api/query?id_list=${encodeURIComponent(id)}&max_results=1`, { headers: { "user-agent": ua }, signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!r.ok) throw new Error(`upstream export.arxiv.org HTTP ${r.status}`);
  const x = await r.text();
  const e = x.match(/<entry>([\s\S]*?)<\/entry>/)?.[1];
  if (!e) return null;
  const title = xmlText(e.match(/<title[^>]*>([\s\S]*?)<\/title>/)?.[1]);
  if (!title || /^error$/i.test(title)) return null;
  const authors = [...e.matchAll(/<name>([\s\S]*?)<\/name>/g)].map((m) => xmlText(m[1])!.split(" ").pop()!).filter(Boolean);
  const pub = e.match(/<published>(\d{4})/)?.[1];
  return { source: "arxiv", id, title, authors, year: pub ? Number(pub) : null, venue: "arXiv", url: `https://arxiv.org/abs/${id}` };
}

async function byPmid(pmid: string, ua: string, mailto: string): Promise<Meta | null> {
  const j = await getJson(`https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi?db=pubmed&id=${pmid}&retmode=json&tool=linkproof&email=${encodeURIComponent(mailto)}`, ua);
  const d = j?.result?.[pmid];
  if (!d || d.error || !d.title) return null;
  const y = String(d.pubdate || d.epubdate || "").match(/\d{4}/)?.[0];
  return { source: "pubmed", id: pmid, title: d.title.replace(/\.$/, ""), authors: (d.authors || []).map((a: any) => String(a.name || "").split(" ")[0]).filter(Boolean),
    year: y ? Number(y) : null, venue: d.fulljournalname || d.source || null, url: `https://pubmed.ncbi.nlm.nih.gov/${pmid}/` };
}

function arxivEntries(x: string): Meta[] {
  const out: Meta[] = [];
  for (const e of x.matchAll(/<entry>([\s\S]*?)<\/entry>/g)) {
    const title = xmlText(e[1].match(/<title[^>]*>([\s\S]*?)<\/title>/)?.[1]) || "";
    const id = e[1].match(/<id>https?:\/\/arxiv\.org\/abs\/([^<]+?)(v\d+)?<\/id>/)?.[1] || "";
    const pub = e[1].match(/<published>(\d{4})/)?.[1];
    if (title && id) out.push({ source: "arxiv", id, title, authors: [...e[1].matchAll(/<name>([\s\S]*?)<\/name>/g)].map((m) => xmlText(m[1])!.split(" ").pop()!), year: pub ? Number(pub) : null, venue: "arXiv", url: `https://arxiv.org/abs/${id}` });
  }
  return out;
}

// "Authors. Title. Venue (year)." -> best-effort title + author surnames from a free-text reference
export function splitReference(raw: string): { title?: string; authors?: string[] } {
  // Vancouver style: "He K, Zhang X, Ren S, Sun J. Title. Venue 2016."
  const v = raw.replace(/\s+/g, " ").match(/^((?:[A-Z][\p{L}'\-]+(?: [A-Z]{1,3})?(?:, | and | & )?)+(?:,? et al\.?)?)\.? ([^.?]{8,}[.?])/u);
  if (v && /\b[A-Z]{1,3}\b/.test(v[1])) {
    const authors = v[1].replace(/,? et al\.?/, "").split(/, | and | & /).map((a) => a.trim()).filter(Boolean).slice(0, 15);
    return { title: v[2].replace(/[.?]$/, ""), authors };
  }
  const parts = raw.replace(/\s+/g, " ").split(/(?<![A-Z])\.\s+|\?\s+/).map((p) => p.trim()).filter(Boolean);
  if (parts.length < 2) return {};
  const first = parts[0];
  const looksAuthors = /,|\bet al\b|\band\b|&|\b[A-Z]{1,2}\b/.test(first) && first.split(" ").length <= 40;
  if (!looksAuthors) return { title: first };
  const authors = first.replace(/\bet al\.?/i, "").split(/,|;|&|\band\b/).map((a) => a.replace(/\(?\d{4}[a-z]?\)?/g, "").trim()).filter((a) => a && !/^([A-Z]\.?\s?-?){1,4}$/.test(a)).slice(0, 15);
  return { title: parts[1].replace(/^["“]|["”]$/g, ""), authors };
}

async function bySearch(it: CitationInput, ua: string, mailto: string): Promise<{ meta: Meta | null; candidates: number }> {
  const q = it.raw || [it.title, (it.authors || []).join(" "), it.year].filter(Boolean).join(" ");
  const fromRaw = it.raw ? splitReference(it.raw) : {};
  const title = it.title || fromRaw.title;
  const authors = it.authors || fromRaw.authors;
  const j = await getJson(`https://api.crossref.org/works?query.bibliographic=${encodeURIComponent(q.slice(0, 400))}&rows=8&select=DOI,title,author,issued,published,container-title,URL,publisher&mailto=${encodeURIComponent(mailto)}`, ua);
  const cands: Meta[] = (j?.message?.items || []).map(crossrefMeta);
  if (title) {
    const r = await fetch(`https://export.arxiv.org/api/query?search_query=${encodeURIComponent(`ti:"${title.replace(/["()]/g, "").slice(0, 200)}"`)}&max_results=3`, { headers: { "user-agent": ua }, signal: AbortSignal.timeout(TIMEOUT_MS) }).catch(() => null);
    if (r?.ok) cands.push(...arxivEntries(await r.text()));
  }
  let best: Meta | null = null, bestScore = -1, bestSim = 0;
  for (const m of cands) {
    const sim = title ? titleSim(title, m.title || "") : containsTitle(q, m.title || "");
    let score = sim;
    if (authors?.length && m.authors.length) { const f = new Set(m.authors.map(norm)); score += 0.25 * (authors.filter((a) => f.has(surname(a))).length / authors.length); }
    if (it.year && m.year) score += Math.abs(it.year - m.year) <= 1 ? 0.15 : 0;
    if (score > bestScore) { bestScore = score; best = m; bestSim = sim; }
  }
  return { meta: best && bestSim >= 0.6 ? best : null, candidates: cands.length };
}

function norm(s: string) { return s.toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "").replace(/<[^>]+>/g, " ").replace(/[^a-z0-9 ]+/g, " ").replace(/\s+/g, " ").trim(); }
function tokens(s: string) { return norm(s).split(" ").filter((w) => w.length > 2); }
export function titleSim(a: string, b: string) {
  const A = new Set(tokens(a)), B = new Set(tokens(b));
  if (!A.size || !B.size) return 0;
  let inter = 0; for (const w of A) if (B.has(w)) inter++;
  return (2 * inter) / (A.size + B.size);
}
function containsTitle(text: string, title: string) {
  const T = tokens(title); if (!T.length) return 0;
  const X = new Set(tokens(text)); let hit = 0; for (const w of T) if (X.has(w)) hit++;
  return hit / T.length;
}
function surname(a: string) {
  const s = a.includes(",") ? a.split(",")[0] : a.trim().split(/\s+/).filter((p) => !/^[A-Z]\.?$/.test(p)).pop() || a;
  return norm(s);
}

export async function verifyCitation(it: CitationInput, ua: string, mailto: string) {
  const started = Date.now();
  const input = it.raw ?? { doi: it.doi, arxiv: it.arxiv, pmid: it.pmid, title: it.title, authors: it.authors, year: it.year };
  const out: Record<string, unknown> = { input };
  try {
    let meta: Meta | null = null, method = "";
    if (it.doi) { method = "doi"; meta = await byDoi(it.doi, ua, mailto); }
    else if (it.arxiv) { method = "arxiv"; meta = await byArxiv(it.arxiv, ua); }
    else if (it.pmid) { method = "pmid"; meta = await byPmid(it.pmid, ua, mailto); }
    else { method = "search"; meta = (await bySearch(it, ua, mailto)).meta; }
    out.lookup = method;
    if (!meta) {
      out.exists = false; out.verdict = "not_found";
      out.confidence = method === "search" ? 0.7 : 0.95;
      out.note = method === "search" ? "No sufficiently similar record in Crossref/arXiv" : `Identifier not found (${method})`;
    } else {
      out.exists = true;
      out.matched = meta;
      const mismatches: Record<string, unknown>[] = [];
      let conf = method === "search" ? 0.75 : 0.95;
      const fromRaw = method === "search" && it.raw ? splitReference(it.raw) : {};
      const claimedTitle = it.title ?? fromRaw.title;
      const claimedAuthors = it.authors ?? fromRaw.authors;
      if (claimedTitle) {
        const s = titleSim(claimedTitle, meta.title || "");
        out.title_similarity = Number(s.toFixed(2));
        if (s < 0.8) mismatches.push({ field: "title", claimed: claimedTitle, found: meta.title, similarity: Number(s.toFixed(2)) });
        else conf = Math.max(conf, 0.85 + 0.1 * s);
      } else if (false) {
        const s = containsTitle(it.raw, meta.title || "");
        out.title_similarity = Number(s.toFixed(2));
        conf = 0.6 + 0.35 * s;
      }
      if (claimedAuthors?.length && meta.authors.length) {
        const found = new Set(meta.authors.map(norm));
        const missing = claimedAuthors.filter((a) => !found.has(surname(a)));
        if (missing.length) mismatches.push({ field: "authors", claimed_not_found: missing, found: meta.authors.slice(0, 15) });
      }
      if (it.year && meta.year && Math.abs(it.year - meta.year) > 1) mismatches.push({ field: "year", claimed: it.year, found: meta.year });
      out.mismatches = mismatches;
      out.verdict = mismatches.length ? "mismatch" : "verified";
      out.confidence = Number((mismatches.length ? Math.min(conf, 0.9) : conf).toFixed(2));
    }
  } catch (e: any) {
    const msg = String(e?.message || e);
    out.exists = null; out.verdict = "error"; out.error = /timeout|abort/i.test(msg) ? "upstream_timeout" : msg.slice(0, 200); out.confidence = 0;
  }
  out.elapsed_ms = Date.now() - started;
  return out;
}

export async function mapLimit<T, R>(xs: T[], limit: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(xs.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(limit, xs.length) }, async () => { while (i < xs.length) { const k = i++; out[k] = await fn(xs[k]); } }));
  return out;
}
