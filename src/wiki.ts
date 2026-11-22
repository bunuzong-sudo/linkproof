// Wikipedia short summary via the Wikimedia REST API, with Cache API (no KV writes).
// Follows Wikimedia API etiquette: descriptive User-Agent with contact, caching, modest volume.
// Returns CC BY-SA 4.0 attribution fields. Not a substitute for reading the article.

import { mapLimit } from "./citations";

export const PRICE_WIKI = "0.005";
export const MAX_WIKI_ITEMS = 3;
export const WIKI_LICENSE = "CC BY-SA 4.0";
export const WIKI_LICENSE_URL = "https://creativecommons.org/licenses/by-sa/4.0/";

const LANG_RE = /^(?:[a-z]{2,3}(?:-[a-z0-9]{2,12}){0,2}|simple)$/;

export type WikiInput = { query?: string; title?: string; lang: string };

export function parseWikiItems(body: any): { items?: WikiInput[]; error?: string } {
  if (!body || typeof body !== "object") {
    return { error: 'Body must be JSON: {"query": "HTTP 402"} or {"title": "HTTP 402", "lang": "en"}' };
  }
  const raw = body.items || body.queries;
  let list: any[];
  if (Array.isArray(raw)) list = raw;
  else if (body.title || body.query) list = [body];
  else return { error: "Provide `title` or `query` (or an `items` array of those)" };
  if (!list.length) return { error: "Provide at least one title or query" };
  if (list.length > MAX_WIKI_ITEMS) return { error: `At most ${MAX_WIKI_ITEMS} lookups per call` };
  const items: WikiInput[] = [];
  for (const r of list) {
    if (typeof r === "string") {
      const q = r.trim();
      if (!q || q.length > 300) return { error: "Each query must be 1–300 characters" };
      items.push({ query: q, lang: "en" });
      continue;
    }
    if (!r || typeof r !== "object") return { error: "Each item must be a string or {title|query, lang}" };
    const title = r.title != null ? String(r.title).trim() : "";
    const query = r.query != null ? String(r.query).trim() : "";
    if (!title && !query) return { error: "Each item needs a `title` or `query`" };
    if ((title && title.length > 300) || (query && query.length > 300)) return { error: "title/query must be 1–300 characters" };
    const lang = String(r.lang || body.lang || "en").trim().toLowerCase();
    if (!LANG_RE.test(lang) || lang.includes(".") || lang.includes("/") || lang.includes(":")) {
      return { error: `Unsupported language code: ${lang}` };
    }
    items.push({ title: title || undefined, query: query || undefined, lang });
  }
  return { items };
}

export function wikiAttribution(title: string, url: string, lang: string) {
  return {
    source: "Wikipedia",
    title,
    lang,
    url,
    license: WIKI_LICENSE,
    license_url: WIKI_LICENSE_URL,
    credit: `Text from the Wikipedia article "${title}" (${url}), licensed under CC BY-SA 4.0. Authors are listed on the article's history page.`,
  };
}

type CacheLike = { match: (r: Request) => Promise<Response | undefined>; put: (r: Request, res: Response) => Promise<void> };

function getCache(): CacheLike | null {
  try {
    const c = (globalThis as any).caches?.default;
    if (c && typeof c.match === "function" && typeof c.put === "function") return c;
  } catch {}
  return null;
}

async function cachedJson(
  url: string,
  ua: string,
  ctx?: { waitUntil?: (p: Promise<unknown>) => void },
): Promise<{ ok: boolean; status: number; json: any | null; cache: "hit" | "miss" | "none"; error?: string }> {
  const req = new Request(url, { method: "GET", headers: { "user-agent": ua, accept: "application/json" } });
  const cache = getCache();
  if (cache) {
    try {
      const hit = await cache.match(req);
      if (hit) {
        let json = null;
        try { json = await hit.json(); } catch { json = null; }
        return { ok: hit.ok, status: hit.status, json, cache: "hit" };
      }
    } catch {}
  }
  try {
    const res = await fetch(url, {
      method: "GET",
      headers: { "user-agent": ua, accept: "application/json", "api-user-agent": ua },
      signal: AbortSignal.timeout(8000),
    });
    const status = res.status;
    let json: any = null;
    const ct = res.headers.get("content-type") || "";
    if (/json/i.test(ct) || status === 200 || status === 404) {
      try { json = await res.json(); } catch { json = null; }
    } else {
      try { await res.body?.cancel(); } catch {}
    }
    if (cache && res.ok && json) {
      const headers = new Headers({ "content-type": "application/json", "cache-control": "public, max-age=3600" });
      const put = cache.put(req, new Response(JSON.stringify(json), { status: res.status, headers }));
      if (ctx?.waitUntil) ctx.waitUntil(put);
      else { try { await put; } catch {} }
    }
    return { ok: res.ok, status, json, cache: cache ? "miss" : "none" };
  } catch (e: any) {
    const msg = String(e?.message || e);
    return { ok: false, status: 0, json: null, cache: cache ? "miss" : "none", error: /timeout|abort/i.test(msg) ? "timeout" : "fetch_failed" };
  }
}

function wikiHost(lang: string): string {
  return `https://${lang}.wikipedia.org`;
}

function encodeTitle(title: string): string {
  return encodeURIComponent(title.replace(/ /g, "_"));
}

export function shapeSummary(j: any, lang: string, cache: string, resolved_via: string) {
  if (!j || typeof j !== "object") return null;
  if (j.type === "https://mediawiki.org/wiki/HyperSwitch/errors/not_found" || j.title === "Not found.") return null;
  const title = String(j.title || j.titles?.normalized || "").trim();
  if (!title) return null;
  const url = j.content_urls?.desktop?.page || `${wikiHost(lang)}/wiki/${encodeTitle(title)}`;
  const extract = typeof j.extract === "string" ? j.extract : "";
  return {
    found: true as const,
    title,
    description: typeof j.description === "string" ? j.description : null,
    extract,
    lang: j.lang || lang,
    url,
    thumbnail: j.thumbnail?.source || j.originalimage?.source || null,
    wikidata_id: j.wikibase_item || null,
    timestamp: j.timestamp || null,
    resolved_via,
    cache,
    attribution: wikiAttribution(title, url, j.lang || lang),
    disclaimer: "Extract is from Wikipedia and is licensed under CC BY-SA 4.0. It may be incomplete or outdated; follow the article URL for context and authors.",
  };
}

export async function wikiSummary(item: WikiInput, ua: string, ctx?: { waitUntil?: (p: Promise<unknown>) => void }) {
  const started = Date.now();
  const lang = item.lang || "en";
  const origin = wikiHost(lang);
  const out: Record<string, unknown> = { query: item.query || null, requested_title: item.title || null, lang };
  try {
    let title = item.title || "";
    let resolved_via = item.title ? "title" : "search";
    let cache: string = "none";
    if (!title && item.query) {
      const searchUrl = `${origin}/w/rest.php/v1/search/page?q=${encodeURIComponent(item.query)}&limit=1`;
      const s = await cachedJson(searchUrl, ua, ctx);
      cache = s.cache;
      if (s.error && !s.json) {
        out.error = s.error;
        out.found = false;
        out.elapsed_ms = Date.now() - started;
        return out;
      }
      title = s.json?.pages?.[0]?.title || s.json?.pages?.[0]?.key || "";
      if (!title) {
        out.found = false;
        out.extract = null;
        out.attribution = {
          source: "Wikipedia",
          license: WIKI_LICENSE,
          license_url: WIKI_LICENSE_URL,
          credit: "No matching Wikipedia article was found.",
        };
        out.elapsed_ms = Date.now() - started;
        return out;
      }
    }
    const sumUrl = `${origin}/api/rest_v1/page/summary/${encodeTitle(title)}`;
    const r = await cachedJson(sumUrl, ua, ctx);
    if (r.cache === "hit") cache = "hit";
    else if (cache !== "hit") cache = r.cache;
    if (r.error && !r.json) {
      // If a title miss, try search once.
      if (item.title && item.title === title) {
        const searchUrl = `${origin}/w/rest.php/v1/search/page?q=${encodeURIComponent(item.title)}&limit=1`;
        const s = await cachedJson(searchUrl, ua, ctx);
        const t2 = s.json?.pages?.[0]?.title;
        if (t2 && t2 !== title) {
          const r2 = await cachedJson(`${origin}/api/rest_v1/page/summary/${encodeTitle(t2)}`, ua, ctx);
          const shaped = shapeSummary(r2.json, lang, r2.cache, "search");
          if (shaped) {
            Object.assign(out, shaped);
            out.elapsed_ms = Date.now() - started;
            return out;
          }
        }
      }
      out.error = r.error;
      out.found = false;
      out.elapsed_ms = Date.now() - started;
      return out;
    }
    let shaped = shapeSummary(r.json, lang, cache, resolved_via);
    if (!shaped && item.title) {
      const searchUrl = `${origin}/w/rest.php/v1/search/page?q=${encodeURIComponent(item.title)}&limit=1`;
      const s = await cachedJson(searchUrl, ua, ctx);
      const t2 = s.json?.pages?.[0]?.title;
      if (t2) {
        const r2 = await cachedJson(`${origin}/api/rest_v1/page/summary/${encodeTitle(t2)}`, ua, ctx);
        shaped = shapeSummary(r2.json, lang, r2.cache === "hit" || s.cache === "hit" ? "hit" : r2.cache, "search");
      }
    }
    if (!shaped) {
      out.found = false;
      out.extract = null;
      out.attribution = {
        source: "Wikipedia",
        license: WIKI_LICENSE,
        license_url: WIKI_LICENSE_URL,
        credit: "No matching Wikipedia article was found.",
      };
      out.elapsed_ms = Date.now() - started;
      return out;
    }
    Object.assign(out, shaped);
  } catch (e: any) {
    const msg = String(e?.message || e);
    out.error = /timeout|abort/i.test(msg) ? "timeout" : msg.slice(0, 200);
    out.found = false;
  }
  out.elapsed_ms = Date.now() - started;
  return out;
}

export async function wikiSummaryMany(items: WikiInput[], ua: string, ctx?: { waitUntil?: (p: Promise<unknown>) => void }) {
  return mapLimit(items, 2, (it) => wikiSummary(it, ua, ctx));
}
