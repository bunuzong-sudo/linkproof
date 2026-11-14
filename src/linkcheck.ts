export const MAX_URLS = 10;
const MAX_BYTES = 64 * 1024;
const MAX_BYTES_EXPECT = 256 * 1024;
const TIMEOUT_MS = 8000;
const UA = "LinkProof/1.0 (+https://linkproof.bsptimber.workers.dev; URL verification for AI agents)";

const SOFT404 = [
  /page (was )?not found/i, /\b404\b[^<]{0,40}(error|not found)/i, /(doesn'?t|does not|no longer) exist/i,
  /could ?n[o']t be found/i, /no longer available/i, /page you (are|were) looking for/i, /nothing (was )?found/i,
];
const PARKED = [
  /domain (name )?(is |may be )?for sale/i, /buy this domain/i, /this domain is parked/i, /parked free/i,
  /hugedomains/i, /sedoparking|sedo\.com/i, /dan\.com/i, /afternic/i, /domain has expired/i,
];

export type Item = { url: string; expect?: string };

export function parseItems(body: any): { items?: Item[]; error?: string } {
  if (!body || typeof body !== "object") return { error: "Body must be JSON: {\"urls\": [\"https://...\"]}" };
  const raw = body.urls;
  if (!Array.isArray(raw) || raw.length === 0) return { error: "`urls` must be a non-empty array" };
  if (raw.length > MAX_URLS) return { error: `At most ${MAX_URLS} URLs per call` };
  const items: Item[] = [];
  for (const r of raw) {
    const it: Item = typeof r === "string" ? { url: r } : { url: r?.url, expect: r?.expect };
    if (typeof it.url !== "string") return { error: "Each entry must be a URL string or {url, expect}" };
    let u: URL;
    try { u = new URL(it.url); } catch { return { error: `Invalid URL: ${String(it.url).slice(0, 200)}` }; }
    if (u.protocol !== "http:" && u.protocol !== "https:") return { error: `Only http(s) URLs: ${it.url}` };
    if (u.username || u.password) return { error: "URLs with credentials are not allowed" };
    if (it.expect !== undefined && (typeof it.expect !== "string" || it.expect.length > 300))
      return { error: "`expect` must be a string up to 300 chars" };
    items.push(it);
  }
  return { items };
}

function decodeEntities(s: string) {
  return s.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'").replace(/&nbsp;/g, " ").replace(/&middot;/g, "·").replace(/&ndash;/g, "–").replace(/&mdash;/g, "—").replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16))).replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n)).replace(/\s+/g, " ").trim();
}

async function readCapped(res: Response, cap = MAX_BYTES): Promise<string> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (total < cap) {
    const { done, value } = await reader.read();
    if (done || !value) break;
    chunks.push(value); total += value.byteLength;
  }
  try { await reader.cancel(); } catch {}
  const buf = new Uint8Array(Math.min(total, cap));
  let off = 0;
  for (const c of chunks) { const n = Math.min(c.byteLength, buf.length - off); buf.set(c.subarray(0, n), off); off += n; if (off >= buf.length) break; }
  return new TextDecoder("utf-8", { fatal: false }).decode(buf);
}

export async function check(item: Item) {
  const started = Date.now();
  const out: Record<string, unknown> = { url: item.url };
  try {
    const res = await fetch(item.url, {
      redirect: "follow",
      headers: { "user-agent": UA, accept: "text/html,application/xhtml+xml,*/*;q=0.8" },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const ct = res.headers.get("content-type") || "";
    out.status = res.status;
    out.final_url = res.url || item.url;
    out.redirected = !!res.redirected && new URL(res.url).href !== new URL(item.url).href;
    out.content_type = ct.split(";")[0] || null;
    let text = "";
    if (/text|html|xml|json/i.test(ct)) text = await readCapped(res, item.expect !== undefined ? MAX_BYTES_EXPECT : MAX_BYTES);
    else { try { await res.body?.cancel(); } catch {} }
    const m = text.match(/<title[^>]*>([\s\S]{0,500}?)<\/title>/i);
    const title = m ? decodeEntities(m[1]).slice(0, 200) : null;
    out.title = title;
    const desc = text.match(/<meta[^>]+(?:name|property)=["'](?:description|og:description)["'][^>]*content=["']([^"']{0,400})/i);
    out.description = desc ? decodeEntities(desc[1]).slice(0, 300) : null;
    const head = (title || "") + " " + text.slice(0, 20000).replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<[^>]+>/g, " ");
    const orig = new URL(item.url), fin = new URL(String(out.final_url));
    const redirectedToRoot = orig.pathname.length > 1 && (fin.pathname === "/" || fin.pathname === "") && orig.host.replace(/^www\./, "") === fin.host.replace(/^www\./, "");
    const soft404 = res.status < 400 && (SOFT404.some((r) => r.test(title || "")) || (SOFT404.some((r) => r.test(head.slice(0, 3000))) && head.length < 15000) || redirectedToRoot);
    const parked = PARKED.some((r) => r.test(head));
    out.soft_404 = soft404;
    out.redirected_to_homepage = redirectedToRoot;
    out.parked_domain = parked;
    if (item.expect !== undefined) {
      const norm = (s: string) => s.toLowerCase().replace(/\s+/g, " ");
      out.expect = item.expect;
      out.expect_found = text ? norm(decodeEntities(text.replace(/<[^>]+>/g, " "))).includes(norm(item.expect)) : false;
      out.expect_note = `searched first ${MAX_BYTES_EXPECT / 1024} KB of the page (case-insensitive, tags stripped)`;
    }
    if (res.status === 530 || res.status === 523) {
      // Cloudflare edge: origin DNS failure / unreachable origin
      out.error = res.status === 530 ? "dns_error" : "origin_unreachable";
      out.verdict = "unreachable";
      out.elapsed_ms = Date.now() - started;
      return out;
    }
    const blocked = res.status === 401 || res.status === 403 || res.status === 429;
    out.verdict = res.status >= 200 && res.status < 400 && !soft404 && !parked
      ? (item.expect !== undefined && !out.expect_found ? "live_but_text_not_found" : "live")
      : blocked ? "blocked_or_rate_limited" : parked ? "parked" : soft404 ? "soft_404" : "dead";
  } catch (e: any) {
    const msg = String(e?.message || e);
    out.status = null;
    out.error = /timeout|abort/i.test(msg) ? "timeout" : /dns|resolve|not found/i.test(msg) ? "dns_error" : msg.slice(0, 200);
    out.verdict = "unreachable";
  }
  out.elapsed_ms = Date.now() - started;
  return out;
}

