// Read a public web page (or PDF / plain text) and return clean Markdown for LLMs, plus metadata and an
// AI-usage hint built from robots.txt (AI crawler rules + Content-Signal), meta robots and X-Robots-Tag.
// HTML is converted by a small single-pass converter (no DOM) and capped so it fits the Workers CPU budget.
// PDFs are converted with Cloudflare Workers AI toMarkdown (free for PDF) when the AI binding exists.
import { parsePublicHttpUrl, safeFetch } from "./urlguard";
import { parseRobots, crawlerAccess, AI_CRAWLERS } from "./policies";

export const PRICE_READ_PAGE = "0.002";
export const MAX_HTML_BYTES = 1024 * 1024; // 1 MB of HTML
export const MAX_PDF_BYTES = 5 * 1024 * 1024; // 5 MB PDF
export const DEFAULT_MAX_CHARS = 20_000;
export const MAX_CHARS_LIMIT = 100_000;
export const MAX_LINKS_OUT = 100;

export type ReadPageInput = { url: string; max_chars: number; include_links: boolean; ai_policy: boolean };

export function parseReadPageInput(body: any): { item?: ReadPageInput; error?: string } {
  if (!body || typeof body !== "object" || Array.isArray(body)) return { error: 'Body must be JSON: {"url": "https://..."}' };
  const raw = typeof body.url === "string" ? body.url : Array.isArray(body.urls) && body.urls.length === 1 ? body.urls[0] : undefined;
  if (typeof raw !== "string") return { error: "`url` (string) is required: one public http(s) page or PDF per call" };
  const p = parsePublicHttpUrl(raw, { allowDomainOnly: true });
  if (p.error || !p.href) return { error: p.error || "Invalid URL" };
  let max = DEFAULT_MAX_CHARS;
  if (body.max_chars !== undefined) {
    const n = Number(body.max_chars);
    if (!Number.isInteger(n) || n < 500 || n > MAX_CHARS_LIMIT) return { error: `\`max_chars\` must be an integer 500-${MAX_CHARS_LIMIT}` };
    max = n;
  }
  if (body.include_links !== undefined && typeof body.include_links !== "boolean") return { error: "`include_links` must be boolean" };
  if (body.ai_policy !== undefined && typeof body.ai_policy !== "boolean") return { error: "`ai_policy` must be boolean" };
  return { item: { url: p.href, max_chars: max, include_links: body.include_links === true, ai_policy: body.ai_policy !== false } };
}

// ---------- HTML helpers ----------
const NAMED: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", ndash: "–", mdash: "—", hellip: "…", rsquo: "’", lsquo: "‘",
  ldquo: "“", rdquo: "”", copy: "©", reg: "®", trade: "™", middot: "·", bull: "•", laquo: "«", raquo: "»", times: "×",
  euro: "€", pound: "£", yen: "¥", cent: "¢", deg: "°", shy: "", zwj: "", zwnj: "", thinsp: " ", ensp: " ", emsp: " ",
  sect: "§", para: "¶", plusmn: "±", frac12: "½", frac14: "¼", frac34: "¾", larr: "←", rarr: "→", uarr: "↑", darr: "↓", hearts: "♥", check: "✓",
};
export function decodeEntities(s: string): string {
  if (s.indexOf("&") < 0) return s;
  return s.replace(/&(#x[0-9a-f]{1,6}|#\d{1,7}|[a-z][a-z0-9]{1,15});/gi, (m, e: string) => {
    if (e[0] === "#") {
      const cp = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      if (!Number.isFinite(cp) || cp <= 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return "";
      return String.fromCodePoint(cp);
    }
    const v = NAMED[e.toLowerCase()];
    return v === undefined ? m : v;
  });
}

const ATTR_RE: Record<string, RegExp> = {};
function attr(attrs: string, name: string): string | null {
  if (!attrs || attrs.toLowerCase().indexOf(name) < 0) return null;
  const re = ATTR_RE[name] || (ATTR_RE[name] = new RegExp(`(?:^|\\s)${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'>]+))`, "i"));
  const m = attrs.match(re);
  return m ? decodeEntities(m[1] ?? m[2] ?? m[3] ?? "") : null;
}

export type PageMeta = { title: string | null; description: string | null; lang: string | null; canonical: string | null; site_name: string | null; author: string | null; published: string | null; meta_robots: string | null };

export function extractMeta(html: string): PageMeta {
  const head = html.slice(0, 200_000);
  const metas: Record<string, string> = {};
  for (const m of head.matchAll(/<meta\b([^>]*)>/gi)) {
    const a = m[1];
    const key = (attr(a, "name") || attr(a, "property") || attr(a, "itemprop") || "").toLowerCase();
    const content = attr(a, "content");
    if (key && content != null && !(key in metas)) metas[key] = content.trim();
  }
  const t = head.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  const title = t ? decodeEntities(t[1].replace(/\s+/g, " ").trim()) : null;
  let canonical: string | null = null;
  for (const m of head.matchAll(/<link\b([^>]*)>/gi)) {
    if ((attr(m[1], "rel") || "").toLowerCase().split(/\s+/).includes("canonical")) { canonical = attr(m[1], "href"); break; }
  }
  const lang = head.match(/<html\b[^>]*\slang\s*=\s*["']?([a-zA-Z-]{2,20})/i)?.[1] ?? null;
  return {
    title: title || metas["og:title"] || metas["twitter:title"] || null,
    description: metas["description"] || metas["og:description"] || metas["twitter:description"] || null,
    lang,
    canonical,
    site_name: metas["og:site_name"] || null,
    author: metas["author"] || metas["article:author"] || null,
    published: metas["article:published_time"] || metas["datepublished"] || metas["date"] || metas["dc.date"] || null,
    meta_robots: [metas["robots"], metas["googlebot"]].filter(Boolean).join(", ") || null,
  };
}

const DROP_BLOCKS = ["script", "style", "noscript", "svg", "template", "iframe", "canvas", "object", "select", "button", "math", "head"];
const BOILERPLATE = ["nav", "footer", "aside", "form", "dialog"];

function stripBlocks(html: string, tags: string[]): string {
  let out = html;
  for (const t of tags) out = out.replace(new RegExp(`<${t}\\b[\\s\\S]*?<\\/${t}\\s*>`, "gi"), " ");
  return out;
}

const BOILER_TOKEN = /(?:^|[\s_-])(?:nav|navbar|navigation|menu|menus|sidebar|toc|breadcrumbs?|cookies?|consent|share|sharing|social|related|footer|langlinks|interlanguage|language-?(?:list|selector|dropdown|switcher)|dropdown|mw-editsection|navbox|vector-(?:menu|header|toc|page-toolbar|column-start|column-end|pinnable)|skip-?links?|advert|adverts|ads|promo|newsletter|subscribe|popup|modal|paywall)(?:[\s_-]|$)/i;
const BOILER_ROLE = /^(?:navigation|banner|contentinfo|complementary|search|dialog|menu|menubar)$/i;

/** Remove elements that look like navigation, menus, cookie bars, share widgets, ... (balanced, nesting-aware). */
export function stripBoilerplateElements(html: string): string {
  const open = /<(div|ul|ol|section|span|nav|aside|header|footer|table|li|p|figure)\b([^>]*)>/gi;
  let out = "", last = 0, m: RegExpExecArray | null, guard = 0;
  while ((m = open.exec(html)) && guard++ < 5000) {
    const a = m[2];
    const cls = (attr(a, "class") || "") + " " + (attr(a, "id") || "");
    const role = attr(a, "role") || "";
    const hidden = /\shidden(?:\s|=|$)/i.test(a) || attr(a, "aria-hidden") === "true" || /display\s*:\s*none/i.test(attr(a, "style") || "");
    if (!(hidden || BOILER_ROLE.test(role) || BOILER_TOKEN.test(cls))) continue;
    if (m[0].endsWith("/>")) continue;
    const tag = m[1].toLowerCase();
    const scan = new RegExp(`<(/?)${tag}\\b[^>]*>`, "gi");
    scan.lastIndex = open.lastIndex;
    let depth = 1, s2: RegExpExecArray | null, end = -1;
    while ((s2 = scan.exec(html))) { if (s2[1]) { if (--depth === 0) { end = scan.lastIndex; break; } } else if (!s2[0].endsWith("/>")) depth++; }
    if (end < 0) continue; // unbalanced: leave it
    out += html.slice(last, m.index) + " ";
    last = end;
    open.lastIndex = end;
  }
  return out + html.slice(last);
}

/** Pick the main content region: the largest <article>, else <main>, else <body>, else everything. */
export function pickMain(html: string): { html: string; region: string } {
  let best = "";
  for (const m of html.matchAll(/<article\b[^>]*>([\s\S]*?)<\/article\s*>/gi)) if (m[1].length > best.length) best = m[1];
  if (best.replace(/<[^>]+>/g, "").trim().length > 400) return { html: best, region: "article" };
  const main = html.match(/<main\b[^>]*>([\s\S]*?)<\/main\s*>/i) || html.match(/<[a-z]+\b[^>]*\brole\s*=\s*["']?main\b[^>]*>([\s\S]*)/i);
  if (main && main[1].replace(/<[^>]+>/g, "").trim().length > 200) return { html: main[1], region: "main" };
  const body = html.match(/<body\b[^>]*>([\s\S]*)/i);
  return { html: body ? body[1] : html, region: "body" };
}

function absUrl(href: string | null, base: string): string | null {
  if (!href) return null;
  const h = href.trim();
  if (!h || h.startsWith("#") || /^(javascript|mailto|tel|data):/i.test(h)) return /^mailto:/i.test(h) ? h : null;
  try { const u = new URL(h, base); return u.protocol === "http:" || u.protocol === "https:" ? u.href : null; } catch { return null; }
}

/** Single-pass HTML -> Markdown. Headings, paragraphs, lists, links, code, quotes and simple tables. */
export function htmlToMarkdown(htmlIn: string, baseUrl: string, opts: { boilerplate?: boolean } = {}): { markdown: string; links: { text: string; url: string }[]; region: string } {
  let html = htmlIn.replace(/<!--[\s\S]*?-->/g, " ").replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, " ");
  html = stripBlocks(html, DROP_BLOCKS);
  if (opts.boilerplate !== false) html = stripBoilerplateElements(html);
  const picked = pickMain(html);
  html = picked.region === "body" && opts.boilerplate !== false ? stripBlocks(picked.html, BOILERPLATE) : picked.html;
  html = html.replace(/<header\b[^>]*>[\s\S]*?<\/header\s*>/gi, (m) => (/<h1\b/i.test(m) ? m : " "));

  // Output is an array of pieces (not one growing string) so tail checks stay O(1) on big pages.
  const buf: string[] = [];
  const links: { text: string; url: string }[] = [];
  const lists: { ordered: boolean; n: number }[] = [];
  const anchors: { idx: number; href: string | null }[] = [];
  const quotes: number[] = [];
  let pre = 0, row: { cells: number } | null = null, rowsInTable = 0, headerDone = false;
  const tail = (n: number) => { let s = ""; for (let i = buf.length - 1; i >= 0 && s.length < n; i--) s = buf[i] + s; return s.slice(-n); };
  const push = (s: string) => { if (s) buf.push(s); };
  const rtrim = () => {
    while (buf.length) {
      const last = buf[buf.length - 1];
      let i = last.length; while (i > 0 && (last.charCodeAt(i - 1) === 32 || last.charCodeAt(i - 1) === 9)) i--;
      if (i === 0) { buf.pop(); continue; }
      if (i < last.length) buf[buf.length - 1] = last.slice(0, i);
      break;
    }
  };
  const block = () => { rtrim(); if (!buf.length) return; const t = tail(2); if (t === "\n\n") return; push(t.endsWith("\n") ? "\n" : "\n\n"); };
  const line = () => { rtrim(); if (buf.length && !tail(1).endsWith("\n")) push("\n"); };
  const take = (idx: number) => { const s = buf.slice(idx).join(""); buf.length = idx; return s; };

  const re = /<\/?([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>|([^<]+)|</g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    if (m[3] !== undefined || m[0] === "<") {
      let t = decodeEntities(m[3] ?? "<");
      if (pre) { push(t); continue; }
      t = t.replace(/\s+/g, " ");
      if (t.charCodeAt(0) === 32) { const l = tail(1); if (!l || l === "\n" || l === " ") t = t.slice(1); }
      push(t);
      continue;
    }
    const tag = m[1].toLowerCase();
    const close = m[0][1] === "/";
    const a = m[2] || "";
    switch (tag) {
      case "h1": case "h2": case "h3": case "h4": case "h5": case "h6":
        block(); if (!close) push("#".repeat(Number(tag[1])) + " "); break;
      case "p": case "figure": block(); break;
      case "div": case "section": case "article": case "main": case "header": case "figcaption":
      case "dl": case "dt": case "dd": case "address": case "details": case "summary": case "center": case "fieldset":
        line(); break;
      case "br": rtrim(); push("\n"); break;
      case "hr": block(); push("---"); block(); break;
      case "ul": case "ol":
        if (close) { lists.pop(); if (!lists.length) block(); else line(); }
        else { if (!lists.length) block(); else line(); const st = attr(a, "start"); lists.push({ ordered: tag === "ol", n: st && /^\d{1,6}$/.test(st.trim()) ? Number(st) - 1 : 0 }); }
        break;
      case "li":
        if (close) break;
        line();
        { const l = lists[lists.length - 1]; push("  ".repeat(Math.max(0, lists.length - 1)) + (l?.ordered ? `${++l.n}. ` : "- ")); }
        break;
      case "a":
        if (!close) { if (anchors.length < 50) anchors.push({ idx: buf.length, href: absUrl(attr(a, "href"), baseUrl) }); }
        else {
          const an = anchors.pop();
          if (an && an.href) {
            const raw = buf.slice(an.idx).join("");
            const text = raw.replace(/\s+/g, " ").trim();
            if (text && !pre && text.length <= 300 && !/\n|\[image:/.test(raw) && !/^#/.test(text)) {
              buf.length = an.idx;
              const lead = raw.startsWith(" ") ? " " : "";
              push(`${lead}[${text.replace(/[\[\]]/g, "")}](${an.href})`);
            }
            if (text && links.length < MAX_LINKS_OUT && !links.some((x) => x.url === an.href)) links.push({ text: text.slice(0, 200), url: an.href });
          }
        }
        break;
      case "strong": case "b": if (!pre) push("**"); break;
      case "code": case "kbd": case "samp": if (!pre) push("`"); break;
      case "pre":
        if (close) { pre = Math.max(0, pre - 1); rtrim(); while (buf.length && buf[buf.length - 1].endsWith("\n")) { buf[buf.length - 1] = buf[buf.length - 1].replace(/\n+$/, ""); if (!buf[buf.length - 1]) buf.pop(); } push("\n```"); block(); }
        else { block(); push("```\n"); pre++; }
        break;
      case "blockquote":
        if (!close) { block(); quotes.push(buf.length); }
        else {
          const s = quotes.pop();
          if (s !== undefined) { const q = take(s).trim(); push(q.split("\n").map((x) => (x ? "> " + x : ">")).join("\n")); }
          block();
        }
        break;
      case "table": if (!close) { rowsInTable = 0; headerDone = false; } block(); break;
      case "tr":
        if (!close) { line(); push("|"); row = { cells: 0 }; }
        else if (row) {
          rowsInTable++;
          if (rowsInTable === 1 && !headerDone && row.cells) { push("\n|" + " --- |".repeat(row.cells)); headerDone = true; }
          row = null;
        }
        break;
      case "td": case "th":
        if (!close) { if (row) row.cells++; push(" "); }
        else { rtrim(); push(" |"); }
        break;
      case "img":
        { const alt = attr(a, "alt"); if (alt && alt.trim().length > 2 && !pre) push(` [image: ${alt.trim().slice(0, 120)}] `); }
        break;
      default: break;
    }
  }
  const out = buf.join("");
  // Clean up: empty emphasis/code markers, trailing spaces, blank-line runs.
  let md = out.replace(/\*\*\s*\*\*/g, "").replace(/(^|[^`])``(?!`)/g, "$1")
    .replace(/[ \t]+\n/g, "\n").replace(/\n{3,}/g, "\n\n").replace(/^(#{1,6}) *\n/gm, "").replace(/^- *$/gm, "").replace(/\n{3,}/g, "\n\n").trim();
  return { markdown: md, links, region: picked.region };
}

// ---------- AI usage hint ----------
export type AiUsage = {
  verdict: "allowed" | "restricted" | "unknown";
  summary: string;
  robots_txt: { present: boolean; status: number | null; generic_allowed: boolean | null; ai_crawlers_blocked: string[]; ai_crawlers_allowed: number; content_signal: Record<string, string> | null };
  meta_robots: string | null;
  x_robots_tag: string | null;
  signals: string[];
};

export function parseContentSignal(robots: string): Record<string, string> | null {
  const out: Record<string, string> = {};
  for (const m of robots.matchAll(/^\s*content-signal\s*:\s*(.+)$/gim)) {
    for (const part of m[1].split(",")) {
      const [k, v] = part.split("=").map((x) => x.trim().toLowerCase());
      if (k && v && !(k in out)) out[k] = v;
    }
  }
  return Object.keys(out).length ? out : null;
}

export function buildAiUsage(robots: { present: boolean; status: number | null; text: string }, path: string, metaRobots: string | null, xRobots: string | null): AiUsage {
  const signals: string[] = [];
  let generic: boolean | null = null, blocked: string[] = [], allowedCount = 0, cs: Record<string, string> | null = null;
  if (robots.present) {
    const parsed = parseRobots(robots.text);
    const acc = crawlerAccess(parsed.groups, path, AI_CRAWLERS);
    generic = acc["*"].allowed;
    for (const name of AI_CRAWLERS) { if (name === "Googlebot" || name === "Applebot") continue; if (acc[name].allowed) allowedCount++; else blocked.push(name); }
    cs = parseContentSignal(robots.text);
    if (generic === false) signals.push("robots.txt disallows this path for all crawlers (*)");
    if (blocked.length) signals.push(`robots.txt blocks ${blocked.length} AI crawler(s) for this path: ${blocked.slice(0, 8).join(", ")}${blocked.length > 8 ? ", ..." : ""}`);
    if (cs) for (const [k, v] of Object.entries(cs)) if (v === "no") signals.push(`Content-Signal ${k}=no`);
  }
  const mr = (metaRobots || "").toLowerCase(), xr = (xRobots || "").toLowerCase();
  for (const [src, v] of [["meta robots", mr], ["X-Robots-Tag", xr]] as const) {
    if (/\bnoai\b/.test(v)) signals.push(`${src}: noai`);
    if (/\bnoimageai\b/.test(v)) signals.push(`${src}: noimageai`);
    if (/\bnoindex\b|\bnone\b/.test(v)) signals.push(`${src}: noindex`);
  }
  const restricted = signals.length > 0;
  const verdict: AiUsage["verdict"] = restricted ? "restricted" : robots.present ? "allowed" : "unknown";
  const summary = verdict === "restricted"
    ? "The site signals limits on automated or AI use of this page; check the signals before storing, training on or republishing it."
    : verdict === "allowed"
      ? "No robots.txt, meta or header signal restricts AI agents from reading this page. Copyright and site terms still apply."
      : "No robots.txt found (or it could not be read) and no meta/header restriction; no machine-readable AI policy.";
  return { verdict, summary, robots_txt: { present: robots.present, status: robots.status, generic_allowed: generic, ai_crawlers_blocked: blocked, ai_crawlers_allowed: allowedCount, content_signal: cs }, meta_robots: metaRobots, x_robots_tag: xRobots, signals };
}

// ---------- fetch + convert ----------
function charsetOf(ct: string | null, bytes: Uint8Array): string {
  const fromCt = ct?.match(/charset\s*=\s*["']?([\w-]+)/i)?.[1];
  if (fromCt) return fromCt.toLowerCase();
  const head = new TextDecoder("latin1").decode(bytes.subarray(0, 4096));
  return (head.match(/<meta[^>]+charset\s*=\s*["']?([\w-]+)/i)?.[1] || "utf-8").toLowerCase();
}
function decode(bytes: Uint8Array, charset: string): string {
  try { return new TextDecoder(charset, { fatal: false }).decode(bytes); } catch { return new TextDecoder("utf-8", { fatal: false }).decode(bytes); }
}

export type AiBinding = { toMarkdown: (doc: { name: string; blob: Blob }) => Promise<any> };

const isPdf = (ct: string | null, bytes: Uint8Array) => /application\/pdf/i.test(ct || "") || (bytes.length > 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46);
const isHtml = (ct: string | null, text: string) => /html|xhtml/i.test(ct || "") || (!ct && /^\s*(<!doctype html|<html)/i.test(text));
const isTextual = (ct: string | null) => !ct || /^text\/|json|xml|javascript|yaml|csv|markdown/i.test(ct);

export async function readPage(item: ReadPageInput, ua: string, ai?: AiBinding | null): Promise<{ status: number; body: any }> {
  const started = Date.now();
  const target = new URL(item.url);
  const headers = { "user-agent": ua, accept: "text/html,application/xhtml+xml,application/pdf;q=0.9,text/plain;q=0.8,*/*;q=0.5", "accept-language": "en,*;q=0.5" };
  const robotsP = item.ai_policy
    ? safeFetch(`${target.origin}/robots.txt`, { headers: { "user-agent": ua }, maxBytes: 64 * 1024, timeoutMs: 5000 }).catch(() => null)
    : Promise.resolve(null);
  const r = await safeFetch(item.url, { headers, maxBytes: MAX_PDF_BYTES, timeoutMs: 10_000, raw: true });
  if (r.error || r.status == null) return { status: 502, body: { error: `Could not fetch the page (${r.error || "no response"}); not charged.`, url: item.url, fetch_error: r.error } };
  if (r.status >= 400) return { status: 502, body: { error: `The page returned HTTP ${r.status}; not charged.`, url: item.url, final_url: r.url, status: r.status } };
  const bytes = r.raw ?? new Uint8Array(0);
  const ct = r.content_type;
  const finalUrl = r.url;
  let source: "html" | "pdf" | "text";
  let markdown = "", meta: PageMeta = { title: null, description: null, lang: null, canonical: null, site_name: null, author: null, published: null, meta_robots: null };
  let links: { text: string; url: string }[] = [], region: string | null = null, truncatedInput = r.truncated, pages: number | null = null;

  if (isPdf(ct, bytes)) {
    source = "pdf";
    if (r.truncated) return { status: 413, body: { error: `PDF is larger than ${MAX_PDF_BYTES / 1024 / 1024} MB; not charged.`, url: item.url } };
    if (!ai) return { status: 422, body: { error: "PDF conversion is not available right now; not charged.", url: item.url } };
    const name = (decodeURIComponent(new URL(finalUrl).pathname.split("/").pop() || "document") || "document").replace(/[^\w.-]/g, "_").replace(/(\.pdf)?$/i, ".pdf");
    let res: any;
    try { res = await ai.toMarkdown({ name, blob: new Blob([bytes as any], { type: "application/pdf" }) }); } catch (e: any) { return { status: 502, body: { error: "PDF conversion failed; not charged.", detail: String(e?.message || e).slice(0, 200), url: item.url } }; }
    const one = Array.isArray(res) ? res[0] : res;
    if (!one || one.format === "error" || typeof one.data !== "string") return { status: 422, body: { error: "Could not extract text from this PDF (scanned image or protected?); not charged.", detail: one?.error ?? null, url: item.url } };
    let md = String(one.data).replace(/\r\n/g, "\n");
    // toMarkdown output: "# file.pdf", "## Metadata" (- Key=Value lines), "## Contents", "### Page N" ...
    const metaBlock = md.match(/^## Metadata\n([\s\S]*?)(?=^## |$(?![\s\S]))/m);
    const kv = (k: string) => metaBlock?.[1].match(new RegExp(`^- ${k}=(.+)$`, "m"))?.[1].trim() || null;
    md = md.replace(/^# [^\n]*\n/, "").replace(/^## Metadata\n[\s\S]*?(?=^## |$(?![\s\S]))/m, "").replace(/^## Contents\n/m, "");
    markdown = md.replace(/\n{3,}/g, "\n\n").trim();
    meta.title = kv("Title") || name;
    meta.author = kv("Author");
    pages = (markdown.match(/^#{2,3} ?Page \d+/gim) || []).length || null;
    if (meta.title) markdown = `# ${meta.title}\n\n${markdown}`;
  } else {
    if (!isTextual(ct)) return { status: 415, body: { error: `Unsupported content type ${ct}; only HTML, plain text and PDF are converted. Not charged.`, url: item.url, content_type: ct } };
    const htmlBytes = bytes.length > MAX_HTML_BYTES ? bytes.subarray(0, MAX_HTML_BYTES) : bytes;
    if (bytes.length > MAX_HTML_BYTES) truncatedInput = true;
    const text = decode(htmlBytes, charsetOf(ct, htmlBytes));
    if (isHtml(ct, text)) {
      source = "html";
      meta = extractMeta(text);
      const conv = htmlToMarkdown(text, finalUrl);
      markdown = conv.markdown; links = conv.links; region = conv.region;
      if (meta.title && !markdown.startsWith("# ")) markdown = `# ${meta.title}\n\n${markdown}`;
    } else {
      source = "text";
      markdown = text.replace(/\r\n/g, "\n").trim();
    }
  }
  const totalChars = markdown.length;
  const truncated = totalChars > item.max_chars;
  const content = truncated ? markdown.slice(0, item.max_chars).replace(/\s+\S*$/, "") + "\n\n[... truncated]" : markdown;
  const words = (markdown.match(/[\p{L}\p{N}]+/gu) || []).length;
  let aiUsage: AiUsage | null = null;
  if (item.ai_policy) {
    const rb = await robotsP;
    const robotsOk = !!rb && !rb.error && rb.status === 200 && !/html/i.test(rb.content_type || "");
    aiUsage = buildAiUsage({ present: robotsOk, status: rb?.status ?? null, text: robotsOk ? rb!.body : "" }, new URL(finalUrl).pathname || "/", meta.meta_robots, r.headers.get("x-robots-tag"));
  }
  if (!content.trim() || (source === "html" && words < 3)) {
    return { status: 422, body: { error: "No readable text found (page may need JavaScript to render); not charged.", url: item.url, final_url: finalUrl, title: meta.title, ai_usage: aiUsage } };
  }
  return { status: 200, body: {
    url: item.url, final_url: finalUrl, status: r.status, content_type: ct, source,
    title: meta.title, description: meta.description, lang: meta.lang, site_name: meta.site_name, author: meta.author, published: meta.published, canonical: meta.canonical,
    ...(pages ? { pdf_pages: pages } : {}),
    format: "markdown", content, content_chars: content.length, total_chars: totalChars, truncated, input_truncated: truncatedInput, word_count: words,
    ...(region ? { content_region: region } : {}),
    ...(item.include_links ? { links } : { links_found: links.length }),
    ai_usage: aiUsage,
    fetched_at: new Date().toISOString(), elapsed_ms: Date.now() - started,
  } };
}
