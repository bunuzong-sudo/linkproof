// Email authentication records via DNS-over-HTTPS (Cloudflare, Google fallback).
// Reads SPF, DMARC, MX and common DKIM selectors only. Never probes a mailbox
// (no SMTP, VRFY, RCPT or similar) and is not a deliverability or safety guarantee.

import { isBlockedHost, isPrivateIPv4 } from "./urlguard";
import { mapLimit } from "./citations";

export const MAX_EMAIL_DOMAINS = 5;
export const PRICE_EMAIL_AUTH = "0.002";
export const EMAIL_AUTH_DISCLAIMER =
  "This is a DNS record check only, not a deliverability or safety guarantee. Mailbox existence is never probed.";

/** Widely used DKIM selectors. Presence of any published key is reported; absence of the rest is normal. */
export const COMMON_DKIM_SELECTORS = [
  "google", "selector1", "selector2", "default", "k1", "k2", "s1", "s2",
  "dkim", "mail", "everlytick", "fm1", "fm2", "s1024", "s2048",
  "amazonses", "dkim1", "dkim2", "sig1", "zendesk1", "s2015", "protonmail",
  "googlemail", "ctct1", "smtpapi",
] as const;

export type DnsLookup = (name: string, type: "TXT" | "MX") => Promise<{ status: number; records: string[]; error?: string; provider?: string }>;

export function parseEmailDomains(body: any): { items?: string[]; error?: string } {
  if (!body || typeof body !== "object") return { error: 'Body must be JSON: {"domains": ["example.com"]}' };
  const raw = body.domains;
  if (!Array.isArray(raw) || raw.length === 0) return { error: "`domains` must be a non-empty array" };
  if (raw.length > MAX_EMAIL_DOMAINS) return { error: `At most ${MAX_EMAIL_DOMAINS} domains per call` };
  const items: string[] = [];
  for (const r of raw) {
    const s = typeof r === "string" ? r : r?.domain;
    const parsed = parseDomain(s);
    if (parsed.error || !parsed.domain) return { error: parsed.error || "Invalid domain" };
    items.push(parsed.domain);
  }
  return { items };
}

/** Accept a domain, an email (domain only is kept; the local part is discarded and never queried), or a URL host. */
export function parseDomain(input: unknown): { domain?: string; error?: string } {
  if (typeof input !== "string" || !input.trim()) return { error: "Domain must be a non-empty string" };
  let s = input.trim();
  if (s.length > 300) return { error: "Domain is too long" };
  if (s.includes("://")) {
    try { s = new URL(s).hostname; } catch { return { error: `Invalid URL: ${input}` }; }
  } else if (s.includes("@")) {
    const at = s.lastIndexOf("@");
    s = s.slice(at + 1);
  }
  s = s.replace(/\.$/, "").toLowerCase().trim();
  if (s.includes("/") || s.includes(":") || s.includes(" ") || s.includes("?")) {
    return { error: `Invalid domain: ${input}` };
  }
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(s) && !s.startsWith("xn--")) {
    // allow punycode / IDN via URL parser
    try {
      const host = new URL("https://" + s).hostname;
      if (!host) return { error: `Invalid domain: ${input}` };
      s = host;
    } catch { return { error: `Invalid domain: ${input}` }; }
  }
  if (s.length > 253 || !s.includes(".")) return { error: `Invalid domain: ${input}` };
  if (isBlockedHost(s) || isPrivateIPv4(s) !== null) return { error: `Private, loopback or non-public hosts are not allowed: ${s}` };
  return { domain: s };
}

function unquoteTxt(data: string): string {
  const parts = [];
  const re = /"((?:\\.|[^"\\])*)"|(\S+)/g;
  let m: RegExpExecArray | null;
  const s = String(data || "").trim();
  if (!s.includes('"')) return s.replace(/\\"/g, '"');
  while ((m = re.exec(s))) parts.push((m[1] ?? m[2] ?? "").replace(/\\"/g, '"'));
  return parts.join("");
}

export async function defaultDnsLookup(name: string, type: "TXT" | "MX", ua?: string): Promise<{ status: number; records: string[]; error?: string; provider?: string }> {
  const headers: Record<string, string> = { accept: "application/dns-json" };
  if (ua) headers["user-agent"] = ua;
  const urls = [
    { provider: "cloudflare", url: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}` },
    { provider: "google", url: `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}` },
  ];
  let lastErr = "dns_error";
  for (const p of urls) {
    try {
      const res = await fetch(p.url, { headers, signal: AbortSignal.timeout(6000) });
      if (!res.ok) { lastErr = `http_${res.status}`; continue; }
      const j = await res.json() as any;
      const answers = Array.isArray(j.Answer) ? j.Answer : [];
      const typ = type === "TXT" ? 16 : 15;
      const records = answers
        .filter((a: any) => !typ || a.type === typ || String(a.type).toUpperCase() === type)
        .map((a: any) => type === "TXT" ? unquoteTxt(String(a.data ?? "")) : String(a.data ?? "").trim())
        .filter(Boolean);
      return { status: Number(j.Status ?? (res.ok ? 0 : res.status)), records, provider: p.provider };
    } catch (e: any) {
      const msg = String(e?.message || e);
      lastErr = /timeout|abort/i.test(msg) ? "timeout" : "dns_error";
    }
  }
  return { status: 2, records: [], error: lastErr };
}

export type SpfRecord = {
  raw: string;
  qual_all: "+" | "-" | "~" | "?" | null;
  includes: string[];
  redirects: string[];
  lookups_this_record: number;
  mechanisms: string[];
};

export function parseSpfRecord(raw: string): SpfRecord | null {
  const text = raw.replace(/^\s*v=spf1\s*/i, "").trim();
  if (!/^v=spf1(?:\s|$)/i.test(raw.trim())) return null;
  const mechanisms: string[] = [];
  const includes: string[] = [];
  const redirects: string[] = [];
  let qual_all: SpfRecord["qual_all"] = null;
  let lookups = 0;
  for (const tok of text.split(/\s+/).filter(Boolean)) {
    mechanisms.push(tok);
    const redir = tok.match(/^redirect=(.+)$/i);
    if (redir) { redirects.push(redir[1].replace(/\.$/, "").toLowerCase()); lookups++; continue; }
    if (/^exp=/i.test(tok)) continue;
    const mech = tok.match(/^([+\-~?])?(all|include|a|mx|ptr|ip4|ip6|exists)(?::(.+))?$/i);
    if (!mech) continue;
    const qual = (mech[1] || "+") as "+" | "-" | "~" | "?";
    const kind = mech[2].toLowerCase();
    const arg = (mech[3] || "").replace(/\.$/, "");
    if (kind === "all") qual_all = qual;
    if (kind === "include" && arg) { includes.push(arg.toLowerCase()); lookups++; }
    if (kind === "a" || kind === "mx" || kind === "ptr" || kind === "exists") lookups++;
  }
  return { raw: raw.trim(), qual_all, includes, redirects, lookups_this_record: lookups, mechanisms };
}

export async function estimateSpfLookups(
  domain: string,
  lookup: DnsLookup,
  startRecords: string[],
  cap = 12,
): Promise<{ estimate: number; chain: string[]; truncated: boolean; multiple: boolean; records: SpfRecord[] }> {
  const spf = startRecords.map(parseSpfRecord).filter((r): r is SpfRecord => !!r);
  const chain: string[] = [domain];
  let estimate = 0;
  const seen = new Set<string>([domain.toLowerCase()]);
  const queue: { domain: string; recs: SpfRecord[] }[] = [{ domain, recs: spf }];
  let truncated = false;
  while (queue.length) {
    const cur = queue.shift()!;
    for (const rec of cur.recs) {
      estimate += rec.lookups_this_record;
      if (estimate > cap) { truncated = true; return { estimate, chain, truncated, multiple: spf.length > 1, records: spf }; }
      const nexts = [...rec.includes, ...rec.redirects];
      for (const n of nexts) {
        if (seen.has(n)) continue;
        seen.add(n);
        chain.push(n);
        const r = await lookup(n, "TXT");
        const nested = (r.records || []).map(parseSpfRecord).filter((x): x is SpfRecord => !!x);
        // include/redirect already counted as 1; nested mechanisms add more
        queue.push({ domain: n, recs: nested });
      }
    }
  }
  return { estimate, chain, truncated, multiple: spf.length > 1, records: spf };
}

export type DmarcRecord = {
  raw: string;
  p: string | null;
  sp: string | null;
  pct: number | null;
  adkim: string | null;
  aspf: string | null;
  rua: string[];
  ruf: string[];
  fo: string | null;
};

export function parseDmarcRecord(raw: string): DmarcRecord | null {
  if (!/^\s*v\s*=\s*DMARC1\s*(;|$)/i.test(raw)) return null;
  const fields: Record<string, string[]> = {};
  for (const part of raw.split(";")) {
    const p = part.trim();
    if (!p) continue;
    const eq = p.indexOf("=");
    if (eq < 1) continue;
    const k = p.slice(0, eq).trim().toLowerCase();
    const v = p.slice(eq + 1).trim();
    if (!v) continue;
    (fields[k] ||= []).push(v);
  }
  const pct = fields["pct"]?.[0];
  return {
    raw: raw.trim(),
    p: fields["p"]?.[0]?.toLowerCase() || null,
    sp: fields["sp"]?.[0]?.toLowerCase() || null,
    pct: pct != null && /^\d+$/.test(pct) ? Number(pct) : (fields["p"] ? 100 : null),
    adkim: fields["adkim"]?.[0]?.toLowerCase() || null,
    aspf: fields["aspf"]?.[0]?.toLowerCase() || null,
    rua: fields["rua"] || [],
    ruf: fields["ruf"] || [],
    fo: fields["fo"]?.[0] || null,
  };
}

export function parseMxRecords(records: string[]): { preference: number; host: string }[] {
  const out: { preference: number; host: string }[] = [];
  for (const r of records) {
    const m = String(r).trim().match(/^(\d+)\s+(\S+)$/);
    if (m) out.push({ preference: Number(m[1]), host: m[2].replace(/\.$/, "").toLowerCase() });
  }
  out.sort((a, b) => a.preference - b.preference);
  return out;
}

export type EmailGradeIn = {
  mx: boolean;
  spf: boolean;
  multiple_spf: boolean;
  qual_all: "+" | "-" | "~" | "?" | null;
  lookups: number | null;
  dmarc_p: string | null;
  dmarc_pct: number | null;
  dkim: boolean;
};

export function gradeEmailAuth(i: EmailGradeIn): { grade: string; score: number; recommendations: string[] } {
  const rec: string[] = [];
  let score = 10;
  if (!i.mx) { score -= 3; rec.push("Add MX records if this domain should receive mail, so other systems know where to deliver it."); }
  if (!i.spf) { score -= 3; rec.push("Publish a single SPF TXT record (v=spf1 …) that lists the servers allowed to send mail for this domain."); }
  else {
    if (i.multiple_spf) { score -= 2.5; rec.push("Multiple SPF records are published. SPF requires exactly one v=spf1 record; merge them."); }
    if (i.qual_all === "+" || i.qual_all == null) { score -= 3; rec.push("The SPF record ends with +all (or has no 'all'), which allows any server to send mail. Use -all (or ~all as a step toward -all)."); }
    else if (i.qual_all === "?") { score -= 2; rec.push("The SPF record uses ?all (neutral). Prefer ~all or -all so unauthorised senders are not treated as valid."); }
    else if (i.qual_all === "~") { score -= 0.5; rec.push("SPF uses ~all (soft fail). Once all legitimate senders are listed, switch to -all."); }
    if (i.lookups != null && i.lookups > 10) { score -= 2; rec.push(`SPF needs about ${i.lookups} DNS lookups, over the limit of 10, so receivers may ignore it. Flatten or reduce include/a/mx/exists/redirect terms.`); }
  }
  if (!i.dmarc_p) { score -= 2.5; rec.push("Publish a DMARC record at _dmarc.<domain> so receivers know how to handle mail that fails SPF or DKIM."); }
  else if (i.dmarc_p === "none") { score -= 1.5; rec.push("DMARC policy is p=none (monitor only). Move to p=quarantine and later p=reject once reports look clean."); }
  else if (i.dmarc_p === "quarantine") { score -= 0.4; rec.push("DMARC is p=quarantine. p=reject is stronger once you are confident all legitimate mail passes."); }
  if (i.dmarc_p && i.dmarc_pct != null && i.dmarc_pct < 100) { score -= 0.5; rec.push(`DMARC pct=${i.dmarc_pct}, so the policy applies only to a fraction of mail. Raise pct to 100 when ready.`); }
  if (!i.dkim) { score -= 1; rec.push("No DKIM key was found on common selectors. If you send mail, publish a DKIM key (for example Google, Microsoft, or your ESP's selector)."); }
  if (score < 0) score = 0;
  score = Math.round(score * 10) / 10;
  let grade = "A";
  if (score < 3) grade = "F";
  else if (score < 5) grade = "D";
  else if (score < 7) grade = "C";
  else if (score < 8.5) grade = "B";
  else if (score < 9.5) grade = "A";
  else grade = "A";
  if (score >= 9.5) grade = "A";
  return { grade, score, recommendations: rec };
}

export async function checkEmailAuth(domain: string, ua: string, lookup: DnsLookup = (n, t) => defaultDnsLookup(n, t, ua)) {
  const started = Date.now();
  const out: Record<string, unknown> = { domain, disclaimer: EMAIL_AUTH_DISCLAIMER };
  try {
    const [txt, dmarcTxt, mx] = await Promise.all([
      lookup(domain, "TXT"),
      lookup(`_dmarc.${domain}`, "TXT"),
      lookup(domain, "MX"),
    ]);
    const dnsFailed = !!(txt.error && dmarcTxt.error && mx.error);
    if (dnsFailed) {
      out.error = txt.error || dmarcTxt.error || mx.error;
      out.elapsed_ms = Date.now() - started;
      return out;
    }

    const spfInfo = await estimateSpfLookups(domain, lookup, txt.records || []);
    const mxHosts = parseMxRecords(mx.records || []);
    const dmarcRecs = (dmarcTxt.records || []).map(parseDmarcRecord).filter((r): r is DmarcRecord => !!r);
    const dmarc = dmarcRecs[0] || null;

    const dkimHits: { selector: string; present: boolean; preview?: string }[] = [];
    const selResults = await mapLimit([...COMMON_DKIM_SELECTORS], 6, async (selector) => {
      const r = await lookup(`${selector}._domainkey.${domain}`, "TXT");
      const recs = (r.records || []).filter((x) => /v=DKIM1|k=rsa|p=[A-Za-z0-9+/]/i.test(x));
      if (!recs.length) return null;
      const p = recs[0];
      // Never return the full key; only a short preview that it exists.
      const preview = p.length > 80 ? p.slice(0, 40) + "…(key omitted)…" + p.slice(-8) : (p.includes("p=") ? p.replace(/p=[A-Za-z0-9+/=]+/, "p=(key omitted)") : p.slice(0, 80));
      return { selector, present: true, preview };
    });
    for (const s of selResults) if (s) dkimHits.push(s);

    const qual = spfInfo.records[0]?.qual_all ?? null;
    const graded = gradeEmailAuth({
      mx: mxHosts.length > 0,
      spf: spfInfo.records.length > 0,
      multiple_spf: spfInfo.multiple,
      qual_all: qual,
      lookups: spfInfo.records.length ? spfInfo.estimate : null,
      dmarc_p: dmarc?.p ?? null,
      dmarc_pct: dmarc?.pct ?? null,
      dkim: dkimHits.length > 0,
    });

    const misconfigs: string[] = [];
    if (spfInfo.multiple) misconfigs.push("multiple_spf");
    if (spfInfo.records.length && spfInfo.estimate > 10) misconfigs.push("spf_lookup_limit");
    if (qual === "+" ) misconfigs.push("spf_plus_all");
    if (spfInfo.records.length && qual == null) misconfigs.push("spf_missing_all");
    if (dmarc?.p === "none") misconfigs.push("dmarc_p_none");
    if (dmarcRecs.length > 1) misconfigs.push("multiple_dmarc");
    if (!spfInfo.records.length) misconfigs.push("missing_spf");
    if (!dmarc) misconfigs.push("missing_dmarc");

    out.mx = { present: mxHosts.length > 0, records: mxHosts, error: mx.error };
    out.spf = {
      present: spfInfo.records.length > 0,
      records: spfInfo.records.map((r) => ({ raw: r.raw, qual_all: r.qual_all, includes: r.includes, redirects: r.redirects })),
      multiple: spfInfo.multiple,
      lookups_estimate: spfInfo.records.length ? spfInfo.estimate : null,
      lookups_truncated: spfInfo.truncated,
      qual_all: qual,
      error: txt.error,
    };
    out.dmarc = {
      present: !!dmarc,
      multiple: dmarcRecs.length > 1,
      record: dmarc,
      error: dmarcTxt.error,
    };
    out.dkim = {
      selectors_checked: COMMON_DKIM_SELECTORS.length,
      found: dkimHits,
      present: dkimHits.length > 0,
    };
    out.misconfigs = misconfigs;
    out.grade = graded.grade;
    out.score = graded.score;
    out.recommendations = graded.recommendations;
  } catch (e: any) {
    const msg = String(e?.message || e);
    out.error = /timeout|abort/i.test(msg) ? "timeout" : msg.slice(0, 200);
  }
  out.elapsed_ms = Date.now() - started;
  return out;
}

export async function checkEmailAuthMany(domains: string[], ua: string, lookup?: DnsLookup) {
  const fn: DnsLookup = lookup || ((n, t) => defaultDnsLookup(n, t, ua));
  return mapLimit(domains, 2, (d) => checkEmailAuth(d, ua, fn));
}
