// Domain health / trust report in one call: DNS (A, AAAA, NS, CAA, DNSSEC), RDAP registration (age, expiry,
// registrar, status), TLS certificate from Certificate Transparency logs (SSLMate Cert Spotter), HTTPS
// reachability + security headers, SPF / DMARC / MX / DKIM, robots.txt AI rules, security.txt and llms.txt.
// Subrequests are budgeted for the Workers free plan (50 per request).
import { parseDomain, checkEmailAuth, defaultDnsLookup } from "./emailauth";
import { checkHeaders } from "./headers";
import { parseRobots, crawlerAccess, AI_CRAWLERS, parseSecurityTxt } from "./policies";
import { safeFetch } from "./urlguard";

export const PRICE_DOMAIN_REPORT = "0.003";
const DKIM_SELECTORS = ["google", "selector1", "selector2", "default", "k1", "s1"] as const;

export function parseDomainReportInput(body: any): { item?: { domain: string }; error?: string } {
  if (!body || typeof body !== "object" || Array.isArray(body)) return { error: 'Body must be JSON: {"domain": "example.com"}' };
  const raw = body.domain ?? body.url ?? (Array.isArray(body.domains) && body.domains.length === 1 ? body.domains[0] : undefined);
  if (typeof raw !== "string") return { error: "`domain` (string) is required: one domain, URL or email address per call" };
  const p = parseDomain(raw);
  if (p.error || !p.domain) return { error: p.error || "Invalid domain" };
  return { item: { domain: p.domain } };
}

type DohAnswer = { name: string; type: number; TTL: number; data: string };
export async function doh(name: string, type: string, ua: string): Promise<{ status: number | null; answers: DohAnswer[]; ad: boolean; error?: string }> {
  const urls = [
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
    `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`,
  ];
  let err = "dns_error";
  for (const u of urls) {
    try {
      const r = await fetch(u, { headers: { accept: "application/dns-json", "user-agent": ua }, signal: AbortSignal.timeout(5000) });
      if (!r.ok) { err = `http_${r.status}`; continue; }
      const j: any = await r.json();
      return { status: Number(j.Status), answers: Array.isArray(j.Answer) ? j.Answer : [], ad: j.AD === true };
    } catch (e: any) { err = /timeout|abort/i.test(String(e?.message || e)) ? "timeout" : "dns_error"; }
  }
  return { status: null, answers: [], ad: false, error: err };
}

const TYPE_NUM: Record<string, number> = { A: 1, NS: 2, CNAME: 5, AAAA: 28, CAA: 257 };

// ---- RDAP ----
let bootstrap: { at: number; services: [string[], string[]][] } | null = null;
async function rdapBase(tld: string, ua: string): Promise<string | null> {
  if (!bootstrap || Date.now() - bootstrap.at > 86400_000) {
    const r = await fetch("https://data.iana.org/rdap/dns.json", { headers: { "user-agent": ua }, signal: AbortSignal.timeout(6000), cf: { cacheTtl: 86400, cacheEverything: true } } as any);
    if (!r.ok) throw new Error(`bootstrap_http_${r.status}`);
    const j: any = await r.json();
    bootstrap = { at: Date.now(), services: j.services || [] };
  }
  for (const [tlds, urls] of bootstrap.services) if (tlds.includes(tld)) return (urls.find((u) => u.startsWith("https://")) || urls[0] || null);
  return null;
}

const daysBetween = (a: number, b: number) => Math.floor((b - a) / 86400_000);

export function shapeRdap(j: any, now = Date.now()) {
  const ev = (action: string) => (Array.isArray(j.events) ? j.events.find((e: any) => String(e.eventAction).toLowerCase() === action)?.eventDate : null) || null;
  const registered = ev("registration"), expires = ev("expiration"), changed = ev("last changed");
  let registrar: string | null = null, iana_id: string | null = null;
  for (const e of j.entities || []) {
    if (!(e.roles || []).includes("registrar")) continue;
    const fn = (e.vcardArray?.[1] || []).find((x: any) => x[0] === "fn");
    registrar = fn?.[3] || e.handle || null;
    iana_id = (e.publicIds || []).find((p: any) => /iana/i.test(p.type))?.identifier || null;
    break;
  }
  const rt = registered ? Date.parse(registered) : NaN, et = expires ? Date.parse(expires) : NaN;
  return {
    found: true,
    domain: String(j.ldhName || "").toLowerCase() || null,
    registered, expires, last_changed: changed,
    age_days: Number.isFinite(rt) ? daysBetween(rt, now) : null,
    expires_in_days: Number.isFinite(et) ? daysBetween(now, et) : null,
    registrar, registrar_iana_id: iana_id,
    status: Array.isArray(j.status) ? j.status : [],
    nameservers: (j.nameservers || []).map((n: any) => String(n.ldhName || "").toLowerCase().replace(/\.$/, "")).filter(Boolean).slice(0, 13),
    dnssec_delegation_signed: j.secureDNS?.delegationSigned ?? null,
  };
}

async function rdapLookup(domain: string, ua: string) {
  const labels = domain.split(".");
  const tld = labels[labels.length - 1];
  let base: string | null;
  try { base = await rdapBase(tld, ua); } catch (e: any) { return { found: null, error: String(e?.message || e).slice(0, 100) }; }
  if (!base) return { found: null, error: `no RDAP server published for .${tld}` };
  // Try the name as given, then parents (handles www.example.com and example.co.uk) down to 2 labels.
  for (let i = 0; i < Math.min(3, labels.length - 1); i++) {
    const name = labels.slice(i).join(".");
    const r = await safeFetch(`${base.replace(/\/?$/, "/")}domain/${name}`, { headers: { "user-agent": ua, accept: "application/rdap+json, application/json" }, maxBytes: 256 * 1024, timeoutMs: 7000, maxRedirects: 3 });
    if (r.status === 200) { try { return { ...shapeRdap(JSON.parse(r.body)), queried: name, source: new URL(r.url).host }; } catch { return { found: null, error: "bad_rdap_json" }; } }
    if (r.status === 404) continue;
    return { found: null, error: r.error || `rdap_http_${r.status}` };
  }
  return { found: false, error: "not found in RDAP (unregistered, or the registry does not publish it)" };
}

// ---- Certificate Transparency (SSLMate Cert Spotter, free tier, unexpired issuances) ----
export function shapeCerts(list: any[], host: string, now = Date.now()) {
  const covers = (names: string[]) => names.some((n) => n === host || (n.startsWith("*.") && host.endsWith(n.slice(1)) && host.split(".").length === n.split(".").length));
  const valid = list.filter((c) => !c.revoked && Date.parse(c.not_after) > now && Date.parse(c.not_before) <= now && covers(c.dns_names || []));
  valid.sort((a, b) => Date.parse(b.not_before) - Date.parse(a.not_before));
  const latest = valid[0];
  const issuers = [...new Set(valid.map((c) => c.issuer?.friendly_name || c.issuer?.name).filter(Boolean))].slice(0, 5);
  return {
    found: valid.length > 0,
    unexpired_count: valid.length,
    issuers,
    latest: latest ? {
      issuer: latest.issuer?.friendly_name || latest.issuer?.name || null,
      issuer_dn: latest.issuer?.name || null,
      not_before: latest.not_before, not_after: latest.not_after,
      days_left: daysBetween(now, Date.parse(latest.not_after)),
      dns_names: (latest.dns_names || []).slice(0, 10),
    } : null,
    max_days_left: valid.length ? Math.max(...valid.map((c) => daysBetween(now, Date.parse(c.not_after)))) : null,
  };
}

async function certLookup(host: string, ua: string) {
  try {
    const u = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(host)}&match_wildcards=true&expand=dns_names&expand=issuer`;
    const r = await fetch(u, { headers: { "user-agent": ua }, signal: AbortSignal.timeout(7000), cf: { cacheTtl: 21600, cacheEverything: true } } as any);
    if (r.status === 429) return { found: null, error: "ct_rate_limited", source: "Cert Spotter (Certificate Transparency)" };
    if (!r.ok) return { found: null, error: `ct_http_${r.status}`, source: "Cert Spotter (Certificate Transparency)" };
    const list: any = await r.json();
    return { ...shapeCerts(Array.isArray(list) ? list : [], host), source: "Cert Spotter (Certificate Transparency logs)" };
  } catch (e: any) {
    return { found: null, error: /timeout|abort/i.test(String(e?.message || e)) ? "timeout" : "ct_error", source: "Cert Spotter (Certificate Transparency)" };
  }
}

async function policyFiles(host: string, ua: string) {
  const origin = `https://${host}`;
  const get = (p: string) => safeFetch(origin + p, { headers: { "user-agent": ua }, maxBytes: 32 * 1024, timeoutMs: 5000, maxRedirects: 3 });
  const [rb, sec, llms] = await Promise.all([get("/robots.txt"), get("/.well-known/security.txt"), get("/llms.txt")]);
  const ok = (r: any) => r && !r.error && r.status === 200 && !/text\/html/i.test(r.content_type || "");
  let robots: any = { present: false, status: rb.status };
  if (ok(rb)) {
    const parsed = parseRobots(rb.body);
    const acc = crawlerAccess(parsed.groups, "/", AI_CRAWLERS);
    const blocked = AI_CRAWLERS.filter((a) => a !== "Googlebot" && a !== "Applebot" && !acc[a].allowed);
    robots = { present: true, status: 200, all_crawlers_allowed_root: acc["*"].allowed, ai_crawlers_blocked: blocked, sitemaps: parsed.sitemaps.slice(0, 5) };
  }
  const security = ok(sec) ? { present: true, ...parseSecurityTxt(sec.body) } : { present: false, status: sec.status };
  return { robots_txt: robots, security_txt: security, llms_txt: { present: ok(llms), status: llms.status } };
}

// ---- report ----
export async function domainReport(domain: string, ua: string) {
  const started = Date.now();
  const lookup = (n: string, t: "TXT" | "MX") => defaultDnsLookup(n, t, ua);
  const [a, aaaa, ns, caa, rdap, certs, headers, email, policies] = await Promise.all([
    doh(domain, "A", ua), doh(domain, "AAAA", ua), doh(domain, "NS", ua), doh(domain, "CAA", ua),
    rdapLookup(domain, ua),
    certLookup(domain, ua),
    checkHeaders({ url: `https://${domain}/` }, ua),
    checkEmailAuth(domain, ua, lookup, { selectors: DKIM_SELECTORS, spfCap: 10 }),
    policyFiles(domain, ua).catch(() => null),
  ]);
  const pick = (r: typeof a, t: string) => r.answers.filter((x) => x.type === TYPE_NUM[t]).map((x) => String(x.data).replace(/\.$/, ""));
  const ipv4 = pick(a, "A"), ipv6 = pick(aaaa, "AAAA");
  const cname = [...a.answers, ...aaaa.answers].filter((x) => x.type === 5).map((x) => String(x.data).replace(/\.$/, ""));
  const dns = {
    resolves: ipv4.length + ipv6.length > 0,
    nxdomain: a.status === 3,
    a: ipv4.slice(0, 10), aaaa: ipv6.slice(0, 10), cname: [...new Set(cname)].slice(0, 3),
    ns: pick(ns, "NS").slice(0, 13),
    caa: pick(caa, "CAA").slice(0, 10),
    dnssec_validated: a.ad,
    ...(a.error ? { error: a.error } : {}),
  };
  const h: any = headers;
  const https = {
    reachable: h.status != null && !h.error ? true : h.status != null,
    status: h.status ?? null,
    final_url: h.final_url ?? null,
    error: h.error ?? null,
    https_redirect: h.https_redirect ?? null,
    headers_grade: h.grade ?? null,
    headers_score: h.score ?? null,
    hsts: h.headers?.hsts?.present ?? null,
    csp: h.headers?.csp?.present ?? null,
    top_fixes: (h.recommendations || []).slice(0, 3),
  };
  const e: any = email;
  const mail = {
    mx: e.mx?.present ?? null, spf: e.spf?.present ?? null, spf_all: e.spf?.qual_all ?? null,
    dmarc: e.dmarc?.present ?? null, dmarc_policy: e.dmarc?.record?.p ?? null, dkim_found: e.dkim?.present ?? null,
    grade: e.grade ?? null, misconfigs: e.misconfigs ?? [], ...(e.error ? { error: e.error } : {}),
  };

  // Plain-language findings and a 0-100 health score.
  const findings: { severity: "high" | "medium" | "low" | "info"; message: string }[] = [];
  let score = 100;
  const add = (severity: "high" | "medium" | "low" | "info", message: string, cost: number) => { findings.push({ severity, message }); score -= cost; };
  const r: any = rdap;
  if (dns.nxdomain) add("high", "Domain does not exist in DNS (NXDOMAIN).", 60);
  else if (!dns.resolves) add("high", "Domain has no A/AAAA record (no website address).", 25);
  if (r.found && r.age_days != null) {
    if (r.age_days < 30) add("high", `Domain was registered only ${r.age_days} days ago (new domains are common in phishing and scams).`, 30);
    else if (r.age_days < 180) add("medium", `Domain is young: registered ${r.age_days} days ago.`, 10);
  }
  if (r.found && r.expires_in_days != null && r.expires_in_days < 30) add(r.expires_in_days < 0 ? "high" : "medium", `Domain registration expires in ${r.expires_in_days} days.`, r.expires_in_days < 0 ? 30 : 10);
  if (r.found && (r.status || []).some((s: string) => /hold|redemption|pending ?delete/i.test(s))) add("high", `Registry status: ${r.status.filter((s: string) => /hold|redemption|pending ?delete/i.test(s)).join(", ")}.`, 30);
  if (dns.resolves) {
    if (!https.reachable || (https.status != null && https.status >= 500)) add("high", `Website over HTTPS is not working (${https.error || "HTTP " + https.status}).`, 20);
    else if (https.https_redirect === false) add("low", "HTTP does not redirect to HTTPS.", 5);
  }
  const c: any = certs;
  if (c.found === false && dns.resolves) add("medium", "No currently valid public TLS certificate found for this exact host in Certificate Transparency logs.", 10);
  if (c.found && c.max_days_left != null && c.max_days_left < 14) add("medium", `Newest TLS certificate expires in ${c.max_days_left} days.`, 10);
  if (https.headers_grade === "F" || https.headers_grade === "D") add("low", `Weak HTTP security headers (grade ${https.headers_grade}).`, 5);
  if (mail.mx) {
    if (!mail.spf) add("medium", "Receives mail (MX) but has no SPF record: easy to spoof.", 8);
    if (!mail.dmarc) add("medium", "No DMARC record: email from this domain can be spoofed.", 8);
    else if (mail.dmarc_policy === "none") add("low", "DMARC policy is p=none (monitoring only).", 3);
  } else if (mail.mx === false && !(mail.spf && mail.dmarc)) {
    add("info", "Domain has no MX record (does not receive email); a strict SPF -all and DMARC p=reject would stop spoofing.", 2);
  }
  if (!dns.dnssec_validated) add("info", "DNSSEC is not enabled.", 0);
  if (!r.found && r.found !== false) add("info", `Registration data unavailable (${r.error || "unknown"}).`, 0);
  score = Math.max(0, Math.min(100, score));
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 65 ? "C" : score >= 50 ? "D" : "F";
  const risk = findings.some((f) => f.severity === "high") ? "high" : findings.some((f) => f.severity === "medium") ? "medium" : "low";
  return {
    domain,
    summary: { health_score: score, grade, risk, findings },
    dns,
    registration: rdap,
    tls_certificate: certs,
    https,
    email: mail,
    policies,
    checked_at: new Date().toISOString(),
    elapsed_ms: Date.now() - started,
    note: "Automated public-data check (DNS, RDAP, CT logs, HTTP). A signal, not a guarantee that a site is safe or unsafe.",
  };
}
