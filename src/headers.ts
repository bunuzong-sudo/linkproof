// Security-header check: HEAD (GET fallback), safe redirects, grade + plain recommendations.
// Cookie values are never returned. No TLS certificate handshake is performed.

import { mapLimit } from "./citations";
import { parsePublicHttpUrl, safeFetch, isBlockedHost, type SafeFetchResult } from "./urlguard";

export const MAX_HEADER_URLS = 5;
export const PRICE_HEADERS = "0.002";
const GET_FALLBACK_BYTES = 8192;

export type HeaderInput = { url: string };

export function parseHeaderItems(body: any): { items?: HeaderInput[]; error?: string } {
  if (!body || typeof body !== "object") return { error: 'Body must be JSON: {"urls": ["https://..."]}' };
  const raw = body.urls;
  if (!Array.isArray(raw) || raw.length === 0) return { error: "`urls` must be a non-empty array" };
  if (raw.length > MAX_HEADER_URLS) return { error: `At most ${MAX_HEADER_URLS} URLs per call` };
  const items: HeaderInput[] = [];
  for (const r of raw) {
    const s = typeof r === "string" ? r : r?.url;
    const parsed = parsePublicHttpUrl(s, { allowDomainOnly: true });
    if (parsed.error || !parsed.href) return { error: parsed.error || "Invalid URL" };
    items.push({ url: parsed.href });
  }
  return { items };
}

export type CookieFlags = { name: string; secure: boolean; httpOnly: boolean; sameSite: string | null };
export type HstsInfo = { present: boolean; max_age: number | null; includeSubDomains: boolean; preload: boolean };
export type CspInfo = { present: boolean; report_only: boolean; frame_ancestors: string | null; preview: string | null };

export function parseSetCookieFlags(header: string): CookieFlags | null {
  const parts = String(header || "").split(";").map((p) => p.trim()).filter(Boolean);
  if (!parts.length) return null;
  const name = parts[0].split("=")[0].trim();
  if (!name) return null;
  let secure = false, httpOnly = false, sameSite: string | null = null;
  for (const p of parts.slice(1)) {
    const [k, ...rest] = p.split("=");
    const key = k.trim().toLowerCase();
    const val = rest.join("=").trim();
    if (key === "secure") secure = true;
    else if (key === "httponly") httpOnly = true;
    else if (key === "samesite") sameSite = val || null;
  }
  return { name, secure, httpOnly, sameSite };
}

export function parseCookies(headers: Headers): CookieFlags[] {
  const raw = typeof headers.getSetCookie === "function" ? headers.getSetCookie() : [];
  return raw.map(parseSetCookieFlags).filter((c): c is CookieFlags => !!c);
}

export function parseHsts(value: string | null): HstsInfo {
  if (!value) return { present: false, max_age: null, includeSubDomains: false, preload: false };
  const v = value.toLowerCase();
  const m = v.match(/max-age\s*=\s*(\d+)/);
  return {
    present: true,
    max_age: m ? Number(m[1]) : null,
    includeSubDomains: /includesubdomains/.test(v),
    preload: /\bpreload\b/.test(v),
  };
}

export function parseCsp(enforcing: string | null, reportOnly: string | null): CspInfo {
  const raw = enforcing || reportOnly;
  if (!raw) return { present: false, report_only: false, frame_ancestors: null, preview: null };
  const fa = raw.match(/frame-ancestors\s+([^;]+)/i);
  return {
    present: true,
    report_only: !enforcing && !!reportOnly,
    frame_ancestors: fa ? fa[1].trim() : null,
    preview: raw.length > 400 ? raw.slice(0, 400) + "…" : raw,
  };
}

export type GradeResult = { grade: "A" | "B" | "C" | "D" | "F"; score: number; recommendations: string[] };

export function gradeHeaders(info: {
  https: boolean;
  https_redirect: boolean | null;
  hsts: HstsInfo;
  csp: CspInfo;
  x_frame_options: string | null;
  x_content_type_options: string | null;
  referrer_policy: string | null;
  permissions_policy: string | null;
  feature_policy: string | null;
  coop: string | null;
  corp: string | null;
  server: string | null;
  x_powered_by: string | null;
  cookies: CookieFlags[];
}): GradeResult {
  const rec: string[] = [];
  if (!info.https) {
    rec.push("This URL is not served over HTTPS. Serve the site on HTTPS so traffic cannot be read or changed in transit.");
    return { grade: "F", score: 0, recommendations: rec };
  }

  let score = 0;
  const SIX_MONTHS = 15552000;

  if (info.hsts.present && (info.hsts.max_age ?? 0) >= SIX_MONTHS) score += 2;
  else if (info.hsts.present && (info.hsts.max_age ?? 0) > 0) {
    score += 1;
    rec.push("Strict-Transport-Security is present, but max-age is under 6 months. Raise it (and consider includeSubDomains) so browsers keep using HTTPS.");
  } else {
    rec.push("Add a Strict-Transport-Security header with max-age of at least 6 months so browsers always use HTTPS.");
  }

  if (info.csp.present && !info.csp.report_only) score += 2;
  else if (info.csp.present && info.csp.report_only) {
    score += 1;
    rec.push("Content-Security-Policy-Report-Only is set, but there is no enforcing Content-Security-Policy. Add an enforcing policy once you are ready.");
  } else {
    rec.push("Add a Content-Security-Policy to limit which scripts, frames and origins the page can load.");
  }

  const clickjacking = !!(info.x_frame_options || info.csp.frame_ancestors);
  if (clickjacking) score += 1;
  else rec.push("Add X-Frame-Options (or CSP frame-ancestors) so other sites cannot embed this page.");

  const nosniff = (info.x_content_type_options || "").trim().toLowerCase() === "nosniff";
  if (nosniff) score += 1;
  else rec.push("Add X-Content-Type-Options: nosniff so browsers do not guess a different content type.");

  const rp = (info.referrer_policy || "").trim().toLowerCase();
  if (rp && rp !== "unsafe-url") score += 1;
  else if (rp === "unsafe-url") rec.push("Referrer-Policy is unsafe-url, which sends full URLs to other sites. Use a stricter policy such as strict-origin-when-cross-origin.");
  else rec.push("Add a Referrer-Policy (for example strict-origin-when-cross-origin) so other sites are not sent full page URLs.");

  if (info.permissions_policy || info.feature_policy) score += 0.5;
  else rec.push("Consider a Permissions-Policy header to turn off unused browser features (camera, microphone, geolocation, and so on).");

  if (info.coop || info.corp) score += 0.5;
  else rec.push("Consider Cross-Origin-Opener-Policy (and Cross-Origin-Resource-Policy) to isolate the page from other origins.");

  if (info.cookies.length) {
    const bad = info.cookies.filter((c) => !c.secure || !c.httpOnly || !c.sameSite || (c.sameSite.toLowerCase() === "none" && !c.secure));
    if (!bad.length) score += 1;
    else {
      const names = bad.slice(0, 5).map((c) => c.name).join(", ");
      rec.push(`Some cookies (${names}) are missing Secure, HttpOnly or SameSite flags. Set those flags so the cookies cannot be read by scripts or sent over HTTP.`);
    }
  } else {
    score += 1; // no cookies to harden
  }

  if (info.server || info.x_powered_by) {
    rec.push("The Server or X-Powered-By header reveals software names. Removing it makes fingerprinting a little harder.");
  } else {
    score += 0.5;
  }

  if (info.https_redirect === false) {
    rec.push("The HTTP version of this host does not redirect to HTTPS. Send visitors from http:// to https://.");
  }

  let grade: GradeResult["grade"];
  if (score >= 9) grade = "A";
  else if (score >= 7) grade = "B";
  else if (score >= 5) grade = "C";
  else if (score >= 3) grade = "D";
  else grade = "F";
  return { grade, score: Math.round(score * 10) / 10, recommendations: rec };
}

function header(h: Headers, name: string): string | null {
  const v = h.get(name);
  return v && v.trim() ? v.trim() : null;
}

function shouldGetFallback(r: SafeFetchResult): boolean {
  if (r.method !== "HEAD") return false;
  if (r.status === 405 || r.status === 501 || r.status === 400) return true;
  if (r.error && r.error !== "timeout" && r.error !== "too_many_redirects" && !/^Redirect blocked:/.test(r.error) && !/^Private, loopback/.test(r.error || "")) return true;
  return false;
}

async function fetchHeaderSet(url: string, ua: string): Promise<SafeFetchResult> {
  const headers = { "user-agent": ua, accept: "text/html,application/xhtml+xml,*/*;q=0.8" };
  const head = await safeFetch(url, { method: "HEAD", headers, maxBytes: 0 });
  if (shouldGetFallback(head)) return safeFetch(url, { method: "GET", headers, maxBytes: GET_FALLBACK_BYTES });
  return head;
}

function chainGoesHttps(chain: SafeFetchResult, fallbackUrl: string): boolean {
  if ((chain.url || fallbackUrl).startsWith("https://")) return true;
  return chain.redirect_chain.some((h) => h.url.startsWith("https://") || (h.location || "").startsWith("https://"));
}

async function probeHttpsRedirect(startUrl: string, chain: SafeFetchResult, ua: string): Promise<boolean | null> {
  const startedHttp = startUrl.startsWith("http://") || chain.redirect_chain[0]?.url.startsWith("http://");
  if (startedHttp) return chainGoesHttps(chain, startUrl);
  let u: URL;
  try { u = new URL(startUrl); } catch { return null; }
  if (isBlockedHost(u.hostname)) return null;
  const httpUrl = `http://${u.host}${u.pathname}${u.search}`;
  const probe = await safeFetch(httpUrl, { method: "HEAD", headers: { "user-agent": ua, accept: "*/*" }, maxBytes: 0 });
  if (chainGoesHttps(probe, httpUrl)) return true;
  // Inconclusive if the HTTP probe failed or returned a server/proxy error.
  if (probe.error || probe.status == null || probe.status >= 500) return null;
  return false;
}

export async function checkHeaders(item: HeaderInput, ua: string) {
  const started = Date.now();
  const out: Record<string, unknown> = { url: item.url };
  try {
    const r = await fetchHeaderSet(item.url, ua);
    if (r.error && r.status == null) {
      out.error = r.error;
      out.redirect_chain = r.redirect_chain;
      out.elapsed_ms = Date.now() - started;
      return out;
    }
    const https = (r.url || item.url).startsWith("https://");
    const cookies = parseCookies(r.headers);
    const hsts = parseHsts(header(r.headers, "strict-transport-security"));
    const csp = parseCsp(header(r.headers, "content-security-policy"), header(r.headers, "content-security-policy-report-only"));
    const xfo = header(r.headers, "x-frame-options");
    const xcto = header(r.headers, "x-content-type-options");
    const referrer = header(r.headers, "referrer-policy");
    const perm = header(r.headers, "permissions-policy");
    const feat = header(r.headers, "feature-policy");
    const coop = header(r.headers, "cross-origin-opener-policy");
    const corp = header(r.headers, "cross-origin-resource-policy");
    const server = header(r.headers, "server");
    const powered = header(r.headers, "x-powered-by");
    const https_redirect = await probeHttpsRedirect(item.url, r, ua);
    const graded = gradeHeaders({
      https, https_redirect, hsts, csp,
      x_frame_options: xfo, x_content_type_options: xcto, referrer_policy: referrer,
      permissions_policy: perm, feature_policy: feat, coop, corp, server, x_powered_by: powered, cookies,
    });
    out.status = r.status;
    out.final_url = r.url;
    out.redirected = r.redirected;
    out.redirect_chain = r.redirect_chain.map((h) => ({ url: h.url, status: h.status }));
    out.method_used = r.method;
    out.https = https;
    out.https_redirect = https_redirect;
    out.headers = {
      hsts, csp,
      x_frame_options: xfo,
      x_content_type_options: xcto,
      referrer_policy: referrer,
      permissions_policy: perm,
      feature_policy: feat,
      coop, corp, server, x_powered_by: powered,
    };
    out.cookies = cookies;
    out.clickjacking_protection = !!(xfo || csp.frame_ancestors);
    out.nosniff = (xcto || "").toLowerCase() === "nosniff";
    out.server_disclosure = !!(server || powered);
    out.grade = graded.grade;
    out.score = graded.score;
    out.recommendations = graded.recommendations;
    if (r.error) out.error = r.error;
  } catch (e: any) {
    const msg = String(e?.message || e);
    out.error = /timeout|abort/i.test(msg) ? "timeout" : msg.slice(0, 200);
  }
  out.elapsed_ms = Date.now() - started;
  return out;
}

export async function checkHeadersMany(items: HeaderInput[], ua: string) {
  return mapLimit(items, 3, (it) => checkHeaders(it, ua));
}
