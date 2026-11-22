// Site policy file lookup: robots.txt (AI crawler rules + path check), llms.txt,
// llms-full.txt, ai.txt, and /.well-known/security.txt. Fetches in parallel with
// a size cap. Sitemap URLs are listed from robots.txt and not fetched.

import { mapLimit } from "./citations";
import { parsePublicHttpUrl, safeFetch } from "./urlguard";

export const MAX_POLICY_URLS = 5;
export const PRICE_POLICIES = "0.002";
export const MAX_FILE_BYTES = 32 * 1024;
export const AI_CRAWLERS = [
  "GPTBot",
  "ChatGPT-User",
  "OAI-SearchBot",
  "ClaudeBot",
  "Anthropic-AI",
  "Claude-Web",
  "Claude-SearchBot",
  "Claude-User",
  "Google-Extended",
  "Googlebot",
  "CCBot",
  "PerplexityBot",
  "Perplexity-User",
  "Bytespider",
  "Amazonbot",
  "Applebot",
  "Applebot-Extended",
  "meta-externalagent",
  "FacebookBot",
  "cohere-ai",
  "Diffbot",
  "YouBot",
] as const;

export type PolicyInput = { url: string; path?: string };

export function parsePolicyItems(body: any): { items?: PolicyInput[]; error?: string } {
  if (!body || typeof body !== "object") return { error: 'Body must be JSON: {"urls": ["https://..."]}' };
  const raw = body.urls;
  if (!Array.isArray(raw) || raw.length === 0) return { error: "`urls` must be a non-empty array" };
  if (raw.length > MAX_POLICY_URLS) return { error: `At most ${MAX_POLICY_URLS} URLs per call` };
  if (body.path !== undefined && (typeof body.path !== "string" || body.path.length > 2000)) {
    return { error: "`path` must be a string up to 2000 chars" };
  }
  const items: PolicyInput[] = [];
  for (const r of raw) {
    const s = typeof r === "string" ? r : r?.url;
    const path = typeof r === "object" && r && r.path !== undefined ? r.path : body.path;
    if (path !== undefined && (typeof path !== "string" || path.length > 2000)) {
      return { error: "`path` must be a string up to 2000 chars" };
    }
    const parsed = parsePublicHttpUrl(s, { allowDomainOnly: true });
    if (parsed.error || !parsed.url) return { error: parsed.error || "Invalid URL" };
    const defaultPath = parsed.url.pathname || "/";
    items.push({ url: parsed.url.origin + "/", path: path || defaultPath || "/" });
  }
  return { items };
}

export type RobotRule = { kind: "allow" | "disallow"; path: string };
export type RobotGroup = { agents: string[]; rules: RobotRule[] };

export function parseRobots(text: string): { groups: RobotGroup[]; sitemaps: string[] } {
  const groups: RobotGroup[] = [];
  const sitemaps: string[] = [];
  let current: RobotGroup | null = null;
  let lastWasAgent = false;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (!line) continue;
    const colon = line.indexOf(":");
    if (colon < 1) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (key === "sitemap") {
      if (value && !sitemaps.includes(value)) sitemaps.push(value);
      continue;
    }
    if (key === "user-agent") {
      const agent = value;
      if (!agent) continue;
      if (!current || !lastWasAgent) {
        current = { agents: [agent], rules: [] };
        groups.push(current);
      } else {
        current.agents.push(agent);
      }
      lastWasAgent = true;
      continue;
    }
    lastWasAgent = false;
    if (!current) continue;
    if (key === "allow" || key === "disallow") {
      current.rules.push({ kind: key, path: value });
    }
  }
  return { groups, sitemaps };
}

function escapeRe(s: string) {
  return s.replace(/[|\\{}()[\]^+?.,\-]/g, "\\$&");
}

export function ruleMatches(pattern: string, path: string): boolean {
  if (!pattern) return false;
  let end = false;
  let p = pattern;
  if (p.endsWith("$")) { end = true; p = p.slice(0, -1); }
  const re = new RegExp("^" + escapeRe(p).replace(/\*/g, ".*") + (end ? "$" : ""));
  return re.test(path);
}

/** Longest matching rule wins; Allow wins ties. Empty Disallow is ignored (allow all). */
export function pathAllowed(path: string, rules: RobotRule[]): boolean {
  const target = path.startsWith("/") ? path : "/" + path;
  let bestLen = -1;
  let allowed = true;
  for (const r of rules) {
    if (!r.path && r.kind === "disallow") continue;
    if (!r.path && r.kind === "allow") continue;
    if (!ruleMatches(r.path, target)) continue;
    const len = r.path.length;
    if (len > bestLen || (len === bestLen && r.kind === "allow")) {
      bestLen = len;
      allowed = r.kind === "allow";
    }
  }
  return allowed;
}

export function groupForAgent(groups: RobotGroup[], agent: string): RobotGroup | null {
  const want = agent.toLowerCase();
  const specific = groups.find((g) => g.agents.some((a) => a.toLowerCase() === want));
  if (specific) return specific;
  return groups.find((g) => g.agents.some((a) => a === "*")) || null;
}

export function crawlerAccess(groups: RobotGroup[], path: string, agents: readonly string[]) {
  const out: Record<string, { group: string; allowed: boolean }> = {};
  for (const a of [...agents, "*"]) {
    const g = groupForAgent(groups, a);
    out[a] = { group: g ? (g.agents.find((x) => x.toLowerCase() === a.toLowerCase()) || g.agents[0]) : "none", allowed: g ? pathAllowed(path, g.rules) : true };
  }
  return out;
}

export type SecurityTxt = {
  contact: string[];
  expires: string | null;
  expired: boolean | null;
  encryption: string[];
  acknowledgments: string[];
  preferred_languages: string | null;
  canonical: string[];
  policy: string[];
  hiring: string[];
  csaf: string[];
};

export function parseSecurityTxt(text: string, now = Date.now()): SecurityTxt {
  const fields: Record<string, string[]> = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const colon = line.indexOf(":");
    if (colon < 1) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (!value) continue;
    (fields[key] ||= []).push(value);
  }
  const expires = fields["expires"]?.[0] || null;
  let expired: boolean | null = null;
  if (expires) {
    const t = Date.parse(expires);
    expired = Number.isFinite(t) ? t < now : null;
  }
  return {
    contact: fields["contact"] || [],
    expires,
    expired,
    encryption: fields["encryption"] || [],
    acknowledgments: fields["acknowledgments"] || fields["acknowledgements"] || [],
    preferred_languages: fields["preferred-languages"]?.[0] || null,
    canonical: fields["canonical"] || [],
    policy: fields["policy"] || [],
    hiring: fields["hiring"] || [],
    csaf: fields["csaf"] || [],
  };
}

function firstLines(text: string, n = 12, maxLen = 200): string[] {
  const lines = text.split(/\r?\n/);
  let i = 0;
  while (i < lines.length && !lines[i].trim()) i++;
  return lines.slice(i, i + n).map((l) => (l.length > maxLen ? l.slice(0, maxLen) + "…" : l));
}

function looksLikeHtml(ct: string | null, text: string): boolean {
  if (ct && /text\/html/i.test(ct)) return true;
  const s = text.slice(0, 200).trim().toLowerCase();
  return s.startsWith("<!doctype html") || s.startsWith("<html");
}

async function fetchTextFile(url: string, ua: string) {
  const r = await safeFetch(url, {
    method: "GET",
    headers: { "user-agent": ua, accept: "text/plain,text/markdown,text/*;q=0.9,*/*;q=0.2" },
    maxBytes: MAX_FILE_BYTES,
  });
  const html = !r.error && r.status === 200 && looksLikeHtml(r.content_type, r.body);
  const present = !r.error && r.status === 200 && !!r.body.trim() && !html;
  const size = present ? new TextEncoder().encode(r.body).length : 0;
  return {
    present,
    status: r.status,
    final_url: r.url,
    size,
    truncated: present && r.truncated,
    first_lines: present ? firstLines(r.body) : [],
    text: present ? r.body : "",
    content_type: r.content_type,
    error: r.error || (html ? "html_page_not_plain_text" : undefined),
  };
}

export async function checkPolicies(item: PolicyInput, ua: string) {
  const started = Date.now();
  const origin = new URL(item.url).origin;
  const path = item.path && item.path.startsWith("/") ? item.path : "/" + (item.path || "");
  const files = {
    robots: `${origin}/robots.txt`,
    llms: `${origin}/llms.txt`,
    llms_full: `${origin}/llms-full.txt`,
    ai: `${origin}/ai.txt`,
    security: `${origin}/.well-known/security.txt`,
  };
  const out: Record<string, unknown> = { url: item.url, origin, path_checked: path };
  try {
    const [robotsF, llmsF, llmsFullF, aiF, secF] = await Promise.all([
      fetchTextFile(files.robots, ua),
      fetchTextFile(files.llms, ua),
      fetchTextFile(files.llms_full, ua),
      fetchTextFile(files.ai, ua),
      fetchTextFile(files.security, ua),
    ]);

    let robotsOut: Record<string, unknown>;
    if (!robotsF.present) {
      robotsOut = { present: false, status: robotsF.status, size: robotsF.size, sitemaps: [], crawlers: null, first_lines: [], error: robotsF.error };
    } else {
      const parsed = parseRobots(robotsF.text);
      robotsOut = {
        present: true,
        status: robotsF.status,
        size: robotsF.size,
        truncated: robotsF.truncated,
        sitemaps: parsed.sitemaps,
        crawlers: crawlerAccess(parsed.groups, path, AI_CRAWLERS),
        first_lines: robotsF.first_lines,
      };
    }

    const fileOut = (f: Awaited<ReturnType<typeof fetchTextFile>>) => ({
      present: f.present,
      status: f.status,
      size: f.size,
      truncated: f.truncated,
      first_lines: f.first_lines,
      ...(f.error ? { error: f.error } : {}),
    });

    let securityOut: Record<string, unknown> = fileOut(secF);
    if (secF.present) Object.assign(securityOut, parseSecurityTxt(secF.text));

    out.robots = robotsOut;
    out.llms_txt = fileOut(llmsF);
    out.llms_full_txt = fileOut(llmsFullF);
    out.ai_txt = fileOut(aiF);
    out.security_txt = securityOut;

    const failed = [robotsF, llmsF, llmsFullF, aiF, secF].every((f) => f.error && f.status == null);
    if (failed) out.error = "all_fetches_failed";
  } catch (e: any) {
    const msg = String(e?.message || e);
    out.error = /timeout|abort/i.test(msg) ? "timeout" : msg.slice(0, 200);
  }
  out.elapsed_ms = Date.now() - started;
  return out;
}

export async function checkPoliciesMany(items: PolicyInput[], ua: string) {
  return mapLimit(items, 2, (it) => checkPolicies(it, ua));
}
