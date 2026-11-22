// Remote MCP server (streamable HTTP) at /mcp. Tools are paid per call via x402 (Cloudflare Agents SDK paidTool).
import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { withX402 } from "agents/x402";
import { createFacilitatorConfig } from "@coinbase/x402";
import { z } from "zod";
import { MAX_URLS, parseItems, check } from "./linkcheck";
import { MAX_CITATIONS, parseCitations, verifyCitation, mapLimit } from "./citations";
import { MAX_ARCHIVE_URLS, parseArchive, findArchive } from "./archive";
import { META } from "./catalog";
import { PRICE_ANSWER, MAX_ANSWER_CHARS, MAX_ANSWER_LINKS, MAX_ANSWER_CITATIONS, parseAnswerInput, verifyAnswer } from "./answer";
import { MAX_HEADER_URLS, PRICE_HEADERS, parseHeaderItems, checkHeadersMany } from "./headers";
import { MAX_POLICY_URLS, PRICE_POLICIES, parsePolicyItems, checkPoliciesMany } from "./policies";
import { MAX_EMAIL_DOMAINS, PRICE_EMAIL_AUTH, parseEmailDomains, checkEmailAuthMany, EMAIL_AUTH_DISCLAIMER } from "./emailauth";
import { PRICE_INJECTION, parseInjectionInput, scanInjection, INJECTION_DISCLAIMER } from "./injection";
import { MAX_WIKI_ITEMS, PRICE_WIKI, parseWikiItems, wikiSummaryMany, WIKI_LICENSE, WIKI_LICENSE_URL } from "./wiki";
import { PRICE_LICENSE, parseLicenseInput, detectLicense, LICENSE_DISCLAIMER } from "./license";
import { PRICE_ICS, parseIcsInput, parseIcs, MAX_OCCURRENCES } from "./ics";

type Env = { CDP_API_KEY_ID?: string; CDP_API_KEY_SECRET?: string; CONTACT_EMAIL: string; NETWORK: string; FACILITATOR_URL: string; PAY_TO: string; PRICE: string; PUBLIC_URL: string };

const text = (obj: unknown, isError = false) => ({ ...(isError ? { isError: true } : {}), content: [{ type: "text" as const, text: JSON.stringify(obj, null, 2) }] });

function createServer(env: Env) {
  const ua = `LinkProof/1.4 (+${env.PUBLIC_URL}; mailto:${env.CONTACT_EMAIL})`;
  const useCdp = env.FACILITATOR_URL === "cdp";
  if (useCdp && !(env.CDP_API_KEY_ID && env.CDP_API_KEY_SECRET)) throw new Error("CDP facilitator selected but secrets missing");
  const server = withX402(
    new McpServer(
      { name: "LinkProof", version: "1.4.0" },
      { instructions: "LinkProof fact-checking and verification tools for AI agents (fact-check a whole AI answer in one call with verify_answer; URLs, citations, archives, security headers, site policy files, email authentication DNS, prompt-injection scanning, Wikipedia summaries, SPDX license detection, ICS calendar parsing). Each tool is paid per call with x402 (USDC on Base); an unpaid call returns the x402 payment requirements. Invalid input is never charged; payment settles only after a successful result." },
    ),
    {
      network: env.NETWORK,
      recipient: env.PAY_TO as `0x${string}`,
      facilitator: useCdp ? createFacilitatorConfig(env.CDP_API_KEY_ID, env.CDP_API_KEY_SECRET) : { url: env.FACILITATOR_URL },
    },
  );

  server.paidTool(
    "verify_answer",
    `${META["/v1/verify-answer"].description} Price: ${PRICE_ANSWER} USDC per call (x402, Base).`,
    Number(PRICE_ANSWER),
    {
      text: z.string().max(MAX_ANSWER_CHARS).optional().describe("The AI answer or document to fact-check; URLs, DOIs, arXiv ids and PubMed ids are extracted automatically"),
      urls: z.array(z.union([z.string(), z.object({ url: z.string(), expect: z.string().max(300).optional() })])).max(MAX_ANSWER_LINKS).optional().describe("Optional extra URLs"),
      citations: z.array(z.union([z.string(), z.record(z.string(), z.any())])).max(MAX_ANSWER_CITATIONS).optional().describe("Optional extra references (DOI, arXiv id, PMID, free text, or {title, authors, year})"),
      archive_dead_links: z.boolean().optional().describe("Look up Wayback Machine copies for dead links (default true)"),
    },
    { readOnlyHint: true, openWorldHint: true, title: "Fact-check an AI answer's links and citations" },
    async (args: any) => {
      const { item, error } = parseAnswerInput(args);
      if (error) return text({ error }, true);
      const out = await verifyAnswer(item!, ua, env.CONTACT_EMAIL);
      if (out.summary.links.total === 0 && out.summary.citations.total > 0 && out.summary.citations.error === out.summary.citations.total) {
        return text({ error: "All upstream registry lookups failed; not charged. Retry later.", ...out }, true);
      }
      return text(out);
    },
  );

  server.paidTool(
    "verify_links",
    `${META["/v1/verify-links"].description} Price: ${env.PRICE} USDC per call (x402, Base).`,
    Number(env.PRICE),
    { urls: z.array(z.union([z.string(), z.object({ url: z.string(), expect: z.string().max(300).optional() })])).min(1).max(MAX_URLS).describe("URL strings, or {url, expect} objects") },
    { readOnlyHint: true, openWorldHint: true, title: "Verify links" },
    async (args: any) => {
      const { items, error } = parseItems(args);
      if (error) return text({ error }, true);
      const results = await Promise.all(items!.map(check));
      const live = results.filter((r: any) => r.verdict === "live").length;
      return text({ summary: { total: results.length, live, problems: results.length - live }, results, checked_at: new Date().toISOString() });
    },
  );

  server.paidTool(
    "verify_citations",
    `${META["/v1/verify-citations"].description} Price: ${"0.01"} USDC per call (x402, Base).`,
    Number("0.01"),
    { citations: z.array(z.union([z.string().min(1).max(1000), z.object({ doi: z.string().optional(), arxiv: z.string().optional(), pmid: z.string().optional(), title: z.string().max(500).optional(), authors: z.array(z.string()).max(30).optional(), year: z.number().int().optional() })])).min(1).max(MAX_CITATIONS) },
    { readOnlyHint: true, openWorldHint: true, title: "Verify citations" },
    async (args: any) => {
      const { items, error } = parseCitations(args);
      if (error) return text({ error }, true);
      const results = await mapLimit(items!, 3, (it) => verifyCitation(it, ua, env.CONTACT_EMAIL));
      const count = (v: string) => results.filter((r: any) => r.verdict === v).length;
      if (results.length && count("error") === results.length) return text({ error: "All upstream registry lookups failed; not charged. Retry later.", results }, true);
      return text({ summary: { total: results.length, verified: count("verified"), mismatch: count("mismatch"), not_found: count("not_found"), error: count("error") }, results, sources: "Crossref, DataCite, arXiv, NCBI PubMed", checked_at: new Date().toISOString() });
    },
  );

  server.paidTool(
    "find_archive",
    `${META["/v1/find-archive"].description} Price: ${"0.005"} USDC per call (x402, Base).`,
    Number("0.005"),
    { urls: z.array(z.union([z.string(), z.object({ url: z.string(), date: z.string().optional() })])).min(1).max(MAX_ARCHIVE_URLS), date: z.string().optional().describe("Default target date") },
    { readOnlyHint: true, openWorldHint: true, title: "Find archived copy" },
    async (args: any) => {
      const { items, error } = parseArchive(args);
      if (error) return text({ error }, true);
      const results = await mapLimit(items!, 5, (it) => findArchive(it, ua));
      const found = results.filter((r: any) => r.found === true).length;
      const errors = results.filter((r: any) => r.found === null).length;
      if (results.length && errors === results.length) return text({ error: "Wayback Machine lookups failed; not charged. Retry later.", results }, true);
      return text({ summary: { total: results.length, found, not_found: results.length - found - errors, error: errors }, results, source: "Internet Archive Wayback Machine", checked_at: new Date().toISOString() });
    },
  );
  server.paidTool(
    "check_headers",
    `${META["/v1/check-headers"].description} Price: ${PRICE_HEADERS} USDC per call (x402, Base).`,
    Number(PRICE_HEADERS),
    { urls: z.array(z.union([z.string(), z.object({ url: z.string() })])).min(1).max(MAX_HEADER_URLS).describe("URLs or domains to inspect") },
    { readOnlyHint: true, openWorldHint: true, title: "Check security headers" },
    async (args: any) => {
      const { items, error } = parseHeaderItems(args);
      if (error) return text({ error }, true);
      const results = await checkHeadersMany(items!, ua);
      const errors = results.filter((r: any) => r.error && r.status == null).length;
      if (results.length && errors === results.length) return text({ error: "All header lookups failed; not charged. Retry later.", results }, true);
      const grades: Record<string, number> = {};
      for (const r of results as any[]) if (r.grade) grades[r.grade] = (grades[r.grade] || 0) + 1;
      return text({ summary: { total: results.length, checked: results.length - errors, errors, grades }, results, checked_at: new Date().toISOString() });
    },
  );

  server.paidTool(
    "site_policies",
    `${META["/v1/site-policies"].description} Price: ${PRICE_POLICIES} USDC per call (x402, Base).`,
    Number(PRICE_POLICIES),
    { urls: z.array(z.union([z.string(), z.object({ url: z.string(), path: z.string().max(2000).optional() })])).min(1).max(MAX_POLICY_URLS), path: z.string().max(2000).optional().describe("Default path to test against robots.txt") },
    { readOnlyHint: true, openWorldHint: true, title: "Read site policy files" },
    async (args: any) => {
      const { items, error } = parsePolicyItems(args);
      if (error) return text({ error }, true);
      const results = await checkPoliciesMany(items!, ua);
      const failed = results.filter((r: any) => r.error === "all_fetches_failed").length;
      if (results.length && failed === results.length) return text({ error: "All policy-file lookups failed; not charged. Retry later.", results }, true);
      return text({ summary: { total: results.length, with_robots: results.filter((r: any) => r.robots?.present).length, with_llms_txt: results.filter((r: any) => r.llms_txt?.present).length, with_security_txt: results.filter((r: any) => r.security_txt?.present).length }, results, checked_at: new Date().toISOString() });
    },
  );

  server.paidTool(
    "email_auth",
    `${META["/v1/email-auth"].description} Price: ${PRICE_EMAIL_AUTH} USDC per call (x402, Base).`,
    Number(PRICE_EMAIL_AUTH),
    { domains: z.array(z.union([z.string(), z.object({ domain: z.string() })])).min(1).max(MAX_EMAIL_DOMAINS).describe("Domains, or email addresses (only the domain is used)") },
    { readOnlyHint: true, openWorldHint: true, title: "Check email authentication" },
    async (args: any) => {
      const { items, error } = parseEmailDomains(args);
      if (error) return text({ error }, true);
      const results = await checkEmailAuthMany(items!, ua);
      const errors = results.filter((r: any) => r.error && !r.mx && !r.spf).length;
      if (results.length && errors === results.length) return text({ error: "All DNS lookups failed; not charged. Retry later.", results, disclaimer: EMAIL_AUTH_DISCLAIMER }, true);
      const grades: Record<string, number> = {};
      for (const r of results as any[]) if (r.grade) grades[r.grade] = (grades[r.grade] || 0) + 1;
      return text({ summary: { total: results.length, checked: results.length - errors, errors, grades }, results, disclaimer: EMAIL_AUTH_DISCLAIMER, checked_at: new Date().toISOString() });
    },
  );

  server.paidTool(
    "injection_scan",
    `${META["/v1/injection-scan"].description} Price: ${PRICE_INJECTION} USDC per call (x402, Base).`,
    Number(PRICE_INJECTION),
    { text: z.string().min(1).max(51200).describe("Text to scan (max 50 KB)") },
    { readOnlyHint: true, openWorldHint: false, title: "Scan for prompt injection" },
    async (args: any) => {
      const { text: input, error } = parseInjectionInput(args);
      if (error) return text({ error, disclaimer: INJECTION_DISCLAIMER }, true);
      return text(scanInjection(input!));
    },
  );

  server.paidTool(
    "wiki_summary",
    `${META["/v1/wiki-summary"].description} Price: ${PRICE_WIKI} USDC per call (x402, Base).`,
    Number(PRICE_WIKI),
    { title: z.string().max(300).optional(), query: z.string().max(300).optional(), lang: z.string().max(20).optional(), items: z.array(z.union([z.string(), z.object({ title: z.string().optional(), query: z.string().optional(), lang: z.string().optional() })])).max(MAX_WIKI_ITEMS).optional() },
    { readOnlyHint: true, openWorldHint: true, title: "Wikipedia summary" },
    async (args: any) => {
      const { items, error } = parseWikiItems(args);
      if (error) return text({ error }, true);
      const results = await wikiSummaryMany(items!, ua);
      const transport = results.filter((r: any) => r.error === "timeout" || r.error === "fetch_failed");
      if (results.length && transport.length === results.length && results.every((r: any) => r.found !== true)) {
        return text({ error: "Wikipedia lookups failed; not charged. Retry later.", results }, true);
      }
      return text({ summary: { total: results.length, found: results.filter((r: any) => r.found === true).length, errors: results.filter((r: any) => r.error).length }, results, license: WIKI_LICENSE, license_url: WIKI_LICENSE_URL, checked_at: new Date().toISOString() });
    },
  );

  server.paidTool(
    "license_detect",
    `${META["/v1/license-detect"].description} Price: ${PRICE_LICENSE} USDC per call (x402, Base).`,
    Number(PRICE_LICENSE),
    { text: z.string().optional().describe("License text"), url: z.string().url().optional().describe("Public URL of a LICENSE file") },
    { readOnlyHint: true, openWorldHint: true, title: "Detect SPDX license" },
    async (args: any) => {
      const { item, error } = parseLicenseInput(args);
      if (error) return text({ error, disclaimer: LICENSE_DISCLAIMER }, true);
      const result = await detectLicense(item!, ua);
      if (result.error && !result.spdx_id && (result.error === "timeout" || result.error === "dns_error" || result.error === "fetch_failed")) {
        return text({ error: "License file lookup failed; not charged. Retry later.", ...result }, true);
      }
      return text(result);
    },
  );

  server.paidTool(
    "ics_parse",
    `${META["/v1/ics-parse"].description} Price: ${PRICE_ICS} USDC per call (x402, Base).`,
    Number(PRICE_ICS),
    { ics: z.string().optional().describe("Raw ICS text"), text: z.string().optional(), url: z.string().url().optional(), from: z.string().optional(), to: z.string().optional(), max_occurrences: z.number().int().min(1).max(MAX_OCCURRENCES).optional() },
    { readOnlyHint: true, openWorldHint: true, title: "Parse ICS calendar" },
    async (args: any) => {
      const { item, error } = parseIcsInput(args);
      if (error) return text({ error }, true);
      const result = await parseIcs(item!, ua);
      if (result.error && result.event_count === 0 && (result.error === "timeout" || result.error === "dns_error" || result.error === "fetch_failed")) {
        return text({ error: "Calendar fetch failed; not charged. Retry later.", ...result }, true);
      }
      return text(result);
    },
  );
  return server;
}

let handler: any;
export function mcpFetch(request: Request, env: Env, ctx: ExecutionContext) {
  if (!handler) handler = createMcpHandler(() => createServer(env) as any, { route: "/mcp" });
  return handler(request, env, ctx);
}
