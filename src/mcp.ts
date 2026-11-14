// Remote MCP server (streamable HTTP) at /mcp. Tools are paid per call via x402 (Cloudflare Agents SDK paidTool).
import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { withX402 } from "agents/x402";
import { createFacilitatorConfig } from "@coinbase/x402";
import { z } from "zod";
import { MAX_URLS, parseItems, check } from "./linkcheck";
import { MAX_CITATIONS, parseCitations, verifyCitation, mapLimit } from "./citations";
import { MAX_ARCHIVE_URLS, parseArchive, findArchive } from "./archive";

type Env = { CDP_API_KEY_ID?: string; CDP_API_KEY_SECRET?: string; CONTACT_EMAIL: string; NETWORK: string; FACILITATOR_URL: string; PAY_TO: string; PRICE: string; PUBLIC_URL: string };

const text = (obj: unknown, isError = false) => ({ ...(isError ? { isError: true } : {}), content: [{ type: "text" as const, text: JSON.stringify(obj, null, 2) }] });

function createServer(env: Env) {
  const ua = `LinkProof/1.1 (+${env.PUBLIC_URL}; mailto:${env.CONTACT_EMAIL})`;
  const useCdp = env.FACILITATOR_URL === "cdp";
  if (useCdp && !(env.CDP_API_KEY_ID && env.CDP_API_KEY_SECRET)) throw new Error("CDP facilitator selected but secrets missing");
  const server = withX402(
    new McpServer(
      { name: "LinkProof", version: "1.1.0" },
      { instructions: "LinkProof verification tools for AI agents. Each tool is paid per call with x402 (USDC on Base); an unpaid call returns the x402 payment requirements. Invalid input is never charged; payment settles only after a successful result." },
    ),
    {
      network: env.NETWORK,
      recipient: env.PAY_TO as `0x${string}`,
      facilitator: useCdp ? createFacilitatorConfig(env.CDP_API_KEY_ID, env.CDP_API_KEY_SECRET) : { url: env.FACILITATOR_URL },
    },
  );

  server.paidTool(
    "verify_links",
    `Check up to ${MAX_URLS} URLs before citing or sending them. Per URL: verdict (live, live_but_text_not_found, soft_404, parked, dead, blocked_or_rate_limited, unreachable), HTTP status, final URL, title, and optional check that an expected phrase appears. Price: ${env.PRICE} USDC per call (x402, Base).`,
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
    `Verify up to ${MAX_CITATIONS} citations really exist and match the claimed title/authors/year, against Crossref, DataCite, arXiv and PubMed. Items: DOI, arXiv id, 'PMID: 123', free-text reference, or {doi|arxiv|pmid|title, authors, year}. Verdicts: verified, mismatch, not_found, error. Price: 0.01 USDC per call (x402, Base).`,
    0.01,
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
    `For up to ${MAX_ARCHIVE_URLS} URLs (e.g. dead links), find the closest Internet Archive Wayback Machine snapshot, optionally nearest a date (YYYY, YYYY-MM or YYYY-MM-DD). Returns snapshot URL, capture time, captured status. Price: 0.005 USDC per call (x402, Base).`,
    0.005,
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
  return server;
}

let handler: any;
export function mcpFetch(request: Request, env: Env, ctx: ExecutionContext) {
  if (!handler) handler = createMcpHandler(() => createServer(env) as any, { route: "/mcp" });
  return handler(request, env, ctx);
}
