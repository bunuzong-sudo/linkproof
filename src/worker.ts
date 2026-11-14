import { Hono } from "hono";
import { paymentMiddleware, x402ResourceServer } from "@x402/hono";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { declareDiscoveryExtension, bazaarResourceServerExtension } from "@x402/extensions/bazaar";
import { createFacilitatorConfig } from "@coinbase/x402";

type Env = { CDP_API_KEY_ID?: string; CDP_API_KEY_SECRET?: string; CONTACT_EMAIL: string; NETWORK: string; FACILITATOR_URL: string; PAY_TO: string; PRICE: string; PUBLIC_URL: string };

import { MAX_URLS, parseItems, check } from "./linkcheck";
import { MAX_CITATIONS, parseCitations, verifyCitation, mapLimit } from "./citations";
import { MAX_ARCHIVE_URLS, parseArchive, findArchive } from "./archive";
import { mcpFetch } from "./mcp";

const PRICE_CITATIONS = "0.01";
const PRICE_ARCHIVE = "0.005";
const ua = (env: Env) => `LinkProof/1.1 (+${env.PUBLIC_URL}; mailto:${env.CONTACT_EMAIL})`;

const CITATION_ITEM = { anyOf: [
  { type: "string", minLength: 1, maxLength: 1000, description: "A DOI, arXiv id (e.g. arXiv:1706.03762), 'PMID: 123', or a free-text reference" },
  { type: "object", properties: {
    doi: { type: "string" }, arxiv: { type: "string" }, pmid: { type: "string" },
    title: { type: "string", maxLength: 500 }, authors: { type: "array", items: { type: "string" }, maxItems: 30 }, year: { type: "integer" } },
    description: "Structured citation. Needs at least one of doi, arxiv, pmid, title. Claimed title/authors/year are checked against the registry record." },
] };
const CITATIONS_EXAMPLE = { citations: ["10.1038/nature14539", { title: "Attention Is All You Need", authors: ["Vaswani", "Shazeer"], year: 2017 }, "Smith J. Quantum avocado folding in martian soil. J Imag Sci. 2019."] };
const CITATIONS_OUT = { summary: { total: 3, verified: 2, mismatch: 0, not_found: 1, error: 0 }, results: [
  { input: "10.1038/nature14539", lookup: "doi", exists: true, verdict: "verified", confidence: 0.95, matched: { source: "crossref", id: "10.1038/nature14539", title: "Deep learning", authors: ["LeCun", "Bengio", "Hinton"], year: 2015, venue: "Nature", url: "https://doi.org/10.1038/nature14539" }, mismatches: [] },
  { input: "Smith J. Quantum avocado folding in martian soil. J Imag Sci. 2019.", lookup: "search", exists: false, verdict: "not_found", confidence: 0.7 } ] };
const ARCHIVE_ITEM = { anyOf: [ { type: "string", format: "uri" }, { type: "object", properties: { url: { type: "string", format: "uri" }, date: { type: "string", description: "YYYY, YYYY-MM or YYYY-MM-DD; find the snapshot closest to this date" } }, required: ["url"] } ] };
const ARCHIVE_EXAMPLE = { urls: ["https://example.com/old-page", { url: "https://www.bbc.com/news", date: "2010-06-01" }] };
const ARCHIVE_OUT = { summary: { total: 2, found: 2, not_found: 0 }, results: [
  { url: "https://www.bbc.com/news", requested_date: "2010-06-01", found: true, snapshot_url: "https://web.archive.org/web/20100721061337/http://www.bbc.com:80/news/", timestamp: "20100721061337", captured_at: "2010-07-21T06:13:37Z", snapshot_status: 200, days_from_requested: 50 } ] };

const app = new Hono<{ Bindings: Env }>();

function docs(env: Env) {
  return {
    service: "LinkProof",
    contact: { email: env.CONTACT_EMAIL },
    summary: "Verification tools for AI agents, paid per call with x402 (USDC on Base): check URLs before citing them, verify that cited papers really exist and match, and find archived copies of dead links.",
    endpoint: { method: "POST", path: "/v1/verify-links", url: `${env.PUBLIC_URL}/v1/verify-links` },
    price: `${env.PRICE} USDC per call (up to ${MAX_URLS} URLs), paid via x402`,
    endpoints: [
      { method: "POST", path: "/v1/verify-links", price_usdc: env.PRICE, does: `Check up to ${MAX_URLS} URLs: live/dead, soft-404, parked, final URL, title, optional expected phrase` },
      { method: "POST", path: "/v1/verify-citations", price_usdc: PRICE_CITATIONS, does: `Verify up to ${MAX_CITATIONS} citations (DOI, arXiv, PubMed, or free text) exist and match claimed title/authors/year. Verdicts: verified, mismatch, not_found, error`, request_example: CITATIONS_EXAMPLE },
      { method: "POST", path: "/v1/find-archive", price_usdc: PRICE_ARCHIVE, does: `Find the closest Wayback Machine snapshot for up to ${MAX_ARCHIVE_URLS} URLs, optionally near a date`, request_example: ARCHIVE_EXAMPLE },
    ],
    mcp: { url: `${env.PUBLIC_URL}/mcp`, transport: "streamable-http", tools: ["verify_links", "verify_citations", "find_archive"], payment: "x402 per tool call (same prices); tools/list is free" },
    data_sources: "Crossref, DataCite, arXiv, NCBI PubMed E-utilities, Internet Archive Wayback Machine (public APIs, polite User-Agent with contact)",
    network: env.NETWORK,
    payTo: env.PAY_TO,
    request_example: { urls: ["https://example.com", { url: "https://en.wikipedia.org/wiki/HTTP_402", expect: "Payment Required" }] },
    verdicts: ["live", "live_but_text_not_found", "soft_404", "parked", "dead", "blocked_or_rate_limited", "unreachable"],
    notes: [
      "Only public http(s) pages are fetched: one GET per URL (redirects followed), first 64 KB read (256 KB when `expect` is set), 8 s timeout per URL.",
      "Invalid input is rejected with HTTP 400 and is never charged (settlement happens only after a successful response).",
      "No content is stored. Logs contain no request bodies.",
    ],
  };
}

app.get("/", (c) => c.json(docs(c.env)));
// Public key proving domain control for the official MCP Registry (HTTP auth). Public value, not a secret.
app.get("/.well-known/mcp-registry-auth", (c) => c.text('v=MCPv1; k=ed25519; p=EWZ2lBxSijXKjr4410MY8jWJMsiyvE+d+Ew22UDBaZ0='));
app.get("/openapi.json", (c) => {
  const env = c.env;
  const urlItem = { anyOf: [ { type: "string", format: "uri" }, { type: "object", properties: { url: { type: "string", format: "uri" }, expect: { type: "string", maxLength: 300, description: "Phrase that should appear on the page" } }, required: ["url"] } ] };
  return c.json({
    openapi: "3.1.0",
    info: {
      title: "LinkProof",
      version: "1.1.0",
      contact: { name: "LinkProof", email: env.CONTACT_EMAIL },
      description: "Verification tools for AI agents: check URLs before citing them (live/dead, soft-404, parked, final URL, title, expected phrase), verify citations against Crossref/arXiv/PubMed, and find Wayback Machine snapshots for dead links.",
      "x-guidance": "POST /v1/verify-links with JSON {\"urls\": [...]} (1-10 items). Each item is a URL string or {\"url\", \"expect\"}. Read results[].verdict: live | live_but_text_not_found | soft_404 | parked | dead | blocked_or_rate_limited | unreachable. POST /v1/verify-citations with {\"citations\": [...]} (1-10; DOI, arXiv id, PMID, free-text reference, or {doi|arxiv|pmid|title, authors, year}); read results[].verdict: verified | mismatch | not_found | error. POST /v1/find-archive with {\"urls\": [...], \"date\"?: \"YYYY-MM-DD\"} to get the closest Wayback snapshot per URL. Pay per call with x402 (USDC on Base).",
    },
    servers: [{ url: env.PUBLIC_URL }],
    paths: {
      "/v1/verify-links": {
        post: {
          operationId: "verifyLinks",
          summary: "Verify up to 10 URLs (live, soft-404, parked, final URL, title, expected phrase)",
          tags: ["Web", "Verification"],
          "x-payment-info": { price: { mode: "fixed", currency: "USD", amount: Number(env.PRICE).toFixed(6) }, protocols: [{ x402: {} }] },
          requestBody: { required: true, content: { "application/json": { schema: { type: "object", properties: { urls: { type: "array", minItems: 1, maxItems: MAX_URLS, items: urlItem } }, required: ["urls"] }, example: { urls: ["https://example.com", { url: "https://en.wikipedia.org/wiki/HTTP_402", expect: "Payment Required" }] } } } },
          responses: {
            "200": { description: "Per-URL verification results", content: { "application/json": { schema: { type: "object", properties: {
              summary: { type: "object", properties: { total: { type: "integer" }, live: { type: "integer" }, problems: { type: "integer" } } },
              results: { type: "array", items: { type: "object", properties: { url: { type: "string" }, verdict: { type: "string" }, status: { type: ["integer", "null"] }, final_url: { type: "string" }, title: { type: ["string", "null"] }, soft_404: { type: "boolean" }, parked_domain: { type: "boolean" }, expect_found: { type: "boolean" } } } },
              checked_at: { type: "string" } }, required: ["summary", "results"] } } } },
            "400": { description: "Invalid input (not charged)" },
            "402": { description: "Payment Required" },
          },
        },
      },
      "/v1/verify-citations": {
        post: {
          operationId: "verifyCitations",
          summary: `Verify up to ${MAX_CITATIONS} citations exist (Crossref/DataCite, arXiv, PubMed) and match claimed title/authors/year`,
          tags: ["Research", "Verification"],
          "x-payment-info": { price: { mode: "fixed", currency: "USD", amount: Number(PRICE_CITATIONS).toFixed(6) }, protocols: [{ x402: {} }] },
          requestBody: { required: true, content: { "application/json": { schema: { type: "object", properties: { citations: { type: "array", minItems: 1, maxItems: MAX_CITATIONS, items: CITATION_ITEM } }, required: ["citations"] }, example: CITATIONS_EXAMPLE } } },
          responses: {
            "200": { description: "Per-citation results", content: { "application/json": { schema: { type: "object", properties: {
              summary: { type: "object" },
              results: { type: "array", items: { type: "object", properties: { input: {}, lookup: { type: "string" }, exists: { type: ["boolean", "null"] }, verdict: { type: "string", enum: ["verified", "mismatch", "not_found", "error"] }, confidence: { type: "number" }, matched: { type: "object" }, mismatches: { type: "array", items: { type: "object" } } } } },
              checked_at: { type: "string" } }, required: ["summary", "results"] }, example: CITATIONS_OUT } } },
            "400": { description: "Invalid input (not charged)" },
            "402": { description: "Payment Required" },
          },
        },
      },
      "/v1/find-archive": {
        post: {
          operationId: "findArchive",
          summary: `Closest Wayback Machine snapshot for up to ${MAX_ARCHIVE_URLS} URLs, optionally near a date`,
          tags: ["Web", "Archive"],
          "x-payment-info": { price: { mode: "fixed", currency: "USD", amount: Number(PRICE_ARCHIVE).toFixed(6) }, protocols: [{ x402: {} }] },
          requestBody: { required: true, content: { "application/json": { schema: { type: "object", properties: { urls: { type: "array", minItems: 1, maxItems: MAX_ARCHIVE_URLS, items: ARCHIVE_ITEM }, date: { type: "string", description: "Default target date for all URLs (YYYY, YYYY-MM, YYYY-MM-DD)" } }, required: ["urls"] }, example: ARCHIVE_EXAMPLE } } },
          responses: {
            "200": { description: "Per-URL snapshot results", content: { "application/json": { schema: { type: "object", properties: {
              summary: { type: "object" },
              results: { type: "array", items: { type: "object", properties: { url: { type: "string" }, found: { type: ["boolean", "null"] }, snapshot_url: { type: "string" }, timestamp: { type: "string" }, captured_at: { type: "string" }, snapshot_status: { type: ["integer", "null"] }, days_from_requested: { type: "integer" } } } },
              checked_at: { type: "string" } }, required: ["summary", "results"] }, example: ARCHIVE_OUT } } },
            "400": { description: "Invalid input (not charged)" },
            "402": { description: "Payment Required" },
          },
        },
      },
      "/": { get: { operationId: "docs", summary: "Human/agent readable docs", security: [], responses: { "200": { description: "Docs" } } } },
      "/health": { get: { operationId: "health", summary: "Health check", security: [], responses: { "200": { description: "OK" } } } },
    },
  });
});
app.get("/health", (c) => c.json({ ok: true }));
app.get("/.well-known/x402", (c) => c.json({ x402Version: 2, resources: [`${c.env.PUBLIC_URL}/v1/verify-links`, `${c.env.PUBLIC_URL}/v1/verify-citations`, `${c.env.PUBLIC_URL}/v1/find-archive`] }));

// Validate input BEFORE settlement so buyers never pay for a malformed request.
// Requests without a payment header always get the 402 challenge (so discovery probes work).
app.post("/v1/verify-links", async (c, next) => {
  const paying = c.req.header("payment-signature") || c.req.header("x-payment");
  if (!paying) return next();
  let body: any;
  try { body = await c.req.json(); } catch { return c.json({ error: "Body must be valid JSON", docs: c.env.PUBLIC_URL }, 400); }
  const { error } = parseItems(body);
  if (error) return c.json({ error, docs: c.env.PUBLIC_URL }, 400);
  return next();
});

function prevalidate(parse: (b: any) => { error?: string }) {
  return async (c: any, next: any) => {
    const paying = c.req.header("payment-signature") || c.req.header("x-payment");
    if (!paying) return next();
    let body: any;
    try { body = await c.req.json(); } catch { return c.json({ error: "Body must be valid JSON", docs: c.env.PUBLIC_URL }, 400); }
    const { error } = parse(body);
    if (error) return c.json({ error, docs: c.env.PUBLIC_URL }, 400);
    return next();
  };
}
app.post("/v1/verify-citations", prevalidate(parseCitations));
app.post("/v1/find-archive", prevalidate(parseArchive));

let mw: any;
app.use("/v1/*", async (c, next) => {
  if (!mw) {
    const env = c.env;
    // Mainnet: Coinbase CDP facilitator (authenticated with Worker secrets) so settled payments get cataloged in the CDP Bazaar.
    const useCdp = env.FACILITATOR_URL === "cdp" && env.CDP_API_KEY_ID && env.CDP_API_KEY_SECRET;
    if (env.FACILITATOR_URL === "cdp" && !useCdp) throw new Error("CDP facilitator selected but CDP_API_KEY_ID / CDP_API_KEY_SECRET secrets are missing");
    const facilitatorClient = new HTTPFacilitatorClient(
      useCdp ? createFacilitatorConfig(env.CDP_API_KEY_ID, env.CDP_API_KEY_SECRET) : { url: env.FACILITATOR_URL },
    );
    const server = new x402ResourceServer(facilitatorClient)
      .register(env.NETWORK as any, new ExactEvmScheme())
      .registerExtension(bazaarResourceServerExtension);
    mw = paymentMiddleware(
      {
        "POST /v1/verify-links": {
          accepts: [{ scheme: "exact", price: `$${env.PRICE}`, network: env.NETWORK as any, payTo: env.PAY_TO }],
          description:
            "LinkProof: verify up to 10 URLs before an agent cites or sends them. Per URL returns verdict (live, soft_404, parked, dead, blocked, unreachable), HTTP status, final URL after redirects, title, meta description, and optional check that an expected phrase appears on the page. Catches hallucinated or rotted links.",
          mimeType: "application/json",
          serviceName: "LinkProof",
          tags: ["url", "link-checker", "citation", "verification", "hallucination", "web"],
          extensions: {
            ...declareDiscoveryExtension({
              bodyType: "json",
              method: "POST",
              input: { urls: ["https://example.com", { url: "https://en.wikipedia.org/wiki/HTTP_402", expect: "Payment Required" }] },
              inputSchema: {
                type: "object",
                properties: {
                  urls: {
                    type: "array", minItems: 1, maxItems: MAX_URLS,
                    description: "URLs to verify. Each item is a URL string, or {url, expect} where expect is a phrase that should appear on the page.",
                    items: {
                      anyOf: [
                        { type: "string", format: "uri" },
                        { type: "object", properties: { url: { type: "string", format: "uri" }, expect: { type: "string", maxLength: 300 } }, required: ["url"] },
                      ],
                    },
                  },
                },
                required: ["urls"],
              },
              output: {
                example: {
                  summary: { total: 2, live: 1, problems: 1 },
                  results: [
                    { url: "https://example.com", verdict: "live", status: 200, final_url: "https://example.com/", title: "Example Domain", soft_404: false, parked_domain: false },
                    { url: "https://example.com/made-up-page", verdict: "dead", status: 404 },
                  ],
                },
              },
            } as any),
          },
        },
        "POST /v1/verify-citations": {
          accepts: [{ scheme: "exact", price: `$${PRICE_CITATIONS}`, network: env.NETWORK as any, payTo: env.PAY_TO }],
          description:
            "LinkProof citations: verify up to 10 references an agent is about to cite. Accepts DOI, arXiv id, PubMed id, free-text reference, or {title, authors, year}. Checks Crossref/DataCite, arXiv and PubMed; returns per citation exists, matched metadata (title, authors, year, venue, URL), field mismatches, confidence and verdict (verified, mismatch, not_found). Catches hallucinated or misattributed papers.",
          mimeType: "application/json",
          serviceName: "LinkProof",
          tags: ["citation", "doi", "verification", "hallucination", "research"],
          extensions: {
            ...declareDiscoveryExtension({
              bodyType: "json",
              method: "POST",
              input: CITATIONS_EXAMPLE,
              inputSchema: { type: "object", properties: { citations: { type: "array", minItems: 1, maxItems: MAX_CITATIONS, items: CITATION_ITEM, description: "Citations to verify" } }, required: ["citations"] },
              output: { example: CITATIONS_OUT },
            } as any),
          },
        },
        "POST /v1/find-archive": {
          accepts: [{ scheme: "exact", price: `$${PRICE_ARCHIVE}`, network: env.NETWORK as any, payTo: env.PAY_TO }],
          description:
            "LinkProof archive: for up to 10 URLs (e.g. dead links), find the closest Internet Archive Wayback Machine snapshot, optionally nearest to a given date. Returns snapshot URL, capture timestamp, captured HTTP status and distance in days from the requested date. Use it to replace or back up rotted citations.",
          mimeType: "application/json",
          serviceName: "LinkProof",
          tags: ["archive", "wayback", "dead-link", "url", "citation"],
          extensions: {
            ...declareDiscoveryExtension({
              bodyType: "json",
              method: "POST",
              input: ARCHIVE_EXAMPLE,
              inputSchema: { type: "object", properties: { urls: { type: "array", minItems: 1, maxItems: MAX_ARCHIVE_URLS, items: ARCHIVE_ITEM, description: "URLs to look up" }, date: { type: "string", description: "Default target date YYYY, YYYY-MM or YYYY-MM-DD" } }, required: ["urls"] },
              output: { example: ARCHIVE_OUT },
            } as any),
          },
        },
      },
      server,
    );
  }
  return mw(c, next);
});

app.post("/v1/verify-links", async (c) => {
  const { items } = parseItems(await c.req.json());
  const results = await Promise.all(items!.map(check));
  const live = results.filter((r) => r.verdict === "live").length;
  return c.json({
    summary: { total: results.length, live, problems: results.length - live },
    results,
    checked_at: new Date().toISOString(),
  });
});

app.post("/v1/verify-citations", async (c) => {
  const { items } = parseCitations(await c.req.json());
  const results = await mapLimit(items!, 3, (it) => verifyCitation(it, ua(c.env), c.env.CONTACT_EMAIL));
  const count = (v: string) => results.filter((r) => r.verdict === v).length;
  if (results.length && count("error") === results.length) return c.json({ error: "All upstream registry lookups failed; not charged. Retry later.", results }, 503);
  return c.json({
    summary: { total: results.length, verified: count("verified"), mismatch: count("mismatch"), not_found: count("not_found"), error: count("error") },
    results,
    sources: "Crossref, DataCite, arXiv, NCBI PubMed",
    checked_at: new Date().toISOString(),
  });
});

app.post("/v1/find-archive", async (c) => {
  const { items } = parseArchive(await c.req.json());
  const results = await mapLimit(items!, 5, (it) => findArchive(it, ua(c.env)));
  const found = results.filter((r) => r.found === true).length;
  const errors = results.filter((r) => r.found === null).length;
  if (results.length && errors === results.length) return c.json({ error: "Wayback Machine lookups failed; not charged. Retry later.", results }, 503);
  return c.json({
    summary: { total: results.length, found, not_found: results.length - found - errors, error: errors },
    results,
    source: "Internet Archive Wayback Machine",
    checked_at: new Date().toISOString(),
  });
});

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const path = new URL(request.url).pathname;
    if (path === "/mcp") return mcpFetch(request, env, ctx);
    return app.fetch(request, env, ctx);
  },
};
