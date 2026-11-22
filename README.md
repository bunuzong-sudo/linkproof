# LinkProof

Fact-checking and web-verification tools for AI agents, paid per call with [x402](https://x402.org) (USDC on Base). No API keys, no accounts, no subscription.

- **HTTP API:** https://linkproof.zopip.com (docs: `/`, OpenAPI: `/openapi.json`, x402 discovery: `/.well-known/x402`, agent guide: [`/llms.txt`](https://linkproof.zopip.com/llms.txt))
- **Remote MCP server (streamable HTTP):** `https://linkproof.zopip.com/mcp` (server card: `/mcp/server-card`)
- **Official MCP Registry:** `dev.workers.bsptimber.linkproof/linkproof`
- Listed in the Coinbase x402 Bazaar and on x402scan.

## Tools and prices

| MCP tool | HTTP route | Price (USDC) | What it does |
| --- | --- | --- | --- |
| `verify_answer` | `POST /v1/verify-answer` | 0.015 | **Hallucination check for a whole AI answer.** Send the text; every URL, DOI, arXiv id and PubMed id is extracted, links are checked, citations verified, and Wayback copies found for dead links. Up to 10 links + 10 citations |
| `verify_links` | `POST /v1/verify-links` | 0.005 | Broken link / dead link checker for up to 10 URLs: live, 404, soft-404, parked domain, blocked, unreachable, final URL, title, optional expected phrase |
| `verify_citations` | `POST /v1/verify-citations` | 0.01 | Citation checker: up to 10 references (DOI, arXiv id, PMID, free text, or `{title, authors, year}`) against Crossref, DataCite, arXiv and PubMed. Verdicts: verified, mismatch, not_found, error |
| `find_archive` | `POST /v1/find-archive` | 0.005 | Wayback Machine lookup: closest archived snapshot for up to 10 URLs, optionally near a date |
| `check_headers` | `POST /v1/check-headers` | 0.002 | HTTP security headers audit for up to 5 URLs: HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy, cookie flags, HTTPS redirect, A–F grade |
| `site_policies` | `POST /v1/site-policies` | 0.002 | robots.txt, llms.txt, llms-full.txt, ai.txt and security.txt checker for up to 5 sites; AI-crawler rules (GPTBot, ClaudeBot, …) |
| `email_auth` | `POST /v1/email-auth` | 0.002 | SPF, DKIM and DMARC checker + MX lookup for up to 5 domains; misconfigurations, grade, fixes. DNS only, mailboxes never probed |
| `injection_scan` | `POST /v1/injection-scan` | 0.003 | Prompt injection detection for untrusted text (max 50 KB): risk level, matches with offsets, sanitized copy. Heuristic |
| `wiki_summary` | `POST /v1/wiki-summary` | 0.005 | Wikipedia summary for up to 3 titles or queries, with CC BY-SA attribution |
| `license_detect` | `POST /v1/license-detect` | 0.003 | Open source license (SPDX) detection from text or a LICENSE URL. Not legal advice |
| `ics_parse` | `POST /v1/ics-parse` | 0.003 | ICS / iCalendar parser with RRULE expansion |

Payment settles only after a successful result. Invalid input is rejected with 400 and never charged. Request bodies are not stored.

## Use over HTTP (x402)

```js
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

const client = new x402Client();
registerExactEvmScheme(client, { signer: privateKeyToAccount(process.env.PRIVATE_KEY) });
const pay = wrapFetchWithPayment(fetch, client);

const res = await pay("https://linkproof.zopip.com/v1/verify-answer", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ text: "Transformers were introduced in arXiv:1706.03762. See also https://doi.org/10.1038/nature14539." }),
});
console.log(await res.json()); // summary.overall: all_ok | problems_found | partial
```

Without payment every paid route answers `402 Payment Required` with the price in the `PAYMENT-REQUIRED` header.

## Use over MCP

```json
{ "mcpServers": { "linkproof": { "url": "https://linkproof.zopip.com/mcp" } } }
```

`initialize` and `tools/list` are free. Calling a tool without payment returns `isError: true` with the x402 requirements in `_meta["x402/error"]`; retry the same `tools/call` with the signed payload in `_meta["x402/payment"]`. The Cloudflare Agents SDK client (`withX402Client` from `agents/x402`) does this automatically.

## Run it yourself

Cloudflare Worker (Hono + `@x402/hono` for HTTP routes, Cloudflare Agents SDK `withX402`/`paidTool` for MCP tools). Route descriptions and tags live in `src/catalog.ts`.

```sh
npm install
# edit [vars] in wrangler.toml (PAY_TO, CONTACT_EMAIL, PUBLIC_URL, ...)
npx wrangler dev        # testnet (Base Sepolia) by default
npx wrangler deploy
```

For mainnet set `NETWORK=eip155:8453`, `FACILITATOR_URL=cdp` and add `CDP_API_KEY_ID` / `CDP_API_KEY_SECRET` as Worker secrets. Check a deployment without spending: `sh scripts/check-402.sh <base-url>` and `node scripts/mcp-check.mjs <base-url>`.

Data sources: Crossref, DataCite, arXiv, NCBI PubMed E-utilities, Internet Archive Wayback Machine, Cloudflare/Google DNS-over-HTTPS, Wikimedia REST API (public APIs, polite User-Agent with contact).

Contact: bunuzong@gmail.com · License: MIT
