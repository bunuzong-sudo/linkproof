# LinkProof

Verification tools for AI agents, paid per call with [x402](https://x402.org) (USDC on Base). No API keys, no accounts.

- **HTTP API:** https://linkproof.bsptimber.workers.dev (docs: `/`, OpenAPI: `/openapi.json`, discovery: `/.well-known/x402`)
- **Remote MCP server (streamable HTTP):** `https://linkproof.bsptimber.workers.dev/mcp`
- **Official MCP Registry:** `dev.workers.bsptimber.linkproof/linkproof`

## Tools and prices

| MCP tool | HTTP route | Price (USDC) | What it does |
| --- | --- | --- | --- |
| `verify_links` | `POST /v1/verify-links` | 0.005 | Check up to 10 URLs: live / dead / soft-404 / parked / blocked / unreachable, HTTP status, final URL, title, optional expected phrase |
| `verify_citations` | `POST /v1/verify-citations` | 0.01 | Check up to 10 references (DOI, arXiv id, PMID, free text, or `{title, authors, year}`) against Crossref, DataCite, arXiv and PubMed. Verdicts: verified, mismatch, not_found, error |
| `find_archive` | `POST /v1/find-archive` | 0.005 | Find the closest Internet Archive Wayback Machine snapshot for up to 10 URLs, optionally near a date |

Payment settles only after a successful result. Invalid input is never charged. Request bodies are not stored.

## Use over HTTP (x402)

```js
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

const client = new x402Client();
registerExactEvmScheme(client, { signer: privateKeyToAccount(process.env.PRIVATE_KEY) });
const pay = wrapFetchWithPayment(fetch, client);

const res = await pay("https://linkproof.bsptimber.workers.dev/v1/verify-links", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ urls: ["https://en.wikipedia.org/wiki/HTTP_402"] }),
});
console.log(await res.json());
```

Without payment every paid route answers `402 Payment Required` with the price in the `PAYMENT-REQUIRED` header.

## Use over MCP

Add the remote server to any MCP client:

```json
{ "mcpServers": { "linkproof": { "url": "https://linkproof.bsptimber.workers.dev/mcp" } } }
```

`initialize` and `tools/list` are free. Calling a tool without payment returns a result with `isError: true` and the x402 payment requirements in `_meta["x402/error"]`. Pay by signing that requirement and retrying the same `tools/call` with the base64 payload in `_meta["x402/payment"]`; the settlement receipt comes back in `_meta["x402/payment-response"]`. The Cloudflare Agents SDK client (`withX402Client` from `agents/x402`) does this automatically.

## Run it yourself

Cloudflare Worker (Hono + `@x402/hono` for HTTP routes, Cloudflare Agents SDK `withX402`/`paidTool` for MCP tools).

```sh
npm install
# edit [vars] in wrangler.toml (PAY_TO, CONTACT_EMAIL, ...)
npx wrangler dev        # testnet (Base Sepolia) by default
npx wrangler deploy
```

For mainnet set `NETWORK=eip155:8453`, `FACILITATOR_URL=cdp` and add `CDP_API_KEY_ID` / `CDP_API_KEY_SECRET` as Worker secrets (`wrangler secret put`). Check a deployment without spending: `node scripts/mcp-check.mjs <base-url>` and `sh scripts/check-402.sh <base-url>`.

Data sources: Crossref, DataCite, arXiv, NCBI PubMed E-utilities, Internet Archive Wayback Machine (public APIs, polite User-Agent with contact).

Contact: bunuzong@gmail.com · License: MIT
