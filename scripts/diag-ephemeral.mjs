// Read-only diagnostic: signs payments from a fresh EMPTY wallet for every paid HTTP route and MCP tool.
// Healthy result = "insufficient_funds"/"insufficient_balance" (facilitator accepted the payload format).
// Any other error (e.g. "paymentPayload is invalid") means real buyers cannot pay that route. Never spends.
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { x402Client, x402HTTPClient } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
const BASE = process.argv[2] || "https://linkproof.zopip.com";
const client = new x402Client(); registerExactEvmScheme(client, { signer: privateKeyToAccount(generatePrivateKey()) });
const http = new x402HTTPClient(client);
const LIC = "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software.";
const jobs = { "verify-answer": { text: "See https://example.com and doi 10.1038/nature14539" }, "verify-links": { urls: ["https://example.com"] }, "verify-citations": { citations: ["10.1038/nature14539"] }, "find-archive": { urls: ["https://example.com"] }, "check-headers": { urls: ["https://example.com"] }, "site-policies": { urls: ["https://example.com"] }, "email-auth": { domains: ["example.com"] }, "injection-scan": { text: "Hello there friend." }, "wiki-summary": { query: "HTTP 402" }, "license-detect": { text: LIC }, "ics-parse": { ics: "BEGIN:VCALENDAR\nVERSION:2.0\nEND:VCALENDAR" } };
let bad = 0;
for (const [r, body] of Object.entries(jobs)) {
  const url = `${BASE}/v1/${r}`;
  const init = { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) };
  const u = await fetch(url, init);
  const pr = http.getPaymentRequiredResponse((n) => u.headers.get(n), await u.json().catch(() => undefined));
  const payload = await client.createPaymentPayload(pr);
  const p = await fetch(url, { ...init, headers: { ...init.headers, ...http.encodePaymentSignatureHeader(payload) } });
  const t = await p.text(); const ok = /insufficient/i.test(t); if (!ok) bad++;
  console.log(`HTTP ${r.padEnd(17)} ${ok ? "OK  " : "FAIL"} ${p.status} ${t.slice(0, ok ? 60 : 1500)}`);
}
const H = { "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": "2025-06-18" };
let id = 0;
async function rpc(method, params) {
  const r = await fetch(BASE + "/mcp", { method: "POST", headers: H, body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }) });
  const t = await r.text(); const line = t.split("\n").find((l) => l.startsWith("data:")); return JSON.parse(line ? line.slice(5) : t);
}
await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "diag", version: "1" } });
for (const [r, args] of Object.entries(jobs)) {
  const name = r.replace(/-/g, "_");
  const c = await rpc("tools/call", { name, arguments: args });
  const err = c.result?._meta?.["x402/error"];
  const payload = await client.createPaymentPayload({ x402Version: 2, resource: err.resource, accepts: err.accepts });
  const p = await rpc("tools/call", { name, arguments: args, _meta: { "x402/payment": btoa(JSON.stringify(payload)) } });
  const e2 = JSON.stringify(p.result?._meta?.["x402/error"] ?? p.result?.content?.[0]?.text ?? p);
  const ok = /insufficient/i.test(e2); if (!ok) bad++;
  console.log(`MCP  ${name.padEnd(17)} ${ok ? "OK  " : "FAIL"} ${e2.slice(0, ok ? 60 : 600)}`);
}
console.log(bad ? `${bad} route(s) FAIL` : "all routes accept payment payloads");
