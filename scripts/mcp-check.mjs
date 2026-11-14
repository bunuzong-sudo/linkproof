// Usage: node scripts/mcp-check.mjs <base-url>   (free checks + unpaid call + call signed by an EMPTY ephemeral wallet; never spends)
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { x402Client } from "@x402/core/client";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
const base = process.argv[2];
const H = { "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": "2025-06-18" };
let id = 0;
async function rpc(method, params, extraHeaders = {}) {
  const r = await fetch(base + "/mcp", { method: "POST", headers: { ...H, ...extraHeaders }, body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }) });
  const t = await r.text(); const line = t.split("\n").find((l) => l.startsWith("data:"));
  return { status: r.status, json: JSON.parse(line ? line.slice(5) : t) };
}
const init = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "check", version: "1" } });
console.log("initialize", init.status, init.json.result?.serverInfo);
const list = await rpc("tools/list", {});
console.log("tools/list", list.status, list.json.result.tools.map((t) => `${t.name} $${t._meta?.["agents-x402/priceUSD"]}`));
const call = await rpc("tools/call", { name: "verify_links", arguments: { urls: ["https://example.com"] } });
const err = call.json.result?._meta?.["x402/error"];
console.log("unpaid call ->", err?.error, err?.accepts?.[0]?.network, err?.accepts?.[0]?.amount, err?.accepts?.[0]?.payTo, "isError", call.json.result?.isError);
// Sign a real-format payment from a fresh EMPTY wallet: must be rejected (no funds), proving the tool is gated by verification.
const client = new x402Client(); registerExactEvmScheme(client, { signer: privateKeyToAccount(generatePrivateKey()) });
const payload = await client.createPaymentPayload({ x402Version: 2, resource: err.resource, accepts: err.accepts });
const paid = await rpc("tools/call", { name: "verify_links", arguments: { urls: ["https://example.com"] }, _meta: { "x402/payment": btoa(JSON.stringify(payload)) } });
const e2 = paid.json.result?._meta?.["x402/error"];
console.log("empty-wallet call ->", e2?.error ?? "NOT REJECTED?!", "| result text starts:", paid.json.result?.content?.[0]?.text?.slice(0, 40));
