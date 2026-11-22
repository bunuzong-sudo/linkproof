// Usage: node make-deploy.js <testnet|mainnet>  -> writes deploy.generated.js for the Cloudflare MCP `execute` tool
const fs = require("fs");
const mode = process.argv[2] || "testnet";
const cfg = {
  testnet: { NETWORK: "eip155:84532", FACILITATOR_URL: "https://x402.org/facilitator" },
  mainnet: { NETWORK: "eip155:8453", FACILITATOR_URL: "cdp" }, // CDP facilitator; needs Worker secrets CDP_API_KEY_ID / CDP_API_KEY_SECRET
}[mode];
const workerName = mode === "mainnet" ? "linkproof" : "linkproof-testnet";
const canonical = mode === "mainnet" ? "https://linkproof.zopip.com" : `https://${workerName}.bsptimber.workers.dev`;
const vars = { ...cfg, PAY_TO: "0x80042a9F07df4373Fa72A798C9764Aea7863c2ec", PRICE: "0.005", CONTACT_EMAIL: "bunuzong@gmail.com", PUBLIC_URL: canonical,
  // Public Glama connector ownership token (not a secret; served at /.well-known/glama.json and /mcp/.well-known/glama.json).
  GLAMA_CLAIM: "glama_claim_UyVGET-Y5waq9Gw0R3fdC0Q8ED7wlCvL" };
const code = fs.readFileSync(__dirname + "/dist/worker.js", "utf8");
const out = `async () => {
  const name = ${JSON.stringify(workerName)};
  const code = ${JSON.stringify(code)};
  const vars = ${JSON.stringify(vars)};
  const metadata = { keep_bindings: ["secret_text"], main_module: "worker.js", compatibility_date: "2026-10-01", compatibility_flags: ["nodejs_compat"],
    bindings: Object.entries(vars).map(([name, text]) => ({ type: "plain_text", name, text })) };
  const form = new FormData();
  form.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }));
  form.append("worker.js", new Blob([code], { type: "application/javascript+module" }), "worker.js");
  const up = await cloudflare.request({ method: "PUT", path: \`/accounts/\${accountId}/workers/scripts/\${name}\`, body: form });
  const sub = await cloudflare.request({ method: "POST", path: \`/accounts/\${accountId}/workers/scripts/\${name}/subdomain\`, body: { enabled: true, previews_enabled: false } });
  return { uploaded: up.success, errors: up.errors, subdomainEnabled: sub.success, mode: ${JSON.stringify(mode)} };
}`;
fs.writeFileSync(__dirname + `/deploy.${mode}.generated.js`, out);
console.log(`wrote deploy.${mode}.generated.js`, out.length, "bytes, mode", mode);
