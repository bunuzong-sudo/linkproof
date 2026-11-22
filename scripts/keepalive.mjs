// Keep LinkProof endpoints visible in the Coinbase CDP Bazaar (it hides resources with no call in 30 days)
// by paying for ONE small call per endpoint from our own payer wallet. These are self-payments, not income.
//
// Usage:
//   node scripts/keepalive.mjs              # dry run (default): shows what would be paid, spends nothing, does not read the key
//   node scripts/keepalive.mjs --pay        # actually pay for the endpoints that are due
//   node scripts/keepalive.mjs --all [--pay]  # treat every endpoint as due (e.g. to refresh Bazaar descriptions)
//   DAYS=25 node scripts/keepalive.mjs      # "due" threshold in days since Bazaar's lastCalledAt (default 25)
//
// Note: the CDP facilitator rejects payments whose resource description is over 500 chars (opaque "paymentPayload is invalid"
// error); run scripts/diag-ephemeral.mjs (empty wallet, never spends) to check all routes before paying.
// Safety: total per run is capped at 0.1 USDC; each call must match the expected price, network (Base),
// asset (USDC) and payTo (our seller wallet) from the live 402 challenge, or the run aborts. Never prints keys.
import fs from "fs";

const BASE_URL = "https://linkproof.zopip.com";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PAYER = "0x206c257134049b8A52Ae7aaB0bd419Da38502733";
const SELLER = "0x80042a9F07df4373Fa72A798C9764Aea7863c2ec";
const KEYFILE = "/home/box/secure/x402-testnet-buyer.key"; // holds the key for PAYER (used on mainnet for Bazaar seeding)
const LOG = new URL("../keepalive-log.jsonl", import.meta.url).pathname;
const MAX_TOTAL_UNITS = 100000; // 0.1 USDC (6 decimals)
const MAX_CALL_UNITS = 20000; // 0.02 USDC
const DAYS = Number(process.env.DAYS || 25);
const PAY = process.argv.includes("--pay");
const ALL = process.argv.includes("--all");

const LICENSE_TEXT = "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the \"Software\"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.";
const ICS = "BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\nUID:1@example.com\nDTSTART:20260101T100000Z\nDTEND:20260101T110000Z\nSUMMARY:Test\nEND:VEVENT\nEND:VCALENDAR";
// Expected prices in USDC base units (6 decimals). A different live price aborts the run.
const JOBS = [
  { route: "verify-answer", units: 15000, body: { text: "See https://example.com and doi 10.1038/nature14539" } },
  { route: "verify-links", units: 5000, body: { urls: ["https://example.com"] } },
  { route: "verify-citations", units: 10000, body: { citations: ["10.1038/nature14539"] } },
  { route: "find-archive", units: 5000, body: { urls: ["https://example.com"] } },
  { route: "check-headers", units: 2000, body: { urls: ["https://example.com"] } },
  { route: "site-policies", units: 2000, body: { urls: ["https://example.com"] } },
  { route: "email-auth", units: 2000, body: { domains: ["example.com"] } },
  { route: "injection-scan", units: 3000, body: { text: "Hello, this is a plain sentence." } },
  { route: "wiki-summary", units: 5000, body: { query: "HTTP 402", lang: "en" } },
  { route: "license-detect", units: 3000, body: { text: LICENSE_TEXT } },
  { route: "ics-parse", units: 3000, body: { ics: ICS } },
];

async function bazaarLastCalled() {
  // Bazaar search returns at most 20 items; LinkProof has ~14 (11 canonical + 3 legacy-host duplicates).
  const r = await fetch("https://api.cdp.coinbase.com/platform/v2/x402/discovery/search?query=linkproof&limit=20");
  if (!r.ok) throw new Error(`Bazaar search HTTP ${r.status}`);
  const d = await r.json();
  const map = {};
  for (const x of d.resources || d.items || []) {
    if (!String(x.resource).startsWith(BASE_URL + "/v1/")) continue;
    map[x.resource.slice((BASE_URL + "/v1/").length)] = { lastCalledAt: x.quality?.lastCalledAt || null, calls30d: x.quality?.l30DaysTotalCalls ?? null, payers30d: x.quality?.l30DaysUniquePayers ?? null };
  }
  return map;
}

async function challenge(job) {
  const url = `${BASE_URL}/v1/${job.route}`;
  const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(job.body) });
  if (r.status !== 402) throw new Error(`${job.route}: expected 402, got ${r.status}`);
  const pr = JSON.parse(Buffer.from(r.headers.get("payment-required") || "", "base64").toString() || "{}");
  const a = pr.accepts?.[0] || {};
  const ok = pr.accepts?.length === 1 && a.scheme === "exact" && a.network === "eip155:8453" && String(a.asset).toLowerCase() === USDC.toLowerCase()
    && Number(a.amount) === job.units && Number(a.amount) <= MAX_CALL_UNITS && String(a.payTo).toLowerCase() === SELLER.toLowerCase()
    && pr.resource?.url === url && !!pr.extensions?.bazaar;
  if (!ok) throw new Error(`${job.route}: unexpected 402 challenge ${JSON.stringify({ amount: a.amount, network: a.network, payTo: a.payTo, resource: pr.resource?.url })}`);
  return url;
}

async function payerUsdc() {
  const data = "0x70a08231" + PAYER.slice(2).toLowerCase().padStart(64, "0");
  const r = await fetch("https://base-rpc.publicnode.com", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to: USDC, data }, "latest"] }) });
  return Number(BigInt((await r.json()).result)) / 1e6;
}

const now = Date.now();
const last = await bazaarLastCalled();
const due = [];
console.log(`mode: ${PAY ? "PAY" : "dry-run"}${ALL ? " (all endpoints)" : ""}; due if no Bazaar call in ${DAYS} days`);
for (const job of JOBS) {
  const info = last[job.route];
  const ageDays = info?.lastCalledAt ? (now - Date.parse(info.lastCalledAt)) / 86400000 : null;
  const isDue = ALL || ageDays === null || ageDays >= DAYS;
  console.log(`${isDue ? "DUE " : "ok  "} ${job.route.padEnd(17)} ${(job.units / 1e6).toFixed(3)} USDC  last call: ${info?.lastCalledAt ?? "not listed / unknown"}${ageDays !== null ? ` (${ageDays.toFixed(1)} d ago)` : ""}`);
  if (isDue) due.push(job);
}
const total = due.reduce((s, j) => s + j.units, 0);
console.log(`plan: ${due.length} call(s), total ${(total / 1e6).toFixed(3)} USDC (cap ${(MAX_TOTAL_UNITS / 1e6).toFixed(3)})`);
if (total > MAX_TOTAL_UNITS) { console.error("ABORT: total exceeds the 0.1 USDC cap"); process.exit(2); }
for (const job of due) await challenge(job); // preflight all before spending anything
const bal = await payerUsdc();
console.log(`payer ${PAYER} USDC balance: ${bal}`);
if (!due.length) process.exit(0);
if (bal < total / 1e6) { console.error("ABORT: payer balance too low"); process.exit(2); }
if (!PAY) { console.log("dry run: nothing paid. Re-run with --pay to pay for the DUE endpoints."); process.exit(0); }

const { privateKeyToAccount } = await import("viem/accounts");
const { x402Client, wrapFetchWithPayment, decodePaymentResponseHeader } = await import("@x402/fetch");
const { registerExactEvmScheme } = await import("@x402/evm/exact/client");
const signer = privateKeyToAccount(fs.readFileSync(KEYFILE, "utf8").trim());
if (signer.address.toLowerCase() !== PAYER.toLowerCase()) { console.error("ABORT: key does not match payer address"); process.exit(1); }
const client = new x402Client();
registerExactEvmScheme(client, { signer });
const pay = wrapFetchWithPayment(fetch, client);
let spent = 0;
for (const job of due) {
  const url = await challenge(job);
  if (spent + job.units > MAX_TOTAL_UNITS) { console.error("ABORT: cap reached"); break; }
  const res = await pay(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(job.body) });
  const bodyText = await res.text();
  const h = res.headers.get("payment-response") || res.headers.get("x-payment-response");
  let tx = null; try { const d = h ? decodePaymentResponseHeader(h) : null; tx = d?.transaction || d?.txHash || null; } catch {}
  const rec = { at: new Date().toISOString(), route: job.route, usdc: job.units / 1e6, status: res.status, tx, self_payment: true };
  if (res.status < 200 || res.status >= 300) {
    // Keep the server's reason (e.g. facilitator rejection) so failures can be diagnosed.
    let reason = null; try { const prh = res.headers.get("payment-required"); reason = prh ? JSON.parse(Buffer.from(prh, "base64").toString()).error : null; } catch {}
    rec.error = reason; rec.body = bodyText.slice(0, 2000);
    console.error(`server said (${res.status}): ${reason ?? ""} ${bodyText.slice(0, 2000)}`);
  }
  fs.appendFileSync(LOG, JSON.stringify(rec) + "\n");
  console.log("paid", JSON.stringify(rec));
  if (res.status < 200 || res.status >= 300) { console.error("ABORT: non-2xx; stopping so nothing is paid twice"); process.exit(4); }
  spent += job.units;
}
console.log(`done: spent ${(spent / 1e6).toFixed(3)} USDC; payer balance now ${await payerUsdc()}`);
