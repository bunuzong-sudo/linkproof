// Base (chain id 8453) on-chain lookup via free public JSON-RPC (PublicNode, Base, dRPC fallback):
// wallet ETH + major token balances, nonce, contract check, Basename forward/reverse resolution,
// ERC-20 token info, and chain status (latest block, base fee, gas price, priority fee).
import { namehash, encodeFunctionData, decodeFunctionResult, parseAbi, formatUnits, getAddress, hexToString, type Hex } from "viem";

export const PRICE_BASE_LOOKUP = "0.001";
export const MAX_EXTRA_TOKENS = 10;
// Order chosen from probes made FROM Cloudflare Workers egress (2026-11-22): several popular public RPCs
// rate-limit shared Cloudflare IPs (429), so those come last. Providers that fail are skipped for 60 s.
export const RPCS = ["https://base.gateway.tenderly.co", "https://base-mainnet.public.blastapi.io", "https://base-pokt.nodies.app", "https://base-public.nodies.app", "https://base-rpc.publicnode.com", "https://mainnet.base.org"];
const cooldown = new Map<string, number>();
const MULTICALL3 = "0xcA11bde05977b3631167028862bE2a173976CA11";
const BASE_REGISTRY = "0xB94704422c2a1E396835A571837Aa5AE53285a95"; // Basenames registry on Base
export const KNOWN_TOKENS: { symbol: string; address: string; decimals: number }[] = [
  { symbol: "USDC", address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", decimals: 6 },
  { symbol: "WETH", address: "0x4200000000000000000000000000000000000006", decimals: 18 },
  { symbol: "cbBTC", address: "0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf", decimals: 8 },
  { symbol: "USDbC", address: "0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA", decimals: 6 },
  { symbol: "EURC", address: "0x60a3E35Cc302bFA44Cb288Bc5a4F316Fdb1adb42", decimals: 6 },
  { symbol: "DAI", address: "0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb", decimals: 18 },
  { symbol: "cbETH", address: "0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22", decimals: 18 },
  { symbol: "AERO", address: "0x940181a94A35A4569E4529A3CDfB74e38FD98631", decimals: 18 },
];
const ABI = parseAbi([
  "function balanceOf(address) view returns (uint256)",
  "function name() view returns (string)",
  "function symbol() view returns (string)",
  "function decimals() view returns (uint8)",
  "function totalSupply() view returns (uint256)",
  "function resolver(bytes32) view returns (address)",
  "function addr(bytes32) view returns (address)",
  "function name(bytes32) view returns (string)",
  "struct Call3 { address target; bool allowFailure; bytes callData; }",
  "struct Result { bool success; bytes returnData; }",
  "function aggregate3(Call3[] calls) payable returns (Result[] returnData)",
]);

export type BaseLookupInput = { address?: string; basename?: string; tokens: string[]; token?: string };

const isHexAddr = (s: string) => /^0x[0-9a-fA-F]{40}$/.test(s);
export function normalizeBasename(s: string): string | null {
  const n = s.trim().toLowerCase().replace(/\.$/, "");
  const m = n.match(/^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.base(?:\.eth)?$/);
  return m ? `${m[1]}.base.eth` : null;
}

export function parseBaseLookupInput(body: any): { item?: BaseLookupInput; error?: string } {
  if (body == null) body = {};
  if (typeof body !== "object" || Array.isArray(body)) return { error: 'Body must be JSON, e.g. {"address": "0x... or name.base.eth"}' };
  const out: BaseLookupInput = { tokens: [] };
  const who = body.address ?? body.wallet ?? body.name ?? body.basename;
  if (who !== undefined) {
    if (typeof who !== "string" || !who.trim()) return { error: "`address` must be a 0x address or a Basename like name.base.eth" };
    if (isHexAddr(who.trim())) out.address = getAddress(who.trim());
    else { const n = normalizeBasename(who); if (!n) return { error: "`address` must be a 0x address (40 hex chars) or a Basename like jesse.base.eth" }; out.basename = n; }
  }
  if (body.token !== undefined) {
    if (typeof body.token !== "string" || !isHexAddr(body.token.trim())) return { error: "`token` must be an ERC-20 contract address (0x + 40 hex)" };
    out.token = getAddress(body.token.trim());
  }
  if (body.tokens !== undefined) {
    if (!Array.isArray(body.tokens) || body.tokens.length > MAX_EXTRA_TOKENS) return { error: `\`tokens\` must be an array of up to ${MAX_EXTRA_TOKENS} ERC-20 addresses` };
    if (!out.address && !out.basename) return { error: "`tokens` needs `address` (whose balances to read)" };
    for (const t of body.tokens) { if (typeof t !== "string" || !isHexAddr(t.trim())) return { error: `Invalid token address in \`tokens\`: ${String(t).slice(0, 60)}` }; out.tokens.push(getAddress(t.trim())); }
    out.tokens = [...new Set(out.tokens)].filter((t) => !KNOWN_TOKENS.some((k) => k.address.toLowerCase() === t.toLowerCase()));
  }
  return { item: out };
}

type RpcReq = { method: string; params: unknown[] };
export type RpcFn = (reqs: RpcReq[]) => Promise<{ results: any[]; provider: string; errors?: string[] }>;

/** JSON-RPC batch with provider fallback. Results are returned in request order; per-item errors become null. */
export const defaultRpc = (ua: string): RpcFn => async (reqs) => {
  const errs: string[] = [];
  let lastErr = "rpc_error";
  const now = Date.now();
  const order = [...RPCS.filter((u) => (cooldown.get(u) ?? 0) <= now), ...RPCS.filter((u) => (cooldown.get(u) ?? 0) > now)];
  for (const url of order) {
    const fail = (msg: string) => { errs.push(lastErr = `${new URL(url).host}: ${msg}`); cooldown.set(url, Date.now() + 60_000); };
    try {
      const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json", "user-agent": ua }, body: JSON.stringify(reqs.map((q, i) => ({ jsonrpc: "2.0", id: i, ...q }))), signal: AbortSignal.timeout(4000) });
      if (!r.ok) { fail(`http_${r.status}`); continue; }
      const j: any = await r.json();
      if (!Array.isArray(j)) { fail(`not a batch response ${JSON.stringify(j).slice(0, 80)}`); continue; }
      const byId = new Map(j.map((x: any) => [Number(x.id), x]));
      const results = reqs.map((_, i) => { const x: any = byId.get(i); return x && x.result !== undefined && !x.error ? x.result : null; });
      if (results.every((x) => x === null) || results.filter((x) => x === null).length > reqs.length / 2) { fail(`calls failed ${JSON.stringify(j.find((x: any) => x.error)?.error ?? "").slice(0, 80)}`); continue; }
      return { results, provider: new URL(url).host, errors: errs };
    } catch (e: any) { fail(/timeout|abort/i.test(String(e?.message || e)) ? "timeout" : "fetch_error"); }
  }
  throw new Error(errs.join("; ") || lastErr);
};

const call = (to: string, data: Hex): RpcReq => ({ method: "eth_call", params: [{ to, data }, "latest"] });
const enc = (fn: string, args: unknown[] = []) => encodeFunctionData({ abi: ABI, functionName: fn as any, args: args as any });
function dec<T = any>(fn: string, data: string | null): T | null {
  if (!data || data === "0x") return null;
  try { return decodeFunctionResult({ abi: ABI, functionName: fn as any, data: data as Hex }) as T; } catch {}
  if ((fn === "name" || fn === "symbol") && data.length === 66) { try { return hexToString(data as Hex, { size: 32 }).replace(/\u0000+$/, "") as any; } catch {} }
  return null;
}
const big = (h: string | null) => (h && /^0x[0-9a-f]*$/i.test(h) ? BigInt(h === "0x" ? 0 : h) : null);
const gwei = (v: bigint | null) => (v == null ? null : Number(formatUnits(v, 9)));
const isZeroAddr = (a: string | null) => !a || /^0x0{40}$/i.test(a);

export async function baseLookup(input: BaseLookupInput, rpc: RpcFn) {
  const started = Date.now();
  const out: any = {};
  let provider = "";
  // 1) Basename -> address (registry.resolver(node) -> resolver.addr(node)).
  let address = input.address;
  if (input.basename) {
    const node = namehash(input.basename);
    const r1 = await rpc([call(BASE_REGISTRY, enc("resolver", [node]))]); provider = r1.provider;
    const resolver = dec<string>("resolver", r1.results[0]);
    if (isZeroAddr(resolver)) return { status: 404, body: { error: `Basename ${input.basename} is not registered or has no resolver; not charged.`, basename: input.basename } };
    const r2 = await rpc([call(resolver!, enc("addr", [node]))]);
    const a = dec<string>("addr", r2.results[0]);
    if (isZeroAddr(a)) return { status: 404, body: { error: `Basename ${input.basename} does not point to an address; not charged.`, basename: input.basename } };
    address = getAddress(a!);
  }
  // 2) One batch for chain status + wallet + token info.
  const reqs: RpcReq[] = [
    { method: "eth_chainId", params: [] },
    { method: "eth_getBlockByNumber", params: ["latest", false] },
    { method: "eth_gasPrice", params: [] },
    { method: "eth_maxPriorityFeePerGas", params: [] },
  ];
  const idx: Record<string, number> = {};
  // eth_calls are bundled into ONE Multicall3.aggregate3 call (allowFailure) so the JSON-RPC batch stays small.
  const mc: { key: string; target: string; callData: Hex }[] = [];
  const add = (key: string, q: RpcReq) => {
    if (q.method === "eth_call") { const p = q.params[0] as { to: string; data: Hex }; mc.push({ key, target: p.to, callData: p.data }); return; }
    idx[key] = reqs.length; reqs.push(q);
  };
  let reverseNode: Hex | null = null;
  if (address) {
    add("balance", { method: "eth_getBalance", params: [address, "latest"] });
    add("nonce", { method: "eth_getTransactionCount", params: [address, "latest"] });
    add("code", { method: "eth_getCode", params: [address, "latest"] });
    for (const t of KNOWN_TOKENS) add(`bal:${t.address}`, call(t.address, enc("balanceOf", [address])));
    for (const t of input.tokens) {
      add(`bal:${t}`, call(t, enc("balanceOf", [address])));
      add(`sym:${t}`, call(t, enc("symbol"))); add(`dec:${t}`, call(t, enc("decimals")));
    }
    reverseNode = namehash(`${address.slice(2).toLowerCase()}.80002105.reverse`);
    add("revres", call(BASE_REGISTRY, enc("resolver", [reverseNode])));
  }
  if (input.token) {
    for (const f of ["name", "symbol", "decimals", "totalSupply"]) add(`t:${f}`, call(input.token, enc(f)));
    add("t:code", { method: "eth_getCode", params: [input.token, "latest"] });
  }
  let mcIndex = -1;
  if (mc.length) { mcIndex = reqs.length; reqs.push(call(MULTICALL3, encodeFunctionData({ abi: ABI, functionName: "aggregate3", args: [mc.map((x) => ({ target: x.target as Hex, allowFailure: true, callData: x.callData }))] }))); }
  const res = await rpc(reqs); provider = res.provider;
  if (res.errors?.length) out.rpc_fallbacks = res.errors;
  const mcOut: Record<string, string | null> = {};
  if (mcIndex >= 0) {
    const raw = res.results[mcIndex];
    if (!raw) throw new Error("multicall failed");
    const decoded = decodeFunctionResult({ abi: ABI, functionName: "aggregate3", data: raw as Hex }) as readonly { success: boolean; returnData: Hex }[];
    mc.forEach((x, i) => { const d = decoded[i]; mcOut[x.key] = d && d.success && d.returnData !== "0x" ? d.returnData : null; });
  }
  const R = (k: string) => (k in mcOut ? mcOut[k] : res.results[idx[k]] ?? null);
  const [chainId, block, gasPrice, prio] = res.results;
  if (chainId && Number(chainId) !== 8453) throw new Error(`unexpected chain id ${chainId}`);
  const baseFee = big(block?.baseFeePerGas ?? null), gp = big(gasPrice), pf = big(prio);
  const ts = block?.timestamp ? Number(block.timestamp) : null;
  const gasUsed = big(block?.gasUsed ?? null), gasLimit = big(block?.gasLimit ?? null);
  out.chain = {
    chain_id: 8453, name: "Base",
    block_number: block?.number ? Number(block.number) : null,
    block_time: ts ? new Date(ts * 1000).toISOString() : null,
    block_age_seconds: ts ? Math.max(0, Math.round(Date.now() / 1000 - ts)) : null,
    base_fee_gwei: gwei(baseFee), gas_price_gwei: gwei(gp), priority_fee_gwei: gwei(pf),
    block_gas_used_pct: gasUsed != null && gasLimit ? Number((gasUsed * 10000n) / gasLimit) / 100 : null,
    est_cost_eth: gp != null ? { eth_transfer: formatUnits(gp * 21000n, 18), erc20_transfer: formatUnits(gp * 65000n, 18), swap: formatUnits(gp * 180000n, 18) } : null,
    note: "Estimated L2 execution cost only; Base also adds a small L1 data fee.",
  };
  if (address) {
    const code = R("code");
    const tokens: any[] = [];
    for (const t of KNOWN_TOKENS) {
      const raw = dec<bigint>("balanceOf", R(`bal:${t.address}`));
      if (raw == null) continue;
      tokens.push({ symbol: t.symbol, address: t.address, decimals: t.decimals, balance: formatUnits(raw, t.decimals), balance_raw: raw.toString() });
    }
    for (const t of input.tokens) {
      const raw = dec<bigint>("balanceOf", R(`bal:${t}`));
      const d = dec<number>("decimals", R(`dec:${t}`));
      const sym = dec<string>("symbol", R(`sym:${t}`));
      tokens.push(raw == null ? { address: t, error: "not an ERC-20 or call failed" } : { symbol: sym, address: t, decimals: d, balance: d != null ? formatUnits(raw, Number(d)) : null, balance_raw: raw.toString() });
    }
    tokens.sort((x, y) => (y.balance_raw && y.balance_raw !== "0" ? 1 : 0) - (x.balance_raw && x.balance_raw !== "0" ? 1 : 0));
    // Reverse (primary) Basename: only reported if it resolves forward to the same address.
    let primary: string | null = null;
    const revResolver = dec<string>("resolver", R("revres"));
    if (!isZeroAddr(revResolver) && reverseNode) {
      try {
        const r3 = await rpc([call(revResolver!, enc("name", [reverseNode]))]);
        const nm = dec<string>("name", r3.results[0]);
        if (nm && /\.base\.eth$/.test(nm)) {
          const fnode = namehash(nm);
          const r4 = await rpc([call(BASE_REGISTRY, enc("resolver", [fnode]))]);
          const fres = dec<string>("resolver", r4.results[0]);
          if (!isZeroAddr(fres)) {
            const r5 = await rpc([call(fres!, enc("addr", [fnode]))]);
            const fa = dec<string>("addr", r5.results[0]);
            if (fa && fa.toLowerCase() === address.toLowerCase()) primary = nm;
          }
        }
      } catch {}
    }
    const eth = big(R("balance"));
    out.wallet = {
      address, input: input.basename ?? input.address, resolved_from_basename: input.basename ?? null, primary_basename: primary,
      is_contract: code ? code !== "0x" : null,
      tx_count: R("nonce") != null ? Number(R("nonce")) : null,
      eth: eth != null ? formatUnits(eth, 18) : null, eth_wei: eth?.toString() ?? null,
      tokens, tokens_checked: tokens.length,
      explorer: `https://basescan.org/address/${address}`,
    };
  }
  if (input.token) {
    const d = dec<number>("decimals", R("t:decimals"));
    const ts2 = dec<bigint>("totalSupply", R("t:totalSupply"));
    const code = R("t:code");
    const nm = dec<string>("name", R("t:name")), sym = dec<string>("symbol", R("t:symbol"));
    out.token = {
      address: input.token, is_contract: code ? code !== "0x" : null,
      looks_like_erc20: d != null && ts2 != null && !!sym,
      name: nm, symbol: sym, decimals: d != null ? Number(d) : null,
      total_supply: ts2 != null && d != null ? formatUnits(ts2, Number(d)) : null, total_supply_raw: ts2?.toString() ?? null,
      known: KNOWN_TOKENS.find((k) => k.address.toLowerCase() === input.token!.toLowerCase())?.symbol ?? null,
      explorer: `https://basescan.org/token/${input.token}`,
    };
  }
  out.rpc_provider = provider;
  if (!out.rpc_fallbacks) delete out.rpc_fallbacks;
  out.fetched_at = new Date().toISOString();
  out.elapsed_ms = Date.now() - started;
  out.note = "Read-only public chain data. No prices or investment advice.";
  return { status: 200, body: out };
}
