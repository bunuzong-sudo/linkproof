// Shared public-URL checks and a size-capped fetch that follows redirects safely.
// Workers already refuse connections to private IPs after DNS; this also blocks
// obvious private/loopback hosts and non-http schemes before any request is made.

export const DEFAULT_TIMEOUT_MS = 8000;
export const MAX_REDIRECTS = 8;

export function parsePublicHttpUrl(input: string, opts?: { allowDomainOnly?: boolean }): { href?: string; url?: URL; error?: string } {
  if (typeof input !== "string" || !input.trim()) return { error: "URL must be a non-empty string" };
  let raw = input.trim();
  if (opts?.allowDomainOnly && !/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(raw)) raw = "https://" + raw;
  let u: URL;
  try { u = new URL(raw); } catch { return { error: `Invalid URL: ${String(input).slice(0, 200)}` }; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return { error: `Only http(s) URLs: ${input}` };
  if (u.username || u.password) return { error: "URLs with credentials are not allowed" };
  if (isBlockedHost(u.hostname)) return { error: `Private, loopback or non-public hosts are not allowed: ${u.hostname}` };
  return { href: u.href, url: u };
}

export function isBlockedHost(hostname: string): boolean {
  const h = String(hostname || "").trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (!h) return true;
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h === "host.docker.internal") return true;
  if (h === "metadata.google.internal" || h.endsWith(".internal")) return true;
  if (h === "0.0.0.0" || h === "::" || h === "::1" || h === "0" || h === "0:0:0:0:0:0:0:0" || h === "0:0:0:0:0:0:0:1") return true;

  const v4mapped = h.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (v4mapped) return isPrivateIPv4(v4mapped[1]) ?? true;
  const v4hex = h.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (v4hex) {
    const a = parseInt(v4hex[1], 16), b = parseInt(v4hex[2], 16);
    return isPrivateIPv4(`${(a >> 8) & 255}.${a & 255}.${(b >> 8) & 255}.${b & 255}`) ?? true;
  }
  if (h.includes(":")) return isPrivateIPv6(h);

  const v4 = isPrivateIPv4(h);
  if (v4 !== null) return v4;
  if (looksLikeNonstandardIp(h)) return true;
  return false;
}

/** true/false if dotted IPv4, else null */
export function isPrivateIPv4(host: string): boolean | null {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const nums: number[] = [];
  for (const p of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    nums.push(n);
  }
  const [a, b] = nums;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a >= 224) return true;
  return false;
}

function looksLikeNonstandardIp(host: string): boolean {
  if (/^0x[0-9a-f]+$/i.test(host)) return true;
  if (/^\d+$/.test(host)) {
    const n = Number(host);
    if (Number.isSafeInteger(n) && n >= 0 && n <= 0xffffffff) return true;
  }
  if (/^0[0-7]+(\.0*[0-7]+)*$/.test(host)) return true;
  if (/^(\d{1,3}\.){1,2}\d{1,3}$/.test(host)) return true;
  return false;
}

function isPrivateIPv6(h: string): boolean {
  if (h === "::" || h === "::1") return true;
  // link-local fe80::/10, unique-local fc00::/7, multicast ff00::/8, unspecified
  if (/^fe[89ab]/i.test(h) || /^f[cd]/i.test(h) || /^ff/i.test(h)) return true;
  return false;
}

export type RedirectHop = { url: string; status: number; location?: string };
export type SafeFetchResult = {
  ok: boolean;
  error?: string;
  status: number | null;
  url: string;
  requested_url: string;
  redirected: boolean;
  redirect_chain: RedirectHop[];
  headers: Headers;
  content_type: string | null;
  body: string;
  body_bytes: number;
  truncated: boolean;
  method: string;
  /** Raw (undecoded, capped) body bytes; only when opts.raw is set. */
  raw?: Uint8Array;
};

export async function readCapped(res: Response, cap: number): Promise<{ text: string; bytes: number; truncated: boolean; buf?: Uint8Array }> {
  if (!res.body || cap <= 0) {
    try { await res.body?.cancel(); } catch {}
    return { text: "", bytes: 0, truncated: false };
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  while (total < cap) {
    const { done, value } = await reader.read();
    if (done || !value) break;
    chunks.push(value);
    total += value.byteLength;
  }
  if (total >= cap) truncated = true;
  try { await reader.cancel(); } catch {}
  const buf = new Uint8Array(Math.min(total, cap));
  let off = 0;
  for (const c of chunks) {
    const n = Math.min(c.byteLength, buf.length - off);
    buf.set(c.subarray(0, n), off);
    off += n;
    if (off >= buf.length) break;
  }
  return { text: new TextDecoder("utf-8", { fatal: false }).decode(buf), bytes: total, truncated, buf };
}

export async function safeFetch(
  input: string,
  opts: { method?: string; headers?: Record<string, string>; timeoutMs?: number; maxRedirects?: number; maxBytes?: number; raw?: boolean } = {},
): Promise<SafeFetchResult> {
  const method = (opts.method || "GET").toUpperCase();
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxRedirects = opts.maxRedirects ?? MAX_REDIRECTS;
  const maxBytes = opts.maxBytes ?? 0;
  const parsed = parsePublicHttpUrl(input);
  const base: SafeFetchResult = {
    ok: false, status: null, url: parsed.href || input, requested_url: input,
    redirected: false, redirect_chain: [], headers: new Headers(), content_type: null,
    body: "", body_bytes: 0, truncated: false, method,
  };
  if (parsed.error || !parsed.href) return { ...base, error: parsed.error || "Invalid URL" };

  let current = parsed.href;
  const chain: RedirectHop[] = [];
  try {
    for (let hop = 0; hop <= maxRedirects; hop++) {
      const res = await fetch(current, {
        method,
        redirect: "manual",
        headers: opts.headers,
        signal: AbortSignal.timeout(timeoutMs),
      });
      const loc = res.headers.get("location") || undefined;
      const isRedirect = res.status >= 301 && res.status <= 308 && !!loc && res.status !== 304;
      chain.push({ url: current, status: res.status, location: loc });
      if (isRedirect) {
        try { await res.body?.cancel(); } catch {}
        if (hop === maxRedirects) return { ...base, error: "too_many_redirects", redirect_chain: chain, url: current, status: res.status };
        let next: URL;
        try { next = new URL(loc!, current); } catch {
          return { ...base, error: `Invalid redirect Location: ${String(loc).slice(0, 200)}`, redirect_chain: chain, url: current, status: res.status };
        }
        const ok = parsePublicHttpUrl(next.href);
        if (ok.error || !ok.href) {
          return { ...base, error: `Redirect blocked: ${ok.error || "invalid URL"}`, redirect_chain: chain, url: current, status: res.status };
        }
        current = ok.href;
        continue;
      }
      const cap = method === "HEAD" ? 0 : maxBytes;
      const body = await readCapped(res, cap);
      const ct = res.headers.get("content-type");
      return {
        ok: res.status >= 200 && res.status < 400,
        status: res.status,
        url: current,
        requested_url: input,
        redirected: chain.length > 1 || current !== parsed.href,
        redirect_chain: chain,
        headers: res.headers,
        content_type: ct,
        body: body.text,
        body_bytes: body.bytes,
        truncated: body.truncated,
        method,
        ...(opts.raw ? { raw: body.buf ?? new Uint8Array(0) } : {}),
      };
    }
    return { ...base, error: "too_many_redirects", redirect_chain: chain, url: current };
  } catch (e: any) {
    const msg = String(e?.message || e);
    const error = /timeout|abort/i.test(msg) ? "timeout" : /dns|resolve|ENOTFOUND|not found/i.test(msg) ? "dns_error" : msg.slice(0, 200);
    return { ...base, error, redirect_chain: chain, url: current };
  }
}
