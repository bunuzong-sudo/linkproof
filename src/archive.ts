// Closest Wayback Machine snapshot lookup (Internet Archive availability API, CDX fallback).
export const MAX_ARCHIVE_URLS = 10;
const TIMEOUT_MS = 9000;
export type ArchiveInput = { url: string; date?: string };

function toTs(d: string | undefined): string | undefined {
  if (!d) return undefined;
  const m = String(d).match(/^(\d{4})(?:-?(\d{2}))?(?:-?(\d{2}))?/);
  return m ? `${m[1]}${m[2] || "01"}${m[3] || "01"}` : undefined;
}
function tsIso(ts: string) { return `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}T${ts.slice(8, 10) || "00"}:${ts.slice(10, 12) || "00"}:${ts.slice(12, 14) || "00"}Z`; }

export function parseArchive(body: any): { items?: ArchiveInput[]; error?: string } {
  if (!body || typeof body !== "object") return { error: 'Body must be JSON: {"urls": ["https://..."]}' };
  const raw = body.urls;
  if (!Array.isArray(raw) || raw.length === 0) return { error: "`urls` must be a non-empty array" };
  if (raw.length > MAX_ARCHIVE_URLS) return { error: `At most ${MAX_ARCHIVE_URLS} URLs per call` };
  if (body.date !== undefined && !toTs(body.date)) return { error: "`date` must be YYYY, YYYY-MM or YYYY-MM-DD" };
  const items: ArchiveInput[] = [];
  for (const r of raw) {
    const it: ArchiveInput = typeof r === "string" ? { url: r, date: body.date } : { url: r?.url, date: r?.date ?? body.date };
    if (typeof it.url !== "string") return { error: "Each entry must be a URL string or {url, date}" };
    let u: URL; try { u = new URL(it.url); } catch { return { error: `Invalid URL: ${String(it.url).slice(0, 200)}` }; }
    if (u.protocol !== "http:" && u.protocol !== "https:") return { error: `Only http(s) URLs: ${it.url}` };
    if (u.username || u.password) return { error: "URLs with credentials are not allowed" };
    if (it.date !== undefined && !toTs(it.date)) return { error: "`date` must be YYYY, YYYY-MM or YYYY-MM-DD" };
    items.push(it);
  }
  return { items };
}

export async function findArchive(it: ArchiveInput, ua: string) {
  const started = Date.now();
  const ts = toTs(it.date);
  const out: Record<string, unknown> = { url: it.url, requested_date: it.date ?? null };
  try {
    let snap: { url: string; timestamp: string; status: string } | null = null;
    let via = "availability";
    const av = await fetch(`https://archive.org/wayback/available?url=${encodeURIComponent(it.url)}${ts ? `&timestamp=${ts}` : ""}`, { headers: { "user-agent": ua }, signal: AbortSignal.timeout(TIMEOUT_MS) }).catch(() => null);
    if (av?.ok) {
      const j: any = await av.json().catch(() => null);
      const c = j?.archived_snapshots?.closest;
      if (c?.available && c.url) snap = { url: String(c.url).replace(/^http:/, "https:"), timestamp: c.timestamp, status: c.status };
    }
    if (!snap) {
      via = "cdx";
      const q = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(it.url)}&output=json&fl=timestamp,original,statuscode&filter=statuscode:[23]..&limit=${ts ? 1 : -1}${ts ? `&closest=${ts}&sort=closest` : ""}`;
      const r = await fetch(q, { headers: { "user-agent": ua }, signal: AbortSignal.timeout(TIMEOUT_MS) });
      if (!r.ok) throw new Error(`wayback cdx HTTP ${r.status}`);
      const rows: any[] = await r.json<any>().catch(() => []);
      const row = rows?.[1];
      if (row) snap = { url: `https://web.archive.org/web/${row[0]}/${row[1]}`, timestamp: row[0], status: row[2] };
    }
    if (snap) {
      out.found = true; out.snapshot_url = snap.url; out.timestamp = snap.timestamp; out.captured_at = tsIso(snap.timestamp);
      out.snapshot_status = snap.status ? Number(snap.status) : null; out.lookup = via;
      if (ts) out.days_from_requested = Math.round(Math.abs(Date.parse(tsIso(snap.timestamp)) - Date.parse(tsIso(ts))) / 86400000);
    } else { out.found = false; out.lookup = via; }
  } catch (e: any) {
    const msg = String(e?.message || e);
    out.found = null; out.error = /timeout|abort/i.test(msg) ? "upstream_timeout" : msg.slice(0, 200);
  }
  out.elapsed_ms = Date.now() - started;
  return out;
}
