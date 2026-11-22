// Parse iCalendar (ICS) text or a public .ics URL. VEVENT fields, timezone
// normalized to UTC/ISO, RRULE expanded for a bounded window. Data is not stored.

import { parsePublicHttpUrl, safeFetch } from "./urlguard";

export const PRICE_ICS = "0.003";
export const MAX_ICS_BYTES = 100 * 1024;
export const MAX_OCCURRENCES = 50;
export const DEFAULT_WINDOW_DAYS = 730;

export type IcsInput = { text?: string; url?: string; from?: Date; to?: Date; max_occurrences: number };

export function parseIcsInput(body: any): { item?: IcsInput; error?: string } {
  if (!body || typeof body !== "object") return { error: 'Body must be JSON: {"ics": "BEGIN:VCALENDAR…"} or {"url": "https://…/calendar.ics"}' };
  const text = body.ics != null ? body.ics : body.text;
  const url = body.url;
  if (text != null && typeof text !== "string") return { error: "`ics` / `text` must be a string" };
  if (url != null && typeof url !== "string") return { error: "`url` must be a string" };
  if (!text && !url) return { error: "Provide `ics` text or a public `url` to an .ics file" };
  if (text && new TextEncoder().encode(text).length > MAX_ICS_BYTES) {
    return { error: `ics text exceeds the ${MAX_ICS_BYTES} byte cap` };
  }
  let from: Date | undefined;
  let to: Date | undefined;
  if (body.from != null) {
    from = new Date(body.from);
    if (Number.isNaN(from.getTime())) return { error: "`from` must be an ISO date/time" };
  }
  if (body.to != null) {
    to = new Date(body.to);
    if (Number.isNaN(to.getTime())) return { error: "`to` must be an ISO date/time" };
  }
  let max = MAX_OCCURRENCES;
  if (body.max_occurrences != null) {
    const n = Number(body.max_occurrences);
    if (!Number.isInteger(n) || n < 1) return { error: "`max_occurrences` must be a positive integer" };
    max = Math.min(MAX_OCCURRENCES, n);
  }
  if (url) {
    const p = parsePublicHttpUrl(url);
    if (p.error || !p.href) return { error: p.error || "Invalid URL" };
    return { item: { text: text || undefined, url: p.href, from, to, max_occurrences: max } };
  }
  return { item: { text, from, to, max_occurrences: max } };
}

export function unfoldIcs(text: string): string[] {
  const raw = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  const lines: string[] = [];
  for (const line of raw) {
    if ((line.startsWith(" ") || line.startsWith("\t")) && lines.length) {
      lines[lines.length - 1] += line.slice(1);
    } else {
      lines.push(line);
    }
  }
  return lines.filter((l) => l.length > 0);
}

export type IcsProp = { name: string; params: Record<string, string>; value: string };

export function parseIcsLine(line: string): IcsProp | null {
  const colon = line.indexOf(":");
  if (colon < 1) return null;
  const left = line.slice(0, colon);
  const value = line.slice(colon + 1);
  const parts = splitUnescaped(left, ";");
  const name = parts[0].toUpperCase();
  const params: Record<string, string> = {};
  for (const p of parts.slice(1)) {
    const eq = p.indexOf("=");
    if (eq < 1) continue;
    params[p.slice(0, eq).toUpperCase()] = p.slice(eq + 1);
  }
  return { name, params, value };
}

function splitUnescaped(s: string, sep: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '"') { quoted = !quoted; cur += c; continue; }
    if (!quoted && c === sep) { out.push(cur); cur = ""; continue; }
    cur += c;
  }
  out.push(cur);
  return out;
}

export function unescapeIcsText(value: string): string {
  return value
    .replace(/\\n/gi, "\n")
    .replace(/\\,/g, ",")
    .replace(/\\;/g, ";")
    .replace(/\\\\/g, "\\");
}

export type IcsBlock = { type: string; props: IcsProp[]; children: IcsBlock[] };

export function parseIcsBlocks(lines: string[]): IcsBlock[] {
  const root: IcsBlock = { type: "ROOT", props: [], children: [] };
  const stack: IcsBlock[] = [root];
  for (const line of lines) {
    const p = parseIcsLine(line);
    if (!p) continue;
    if (p.name === "BEGIN") {
      const child: IcsBlock = { type: p.value.toUpperCase(), props: [], children: [] };
      stack[stack.length - 1].children.push(child);
      stack.push(child);
    } else if (p.name === "END") {
      if (stack.length > 1) stack.pop();
    } else {
      stack[stack.length - 1].props.push(p);
    }
  }
  return root.children;
}

function prop(block: IcsBlock, name: string): IcsProp | undefined {
  return block.props.find((p) => p.name === name);
}

export type ParsedDate = {
  instant: Date | null;
  iso: string | null;
  all_day: boolean;
  tzid: string | null;
  floating: boolean;
  raw: string;
};

/** Convert a wall-clock time in an IANA zone to a UTC Date using Intl. */
export function zonedLocalToUtc(y: number, mo: number, d: number, h: number, mi: number, s: number, timeZone: string): Date {
  const wall = Date.UTC(y, mo - 1, d, h, mi, s);
  const fmt = new Intl.DateTimeFormat("en-US", {
    timeZone,
    hour12: false,
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
  const asLocal = (ms: number) => {
    const parts: Record<string, string> = {};
    for (const p of fmt.formatToParts(new Date(ms))) if (p.type !== "literal") parts[p.type] = p.value;
    let hour = Number(parts.hour);
    if (hour === 24) hour = 0;
    return Date.UTC(Number(parts.year), Number(parts.month) - 1, Number(parts.day), hour, Number(parts.minute), Number(parts.second));
  };
  let instant = wall - (asLocal(wall) - wall);
  instant = wall - (asLocal(instant) - instant);
  return new Date(instant);
}

export function parseIcsDate(raw: string, params: Record<string, string> = {}): ParsedDate {
  const v = raw.trim();
  const valueParam = (params.VALUE || "").toUpperCase();
  const tzid = params.TZID ? params.TZID.replace(/^"|"$/g, "") : null;
  const dateOnly = valueParam === "DATE" || (/^\d{8}$/.test(v) && !v.includes("T"));
  const m = v.match(/^(\d{4})(\d{2})(\d{2})(?:T(\d{2})(\d{2})(\d{2})(Z)?)?$/);
  if (!m) return { instant: null, iso: null, all_day: dateOnly, tzid, floating: !tzid && !v.endsWith("Z"), raw: v };
  const y = Number(m[1]), mo = Number(m[2]), d = Number(m[3]);
  const h = Number(m[4] || "0"), mi = Number(m[5] || "0"), s = Number(m[6] || "0");
  const z = !!m[7] || /z$/i.test(v);
  if (dateOnly) {
    const iso = `${m[1]}-${m[2]}-${m[3]}`;
    return { instant: new Date(Date.UTC(y, mo - 1, d, 0, 0, 0)), iso, all_day: true, tzid: tzid, floating: !tzid && !z, raw: v };
  }
  if (z) {
    const inst = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
    return { instant: inst, iso: inst.toISOString(), all_day: false, tzid: "UTC", floating: false, raw: v };
  }
  if (tzid) {
    try {
      const inst = zonedLocalToUtc(y, mo, d, h, mi, s, tzid);
      if (!Number.isNaN(inst.getTime())) {
        return { instant: inst, iso: inst.toISOString(), all_day: false, tzid, floating: false, raw: v };
      }
    } catch {}
  }
  // Floating (no zone): report the wall time as an ISO-like local timestamp without Z.
  const iso = `${m[1]}-${m[2]}-${m[3]}T${String(h).padStart(2, "0")}:${String(mi).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  const inst = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
  return { instant: inst, iso, all_day: false, tzid: tzid, floating: true, raw: v };
}

function addDuration(start: Date, duration: string): Date | null {
  const m = duration.trim().match(/^P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/i);
  if (!m) return null;
  const ms =
    Number(m[1] || 0) * 7 * 86400000 +
    Number(m[2] || 0) * 86400000 +
    Number(m[3] || 0) * 3600000 +
    Number(m[4] || 0) * 60000 +
    Number(m[5] || 0) * 1000;
  return new Date(start.getTime() + ms);
}

const DOW: Record<string, number> = { SU: 0, MO: 1, TU: 2, WE: 3, TH: 4, FR: 5, SA: 6 };

export type RRule = {
  freq: "DAILY" | "WEEKLY" | "MONTHLY" | "YEARLY";
  interval: number;
  count?: number;
  until?: Date;
  byday?: { nth: number | null; dow: number }[];
  bymonthday?: number[];
  bymonth?: number[];
  wkst: number;
};

export function parseRRule(value: string): RRule | null {
  const parts: Record<string, string> = {};
  for (const p of value.split(";")) {
    const eq = p.indexOf("=");
    if (eq < 1) continue;
    parts[p.slice(0, eq).toUpperCase()] = p.slice(eq + 1);
  }
  const freq = (parts.FREQ || "").toUpperCase();
  if (!["DAILY", "WEEKLY", "MONTHLY", "YEARLY"].includes(freq)) return null;
  const interval = Math.max(1, Number(parts.INTERVAL || "1") || 1);
  const count = parts.COUNT ? Number(parts.COUNT) : undefined;
  let until: Date | undefined;
  if (parts.UNTIL) {
    const d = parseIcsDate(parts.UNTIL, parts.UNTIL.length === 8 ? { VALUE: "DATE" } : {});
    if (d.instant) until = d.instant;
  }
  const byday = parts.BYDAY
    ? parts.BYDAY.split(",").map((tok) => {
        const m = tok.trim().toUpperCase().match(/^([+-]?\d+)?(SU|MO|TU|WE|TH|FR|SA)$/);
        if (!m) return null;
        return { nth: m[1] ? Number(m[1]) : null, dow: DOW[m[2]] };
      }).filter((x): x is { nth: number | null; dow: number } => !!x)
    : undefined;
  const bymonthday = parts.BYMONTHDAY ? parts.BYMONTHDAY.split(",").map(Number).filter((n) => Number.isFinite(n)) : undefined;
  const bymonth = parts.BYMONTH ? parts.BYMONTH.split(",").map(Number).filter((n) => Number.isFinite(n)) : undefined;
  const wkst = parts.WKST && DOW[parts.WKST.toUpperCase()] != null ? DOW[parts.WKST.toUpperCase()] : 1;
  return { freq: freq as RRule["freq"], interval, count, until, byday, bymonthday, bymonth, wkst };
}

function ymd(d: Date): { y: number; m: number; d: number } {
  return { y: d.getUTCFullYear(), m: d.getUTCMonth() + 1, d: d.getUTCDate() };
}

function utcDate(y: number, m: number, d: number, h = 0, mi = 0, s = 0): Date {
  return new Date(Date.UTC(y, m - 1, d, h, mi, s));
}

function daysInMonth(y: number, m: number): number {
  return new Date(Date.UTC(y, m, 0)).getUTCDate();
}

function nthWeekdayOfMonth(y: number, m: number, dow: number, nth: number): Date | null {
  if (nth > 0) {
    const first = utcDate(y, m, 1);
    const shift = (dow - first.getUTCDay() + 7) % 7;
    const day = 1 + shift + (nth - 1) * 7;
    if (day > daysInMonth(y, m)) return null;
    return utcDate(y, m, day);
  }
  // negative: last, 2nd last, ...
  const last = daysInMonth(y, m);
  const lastD = utcDate(y, m, last);
  const shift = (lastD.getUTCDay() - dow + 7) % 7;
  const day = last - shift + (nth + 1) * 7;
  if (day < 1) return null;
  return utcDate(y, m, day);
}

function matchesByDay(date: Date, byday?: RRule["byday"]): boolean {
  if (!byday || !byday.length) return true;
  const dow = date.getUTCDay();
  const { y, m, d } = ymd(date);
  for (const b of byday) {
    if (b.dow !== dow) continue;
    if (b.nth == null) return true;
    const target = nthWeekdayOfMonth(y, m, b.dow, b.nth);
    if (target && target.getUTCDate() === d) return true;
  }
  return false;
}

function matchesMonthDay(date: Date, bymonthday?: number[]): boolean {
  if (!bymonthday || !bymonthday.length) return true;
  const dim = daysInMonth(date.getUTCFullYear(), date.getUTCMonth() + 1);
  const d = date.getUTCDate();
  return bymonthday.some((n) => (n > 0 ? n === d : dim + n + 1 === d));
}

export function expandRRule(
  dtstart: Date,
  rule: RRule,
  opts: { from: Date; to: Date; max: number; exdates: Set<number> },
): Date[] {
  const out: Date[] = [];
  const h = dtstart.getUTCHours(), mi = dtstart.getUTCMinutes(), s = dtstart.getUTCSeconds();
  const stamp = (d: Date) => utcDate(d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate(), h, mi, s);

  const push = (d: Date) => {
    const inst = stamp(d);
    if (inst < opts.from || inst > opts.to) return;
    if (rule.until && inst > rule.until) return;
    if (opts.exdates.has(inst.getTime())) return;
    if (out.some((x) => x.getTime() === inst.getTime())) return;
    out.push(inst);
  };

  // Count includes DTSTART if it matches, and stops after `count` occurrences from DTSTART (not from `from`).
  let produced = 0;
  const consider = (d: Date) => {
    const inst = stamp(d);
    if (rule.until && inst > rule.until) return false;
    if (inst < dtstart) return true;
    if (rule.freq === "WEEKLY" && !matchesByDay(inst, rule.byday)) return true;
    if ((rule.freq === "MONTHLY" || rule.freq === "YEARLY") && rule.byday && !matchesByDay(inst, rule.byday)) return true;
    if (rule.bymonthday && !matchesMonthDay(inst, rule.bymonthday)) return true;
    if (rule.bymonth && !rule.bymonth.includes(inst.getUTCMonth() + 1)) return true;
    produced++;
    if (inst >= opts.from && inst <= opts.to && !opts.exdates.has(inst.getTime())) {
      if (!out.some((x) => x.getTime() === inst.getTime())) out.push(inst);
    }
    if (rule.count && produced >= rule.count) return false;
    if (out.length >= opts.max && inst >= opts.from) {
      // keep generating only if we still need count to stop correctly... if no count, we can stop
      if (!rule.count) return false;
    }
    return !(rule.count && produced >= rule.count);
  };

  const maxLoops = 20000;
  let loops = 0;
  if (rule.freq === "DAILY") {
    let cur = new Date(dtstart.getTime());
    while (loops++ < maxLoops) {
      if (!consider(cur)) break;
      cur = new Date(cur.getTime() + rule.interval * 86400000);
      if (cur > opts.to && (!rule.count || produced >= (rule.count || 0))) break;
      if (rule.until && cur > rule.until) break;
    }
  } else if (rule.freq === "WEEKLY") {
    const days = (rule.byday && rule.byday.length) ? [...new Set(rule.byday.map((b) => b.dow))] : [dtstart.getUTCDay()];
    // start at beginning of the week that contains DTSTART (wkst)
    let weekStart = new Date(dtstart.getTime());
    const back = (weekStart.getUTCDay() - rule.wkst + 7) % 7;
    weekStart = new Date(weekStart.getTime() - back * 86400000);
    while (loops++ < maxLoops) {
      for (const dow of days) {
        const d = new Date(weekStart.getTime() + ((dow - rule.wkst + 7) % 7) * 86400000);
        if (!consider(d)) { loops = maxLoops + 1; break; }
      }
      weekStart = new Date(weekStart.getTime() + rule.interval * 7 * 86400000);
      if (weekStart > opts.to && (!rule.count || produced >= (rule.count || 0))) break;
      if (rule.until && weekStart > rule.until) break;
    }
  } else if (rule.freq === "MONTHLY") {
    let y = dtstart.getUTCFullYear();
    let m = dtstart.getUTCMonth() + 1;
    while (loops++ < maxLoops) {
      if (rule.byday && rule.byday.some((b) => b.nth != null)) {
        for (const b of rule.byday) {
          const nth = b.nth == null ? 1 : b.nth;
          const day = nthWeekdayOfMonth(y, m, b.dow, nth);
          if (day && !consider(day)) { loops = maxLoops + 1; break; }
        }
      } else if (rule.bymonthday && rule.bymonthday.length) {
        for (const md of rule.bymonthday) {
          const dim = daysInMonth(y, m);
          const d = md > 0 ? md : dim + md + 1;
          if (d >= 1 && d <= dim && !consider(utcDate(y, m, d))) { loops = maxLoops + 1; break; }
        }
      } else {
        const dim = daysInMonth(y, m);
        const d = Math.min(dtstart.getUTCDate(), dim);
        if (!consider(utcDate(y, m, d))) break;
      }
      m += rule.interval;
      while (m > 12) { m -= 12; y++; }
      const monthStart = utcDate(y, m, 1, h, mi, s);
      if (monthStart > opts.to && (!rule.count || produced >= (rule.count || 0))) break;
      if (rule.until && monthStart > rule.until) break;
    }
  } else if (rule.freq === "YEARLY") {
    let y = dtstart.getUTCFullYear();
    const months = rule.bymonth && rule.bymonth.length ? rule.bymonth : [dtstart.getUTCMonth() + 1];
    while (loops++ < maxLoops) {
      for (const m of months) {
        if (rule.byday && rule.byday.some((b) => b.nth != null)) {
          for (const b of rule.byday) {
            const nth = b.nth == null ? 1 : b.nth;
            const day = nthWeekdayOfMonth(y, m, b.dow, nth);
            if (day && !consider(day)) { loops = maxLoops + 1; break; }
          }
        } else {
          const dim = daysInMonth(y, m);
          const d = Math.min(dtstart.getUTCDate(), dim);
          if (!consider(utcDate(y, m, d))) { loops = maxLoops + 1; break; }
        }
      }
      y += rule.interval;
      const yearStart = utcDate(y, 1, 1, h, mi, s);
      if (yearStart > opts.to && (!rule.count || produced >= (rule.count || 0))) break;
      if (rule.until && yearStart > rule.until) break;
    }
  }
  out.sort((a, b) => a.getTime() - b.getTime());
  return out.slice(0, opts.max);
}

function exdateSet(block: IcsBlock): Set<number> {
  const s = new Set<number>();
  for (const p of block.props) {
    if (p.name !== "EXDATE") continue;
    for (const part of splitUnescaped(p.value, ",")) {
      const d = parseIcsDate(part.trim(), p.params);
      if (d.instant) s.add(d.instant.getTime());
    }
  }
  return s;
}

export type VEventOut = {
  uid: string | null;
  summary: string | null;
  description: string | null;
  location: string | null;
  status: string | null;
  start: string | null;
  end: string | null;
  all_day: boolean;
  timezone: string | null;
  floating: boolean;
  rrule: string | null;
  occurrences: { start: string; end: string | null }[];
  occurrence_count: number;
  truncated: boolean;
};

function durationMs(start: ParsedDate, end: ParsedDate | null, duration: string | null): number | null {
  if (end?.instant && start.instant) return end.instant.getTime() - start.instant.getTime();
  if (duration && start.instant) {
    const e = addDuration(start.instant, duration);
    return e ? e.getTime() - start.instant.getTime() : null;
  }
  if (start.all_day) return 86400000;
  return null;
}

export function eventToJson(block: IcsBlock, window: { from: Date; to: Date; max: number }): VEventOut {
  const dtstartP = prop(block, "DTSTART");
  const dtendP = prop(block, "DTEND");
  const durP = prop(block, "DURATION");
  const start = dtstartP ? parseIcsDate(dtstartP.value, dtstartP.params) : { instant: null, iso: null, all_day: false, tzid: null, floating: false, raw: "" };
  const end = dtendP ? parseIcsDate(dtendP.value, dtendP.params) : null;
  const rruleP = prop(block, "RRULE");
  const rrule = rruleP ? parseRRule(rruleP.value) : null;
  const dur = durationMs(start, end, durP?.value || null);
  const endIso = (st: Date) => dur != null ? new Date(st.getTime() + dur).toISOString() : (end?.iso || null);

  let occurrences: { start: string; end: string | null }[] = [];
  let truncated = false;
  if (start.instant && rrule) {
    const insts = expandRRule(start.instant, rrule, { from: window.from, to: window.to, max: window.max + 1, exdates: exdateSet(block) });
    truncated = insts.length > window.max;
    occurrences = insts.slice(0, window.max).map((d) => ({
      start: start.floating ? d.toISOString().replace(/Z$/, "") : d.toISOString(),
      end: endIso(d),
    }));
  } else if (start.instant) {
    const inst = start.instant;
    if (inst >= window.from && inst <= window.to) {
      occurrences = [{ start: start.iso || inst.toISOString(), end: end?.iso || (dur != null ? new Date(inst.getTime() + dur).toISOString() : null) }];
    } else if (!rrule) {
      // Always include a one-off event even if it is in the past, so the caller sees it.
      occurrences = [{ start: start.iso || inst.toISOString(), end: end?.iso || (dur != null ? new Date(inst.getTime() + dur).toISOString() : null) }];
    }
  }

  return {
    uid: prop(block, "UID")?.value || null,
    summary: prop(block, "SUMMARY") ? unescapeIcsText(prop(block, "SUMMARY")!.value) : null,
    description: prop(block, "DESCRIPTION") ? unescapeIcsText(prop(block, "DESCRIPTION")!.value) : null,
    location: prop(block, "LOCATION") ? unescapeIcsText(prop(block, "LOCATION")!.value) : null,
    status: prop(block, "STATUS")?.value || null,
    start: start.iso,
    end: end?.iso || (start.instant && dur != null ? new Date(start.instant.getTime() + dur).toISOString() : null),
    all_day: start.all_day,
    timezone: start.floating ? "floating" : (start.tzid || null),
    floating: start.floating,
    rrule: rruleP?.value || null,
    occurrences,
    occurrence_count: occurrences.length,
    truncated,
  };
}

export function parseIcsText(text: string, window: { from: Date; to: Date; max: number }) {
  const lines = unfoldIcs(text);
  const blocks = parseIcsBlocks(lines);
  const calendars = blocks.filter((b) => b.type === "VCALENDAR");
  const roots = calendars.length ? calendars : [{ type: "VCALENDAR", props: [], children: blocks }];
  const events: VEventOut[] = [];
  for (const cal of roots) {
    for (const ev of cal.children.filter((c) => c.type === "VEVENT")) {
      events.push(eventToJson(ev, window));
    }
  }
  return {
    events,
    event_count: events.length,
    window: { from: window.from.toISOString(), to: window.to.toISOString(), max_occurrences: window.max },
  };
}

export async function parseIcs(item: IcsInput, ua: string) {
  const started = Date.now();
  const now = new Date();
  const from = item.from || now;
  const to = item.to || new Date(now.getTime() + DEFAULT_WINDOW_DAYS * 86400000);
  const window = { from, to, max: item.max_occurrences || MAX_OCCURRENCES };
  let text = item.text || "";
  let truncated = false;
  const out: Record<string, unknown> = { input_source: item.url && !item.text ? "url" : "text" };
  if (item.url) out.url = item.url;
  try {
    if (item.url && !item.text) {
      const r = await safeFetch(item.url, {
        method: "GET",
        headers: { "user-agent": ua, accept: "text/calendar,text/plain,*/*;q=0.2" },
        maxBytes: MAX_ICS_BYTES,
      });
      if (r.error && !r.body) {
        return { ...out, error: r.error, events: [], event_count: 0, elapsed_ms: Date.now() - started };
      }
      text = r.body;
      truncated = r.truncated;
    }
    if (!/BEGIN:VCALENDAR|BEGIN:VEVENT/i.test(text)) {
      return { ...out, error: "not_ics", events: [], event_count: 0, elapsed_ms: Date.now() - started };
    }
    const parsed = parseIcsText(text, window);
    return { ...out, ...parsed, truncated: truncated || undefined, elapsed_ms: Date.now() - started };
  } catch (e: any) {
    const msg = String(e?.message || e);
    return { ...out, error: /timeout|abort/i.test(msg) ? "timeout" : msg.slice(0, 200), events: [], event_count: 0, elapsed_ms: Date.now() - started };
  }
}
