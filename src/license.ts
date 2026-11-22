// Identify a common open-source license (SPDX id) by normalized text matching
// against bundled fingerprints. Optional public LICENSE URL (size-capped, private
// hosts blocked). Not legal advice.

import { parsePublicHttpUrl, safeFetch } from "./urlguard";

export const PRICE_LICENSE = "0.003";
export const MAX_LICENSE_BYTES = 100 * 1024;
export const LICENSE_DISCLAIMER =
  "This is an automated SPDX identification from text patterns, not legal advice and not a certification of the license that applies to a project.";

export type LicenseInput = { text?: string; url?: string };

export function parseLicenseInput(body: any): { item?: LicenseInput; error?: string } {
  if (!body || typeof body !== "object") return { error: 'Body must be JSON: {"text": "MIT License…"} or {"url": "https://…/LICENSE"}' };
  const text = body.text != null ? body.text : body.license;
  const url = body.url;
  if (text != null && typeof text !== "string") return { error: "`text` must be a string" };
  if (url != null && typeof url !== "string") return { error: "`url` must be a string" };
  if (!text && !url) return { error: "Provide `text` or a public `url` to a LICENSE file" };
  if (text && new TextEncoder().encode(text).length > MAX_LICENSE_BYTES) {
    return { error: `text exceeds the ${MAX_LICENSE_BYTES} byte cap` };
  }
  if (url) {
    const p = parsePublicHttpUrl(url);
    if (p.error || !p.href) return { error: p.error || "Invalid URL" };
    return { item: { text: text || undefined, url: p.href } };
  }
  return { item: { text } };
}

export type LicenseTerms = {
  permissions: string[];
  conditions: string[];
  limitations: string[];
};

export type LicenseDef = {
  spdx: string;
  name: string;
  family: string;
  required: string[];
  optional: string[];
  exclude?: string[];
  terms: LicenseTerms;
};

const NOTICE = ["keep copyright and license notice"];
const ASIS = ["no warranty", "no liability"];
const COPYLEFT = ["disclose source", "same license (copyleft)"];

export const LICENSE_CATALOG: LicenseDef[] = [
  { spdx: "MIT", name: "MIT License", family: "mit",
    required: ["permission is hereby granted, free of charge", "the software is provided \"as is\"", "without warranty of any kind"],
    optional: ["sublicense", "and/or sell copies of the software", "mit license"],
    exclude: ["gnu general public license", "mozilla public license"],
    terms: { permissions: ["commercial use", "modification", "distribution", "private use", "sublicense"], conditions: NOTICE, limitations: ASIS } },
  { spdx: "Apache-2.0", name: "Apache License 2.0", family: "apache",
    required: ["apache license", "version 2.0", "licensed under the apache license"],
    optional: ["appendix: how to apply the apache license", "patent", "state changes"],
    terms: { permissions: ["commercial use", "modification", "distribution", "private use", "patent use", "sublicense"], conditions: [...NOTICE, "state changes"], limitations: [...ASIS, "no trademark use"] } },
  { spdx: "GPL-3.0-or-later", name: "GNU General Public License v3.0 or later", family: "gpl3",
    required: ["gnu general public license", "version 3", "or (at your option) any later version"],
    optional: ["gnu affero", "corresponding source", "additional terms"],
    exclude: ["gnu affero general public license", "lesser general public license"],
    terms: { permissions: ["commercial use", "modification", "distribution", "patent use", "private use"], conditions: [...NOTICE, ...COPYLEFT], limitations: ASIS } },
  { spdx: "GPL-3.0-only", name: "GNU General Public License v3.0 only", family: "gpl3",
    required: ["gnu general public license", "version 3"],
    optional: ["corresponding source", "additional terms"],
    exclude: ["or (at your option) any later version", "gnu affero general public license", "lesser general public license"],
    terms: { permissions: ["commercial use", "modification", "distribution", "patent use", "private use"], conditions: [...NOTICE, ...COPYLEFT], limitations: ASIS } },
  { spdx: "GPL-2.0-or-later", name: "GNU General Public License v2.0 or later", family: "gpl2",
    required: ["gnu general public license", "version 2", "or (at your option) any later version"],
    optional: ["library general public"],
    exclude: ["version 3", "lesser general public license", "gnu affero"],
    terms: { permissions: ["commercial use", "modification", "distribution", "private use"], conditions: [...NOTICE, ...COPYLEFT], limitations: ASIS } },
  { spdx: "GPL-2.0-only", name: "GNU General Public License v2.0 only", family: "gpl2",
    required: ["gnu general public license", "version 2"],
    optional: ["this program is free software"],
    exclude: ["or (at your option) any later version", "version 3", "lesser general public license", "gnu affero"],
    terms: { permissions: ["commercial use", "modification", "distribution", "private use"], conditions: [...NOTICE, ...COPYLEFT], limitations: ASIS } },
  { spdx: "AGPL-3.0-or-later", name: "GNU Affero General Public License v3.0 or later", family: "agpl",
    required: ["gnu affero general public license", "version 3", "or (at your option) any later version"],
    optional: ["network interaction", "remote network"],
    terms: { permissions: ["commercial use", "modification", "distribution", "patent use", "private use"], conditions: [...NOTICE, ...COPYLEFT, "network use is distribution"], limitations: ASIS } },
  { spdx: "AGPL-3.0-only", name: "GNU Affero General Public License v3.0 only", family: "agpl",
    required: ["gnu affero general public license", "version 3"],
    optional: ["network interaction"],
    exclude: ["or (at your option) any later version"],
    terms: { permissions: ["commercial use", "modification", "distribution", "patent use", "private use"], conditions: [...NOTICE, ...COPYLEFT, "network use is distribution"], limitations: ASIS } },
  { spdx: "LGPL-3.0-or-later", name: "GNU Lesser General Public License v3.0 or later", family: "lgpl3",
    required: ["gnu lesser general public license", "version 3", "or (at your option) any later version"],
    optional: ["gnu general public license is a free"],
    terms: { permissions: ["commercial use", "modification", "distribution", "patent use", "private use"], conditions: [...NOTICE, "disclose source", "same license for library changes"], limitations: ASIS } },
  { spdx: "LGPL-3.0-only", name: "GNU Lesser General Public License v3.0 only", family: "lgpl3",
    required: ["gnu lesser general public license", "version 3"],
    optional: ["this version of the gnu lesser"],
    exclude: ["or (at your option) any later version"],
    terms: { permissions: ["commercial use", "modification", "distribution", "patent use", "private use"], conditions: [...NOTICE, "disclose source", "same license for library changes"], limitations: ASIS } },
  { spdx: "LGPL-2.1-or-later", name: "GNU Lesser General Public License v2.1 or later", family: "lgpl21",
    required: ["gnu lesser general public license", "version 2.1", "or (at your option) any later version"],
    optional: ["library general public"],
    terms: { permissions: ["commercial use", "modification", "distribution", "private use"], conditions: [...NOTICE, "disclose source", "same license for library changes"], limitations: ASIS } },
  { spdx: "LGPL-2.1-only", name: "GNU Lesser General Public License v2.1 only", family: "lgpl21",
    required: ["gnu lesser general public license", "version 2.1"],
    optional: ["this library is free software"],
    exclude: ["or (at your option) any later version"],
    terms: { permissions: ["commercial use", "modification", "distribution", "private use"], conditions: [...NOTICE, "disclose source", "same license for library changes"], limitations: ASIS } },
  { spdx: "BSD-3-Clause", name: "BSD 3-Clause \"New\" or \"Revised\" License", family: "bsd",
    required: ["redistribution and use in source and binary forms", "neither the name of", "nor the names of its contributors may be used to endorse"],
    optional: ["3-clause", "revised license", "new bsd"],
    terms: { permissions: ["commercial use", "modification", "distribution", "private use"], conditions: NOTICE, limitations: [...ASIS, "no endorsement using names"] } },
  { spdx: "BSD-2-Clause", name: "BSD 2-Clause \"Simplified\" License", family: "bsd",
    required: ["redistribution and use in source and binary forms", "redistributions of source code must retain"],
    optional: ["2-clause", "simplified license"],
    exclude: ["neither the name of", "nor the names of its contributors may be used to endorse"],
    terms: { permissions: ["commercial use", "modification", "distribution", "private use"], conditions: NOTICE, limitations: ASIS } },
  { spdx: "MPL-2.0", name: "Mozilla Public License 2.0", family: "mpl",
    required: ["mozilla public license", "version 2.0"],
    optional: ["exhibit a", "incompatible with secondary licenses"],
    terms: { permissions: ["commercial use", "modification", "distribution", "patent use", "private use"], conditions: [...NOTICE, "disclose source", "same license for modified files"], limitations: [...ASIS, "no trademark use"] } },
  { spdx: "ISC", name: "ISC License", family: "isc",
    required: ["permission to use, copy, modify, and/or distribute this software for any purpose with or without fee"],
    optional: ["isc license", "provided that the above copyright notice"],
    exclude: ["permission is hereby granted, free of charge"],
    terms: { permissions: ["commercial use", "modification", "distribution", "private use"], conditions: NOTICE, limitations: ASIS } },
  { spdx: "Unlicense", name: "The Unlicense", family: "unlicense",
    required: ["this is free and unencumbered software released into the public domain"],
    optional: ["anyone is free to copy, modify, publish, use, compile, sell", "the unlicense"],
    terms: { permissions: ["commercial use", "modification", "distribution", "private use"], conditions: [], limitations: ASIS } },
  { spdx: "CC0-1.0", name: "Creative Commons Zero v1.0 Universal", family: "cc0",
    required: ["creative commons", "cc0", "public domain"],
    optional: ["waiving all of his or her rights", "fallback"],
    exclude: ["attribution 4.0", "sharealike"],
    terms: { permissions: ["commercial use", "modification", "distribution", "private use"], conditions: [], limitations: ["no warranty", "no liability", "no patent/trademark grant stated"] } },
  { spdx: "CC-BY-SA-4.0", name: "Creative Commons Attribution-ShareAlike 4.0", family: "cc",
    required: ["creative commons", "attribution", "sharealike", "4.0"],
    optional: ["by-sa", "adapted material"],
    terms: { permissions: ["commercial use", "modification", "distribution", "private use"], conditions: ["give credit", "indicate changes", "share adaptations under the same license"], limitations: ["no warranty", "no liability", "no endorsement"] } },
  { spdx: "CC-BY-4.0", name: "Creative Commons Attribution 4.0", family: "cc",
    required: ["creative commons", "attribution", "4.0"],
    optional: ["by 4.0", "international public license"],
    exclude: ["sharealike", "noncommercial", "noderivatives", "share-alike"],
    terms: { permissions: ["commercial use", "modification", "distribution", "private use"], conditions: ["give credit", "indicate changes"], limitations: ["no warranty", "no liability", "no endorsement"] } },
  { spdx: "0BSD", name: "BSD Zero Clause License", family: "0bsd",
    required: ["permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted"],
    optional: ["zero-clause", "0bsd"],
    exclude: ["provided that the above copyright notice and this permission notice appear"],
    terms: { permissions: ["commercial use", "modification", "distribution", "private use"], conditions: [], limitations: ASIS } },
  { spdx: "EPL-2.0", name: "Eclipse Public License 2.0", family: "epl",
    required: ["eclipse public license", "v 2.0"],
    optional: ["epl-2.0", "secondary license"],
    terms: { permissions: ["commercial use", "modification", "distribution", "patent use", "private use"], conditions: [...NOTICE, "disclose source", "same license for modified files"], limitations: ASIS } },
  { spdx: "BSL-1.0", name: "Boost Software License 1.0", family: "boost",
    required: ["boost software license", "version 1.0"],
    optional: ["permission is hereby granted, free of charge"],
    terms: { permissions: ["commercial use", "modification", "distribution", "private use"], conditions: ["keep license notice in source"], limitations: ASIS } },
  { spdx: "WTFPL", name: "Do What The F*ck You Want To Public License", family: "wtfpl",
    required: ["do what the fuck you want to", "wtfpl"],
    optional: ["version 2"],
    terms: { permissions: ["commercial use", "modification", "distribution", "private use"], conditions: [], limitations: [] } },
  { spdx: "BlueOak-1.0.0", name: "Blue Oak Model License 1.0.0", family: "blueoak",
    required: ["blue oak model license"],
    optional: ["1.0.0"],
    terms: { permissions: ["commercial use", "modification", "distribution", "patent use", "private use"], conditions: NOTICE, limitations: ASIS } },
];

const SPDX_HEADER = /(?:^|\n)\s*(?:spdx-license-identifier|spdx licence identifier)\s*:\s*([A-Za-z0-9.+-]+(?:\s+(?:or|and)\s+[A-Za-z0-9.+-]+)*)/i;

export function normalizeLicenseText(text: string): string {
  return text
    .replace(/\u00a0/g, " ")
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201c\u201d]/g, '"')
    .replace(/©/g, "(c)")
    .replace(/^\s*copyright\b[^\n]*/gim, " ")
    .replace(/\ball rights reserved\b/gi, " ")
    .replace(/\r\n/g, "\n")
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();
}

function present(norm: string, phrase: string): boolean {
  return norm.includes(phrase.toLowerCase());
}

export function scoreLicense(norm: string, def: LicenseDef): number {
  if (def.exclude && def.exclude.some((p) => present(norm, p))) return 0;
  let hit = 0;
  for (const p of def.required) if (present(norm, p)) hit++;
  if (hit < def.required.length) {
    // partial credit only if most required phrases match
    if (hit === 0 || hit / def.required.length < 0.7) return 0;
  }
  let score = 0.55 + 0.3 * (hit / def.required.length);
  if (def.optional.length) {
    let o = 0;
    for (const p of def.optional) if (present(norm, p)) o++;
    score += 0.15 * (o / def.optional.length);
  }
  return Math.min(0.98, Math.round(score * 100) / 100);
}

export type LicenseResult = {
  input_source: "text" | "url";
  url?: string;
  spdx_id: string | null;
  name: string | null;
  confidence: number;
  alternatives: { spdx_id: string; name: string; confidence: number }[];
  spdx_header: string | null;
  permissions: string[];
  conditions: string[];
  limitations: string[];
  disclaimer: string;
  truncated?: boolean;
  error?: string;
  elapsed_ms: number;
};

export function detectLicenseFromText(text: string, meta?: { url?: string; truncated?: boolean; input_source?: "text" | "url" }): LicenseResult {
  const started = Date.now();
  const norm = normalizeLicenseText(text);
  const headerM = text.match(SPDX_HEADER);
  const header = headerM ? headerM[1].trim() : null;
  const scored = LICENSE_CATALOG
    .map((d) => ({ def: d, confidence: scoreLicense(norm, d) }))
    .filter((x) => x.confidence > 0)
    .sort((a, b) => b.confidence - a.confidence || a.def.spdx.localeCompare(b.def.spdx));

  let best = scored[0] || null;
  // A declared SPDX identifier wins if we know it, unless the body strongly matches a different family.
  if (header) {
    const ids = header.split(/\s+(?:or|and)\s+/i).map((s) => s.trim());
    const known = LICENSE_CATALOG.filter((d) => ids.some((id) => id.toLowerCase() === d.spdx.toLowerCase()));
    if (known.length) {
      const body = best;
      const declared = known[0];
      const bodyConflicts = body && body.def.family !== declared.family && body.confidence >= 0.85;
      if (!bodyConflicts) {
        best = { def: declared, confidence: Math.max(0.9, body && body.def.spdx === declared.spdx ? body.confidence : 0.9) };
        // keep other declared ids as alternatives
      }
    }
  }

  const alternatives = scored
    .filter((x) => !best || x.def.spdx !== best.def.spdx)
    .slice(0, 3)
    .map((x) => ({ spdx_id: x.def.spdx, name: x.def.name, confidence: x.confidence }));

  const out: LicenseResult = {
    input_source: meta?.input_source || "text",
    url: meta?.url,
    spdx_id: best ? best.def.spdx : null,
    name: best ? best.def.name : null,
    confidence: best ? best.confidence : 0,
    alternatives,
    spdx_header: header,
    permissions: best ? best.def.terms.permissions : [],
    conditions: best ? best.def.terms.conditions : [],
    limitations: best ? best.def.terms.limitations : [],
    disclaimer: LICENSE_DISCLAIMER,
    elapsed_ms: Date.now() - started,
  };
  if (meta?.truncated) out.truncated = true;
  return out;
}

export async function detectLicense(item: LicenseInput, ua: string): Promise<LicenseResult> {
  const started = Date.now();
  let text = item.text || "";
  let truncated = false;
  let url = item.url;
  if (url) {
    const r = await safeFetch(url, {
      method: "GET",
      headers: { "user-agent": ua, accept: "text/plain,text/markdown,text/*;q=0.9,*/*;q=0.2" },
      maxBytes: MAX_LICENSE_BYTES,
    });
    if (r.error && !r.body) {
      return {
        input_source: "url", url,
        spdx_id: null, name: null, confidence: 0, alternatives: [], spdx_header: null,
        permissions: [], conditions: [], limitations: [],
        disclaimer: LICENSE_DISCLAIMER,
        error: r.error,
        elapsed_ms: Date.now() - started,
      };
    }
    const html = !!(r.content_type && /text\/html/i.test(r.content_type)) || /^\s*<!doctype html|^\s*<html/i.test(r.body);
    if (html && !item.text) {
      return {
        input_source: "url", url,
        spdx_id: null, name: null, confidence: 0, alternatives: [], spdx_header: null,
        permissions: [], conditions: [], limitations: [],
        disclaimer: LICENSE_DISCLAIMER,
        error: "html_page_not_plain_text",
        elapsed_ms: Date.now() - started,
      };
    }
    if (!item.text) text = r.body;
    truncated = r.truncated;
  }
  if (!text.trim()) {
    return {
      input_source: url ? "url" : "text", url,
      spdx_id: null, name: null, confidence: 0, alternatives: [], spdx_header: null,
      permissions: [], conditions: [], limitations: [],
      disclaimer: LICENSE_DISCLAIMER,
      error: "empty_license_text",
      elapsed_ms: Date.now() - started,
    };
  }
  return detectLicenseFromText(text, { url, truncated, input_source: url && !item.text ? "url" : "text" });
}
