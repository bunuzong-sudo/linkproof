// Bazaar/CDP facilitator rejects payments whose resource description exceeds 500 characters: keep every description <= 480.
// Single source for the public wording of each paid route: Bazaar description + tags (Bazaar keeps the first 5 tags),
// docs, OpenAPI summaries, MCP tool text and llms.txt. Wording leads with the phrases agents search for.
export const CANONICAL_URL = "https://linkproof.zopip.com";

export type RouteMeta = { path: string; tool: string; title: string; tags: string[]; description: string; short: string };

export const CATALOG: RouteMeta[] = [
  { path: "/v1/verify-answer", tool: "verify_answer", title: "Fact-check an AI answer's sources",
    tags: ["hallucination-check", "fact-check", "citation-verification", "broken-link-checker", "ai-answer"],
    short: "Fact-check the sources in an AI answer: extract every URL, DOI, arXiv id and PubMed id, check the links, verify the citations and find archived copies of dead links, in one call",
    description: "Hallucination check / source checker for an AI answer in one call. Send the answer text (max 50,000 chars); LinkProof extracts every URL, DOI, arXiv id and PubMed id (or pass urls/citations), checks each link (live, dead/404, soft-404, parked, unreachable), verifies each citation in Crossref, arXiv or PubMed against claimed title/authors/year, and finds Wayback copies of dead links. Up to 10 links + 10 citations. Returns all_ok or problems_found plus per-item verdicts." },
  { path: "/v1/read-page", tool: "read_page", title: "Web page to Markdown reader (HTML + PDF)",
    tags: ["web-scraping", "html-to-markdown", "web-reader", "pdf-to-text", "content-extraction"],
    short: "Read any web page or PDF URL as clean Markdown for LLMs: main content, title, metadata, links, plus an AI-usage hint from robots.txt and meta tags",
    description: "Web page reader / scraper for AI agents: fetch one public URL and get clean Markdown of the main content (boilerplate, menus and scripts removed), or text from a PDF link. Returns title, description, language, author, publish date, word count, optional links, and an AI-usage hint (robots.txt AI crawler rules, Content-Signal, meta robots noai, X-Robots-Tag). Up to 100,000 chars. Failed fetches and JS-only pages are not charged." },
  { path: "/v1/domain-report", tool: "domain_report", title: "Domain health and trust report",
    tags: ["domain-lookup", "whois", "ssl-certificate", "dns-lookup", "phishing-check"],
    short: "Domain report in one call: DNS, WHOIS/RDAP age and expiry, SSL certificate, HTTPS + security headers, SPF/DMARC, robots.txt; 0-100 health score",
    description: "Domain health / trust check in one call: DNS (A, AAAA, NS, CAA, DNSSEC), WHOIS via RDAP (registration date, domain age, expiry, registrar, status), SSL/TLS certificate from Certificate Transparency logs (issuer, days left), HTTPS reachability and security headers grade, SPF / DMARC / MX / DKIM, robots.txt AI rules, security.txt and llms.txt. Returns a 0-100 health score, risk level and plain-language findings (new domain, expiring cert, no DMARC...)." },
  { path: "/v1/base-lookup", tool: "base_lookup", title: "Base wallet, token and gas lookup",
    tags: ["base", "wallet-balance", "erc20", "basename", "gas-price"],
    short: "Base chain lookup: wallet ETH + token balances (USDC, WETH, cbBTC...), Basename resolve, ERC-20 token info, latest block and gas price",
    description: "Base (chain 8453) on-chain lookup for AI agents: wallet ETH balance and ERC-20 token balances (USDC, WETH, cbBTC, USDbC, EURC, DAI, cbETH, AERO plus up to 10 custom tokens), nonce and contract check; resolve a Basename (name.base.eth) to an address and the wallet's primary Basename; ERC-20 token info (name, symbol, decimals, total supply); latest block, base fee, gas price and transfer cost estimate. Read-only public RPC data." },
  { path: "/v1/verify-links", tool: "verify_links", title: "Broken link checker",
    tags: ["broken-link-checker", "dead-link", "url-checker", "link-verification", "hallucination"],
    short: "Broken link / dead link checker: live, 404, soft-404, parked domain, redirects, title, optional expected phrase (up to 10 URLs)",
    description: "Broken link checker and dead link checker for AI agents: verify up to 10 URLs before citing or sending them. Per URL returns a verdict (live, dead/404, soft_404, parked domain, blocked_or_rate_limited, unreachable/DNS error), HTTP status, final URL after redirects, page title, meta description, and optionally whether an expected phrase appears on the page. Catches hallucinated, rotted and redirected-to-homepage links." },
  { path: "/v1/verify-citations", tool: "verify_citations", title: "Citation checker (DOI, arXiv, PubMed)",
    tags: ["citation-checker", "doi-lookup", "hallucination", "crossref", "reference-verification"],
    short: "Citation checker: verify DOIs, arXiv ids, PubMed ids and free-text references exist and match claimed title/authors/year (up to 10)",
    description: "Citation checker / reference verifier: check that up to 10 references an AI cites really exist. Accepts DOI, arXiv id, PubMed id (PMID), free-text reference, or {title, authors, year}. Looks them up in Crossref (DataCite fallback), arXiv and NCBI PubMed and returns, per citation, exists, matched metadata (title, authors, year, venue, URL), field mismatches, confidence and a verdict: verified, mismatch, not_found or error. Catches hallucinated or misattributed papers." },
  { path: "/v1/find-archive", tool: "find_archive", title: "Wayback Machine archive lookup",
    tags: ["wayback-machine", "archive", "dead-link", "link-rot", "web-archive"],
    short: "Wayback Machine lookup: closest archived snapshot for up to 10 URLs (dead links, link rot), optionally near a date",
    description: "Wayback Machine / Internet Archive lookup for dead links and link rot: for up to 10 URLs, find the closest archived snapshot, optionally nearest to a given date. Returns snapshot URL, capture timestamp, captured HTTP status and distance in days from the requested date. Use it to replace or back up broken citations." },
  { path: "/v1/check-headers", tool: "check_headers", title: "Security headers audit",
    tags: ["security-headers", "hsts", "csp", "website-security", "audit"],
    short: "HTTP security headers audit: HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy, cookie flags, HTTPS redirect, A-F grade (up to 5 URLs)",
    description: "HTTP security headers audit / scanner for up to 5 URLs or domains: HSTS, Content-Security-Policy (CSP), X-Frame-Options / frame-ancestors (clickjacking), X-Content-Type-Options (nosniff), Referrer-Policy, Permissions-Policy, COOP/CORP, cookie flags (Secure, HttpOnly, SameSite; names only), HTTPS redirect and server version disclosure. Returns an A-F grade, score and fixes. Headers only; no TLS certificate check." },
  { path: "/v1/site-policies", tool: "site_policies", title: "robots.txt, llms.txt and security.txt checker",
    tags: ["robots-txt", "llms-txt", "ai-crawler", "security-txt", "seo"],
    short: "robots.txt + llms.txt + ai.txt + security.txt checker: AI crawler rules (GPTBot, ClaudeBot, ...), path allowed?, sitemaps (up to 5 sites)",
    description: "robots.txt, llms.txt and security.txt checker for up to 5 sites: fetches robots.txt, llms.txt, llms-full.txt, ai.txt and /.well-known/security.txt in parallel. Parses robots.txt rules for AI crawlers (GPTBot, ClaudeBot, Google-Extended, CCBot, PerplexityBot and others) and the * group, says whether a given path is allowed to crawl, lists sitemap URLs, and reports security.txt contact and expiry. Use it before crawling or scraping a site." },
  { path: "/v1/email-auth", tool: "email_auth", title: "SPF / DKIM / DMARC checker",
    tags: ["spf", "dmarc", "dkim", "email-security", "dns-lookup"],
    short: "SPF, DKIM and DMARC checker + MX lookup for up to 5 domains: misconfigurations, grade, fixes (DNS only, mailboxes never probed)",
    description: "SPF, DKIM and DMARC checker (email authentication audit) for up to 5 domains: reads SPF, DMARC, MX and common DKIM selectors via DNS-over-HTTPS (Cloudflare, Google fallback). Reports presence, policy strength, common misconfigurations (multiple SPF records, more than 10 SPF DNS lookups, +all or missing all, missing or multiple DMARC, DMARC p=none), a simple A-F grade and recommendations. DNS check only: mailboxes are never probed and it is not a deliverability guarantee." },
  { path: "/v1/injection-scan", tool: "injection_scan", title: "Prompt injection detection",
    tags: ["prompt-injection", "llm-security", "jailbreak-detection", "ai-safety", "sanitization"],
    short: "Prompt injection detection for untrusted text (web pages, emails, tool output): risk level, matches, sanitized copy (max 50 KB)",
    description: "Prompt injection detection / scanner for untrusted text before an LLM agent reads it (web pages, emails, documents, tool output). Rule-based scan of up to 50 KB for instruction-override phrases, system-prompt reveal requests, DAN-style jailbreaks, hidden or bidi unicode, base64-encoded instructions and tool/markdown-image exfiltration. Returns risk (none to critical), matches with offsets and a sanitized copy. Heuristic; text not stored." },
  { path: "/v1/wiki-summary", tool: "wiki_summary", title: "Wikipedia summary",
    tags: ["wikipedia", "summary", "knowledge", "wikidata", "research"],
    short: "Wikipedia summary lookup by title or search query (any language): extract, URL, thumbnail, Wikidata id, CC BY-SA attribution (up to 3)",
    description: "Wikipedia summary / article lookup: for up to 3 titles or search queries (optional language code), return the short extract, article URL, thumbnail, Wikidata id and ready-to-use CC BY-SA 4.0 attribution from the Wikimedia REST API. Cached." },
  { path: "/v1/license-detect", tool: "license_detect", title: "Open source license detector (SPDX)",
    tags: ["license-detection", "spdx", "open-source", "compliance", "license"],
    short: "Open source license detector: SPDX id (MIT, Apache-2.0, GPL, BSD, MPL, ...) from LICENSE text or URL, with permissions and conditions",
    description: "Open source license detector: identify the SPDX license id (MIT, Apache-2.0, GPL-2.0/3.0, LGPL, AGPL, BSD-2/3-Clause, MPL-2.0, ISC, Unlicense, CC0-1.0, CC-BY/SA, EPL-2.0 and others) from license text or a public LICENSE file URL. Returns confidence and key permissions, conditions and limitations. Not legal advice." },
  { path: "/v1/ics-parse", tool: "ics_parse", title: "ICS / iCalendar parser",
    tags: ["ics-parser", "icalendar", "calendar", "rrule", "events"],
    short: "ICS / iCalendar parser: events with UTC/ISO times and RRULE recurrences expanded (text or public .ics URL)",
    description: "ICS / iCalendar parser: parse ICS text or a public .ics calendar URL. Returns VEVENTs with summary, start/end normalized to UTC/ISO (or marked floating), timezone, location, and RRULE recurring events expanded to at most 50 occurrences in a bounded window. Data is not stored." },
];

export const META: Record<string, RouteMeta> = Object.fromEntries(CATALOG.map((m) => [m.path, m]));

/** MCP tool description: the price suffix is added only when the total stays under the CDP 500-char resource.description limit. */
export function withPrice(description: string, price: string | number): string {
  const s = `${description} Price: ${price} USDC per call (x402, Base).`;
  return s.length <= 490 ? s : description;
}
