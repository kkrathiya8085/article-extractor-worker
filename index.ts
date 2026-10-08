export interface Env {
  ALLOWED_ORIGIN: string;
  MAX_REDIRECTS: string;
  MAX_HTML_BYTES: string;
  FETCH_TIMEOUT_MS: string;
  MAX_BODY_CHARS: string;
}

type ExtractSuccess = {
  success: true;
  title: string;
  body: string;
};

type ExtractFailure = {
  success: false;
  code: string;
  message: string;
};

type ExtractResult = ExtractSuccess | ExtractFailure;

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "localhost.localdomain",
  "ip6-localhost",
  "ip6-loopback",
  "0.0.0.0",
  "::",
  "::1",
]);

const BLOCKED_LINE_PATTERNS = [
  /^author\s*:/i,
  /^author$/i,
  /^by\s*:/i,
  /^written\s+by\b/i,
  /^published\s*:/i,
  /^updated\s*:/i,
  /^published\s+on\b/i,
  /^updated\s+on\b/i,
  /^यह\s+भी\s+पढ़ें/i,
  /^यह\s+भी\s+पढ़ें/i,
  /^और\s+पढ़ें/i,
  /^और\s+पढ़ें/i,
  /^read\s+more\b/i,
  /^related\s+(news|articles?)\b/i,
  /^more\s+news\b/i,
  /^क्लिक\s+करें\s+और\s+पढ़ें\s+पूरी\s+खबर/i,
  /^क्लिक\s+करें\s+और\s+पढ़ें\s+पूरी\s+खबर/i,
  /^read\s+more\s+news\s+like\s+this\s+on\s*:/i,
  /^like\b/i,
  /^share\b/i,
  /^follow\b/i,
  /^subscribe\b/i,
  /^comments?\b/i,
  /^advertisement\b/i,
  /^advertisements\b/i,
  /^sponsored\b/i,
  /^promoted\b/i,
];

const BLOCKED_PHRASES = [
  "क्लिक करें और पढ़ें पूरी खबर",
  "क्लिक करें और पढ़ें पूरी खबर",
  "read more news like this on:",
  "यह भी पढ़ें",
  "यह भी पढ़ें",
  "related news",
  "related articles",
];

const BLOCKED_TAGS = new Set([
  "script", "style", "noscript", "nav", "footer", "aside", "form",
  "button", "svg", "iframe", "canvas", "dialog", "menu"
]);

function json(data: unknown, status = 200, origin = "*"): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": origin,
      "access-control-allow-methods": "POST, OPTIONS, GET",
      "access-control-allow-headers": "Content-Type",
      "x-content-type-options": "nosniff",
    },
  });
}

function corsOrigin(env: Env, request: Request): string {
  const configured = env.ALLOWED_ORIGIN?.trim() || "*";
  if (configured === "*") return "*";
  const incoming = request.headers.get("Origin") || "";
  return incoming === configured ? configured : configured;
}

function failure(code: string, message: string, status = 400): ExtractFailure {
  return { success: false, code, message };
}

function isIPv4(host: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
}

function ipv4ToParts(host: string): number[] | null {
  if (!isIPv4(host)) return null;
  const p = host.split(".").map(Number);
  return p.every((n) => n >= 0 && n <= 255) ? p : null;
}

function blockedIPv4(host: string): boolean {
  const p = ipv4ToParts(host);
  if (!p) return false;
  const [a, b] = p;

  if (a === 0) return true;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 224) return true; // multicast/reserved
  return false;
}

function blockedIPv6(host: string): boolean {
  const h = host.toLowerCase();
  if (!h.includes(":")) return false;
  if (h === "::" || h === "::1") return true;
  if (h.startsWith("fc") || h.startsWith("fd")) return true; // ULA
  if (h.startsWith("fe8") || h.startsWith("fe9") || h.startsWith("fea") || h.startsWith("feb")) return true; // link-local
  return false;
}

function validateUrl(raw: string): URL | null {
  if (!raw || raw.length > 8192) return null;

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (url.username || url.password) return null;

  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!hostname || BLOCKED_HOSTNAMES.has(hostname)) return null;
  if (blockedIPv4(hostname) || blockedIPv6(hostname)) return null;

  return url;
}

async function dnsLooksPublic(hostname: string): Promise<boolean> {
  // Defense-in-depth only. The actual fetch is still performed by the Workers runtime.
  // DoH calls add subrequests, so this remains limited to A/AAAA checks.
  if (isIPv4(hostname) || hostname.includes(":")) return !blockedIPv4(hostname) && !blockedIPv6(hostname);

  const endpoint = "https://cloudflare-dns.com/dns-query?name=" +
    encodeURIComponent(hostname) + "&type=A";

  try {
    const a = await fetch(endpoint, {
      headers: { "accept": "application/dns-json" },
      cf: { cacheTtl: 300, cacheEverything: true },
    } as RequestInit & { cf?: unknown });

    if (!a.ok) return false;
    const data = await a.json() as { Answer?: Array<{ type?: number; data?: string }> };
    const answers = data.Answer || [];

    // A record answers must not point to blocked IPv4 ranges.
    for (const answer of answers) {
      if (answer.type === 1 && answer.data && blockedIPv4(answer.data)) return false;
    }

    // If there is an explicit public A answer, accept it.
    if (answers.some((x) => x.type === 1 && !!x.data)) return true;

    // If no A answer exists, try AAAA.
    const aaaa = await fetch(
      "https://cloudflare-dns.com/dns-query?name=" +
      encodeURIComponent(hostname) + "&type=AAAA",
      {
        headers: { "accept": "application/dns-json" },
        cf: { cacheTtl: 300, cacheEverything: true },
      } as RequestInit & { cf?: unknown }
    );

    if (!aaaa.ok) return false;
    const v6 = await aaaa.json() as { Answer?: Array<{ type?: number; data?: string }> };
    const v6Answers = v6.Answer || [];

    for (const answer of v6Answers) {
      if (answer.type === 28 && answer.data && blockedIPv6(answer.data)) return false;
    }

    return v6Answers.some((x) => x.type === 28 && !!x.data);
  } catch {
    return false;
  }
}

function normalizeText(text: string): string {
  return text
    .replace(/\u00a0/g, " ")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n[ \t]+/g, "\n")
    .replace(/[ \t]{2,}/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function isBlockedLine(line: string): boolean {
  const s = line.trim();
  if (!s) return true;

  for (const p of BLOCKED_LINE_PATTERNS) {
    if (p.test(s)) return true;
  }

  const lower = s.toLowerCase();
  if (BLOCKED_PHRASES.some((p) => lower.includes(p.toLowerCase()))) return true;

  // Standalone social labels.
  if (/^(facebook|instagram|youtube|whatsapp|telegram)$/i.test(s)) return true;

  return false;
}

function cleanBody(raw: string, maxChars: number): string {
  const normalized = normalizeText(raw);
  const lines = normalized.split(/\n+/);
  const kept: string[] = [];

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;
    if (isBlockedLine(line)) continue;

    // Drop obvious URL-only recommendation/navigation lines.
    if (/^https?:\/\/\S+$/i.test(line)) continue;

    kept.push(line);
  }

  let result = kept.join("\n\n").trim();

  // Hard cap to avoid returning pathological pages.
  if (result.length > maxChars) {
    result = result.slice(0, maxChars).trim();
    result += "\n\n[EXTRACTION_TRUNCATED]";
  }

  return result;
}

function cleanTitle(raw: string): string {
  return normalizeText(raw)
    .split("\n")
    .map((x) => x.trim())
    .filter(Boolean)[0] || "";
}

function looksLikeMetadataTitle(title: string): boolean {
  if (!title) return true;
  return BLOCKED_LINE_PATTERNS.some((p) => p.test(title));
}

function scoreCandidate(text: string): number {
  const t = normalizeText(text);
  if (!t) return -Infinity;

  const paragraphs = t.split(/\n+/).filter(Boolean);
  let score = Math.min(t.length, 12000) / 100;

  // Prefer prose over navigation/short link collections.
  if (paragraphs.length >= 3) score += 10;
  if (paragraphs.length >= 6) score += 10;
  if (t.length >= 800) score += 15;
  if (t.length < 250) score -= 20;

  const blockedCount = paragraphs.filter(isBlockedLine).length;
  score -= blockedCount * 8;

  const urlOnly = paragraphs.filter((x) => /^https?:\/\//i.test(x)).length;
  score -= urlOnly * 10;

  return score;
}

type Candidate = { kind: string; text: string };

class Collector {
  candidates: Candidate[] = [];
  titles: string[] = [];
  jsonLd: unknown[] = [];
  nextDataText = "";

  addCandidate(kind: string, text: string) {
    const t = normalizeText(text);
    if (t) this.candidates.push({ kind, text: t });
  }

  addTitle(text: string) {
    const t = cleanTitle(text);
    if (t && !looksLikeMetadataTitle(t)) this.titles.push(t);
  }
}

function extractJsonLdValues(value: unknown, out: { title?: string; body?: string }) {
  if (!value) return;

  if (Array.isArray(value)) {
    for (const item of value) extractJsonLdValues(item, out);
    return;
  }

  if (typeof value !== "object") return;

  const obj = value as Record<string, unknown>;
  const type = obj["@type"];
  const typeText = Array.isArray(type) ? type.join(" ") : String(type || "");

  if (/Article|NewsArticle|BlogPosting/i.test(typeText)) {
    if (!out.title && typeof obj.headline === "string") out.title = obj.headline;
    if (!out.body && typeof obj.articleBody === "string") out.body = obj.articleBody;
  }

  for (const key of ["mainEntity", "mainEntityOfPage", "itemListElement", "@graph"]) {
    if (key in obj) extractJsonLdValues(obj[key], out);
  }
}

async function parseHtml(html: string, maxBodyChars: number): Promise<{ title: string; body: string }> {
  const collector = new Collector();

  // HTMLRewriter lets us inspect structured content without adding a DOM library.
  const rewriter = new HTMLRewriter();

  rewriter.on("h1", {
    text(text) {
      if (!text.lastInTextNode) collector.addTitle(text.text);
    }
  });

  rewriter.on("script#__NEXT_DATA__", {
    text(text) {
      collector.nextDataText += text.text;
    }
  });

  rewriter.on('script[type="application/ld+json"]', {
    text(text) {
      if (text.lastInTextNode) {
        const raw = collector.nextDataText;
        // JSON-LD is handled below by a separate per-script buffer.
        void raw;
      }
    }
  });

  // Generic structured candidates.
  const selectors = [
    "article",
    "main",
    "[itemprop='articleBody']",
    "[class*='article-body']",
    "[class*='articleBody']",
    "[class*='article-content']",
    "[class*='articleContent']",
    "[class*='story-content']",
    "[class*='storyContent']",
    "[class*='post-content']",
    "[class*='entry-content']",
    "[class*='news-content']",
  ];

  for (const selector of selectors) {
    rewriter.on(selector, {
      text(text) {
        // Collect text from all text nodes; normalization later collapses whitespace.
        collector.addCandidate(selector, text.text);
      }
    });
  }

  // The handlers above receive individual text nodes, so candidate fragments can be
  // numerous. Run a second lightweight pass using HTMLRewriter to capture script JSON
  // blocks and complete candidate text streams.
  const jsonLdTexts: string[] = [];
  let jsonLdBuffer = "";

  const rewriter2 = new HTMLRewriter();

  rewriter2.on('script[type="application/ld+json"]', {
    text(text) {
      jsonLdBuffer += text.text;
      if (text.lastInTextNode) {
        jsonLdTexts.push(jsonLdBuffer);
        jsonLdBuffer = "";
      }
    }
  });

  const candidateBuffers = new Map<string, string>();
  for (const selector of selectors) {
    rewriter2.on(selector, {
      text(text) {
        const current = candidateBuffers.get(selector) || "";
        candidateBuffers.set(selector, current + text.text);
      }
    });
  }

  await rewriter2.transform(new Response(html)).arrayBuffer();

  for (const [kind, text] of candidateBuffers.entries()) {
    collector.addCandidate(kind, text);
  }

  // Parse JSON-LD.
  let jsonTitle = "";
  let jsonBody = "";

  for (const raw of jsonLdTexts) {
    try {
      const parsed = JSON.parse(raw);
      const out: { title?: string; body?: string } = {};
      extractJsonLdValues(parsed, out);
      if (!jsonTitle && out.title) jsonTitle = out.title;
      if (!jsonBody && out.body) jsonBody = out.body;
    } catch {
      // Ignore malformed JSON-LD and continue with other extraction paths.
    }
  }

  // Parse __NEXT_DATA__.
  let nextTitle = "";
  let nextBody = "";
  if (collector.nextDataText) {
    try {
      const data = JSON.parse(collector.nextDataText);
      const strings: string[] = [];
      collectStructuredStrings(data, strings, 0);

      // Only accept clearly named articleBody/content/title-like keys.
      const found = findNamedFields(data);
      nextTitle = found.title || "";
      nextBody = found.body || "";

      // Avoid treating arbitrary page data as article body.
      if (!nextBody && strings.length) {
        const likely = strings.find((s) => s.length > 500);
        if (likely) nextBody = likely;
      }
    } catch {
      // Ignore malformed __NEXT_DATA__.
    }
  }

  const title = cleanTitle(nextTitle || jsonTitle || collector.titles[0] || "");
  let body = "";

  if (nextBody) body = cleanBody(nextBody, maxBodyChars);
  if (!body && jsonBody) body = cleanBody(jsonBody, maxBodyChars);

  if (!body) {
    const scored = collector.candidates
      .map((c) => ({ ...c, score: scoreCandidate(c.text) }))
      .sort((a, b) => b.score - a.score);

    if (scored[0]) body = cleanBody(scored[0].text, maxBodyChars);
  }

  // If body is only one tiny fragment, try combining candidate blocks.
  if (body.length < 250 && collector.candidates.length > 1) {
    const combined = collector.candidates
      .map((c) => c.text)
      .sort((a, b) => b.length - a.length)
      .slice(0, 5)
      .join("\n\n");

    const cleaned = cleanBody(combined, maxBodyChars);
    if (cleaned.length > body.length) body = cleaned;
  }

  return { title, body };
}

function collectStructuredStrings(value: unknown, out: string[], depth: number) {
  if (depth > 8 || out.length > 500) return;

  if (typeof value === "string") {
    if (value.length >= 80) out.push(value);
    return;
  }

  if (Array.isArray(value)) {
    for (const item of value) collectStructuredStrings(item, out, depth + 1);
    return;
  }

  if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      // Avoid dumping arbitrary metadata into the candidate pool.
      if (/^(html|content|body|articleBody|description|text|title|headline)$/i.test(key)) {
        collectStructuredStrings(item, out, depth + 1);
      } else if (depth < 4) {
        collectStructuredStrings(item, out, depth + 1);
      }
    }
  }
}

function findNamedFields(value: unknown): { title?: string; body?: string } {
  const result: { title?: string; body?: string } = {};

  function walk(v: unknown, depth: number) {
    if (depth > 8 || (result.title && result.body)) return;

    if (Array.isArray(v)) {
      for (const x of v) walk(x, depth + 1);
      return;
    }

    if (!v || typeof v !== "object") return;

    for (const [key, child] of Object.entries(v as Record<string, unknown>)) {
      if (!result.title && /^(title|headline)$/i.test(key) && typeof child === "string" && child.length > 10) {
        result.title = child;
      }

      if (!result.body && /^(articleBody|article_body)$/i.test(key) && typeof child === "string" && child.length > 150) {
        result.body = child;
      }

      if (!result.body && /^(content|body)$/i.test(key) && typeof child === "string" && child.length > 300) {
        result.body = child;
      }

      walk(child, depth + 1);
    }
  }

  walk(value, 0);
  return result;
}

async function fetchHtml(
  startUrl: URL,
  env: Env
): Promise<{ ok: true; html: string; finalUrl: string } | { ok: false; result: ExtractFailure }> {
  const maxRedirects = Math.min(Math.max(Number(env.MAX_REDIRECTS || 5), 0), 5);
  const maxBytes = Math.min(Math.max(Number(env.MAX_HTML_BYTES || 5_000_000), 100_000), 5_000_000);
  const timeoutMs = Math.min(Math.max(Number(env.FETCH_TIMEOUT_MS || 12_000), 3_000), 20_000);

  let current = startUrl;

  for (let i = 0; i <= maxRedirects; i++) {
    if (!(await dnsLooksPublic(current.hostname))) {
      return { ok: false, result: failure("SSRF_BLOCKED", "यह लिंक सुरक्षित रूप से उपलब्ध नहीं है", 400) };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let response: Response;
    try {
      response = await fetch(current.toString(), {
        method: "GET",
        redirect: "manual",
        headers: {
          "accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
          "user-agent": "ARTICLE-EXTRACTOR/1.0",
        },
        signal: controller.signal,
      });
    } catch (err) {
      clearTimeout(timer);
      const message = err instanceof Error && err.name === "AbortError"
        ? "नेटवर्क की समस्या"
        : "सर्वर से संपर्क नहीं हो पाया";
      return { ok: false, result: failure("NETWORK_ERROR", message, 502) };
    } finally {
      clearTimeout(timer);
    }

    if (response.status >= 300 && response.status < 400) {
      if (i >= maxRedirects) {
        return { ok: false, result: failure("REDIRECT_LIMIT", "लिंक बहुत अधिक redirect हुआ", 400) };
      }

      const location = response.headers.get("location");
      if (!location) {
        return { ok: false, result: failure("NETWORK_ERROR", "सर्वर से संपर्क नहीं हो पाया", 502) };
      }

      const next = validateUrl(new URL(location, current).toString());
      if (!next) {
        return { ok: false, result: failure("INVALID_REDIRECT", "अमान्य redirect लिंक", 400) };
      }

      current = next;
      continue;
    }

    if (!response.ok) {
      if (response.status === 404) {
        return { ok: false, result: failure("ARTICLE_NOT_FOUND", "आर्टिकल नहीं मिला", 404) };
      }
      return { ok: false, result: failure("NETWORK_ERROR", "सर्वर से संपर्क नहीं हो पाया", 502) };
    }

    const contentType = response.headers.get("content-type")?.toLowerCase() || "";
    if (!contentType.includes("text/html") && !contentType.includes("application/xhtml+xml")) {
      return { ok: false, result: failure("UNSUPPORTED_CONTENT", "यह सामग्री समर्थित नहीं है", 415) };
    }

    const lengthHeader = response.headers.get("content-length");
    if (lengthHeader && Number(lengthHeader) > maxBytes) {
      return { ok: false, result: failure("CONTENT_TOO_LARGE", "आर्टिकल बहुत बड़ा है", 413) };
    }

    const buffer = await response.arrayBuffer();
    if (buffer.byteLength > maxBytes) {
      return { ok: false, result: failure("CONTENT_TOO_LARGE", "आर्टिकल बहुत बड़ा है", 413) };
    }

    const html = new TextDecoder("utf-8", { fatal: false }).decode(buffer);
    return { ok: true, html, finalUrl: current.toString() };
  }

  return { ok: false, result: failure("REDIRECT_LIMIT", "लिंक बहुत अधिक redirect हुआ", 400) };
}

function validateExtraction(title: string, body: string): ExtractResult {
  const cleanT = cleanTitle(title);
  const cleanB = normalizeText(body);

  if (!cleanT) {
    return failure("ARTICLE_NOT_FOUND", "आर्टिकल नहीं मिला", 422);
  }

  if (!cleanB || cleanB.length < 250) {
    return failure("INCOMPLETE_TEXT", "अधूरा टेक्स्ट प्राप्त हुआ", 422);
  }

  const blockedLines = cleanB.split(/\n+/).filter(isBlockedLine).length;
  const totalLines = cleanB.split(/\n+/).filter(Boolean).length;

  if (totalLines > 0 && blockedLines / totalLines > 0.35) {
    return failure("INCOMPLETE_TEXT", "अधूरा टेक्स्ट प्राप्त हुआ", 422);
  }

  return { success: true, title: cleanT, body: cleanB };
}

async function handleExtract(request: Request, env: Env): Promise<ExtractResult> {
  let payload: unknown;

  try {
    payload = await request.json();
  } catch {
    return failure("INVALID_REQUEST", "अमान्य अनुरोध", 400);
  }

  if (!payload || typeof payload !== "object") {
    return failure("INVALID_REQUEST", "अमान्य अनुरोध", 400);
  }

  const rawUrl = (payload as Record<string, unknown>).url;
  if (typeof rawUrl !== "string" || !rawUrl.trim()) {
    return failure("NO_URL", "लिंक उपलब्ध नहीं है", 400);
  }

  const url = validateUrl(rawUrl.trim());
  if (!url) {
    return failure("INVALID_URL", "अमान्य लिंक", 400);
  }

  const fetched = await fetchHtml(url, env);
  if (!fetched.ok) return fetched.result;

  const maxBodyChars = Math.min(
    Math.max(Number(env.MAX_BODY_CHARS || 120_000), 10_000),
    120_000
  );

  try {
    const extracted = await parseHtml(fetched.html, maxBodyChars);
    return validateExtraction(extracted.title, extracted.body);
  } catch {
    return failure("EXTRACTION_FAILED", "टेक्स्ट एक्स्ट्रैक्ट नहीं हो पाया", 422);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = corsOrigin(env, request);
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": origin,
          "access-control-allow-methods": "POST, OPTIONS, GET",
          "access-control-allow-headers": "Content-Type",
          "access-control-max-age": "86400",
        },
      });
    }

    if (request.method === "GET" && url.pathname === "/") {
      return json({
        service: "ARTICLE EXTRACTOR",
        version: "1.0.0",
        status: "ok",
        ai: false,
        extractionApi: false,
        endpoint: "/extract",
      }, 200, origin);
    }

    if (request.method !== "POST" || url.pathname !== "/extract") {
      return json(
        { success: false, code: "NOT_FOUND", message: "Endpoint उपलब्ध नहीं है" },
        404,
        origin
      );
    }

    const contentType = request.headers.get("content-type")?.toLowerCase() || "";
    if (!contentType.includes("application/json")) {
      return json(
        failure("INVALID_REQUEST", "JSON अनुरोध आवश्यक है"),
        415,
        origin
      );
    }

    const result = await handleExtract(request, env);
    const status = result.success ? 200 : (
      result.code === "ARTICLE_NOT_FOUND" ? 404 :
      result.code === "NETWORK_ERROR" ? 502 :
      result.code === "CONTENT_TOO_LARGE" ? 413 :
      result.code === "UNSUPPORTED_CONTENT" ? 415 :
      422
    );

    return json(result, status, origin);
  },
};
