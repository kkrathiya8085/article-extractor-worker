# ARTICLE EXTRACTOR — External Extraction Worker v1.1 (5,000/day target)

Deterministic Cloudflare Worker backend for ARTICLE EXTRACTOR.

## Target workload

- Expected extraction requests: **5,000/day**
- Cloudflare Workers Free documented inbound request limit: **100,000/day**
- 5,000/day is therefore 5% of that daily request allowance.
- This project does **not** claim unlimited usage.
- `EXPECTED_DAILY_REQUESTS=5000` is a planning/monitoring target, not a built-in daily quota counter.

Cloudflare Free also limits a Worker invocation to 50 external subrequests and 6 simultaneous outgoing connections. The extractor therefore avoids crawling and performs only the requests needed to validate DNS/redirects and fetch the source article.

## Rules

- No AI.
- No Workers AI.
- No external article-extraction API.
- No Base44 backend function dependency.
- Returns only `title` + `body` on successful extraction.
- Uses structured extraction first, then HTML article/main/content containers.
- Applies contamination filtering for author/byline, date/time metadata, related articles, CTA text, social/promotional blocks, and navigation.
- Performs URL validation, redirect validation, timeout and response-size checks.
- This is v1.1 and must be tested against real DailyHunt destination URLs before connecting Base44.

## API

### Health

GET `/`

Example response:

```json
{
  "service": "ARTICLE EXTRACTOR",
  "version": "1.0.0",
  "status": "ok",
  "ai": false,
  "extractionApi": false,
  "expectedDailyRequests": 5000,
  "endpoint": "/extract"
}
```

### Extract

POST `/extract`

Body:

```json
{"url":"https://example.com/article"}
```

Success:

```json
{
  "success": true,
  "title": "Article title",
  "body": "Article body"
}
```

Error:

```json
{
  "success": false,
  "code": "INVALID_URL",
  "message": "अमान्य लिंक"
}
```

## Mobile-friendly deployment plan

The project is intended to be uploaded to GitHub first, then connected/deployed through Cloudflare.

Do not change the Base44 app yet.

## Security

- HTTP/HTTPS only
- credentials in URL rejected
- obvious loopback/private/link-local/reserved IP literals blocked
- DNS A/AAAA checks against Cloudflare DNS-over-HTTPS
- every redirect is revalidated
- maximum 5 redirects
- 12-second fetch timeout
- 5 MB source HTML limit
- HTML/XHTML content types only
- no sensitive request-body logging
- no AI or third-party article-extraction service

The DNS check is defense-in-depth, not a claim of perfect DNS-rebinding prevention. Production testing must include redirect and SSRF cases.

## v1.1 limitations

1. Publisher HTML varies widely; extraction quality must be verified on real URLs.
2. The Worker intentionally fails rather than fabricating text when confidence is low.
3. No persistent global daily-request counter is included; the 5,000/day value is a capacity target.
4. No persistent rate-limit database is required for the first standalone test.
5. Before broad public release, add Cloudflare rate limiting/WAF appropriate to the chosen plan.

## Test order

1. Deploy Worker.
2. Open `/` and confirm health JSON.
3. Test `/extract` with real article URLs.
4. Run contamination/security regression tests.
5. Only after successful testing, connect Base44.
6. Keep the old Base44 extraction function as rollback until migration is verified.
