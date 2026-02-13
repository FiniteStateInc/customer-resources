# API Enhancements to Support Large-Instance Reporting

**Priority:** High
**Labels:** api, performance, scalability

---

## Context

The `fs-report` CLI tool generates portfolio-level reports (Findings by Project, Triage Prioritization, Component List, etc.) by fetching data from the public API. On large instances like Netgear (~450 projects, 2,000-4,000 findings each, ~1.2M total findings), the tool:

- Must fetch **all findings across all project versions** — there is no server-side aggregation
- Receives massive JSON payloads because every finding includes the full `factors` array regardless of whether the report needs it
- Overwhelms the server with sequential paginated requests, causing repeated **500/502/503 errors** and pod restarts
- Takes **4+ hours** to complete (if it completes at all)

## Data from Netgear Instance Investigation

| Metric | Value |
|--------|-------|
| Projects | 450 |
| Project versions to fetch | 378 |
| Total findings | ~1.2 million |
| Avg findings per version | ~3,300 |
| Raw API response size (all findings) | **~8-9 GB** |
| `factors` field alone | **~97% of that payload** |
| Single largest `factors` value | 7.6 MB (104 entries x 367 binary paths each) |
| Reports that actually use `factors` | 1 of 8 (Triage Prioritization) |

---

## Short-Term Requests (Things That Could Help Us Right Now)

### 1. Sparse Field Selection on `/findings` Endpoint

**Request:** Support a `fields` query parameter (e.g., `?fields=id,severity,status,risk,component,project,projectVersion,cwes,inKev,epssPercentile`) that limits which fields are included in the response.

**Why:** The "Findings by Project" report needs ~10 fields. It does not need `factors`, `exploitInfo`, `attackVector`, or `reachabilityScore`. Excluding `factors` alone would reduce the Netgear response from ~8 GB to ~200 MB — a **97% reduction** in data transfer and server-side serialization work.

**Alternatively:** A `?exclude=factors` parameter or a `?detailed=false` flag that omits heavy nested fields would achieve the same goal.

### 2. `Retry-After` Header on 429/503 Responses

**Request:** Return a `Retry-After` header (in seconds) on rate-limited (429) and overloaded (503) responses.

**Why:** We currently guess backoff durations (30s, 60s, 90s, 120s). If the server told us exactly when to retry, we could avoid both under-waiting (causing more failures) and over-waiting (wasting time). The API already returns 429 on rate limits but without `Retry-After`.

### 3. `X-RateLimit-Remaining` / `X-RateLimit-Reset` Response Headers

**Request:** Include standard rate-limit headers on all responses so clients can self-throttle proactively.

**Why:** We currently use fixed inter-request delays and adaptive cooldowns based on observing failures. With remaining-quota headers, we could pace requests precisely — fetching fast when headroom exists and slowing down before hitting the limit, instead of after.

### 4. Lightweight `factors` Mode

**Request:** A query parameter like `?factors_detail=summary` that returns trimmed factor objects containing only `entity_type`, `entity_name`, `summary`, and `score_change` — omitting the `details` sub-object entirely.

**Why:** The `details` object contains lists of every binary path in the firmware image (`stripped_bins`, `non_stripped_bins`, `component_files`, etc.), often 100-367 paths at ~200 chars each, **duplicated identically across every factor entry in the same finding**. A single finding can have 104 factor entries each with the same 367 paths = 7.6 MB. The summaries and entity names alone are ~15 KB for that same finding. We currently trim these client-side before caching, but the server still has to serialize and transmit them.

---

## Long-Term Requests (Things That Would Make Portfolio Reporting Dramatically More Efficient)

### 5. Server-Side Aggregation Endpoint for Findings

**Request:** An endpoint like `GET /findings/summary?groupBy=project` that returns pre-aggregated counts:

```json
[
  {
    "projectId": "123",
    "projectName": "Router-FW",
    "critical": 42,
    "high": 156,
    "medium": 891,
    "low": 2034,
    "total": 3123
  }
]
```

**Why:** The "Findings by Project" report fetches **1.2 million individual finding records** across 378 API calls just to count them by severity per project. A single aggregation query could replace all of that with one small response. This is the single biggest efficiency win possible — it would reduce the Netgear report from 4+ hours to seconds.

### 6. Delta/Incremental Fetching

**Request:** Support a `?modifiedSince=<ISO timestamp>` parameter on `/findings` that returns only findings created or updated after the given time.

**Why:** With `--cache-ttl`, subsequent report runs currently re-fetch everything from scratch when the cache expires. If the API supported delta queries, a 24-hour refresh would only need to fetch the handful of findings that changed, not all 1.2 million. This would make daily scheduled reports practical on large instances.

### 7. Cursor-Based Pagination

**Request:** Support cursor-based pagination (`?cursor=<opaque token>`) as an alternative to offset-based (`?offset=N`).

**Why:** Offset-based pagination becomes inefficient at high offsets (the server must skip N rows). For a version with 6,000 findings at limit=10,000 this isn't a problem, but if we ever need smaller page sizes to reduce per-request memory, offset pagination will degrade. Cursor-based pagination is O(1) regardless of position.

### 8. Compressed Responses (gzip/brotli)

**Request:** Support `Accept-Encoding: gzip` on API responses.

**Why:** The findings JSON is highly compressible (repetitive field names, similar values across findings). Gzip typically achieves 5-10x compression on JSON, which would reduce the ~8 GB Netgear payload to ~1 GB on the wire, significantly reducing transfer time and server egress load. (This may already be handled by the reverse proxy — if so, just confirming it's enabled for the API endpoints would be helpful.)

---

## Summary of Impact

| Request | Effort | Impact on Netgear |
|---------|--------|-------------------|
| Field selection (#1) | Medium | 8 GB -> 200 MB transfer |
| Retry-After headers (#2) | Low | Eliminates retry guessing |
| Rate-limit headers (#3) | Low | Enables proactive throttling |
| Lightweight factors (#4) | Medium | 8 GB -> ~500 MB (if factors needed) |
| Aggregation endpoint (#5) | High | 4 hours -> seconds for most reports |
| Delta fetching (#6) | High | Subsequent runs: minutes instead of hours |
| Cursor pagination (#7) | Medium | Future-proofing for large datasets |
| Compressed responses (#8) | Low | 5-10x wire reduction |
