# Performance Guide

## Executive Dashboard: Summary Mode (Default)

Starting in v1.9.6, Executive Dashboard runs in **summary mode** by default. Instead of fetching every finding in the portfolio, summary mode composes the dashboard from platform summary-count endpoints (`/findings/summary-counts`, version history, policy rollups).

### When to use each mode

| Mode | How it fetches | What you give up |
|------|----------------|------------------|
| Summary (default) | Platform count rollups; no per-finding fetch | Severity-over-time split into Critical/High lines; per-finding detection-date age histogram |
| `--detailed` | Full per-finding pipeline (legacy) | Slower on large portfolios |

### Semantic differences in summary mode

- **Severity Trends** plots a single *Total Findings* line from month-end version inventory. Per-severity Critical/High lines require `--detailed`.
- **Finding Age** buckets by the age of the version the finding lives in, not per-finding detection date.
- **Open Issues** panel is renamed *Findings by Triage Status* and shows all 7 VEX statuses.
- **Exploit Intelligence** expands from 2 bars (KEV, Known Exploits) to 9 categories.

### Usage

```bash
# Default: summary mode
fs-report run --recipe "Executive Dashboard" --output ./reports

# Legacy per-finding pipeline
fs-report run --recipe "Executive Dashboard" --detailed --output ./reports
```

---

## Version Filtering (Default: Latest Only)

By default, fs-report only fetches findings from the **latest version** of each project. This dramatically improves performance for large portfolios.

### Why This Matters

| Mode | Data Volume | Speed | Use Case |
|------|-------------|-------|----------|
| `--current-version-only` (default) | 60-70% less | Fast | Current security posture |
| `--all-versions` | Full historical | Slower | Trend analysis, audits |

### Usage

```bash
# Default: Latest version only (recommended for most use cases)
fs-report run --period 1w

# Include all historical versions when needed
fs-report run --period 1w --all-versions
```

---

## Caching System

The reporting kit includes an intelligent caching system that significantly improves performance when running multiple reports.

### How It Works

1. **First Report**: Makes API calls and caches the data
2. **Subsequent Reports**: Use cached data when possible
3. **Progress Indicators**: Clear visual feedback about cache usage

### Cache Behavior

- **Same Filter = Same Cache**: Reports with identical filters share cache
- **Automatic Invalidation**: Cache is cleared between different filter combinations
- **Complete Fetches Only**: With `--cache-ttl`, a fetch is cached only once it completes, so an interrupted run never leaves a partial result behind

### Performance Benefits

- **Reduced API calls** when several recipes share the same scope and run in one invocation (the underlying `/findings` fetch is shared)
- **Faster subsequent reports** that reuse already-fetched pages
- **Lower bandwidth** for the second and later recipes in a multi-recipe run
- **Less rework after an interruption**: fetches that completed before it (e.g. finished version batches of a portfolio sweep) are reused

### Monitoring Cache Usage

Use `--verbose` to see detailed cache information:

```bash
fs-report run --verbose
```

Look for these indicators:
- `Cache hit for /public/v0/findings:...` - Data found in cache
- `Using cached data for /public/v0/findings (X records)` - Using cache
- `Using cache for /public/v0/findings` - Progress bar shows cache usage

### Per-Version SBOM Group Lookup Cache

License Report, Component List, and Findings by Project cache per-version CycloneDX SBOM group lookups (raw cache key `sbom_group_lookup:{version_id}`) with a dedicated 7-day TTL that is independent of `--cache-ttl` and fingerprint-invalidated whenever the version's component inventory changes (a metadata-only rescan on an unchanged inventory refreshes via the 7-day TTL, or immediately with `--refresh`). Caching activates whenever a cache exists (any `--cache-ttl > 0`; the web UI defaults to 4h), so repeat portfolio runs skip redundant full-SBOM downloads — the first run still costs one SBOM download per version. The run log prints a line like `SBOM group enrichment: N SBOM(s) fetched, M version(s) served from cache`.

## Filtering Performance

### Project and Version Filtering

- **API-Level Filtering**: Filters applied at API level, not in memory
- **Reduced Data Transfer**: Only relevant data is fetched
- **Consistent Results**: All reports use the same filtered dataset

### Best Practices

1. **Use Specific Filters**: Narrow down data with project/version filters
2. **Run Multiple Reports**: Take advantage of cache sharing
3. **Monitor Progress**: Use verbose mode to see cache usage
4. **Re-run With The Same `--cache-ttl`**: completed fetches are reused instead of fetched again

## [BETA] SQLite Cache with TTL

For long-running reports or iterative development, the SQLite cache keeps completed fetches across runs, so a re-run or a related report reuses them.

### When to Use `--cache-ttl`

| Scenario | Recommendation |
|----------|---------------|
| Quick ad-hoc report | No flag needed (default) |
| Full portfolio, risk of interruption | `--cache-ttl 1h` |
| Iterating on recipe development | `--cache-ttl 1d` |
| CI/CD scheduled runs | `--cache-ttl 30m` |
| Debugging stale data issues | `--no-cache` |
| Cache corruption | `fs-report cache clear --api` |

### Usage

```bash
# Enable persistent cache with 1-hour TTL
fs-report run --cache-ttl 1h

# Other TTL formats: 30m, 2h, 1d, 1w
fs-report run --cache-ttl 30m

# Force fresh data (ignore any cached data)
fs-report run --no-cache

# Clear the API data cache for this domain (what a bare `cache clear` does,
# without its confirmation prompt)
fs-report cache clear --api
```

### Benefits Over JSON Progress Files

- **80% smaller storage**: Only essential fields are stored
- **Safe under interruption and concurrency**: only complete fetches are cached, and two runs fetching the same data never overwrite each other's entry
- **Cross-run caching**: Reuse data within TTL window
- **No manual cleanup**: Cache expires automatically

### Cache Location

- `~/.fs-report/<domain>-<account digest>.db` (e.g. `your-domain.finitestate.io-0123456789abcdef.db`) — one file per platform domain and account. `fs-report cache status` prints the exact path.

---

## Interrupted and Concurrent Runs

### How It Works

With `--cache-ttl` set, each paginated fetch **claims** its cache entry and
keeps a heartbeat on it while it pages:

- **An interrupted fetch starts again from the first page.** Nothing from a
  fetch that did not finish is cached, so the next run never serves a partial
  result as complete. Fetches that *did* complete before the interruption — for
  example the finished version batches of a portfolio sweep — are cache hits on
  the re-run, which is where the time is saved.
- **Two runs at once are safe.** A run that finds another run's live fetch of
  the same data fetches on its own, without the cache, instead of touching the
  first run's rows. A claim whose heartbeat has been quiet for 10 minutes (its
  run was killed) is treated as abandoned.

Fetches are deliberately not resumed mid-way: stitching together two snapshots
of an offset-paginated API taken minutes or hours apart can skip records with
no error.

```bash
# If a report is interrupted, rerun the same command with the same TTL;
# completed fetches are reused, the interrupted one is fetched again
fs-report run --period 1w --cache-ttl 1h
```

### Legacy JSON Progress Files (Deprecated)

JSON progress files (`*_progress.json`) are deprecated. If you have old progress files:

```bash
# Remove legacy progress files
rm ~/reports/*_progress.json

# Use SQLite cache instead
fs-report run --cache-ttl 1h
```

## Performance Tips

### 1. Use Appropriate Date Ranges

```bash
# Good: Specific date range
fs-report run --start 2024-01-01 --end 2024-01-31

# Better: Use period shortcuts for recent data
fs-report run --period 1m
fs-report run --period 7d
```

### 2. Filter by Project When Possible

```bash
# Good: All projects
fs-report run --period 1w

# Better: Specific project
fs-report run --period 1w --project "MyProject"
```

### 3. Run Multiple Reports Together

```bash
# Efficient: Run all reports together to share cache
fs-report run --period 1w --recipe "Executive Summary" --recipe "Component Vulnerability Analysis" --recipe "Findings by Project"

# Less efficient: Run reports separately
fs-report run --period 1w --recipe "Executive Summary"
fs-report run --period 1w --recipe "Component Vulnerability Analysis"
fs-report run --period 1w --recipe "Findings by Project"
```

### 4. Monitor Performance

```bash
# Use verbose mode to see cache usage and performance
fs-report run --verbose --period 1w
```

## Troubleshooting Performance Issues

### Slow Report Generation

1. **Check Network**: Ensure stable internet connection
2. **Use Filters**: Narrow down data with project/version filters
3. **Re-run With The Same `--cache-ttl`**: an interrupted run reuses the fetches that completed
4. **Monitor Cache**: Use verbose mode to see cache usage

### High API Usage

1. **Run Reports Together**: Take advantage of cache sharing
2. **Use Specific Filters**: Reduce data transfer with project/version filters
3. **Check Date Ranges**: Use appropriate time periods
4. **Re-run With The Same `--cache-ttl`**: completed fetches are not fetched again
5. **Tune throughput**: `--batch-size N` (project versions per batch, default 5, max 25) and `--request-delay S` (seconds between requests, default 0.5) trade speed against server load. Lower the delay / raise the batch size to go faster on a healthy server; raise the delay if you hit rate limits.
6. **Skip NVD enrichment**: `--no-nvd` avoids per-CVE NVD lookups when you don't need enriched descriptions.
7. **VEX apply throughput**: VEX application (Autotriage / bulk apply) uses the platform's native bulk-set endpoint (`PUT /public/v0/findings/{projectVersionId}/status/set/bulk`) for integer-ID findings; `--vex-concurrency N` (1-5, default 5) meters parallel VEX-apply work units — concurrent bulk batches plus single-PUT fallbacks for UUID/non-integer IDs — not per-finding requests. The CLI VEX summary reports throughput as items/s. `--batch-size` and `--request-delay` are fetch-side levers and do not affect VEX-apply throughput.

### Gateway Timeouts (HTTP 504)

A 504 whose body says the backend query timed out (`Database query timed out.
Try narrowing the request or retrying.`) means the requested page is too
expensive for the server, not that it is busy. fs-report answers it by
**narrowing the page** — 10,000 → 5,000 → 2,000 → 1,000 rows — immediately,
and remembers the smaller size for that endpoint for the rest of the run. If
even 1,000 rows times out it makes two paced retries and then stops with an
error naming the offset and quoting the server's response, which carries a
`requestId`, after about 90 seconds of
waiting (plus the time each timed-out request takes). Other 5xx and 429
responses keep the patient backoff, since for a busy server waiting is the
right response.

If a run still stops on this error, narrow the scope yourself — a single
`--version` instead of `--all-versions`, a `--project` or `--folder`, or
`--finding-types cve` — and report the `requestId` from that error to Finite State.

### Memory Issues

1. **`--low-memory`**: the primary lever — drops heavy columns and skips HTML/XLSX rendering to keep peak RSS down on large portfolios.
2. **Use Project Filters**: Reduce dataset size
3. **Lower `--batch-size`**: fewer versions fetched per batch means less data held in memory at once
4. **Re-run With The Same `--cache-ttl`**: completed fetches are reused
5. **Monitor Verbose Output**: Watch for memory-related messages

## Order-of-Magnitude Expectations

These numbers come from internal portfolio runs and vary widely by tenant size, scope, and network. Treat as ballpark, not guarantees.

- **Cache sharing across recipes in one invocation**: substantial — the per-finding fetch happens once and is reused. Two or three recipes in one command typically run nearly as fast as one.
- **Re-run after an interruption (`--cache-ttl`)**: skips every fetch that completed before it; the fetch that was interrupted is fetched again from the start.
- **Project / version scoping at the API level**: cuts data transfer by however much narrower the scope is than the full portfolio (often 1–2 orders of magnitude for a single project on a large portfolio).
- **`--current-version-only` (default)**: skips historical version findings; on a portfolio with many versions per project, this is typically a multi-x reduction over `--all-versions`.

If you want concrete numbers for your portfolio, run with `--verbose` and compare a cold run to a warm cache-hit run.
