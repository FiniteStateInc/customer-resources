# Performance Guide

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
poetry run fs-report --period 1w

# Include all historical versions when needed
poetry run fs-report --period 1w --all-versions
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
- **SQLite Progress Tracking**: Large datasets use SQLite for crash recovery

### Performance Benefits

- **Reduced API Calls**: Up to 67% reduction when running multiple reports
- **Faster Execution**: Subsequent reports run much faster
- **Reduced Data Transfer**: Less bandwidth usage
- **Better Reliability**: Resume capability for large reports

### Monitoring Cache Usage

Use `--verbose` to see detailed cache information:

```bash
poetry run fs-report --verbose
```

Look for these indicators:
- `Cache hit for /public/v0/findings:...` - Data found in cache
- `Using cached data for /public/v0/findings (X records)` - Using cache
- `Using cache for /public/v0/findings` - Progress bar shows cache usage

## Filtering Performance

### Project and Version Filtering

- **API-Level Filtering**: Filters applied at API level, not in memory
- **Reduced Data Transfer**: Only relevant data is fetched
- **Consistent Results**: All reports use the same filtered dataset

### Best Practices

1. **Use Specific Filters**: Narrow down data with project/version filters
2. **Run Multiple Reports**: Take advantage of cache sharing
3. **Monitor Progress**: Use verbose mode to see cache usage
4. **Resume Interrupted Reports**: Don't restart from scratch

## [BETA] SQLite Cache with TTL

For long-running reports or iterative development, the SQLite cache provides persistent storage with crash recovery.

### When to Use `--cache-ttl`

| Scenario | Recommendation |
|----------|---------------|
| Quick ad-hoc report | No flag needed (default) |
| Full portfolio, risk of interruption | `--cache-ttl 1h` |
| Iterating on recipe development | `--cache-ttl 1d` |
| CI/CD scheduled runs | `--cache-ttl 30m` |
| Debugging stale data issues | `--no-cache` |
| Cache corruption | `--clear-cache` |

### Usage

```bash
# Enable persistent cache with 1-hour TTL
poetry run fs-report --cache-ttl 1h

# Other TTL formats: 30m, 2h, 1d, 1w
poetry run fs-report --cache-ttl 30m

# Force fresh data (ignore any cached data)
poetry run fs-report --no-cache

# Clear all cached data and exit
poetry run fs-report --clear-cache
```

### Benefits Over JSON Progress Files

- **80% smaller storage**: Only essential fields are stored
- **Automatic crash recovery**: Progress tracked in SQLite, not JSON
- **Cross-run caching**: Reuse data within TTL window
- **No manual cleanup**: Cache expires automatically

### Cache Location

- Default: `~/.fs-report/cache.db`

---

## Progress Tracking and Recovery

### How It Works

Progress is now tracked in SQLite (when `--cache-ttl` is set) for better crash recovery:

- **Automatic Resume**: Interrupted fetches resume from the last saved offset
- **No Data Loss**: Partial results are preserved
- **Smaller Storage**: Only essential fields stored (80% reduction)

### Using Progress Recovery

```bash
# If a report is interrupted, simply rerun the same command
poetry run fs-report --period 1w --cache-ttl 1h

# The tool automatically resumes from where it left off
# Look for: "Resuming from offset X, Y records already fetched"
```

### Legacy JSON Progress Files (Deprecated)

JSON progress files (`*_progress.json`) are deprecated. If you have old progress files:

```bash
# Remove legacy progress files
rm ~/reports/*_progress.json

# Use SQLite cache instead
poetry run fs-report --cache-ttl 1h
```

## Performance Tips

### 1. Use Appropriate Date Ranges

```bash
# Good: Specific date range
poetry run fs-report --start 2024-01-01 --end 2024-01-31

# Better: Use period shortcuts for recent data
poetry run fs-report --period 1m
poetry run fs-report --period 7d
```

### 2. Filter by Project When Possible

```bash
# Good: All projects
poetry run fs-report --period 1w

# Better: Specific project
poetry run fs-report --period 1w --project "MyProject"
```

### 3. Run Multiple Reports Together

```bash
# Efficient: Run all reports together to share cache
poetry run fs-report --period 1w --recipe "Executive Summary" --recipe "Component Vulnerability Analysis" --recipe "Findings by Project"

# Less efficient: Run reports separately
poetry run fs-report --period 1w --recipe "Executive Summary"
poetry run fs-report --period 1w --recipe "Component Vulnerability Analysis"
poetry run fs-report --period 1w --recipe "Findings by Project"
```

### 4. Monitor Performance

```bash
# Use verbose mode to see cache usage and performance
poetry run fs-report --verbose --period 1w
```

## Troubleshooting Performance Issues

### Slow Report Generation

1. **Check Network**: Ensure stable internet connection
2. **Use Filters**: Narrow down data with project/version filters
3. **Check Progress Files**: Resume interrupted reports instead of restarting
4. **Monitor Cache**: Use verbose mode to see cache usage

### High API Usage

1. **Run Reports Together**: Take advantage of cache sharing
2. **Use Specific Filters**: Reduce data transfer with project/version filters
3. **Check Date Ranges**: Use appropriate time periods
4. **Resume Interrupted Reports**: Don't restart from scratch

### Memory Issues

1. **Use Project Filters**: Reduce dataset size
2. **Check Progress Files**: Resume instead of restarting
3. **Monitor Verbose Output**: Watch for memory-related messages

## Performance Metrics

### Typical Performance Improvements

- **Cache Sharing**: 67% reduction in API calls when running multiple reports
- **Resume Capability**: 50-90% time savings when resuming interrupted reports
- **API-Level Filtering**: 80-95% reduction in data transfer with project filters
- **Progress Files**: Eliminate redundant API calls for large datasets

### Example Performance Comparison

**Without Optimizations:**
```
Executive Summary: 2 API calls (178,375 + 8,338 records)
CVA: 2 API calls (178,375 + 11,424 records)
Findings by Project: 2 API calls (178,375 + 8,338 records)
Total: 6 API calls, ~2GB+ data transfer
```

**With Optimizations:**
```
Executive Summary: 1 API call (38,879 records)
CVA: Uses cache
Findings by Project: Uses cache
Total: 1 API call, minimal data transfer
```

This represents a **83% reduction** in API calls and **95% reduction** in data transfer.
