# Release Notes

## Version 1.1.0 (February 2026)

### New Features

- **Triage Prioritization Report** - New risk-based vulnerability triage report
  - Tiered-gates scoring model with additive scoring across reachability, exploitability, and severity
  - Risk bands (CRITICAL ≥ 85, HIGH ≥ 70, MEDIUM ≥ 40, LOW ≥ 25, INFO < 25) for prioritization
  - CVSS vs. Priority Band heatmap visualization
  - Top Riskiest Components analysis
  - Detailed findings table with clickable links to Finite State platform
  - AI-powered remediation guidance (optional, requires `--ai` flag)
  - VEX status recommendations with exportable JSON

- **Clickable Entities in Reports** - Findings, projects, versions, and components in the Triage report link directly to the Finite State platform
  - Finding IDs link to finding detail pages
  - Project names link to project overview
  - Version names link to version overview
  - Components link to Bill of Materials with specific component selected

- **AI Cache Management** - New `--clear-ai-cache` flag to clear AI-generated content (LLM summaries, remediation guidance) independently of API data cache

- **Assessment / Operational Report Classification** - Reports are now formally classified:
  - **Operational** reports (Executive Summary, Scan Analysis, User Activity) are period-bound — `--period` filters data to events within the time window
  - **Assessment** reports (CVA, Findings by Project, Component List, Triage) show current state — `--period` identifies active projects but always shows the latest version
  - New `--detected-after YYYY-MM-DD` flag lets users opt Assessment reports into date filtering
  - Component List no longer applies date filters by default (shows full current inventory)
  - Recipe YAML files include a `category: assessment|operational` field

### Improvements

- **Folder-Scoped Version Filtering** - `--current-version-only` (default) now works correctly with `--folder` scoping, fetching only findings for the latest version of each project
- **Accurate Version Resolution** - Uses `defaultBranch.latestVersion.id` from the project object for authoritative current version detection

### Bug Fixes

- Fixed `--clear-cache` and `--clear-ai-cache` not working when both specified together
- Fixed controlled exit errors showing unnecessary stack traces
- Fixed component deep links using wrong ID (now uses `vcId` for version-specific BOM links)
- Fixed SQLite cache not preserving `component.vcId` field

---

## Version 1.0.5 (February 2026)

### New Features

- **Persistent Cache (Beta)** - Dramatically faster report generation when running multiple times
  - Cache your API data and reuse it across runs with `--cache-ttl 1h` (or `30m`, `1d`, etc.)
  - Reduces storage by ~80% compared to previous caching
  - Automatic crash recovery - interrupted fetches resume where they left off
  - Default behavior unchanged - fresh data fetched each run unless you opt-in

- **New Cache Control Flags**:
  - `--cache-ttl DURATION` - Enable persistent cache (e.g., `--cache-ttl 1h`)
  - `--no-cache` - Force fresh data fetch, ignore any cached data
  - `--clear-cache` - Delete all cached data and exit

---

## Version 1.0.4 (February 2026)

### Important Changes

- **Faster Default Performance** - Reports now default to analyzing only the latest version of each project
  - Reduces data volume by 60-70% for most portfolios
  - Use `--all-versions` flag if you need historical data from all versions

### Improvements

- **Scan Analysis Report**: Improved failure visualization
  - New time-series chart showing failure trends by scan type
  - Easier to identify problematic periods and scan types

### Bug Fixes

- Fixed success rate calculation to show actual success rate
- Fixed date filtering for several Scan Analysis metrics

---

## Version 1.0.3 (February 2026)

### Important Changes

- **Better Vulnerability Coverage** - Findings reports now show ALL current findings for recently-scanned projects
  - Previously only showed newly-detected findings during the period
  - Now shows complete vulnerability picture for any project scanned in your date range

### Bug Fixes

- Fixed Open Issues count in Executive Summary (now includes un-triaged findings)

---

## Version 1.0.2 (February 2026)

### New Features

- **Finding Type Filter** - Control which findings appear in reports
  - New `--finding-types` flag (default: `cve` for vulnerabilities only)
  - Options: `cve`, `sast`, `thirdparty`, `credentials`, `config_issues`, `crypto_material`, `all`
  - Example: `--finding-types cve,credentials`

### Improvements

- Component List report now excludes placeholder FILE components for cleaner output

---

## Version 1.0.1 (February 2026)

### Bug Fixes

- Fixed date filtering for Executive Summary, CVA, and Findings by Project reports
- Component List now respects date range filters

---

## Version 1.0.0 (February 2026)

### First Stable Release

Complete reporting solution with 6 report types:
- **Executive Summary** - High-level security posture overview
- **Component Vulnerability Analysis (CVA)** - Detailed component risk analysis
- **Findings by Project** - Project-level vulnerability breakdown
- **Scan Analysis** - Operational metrics and scan throughput
- **Component List** - Complete software inventory
- **User Activity** - Platform usage and engagement tracking

---

## Version 0.9.0 (January 2026)

### Scan Analysis Enhancements

- Version tracking to identify which project versions were scanned
- New/Existing project classification
- Failure type distribution chart
- Moving average trendlines for trend analysis

---

## Version 0.2.0 (January 2026)

### New Reports

- **Component List** - Comprehensive inventory of all software components
- **User Activity** - Platform usage tracking and engagement metrics

### CLI Improvements

- Portfolio-wide version listing without specifying a project
- `--top N` option to show only top N projects

---

## Version 0.1.x (October 2025)

### Initial Release

- Core reporting infrastructure
- Four initial report types: CVA, Executive Summary, Findings by Project, Scan Analysis
- Multiple output formats: CSV, XLSX, HTML
- Docker support
