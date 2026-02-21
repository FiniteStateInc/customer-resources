# Release Notes

## Version 1.5.3 (February 2026)

### New Features

- **VEX Import** — Apply VEX triage recommendations directly from the CLI with `fs-report run --apply-vex-triage recommendations.json`. Supports `--dry-run` for previewing changes, `--filter-band CRITICAL` to limit scope, and `--vex-concurrency` for throughput control. Use `--autotriage` to generate a Triage report and apply recommendations in one step.
- **Custom logo support** — Add your organization's logo to all HTML reports with `--logo path/to/logo.png`, via the web UI settings page, or in your config file.
- **AI guidance in CSV/XLSX** — Triage Prioritization CSV and XLSX exports now include `ai_fix_version`, `ai_guidance`, `ai_workaround`, and `ai_confidence` columns when `--ai` is enabled.

### Improvements

- **Rationalized CSV/XLSX column ordering** — All tabular reports now follow a consistent layout: identity columns first, then severity/risk, triage outputs, context, threat intel, and wordy/internal columns last. This makes CSV and XLSX exports easier to scan and more consistent across reports.
- **Smarter AI guidance** — NVD fix version data and component-level AI guidance now cascade upward into project and portfolio prompts, producing more grounded remediation advice. Component ranking uses multi-signal scoring (CRITICAL/HIGH count + score sum). Per-finding guidance covers the top 100 findings.

### Bug Fixes

- **CVE Impact version scoping** — Fixed a bug where CVE reachability data included findings from all versions instead of just the latest version per project.
- **AI parser hardening** — Fixed a parser bug where LLM output after the CONFIDENCE field corrupted results. Confidence values are now validated to known levels (high/medium/low).
- **Scan queue stability** — Fixed a rate-limit spiral in the scan queue monitor that could cause cascading 429 errors.

---

## Version 1.5.2 (February 2026)

### New Features

- **Scan Queue dashboard** — Live scan monitoring panel in the web UI showing queued/processing counts, per-version grouping, stuck scan detection, and auto-refresh every 30 seconds.
- **Configurable AI models** — `--ai-model-high` / `--ai-model-low` CLI flags and `ai_model_high` / `ai_model_low` config keys let users override default LLM models per provider.

### Bug Fixes

- **Triage reachability regression** — Reachability labels no longer replaced with UNKNOWN in HTML reports (DataFrame mutation in `_prepare_table_data` now operates on a copy).
- **Stable model alias IDs** — Prevent 404 errors when Anthropic retires date-pinned model versions.
- **SQLite cache preserves nested reachability data** — Alternate API format with nested reachability fields is now correctly persisted.
- **`serve` command accepts `--port` in any position** — Interspersed argument parsing fixed.
- **Fixed infinite recursion in `_design_system.html`** — Template include loop resolved.

---

## Version 1.5.0 (February 2026)

### New Features

- **Executive Dashboard** — 11-section executive-level security report with KPI cards, findings by folder/project, severity trends, risk donut, open issues, license distribution, exploit intelligence, findings by type, finding age, and project table. Supports portfolio-wide and `--folder`-scoped views. HTML-only output.

### Improvements

- **Enhanced web UI** — Directory browser, scope dropdowns, and improved dashboard layout.
- **Exploit intelligence refactored** — Derived from findings-level booleans (KEV, Known Exploits) instead of a separate CVE fetch, significantly improving performance.
- **Scoped component fetch** — Prevents timeout on large portfolios by scoping component queries to relevant projects.

### Bug Fixes

- **Combined finding-types filter** — `--finding-types cve,sast` now works correctly when multiple types are specified.
- **Date validation and XLSX rendering errors** — Resolved timezone-aware datetime comparisons and Excel formatting issues.
- **Jira "not configured" notice** — Only shown on reports that actually use Jira integration.

---

## Version 1.4.2 (February 2026)

### Improvements

- **Cross-directory report history** — Report history is now shared across working directories.
- **Reports UI distinguishes file types** — HTML, CSV, and XLSX files are visually differentiated in the reports browser.
- **View Report button** — Links directly to the generated file after a run.
- **Middleware hardening** — Improved security and error handling in web middleware.

### Bug Fixes

- **Jira integration fixes** — Resolved issues with Jira ticket creation and session management.
- **Relative path resolution** — `generated_files` paths are now resolved before being recorded in history.

---

## Version 1.4.0 (February 2026)

### Improvements

- **Enhanced logging and session management** — Improved logging utilities and web session handling.
- **Updated report command syntax** — CLI commands updated to use `fs-report run` subcommand pattern consistently.

---

## Version 1.3.2 (February 2026)

### Bug Fixes

- **Token login in web UI** — The setup wizard now correctly persists the API token to `~/.fs-report/config.yaml`. Previously the token was set in memory but never saved to disk, causing the setup to loop.
- **Cancel button during NVD lookups** — Cancel now responds within ~0.5 seconds regardless of where the run is in the NVD fetch cycle. Previously, cancel was ignored until all NVD API calls completed (potentially 10+ minutes without an API key).

### Improvements

- **Direct report linking** — After a successful single-recipe run, the "View Report" button opens the generated HTML directly instead of navigating to the reports listing page.
- **One-line curl installer** — Customers can install with a single command: `bash -c "$(curl -fsSL https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/05-reporting-and-compliance/fs-report/setup.sh)"`

### New Features

- **Changelog CLI** — `fs-report changelog` shows per-report change history with optional `--report` filter.
- **Upgrade notification** — A one-line notice appears after CLI runs when a newer PyPI version is available.

---

## Version 1.3.0 (February 2026)

### New Features

- **Web UI** — Launch with bare `fs-report` to open an interactive browser-based interface
  - Dashboard with workflow cards for common report scenarios
  - Real-time progress streaming during report generation
  - Settings management and reports browser
  - Runs on `http://localhost:8321` with CSRF protection

- **CLI v2 — Organized command groups** for better discoverability
  - `fs-report run` — generate reports (all existing flags work)
  - `fs-report list {recipes,projects,folders,versions}` — explore resources
  - `fs-report cache {clear,status}` — manage cached data
  - `fs-report config {init,show}` — manage configuration
  - `fs-report serve [directory]` — serve reports via local HTTP server
  - Old command names (`list-recipes`, `show-periods`, bare `fs-report --recipe ...`) still work

- **Config file support** — Set defaults in `.fs-report.yaml` or `~/.fs-report/config.yaml`
  - Create interactively: `fs-report config init`
  - View resolved config: `fs-report config show`
  - Priority: CLI flags > environment variables > config file > defaults

- **Enhanced Findings by Project report** — 7 new columns for richer vulnerability context
  - Severity (color-coded badge), Description (from NVD), CVSS v2/v3 Vector strings
  - NVD URL and FS Link for direct navigation to NVD and Finite State platform
  - CVE details fetched in parallel with deduplication (1 API call per unique CVE)

### Changes

- Default invocation (`fs-report` with no arguments) now launches the web UI instead of the TUI
- TUI moved to optional dependency (`poetry install --with tui`)
- Version bumped to 1.3.0

---

## Version 1.1.4 (February 2026)

### New Features

- **CVE Impact Report** - Investigate specific CVEs across your portfolio with detailed dossiers
  - See which projects are affected, with per-project reachability status, known exploits, EPSS scores, and CWE details
  - Single CVE analysis: `--cve CVE-2024-1234`
  - Multi-CVE analysis: `--cve CVE-2024-1234,CVE-2024-5678`
  - Narrow to one project: `--cve CVE-2024-1234 --project myproject`
  - AI prompt export: Use `--ai-prompts` to generate structured LLM prompts alongside the report (no API key required)
  - AI remediation guidance: Use `--ai` for live AI-powered remediation advice (requires `ANTHROPIC_AUTH_TOKEN`)

### Improvements

- **Faster CVE queries** - Portfolio-level CVE data is now fetched via a single optimized query instead of per-version batching
- **Finding titles in cache** - The `title` field is now persisted in the SQLite cache (existing caches auto-migrate)

---

## Version 1.1.2 (February 2026)

### Improvements

- **Large instance stability** - Reports with 1M+ findings no longer crash due to memory exhaustion
- **Improved API throttling** - Smarter batch cooldowns prevent server overload (500/502/503 errors) on large instances
- **Dramatically reduced cache size** - Cache files are ~97% smaller, improving disk usage and startup time
- **Faster version resolution** - Project version lookup now uses a single batch call instead of per-project requests

### New Features

- `--batch-size` flag (1-25, default 5) to control how many project versions are fetched per API batch. Lower values reduce server load on large instances.

### Bug Fixes

- `--clear-cache` now properly reclaims disk space (previously the database file remained large after clearing)

---

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
