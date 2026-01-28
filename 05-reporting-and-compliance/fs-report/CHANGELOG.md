# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2026-01-28

### Enhanced
- **Scan Analysis Report**: Major enhancements for operational insights
  - **Version Tracking**: Added version column to identify which project version was scanned (helps detect duplicate binary submissions vs multiple versions)
  - **Unique Projects/Versions**: New metrics showing distinct projects and versions processed per day
  - **New vs Existing Projects**: Tracks whether scans are going into newly created projects (within report period) or existing projects (created before report period)
  - **Failure Type Distribution**: New pie chart showing which scan types fail most frequently
  - **Moving Average Trendlines**: Adaptive 7-day or 14-day moving averages on throughput chart (dashed lines) for trend analysis
  - **Project Data Integration**: Fetches project creation dates for accurate new/existing classification

### Technical Details
- Added `project_list_query` field to Recipe model for multi-query recipes
- Updated `report_engine.py` to fetch project data for Scan Analysis
- Updated project query limits to 10,000 for portfolio-scale operations
- Enhanced `scan_analysis.py` transform with version extraction and new/existing project classification

## [0.2.0] - 2026-01-20

### Added
- **Component List Report**: New recipe for comprehensive inventory of software components
  - Lists all components across the portfolio with project, version, and branch details
  - Supports filtering by project and version
  - Includes license information, findings count, warnings, and violations
  - Output formats: CSV, XLSX, HTML
  
- **User Activity Report**: New recipe for tracking platform usage and user engagement
  - Tracks unique active users per day from audit trail events
  - Calculates average daily users and days with activity
  - Shows activity breakdown by event type (pie chart)
  - Identifies most active users (bar chart)
  - Daily activity trend with dual-axis chart for users and events
  - Recent activity log with user, event type, and timestamp

- **Portfolio-Wide Version Listing**: Enhanced `list-versions` CLI command
  - Now supports running without a project argument to list all versions across portfolio
  - Added `--top` / `-n` option to show only top N projects by version count
  - Added progress bar with `tqdm` for long-running portfolio scans
  - Improved error handling with automatic retries for rate limits and timeouts
  - Added 100ms delay between API calls to prevent rate limiting

### Technical Details
- New transforms: `component_list_pandas_transform`, `user_activity_pandas_transform`
- New templates: `component_list.html`, `user_activity.html`
- Updated `report_engine.py` to handle component filtering and audit date filtering
- Enhanced CLI with `tenacity` retry logic for robustness

## [0.1.1] - 2025-10-24

### Fixed
- **Scan Analysis Report**: Fixed incorrect queue size and failure metrics
  - INITIAL scans are now correctly classified as failed attempts rather than "waiting" scans
  - Queue size now only shows STARTED scans (actually processing)
  - Failed scans now includes both ERROR status scans and INITIAL scans (failed attempts)
  - Daily metrics now consistently reflect the corrected scan lifecycle logic
  - Summary cards updated to show accurate "Queue Size" and "Failed Scans" counts

### Changed
- **Scan Analysis Logic**: Updated scan status interpretation
  - INITIAL scans: Now considered failed attempts (regardless of age)
  - STARTED scans: Only scans actually waiting/processing
  - ERROR scans: Actual failures (unchanged)
  - External scans (SOURCE_SCA, JAR, SBOM_IMPORT): Still treated as instantly completed

### Technical Details
- Modified `calculate_daily_metrics()` and `calculate_summary_metrics()` in `fs_report/transforms/pandas/scan_analysis.py`
- Updated HTML template column indices for correct data display
- Improved scan type headers in daily metrics table for better readability

## [0.1.0] - 2025-10-23

### Added
- Initial release of Finite State Stand-Alone Reporting Kit
- Support for Component Vulnerability Analysis, Executive Summary, Findings by Project, and Scan Analysis reports
- Multiple output formats: CSV, XLSX, HTML
- Project and version filtering capabilities
- Data caching for improved performance
- Docker support for deployment

