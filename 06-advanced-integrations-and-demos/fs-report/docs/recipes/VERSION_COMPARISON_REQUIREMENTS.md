# Version Comparison Report – Requirements

## 📌 Purpose

Define the specifications for generating a **Version Comparison** report. This report provides a **full version and component changelog** for every active project: progression across *all* scanned versions (v1→v2, v2→v3, …), showing for each version pair what was fixed, what was new, and which component changes drove the difference. It is not a single two-version comparison; it is a complete changelog. Scope can be limited to a project or folder, or to a single version pair via `--baseline-version` and `--current-version`.

No implementation should begin until all requirements are clarified and approved.

---

## 🧭 Narrative Context

The Version Comparison report answers the question: **"Across every version step, what exactly changed?"**

When a development team releases multiple versions, they need a full changelog: for each version pair (e.g. 3.14→3.15, 3.15→3.16), what was fixed, what was new, and which component changes drove it. This report provides that full progression—not just the latest two versions—so stakeholders can see the complete history of finding and component churn.

The report helps organizations:

- **Validate remediation work** — confirm that reported issues actually disappeared
- **Detect regressions** — identify new findings introduced by component updates or code changes
- **Understand root causes** — see which component additions/removals/updates drove the finding changes
- **Communicate results** — provide clear before/after evidence for stakeholders
- **Plan next steps** — prioritize remaining findings based on the current state

### "Fixed" Definition

A finding is considered **fixed** if it is **present in the baseline version's findings but absent from the current version's findings**. Matching is performed by CVE ID (for CVE findings) or finding ID as a fallback.

---

## ✅ Current State Summary

* An archived requirements doc exists at `archive/obsolete_docs/unimplemented_reports/ASSET_VERSION_COMPARISON_REQUIREMENTS.md` but was never implemented
* No existing report provides version-to-version comparison
* Current reports show single-version snapshots
* The `list-versions` CLI command already exists to help users discover version IDs

---

## 🔗 API Specification

All data for this report must be sourced using the official **Finite State API**.

### Endpoints Used

* `/public/v0/findings` with `projectVersion==<id>` — Findings for each version
* `/public/v0/components` with `projectVersion==<id>` — Components for each version
* `/public/v0/projects/{projectId}/versions` — Version metadata (names, dates)

### 🛠 Data Access Strategy

* Fetch findings and components for both versions (4 independent API calls)
* Use `projectVersion==<id>` filter to scope to exact versions
* Handle pagination for versions with large finding/component counts
* Validate that both version IDs exist before proceeding

---

## 📊 Data Requirements

### Core Data Fields

| Field | Source | Description | Required |
|-------|--------|-------------|----------|
| finding.id | findings | Unique finding identifier | Yes |
| finding.cveId | findings | CVE identifier for matching | Yes |
| finding.severity | findings | Severity level | Yes |
| finding.risk | findings | Numeric risk score | No |
| finding.component.name | findings | Associated component name | Yes |
| finding.component.version | findings | Associated component version | No |
| component.id | components | Unique component identifier | Yes |
| component.name | components | Component name | Yes |
| component.version | components | Component version string | Yes |
| component.type | components | Component type (library, OS, etc.) | No |
| component.warnings | components | Warning count | No |
| component.violations | components | Violation count | No |

### Data Scope

- **Default (portfolio-wide)**: Auto-discovers all projects with scan activity in the period; for each project, loads *all* scanned versions and builds the full progression (v1→v2→v3→…)
- **Folder scoped**: `--folder` limits to projects within a specific folder hierarchy
- **Project scoped**: `--project` limits to a single project (still full changelog for that project)
- **Explicit override**: `--baseline-version` + `--current-version` limits to a single version pair (advanced use)
- **Finding Types**: Respects `--finding-types` flag (default: CVE only)

---

## 📊 Visualization Strategy

### 1. 🎯 KPI Delta Cards

* **Layout**: Four cards in a row at the top of the report
* **Card 1**: Total Findings — baseline count, current count, delta with arrow and % change
* **Card 2**: Critical Findings — same treatment
* **Card 3**: High Findings — same treatment
* **Card 4**: Components — baseline count, current count, delta
* **Color coding**: Green arrows/badges for improvements (fewer findings), red for regressions

### 2. 📊 Severity Comparison — Grouped Bar Chart

* **Chart Type**: Grouped bar chart
* **X-axis**: Severity levels (Critical, High, Medium, Low, Info)
* **Bars**: Side-by-side for baseline (blue/gray) and current (teal/green)
* **Goal**: Show at-a-glance whether each severity level improved

### 3. ✅ Fixed Findings Table

* **Header**: Green header with checkmark icon and count of fixed findings
* **Columns**: CVE ID, Severity (with colored badge), Component, CVSS Score
* **Sorted by**: Severity (Critical first), then CVSS descending
* **Truncation**: Show top entries with "... N more" link to expand
* **Goal**: Celebrate the wins — these are issues that were resolved

### 4. ⚠️ New Findings Table

* **Header**: Red/coral header with warning icon and count of new findings
* **Columns**: CVE ID, Severity (with colored badge), Component, CVSS Score
* **Sorted by**: Severity (Critical first), then CVSS descending
* **Truncation**: Show top entries with "... N more" link to expand
* **Goal**: Highlight regressions requiring attention

### 5. 🔄 Component Churn Table

* **Columns**: Change Type (Added/Removed/Updated), Component Name + Version, Findings Impact
* **Change Types**:
  * **+ Added** (green badge): Component not in baseline, present in current
  * **- Removed** (red badge): Component in baseline, not in current
  * **↑ Updated** (blue badge): Same component name, different version
* **Findings Impact**: Count of findings associated with that component change
* **Goal**: Explain *why* findings changed — component updates are the primary driver

All charts must:

* Include **clear legends** and **axis labels**
* Use **colorblind-safe** color schemes
* Show **version names** in titles and legends
* Support **interactive features** in HTML output via Chart.js

---

## 🔧 Technical Requirements

### Transform Function

- **Approach**: Pandas-based transform
- **Function Name**: `version_comparison_transform`
- **Location**: `fs_report/transforms/pandas/version_comparison.py`

### Data Processing Logic

1. **Fetch data**: Get findings and components for both versions (4 API calls).
2. **Match findings**: Use CVE ID as primary match key, finding ID as fallback.
   - Present in baseline AND current → **unchanged**
   - Present in baseline ONLY → **fixed**
   - Present in current ONLY → **new**
3. **Match components**: Use component name as match key, version for update detection.
   - Present in baseline AND current with same version → **unchanged**
   - Present in baseline AND current with different version → **updated**
   - Present in baseline ONLY → **removed**
   - Present in current ONLY → **added**
4. **Compute severity deltas**: Count findings by severity for both versions.
5. **Build findings impact**: For each component change, count associated findings that were fixed or introduced.
6. **Prepare output DataFrames**: KPI summary, severity comparison, fixed list, new list, component churn.

### Finding Matching Logic

```python
def classify_findings(
    baseline_findings: pd.DataFrame,
    current_findings: pd.DataFrame
) -> dict[str, pd.DataFrame]:
    """
    Classify findings as fixed, new, or unchanged by comparing
    two version finding sets.
    
    Match primarily by CVE ID (cveId field). If cveId is missing,
    fall back to finding ID.
    """
    baseline_ids = set(baseline_findings['match_key'])
    current_ids = set(current_findings['match_key'])
    
    fixed_ids = baseline_ids - current_ids
    new_ids = current_ids - baseline_ids
    unchanged_ids = baseline_ids & current_ids
    
    return {
        'fixed': baseline_findings[baseline_findings['match_key'].isin(fixed_ids)],
        'new': current_findings[current_findings['match_key'].isin(new_ids)],
        'unchanged_count': len(unchanged_ids),
    }
```

### Component Matching Logic

```python
def classify_components(
    baseline_components: pd.DataFrame,
    current_components: pd.DataFrame
) -> pd.DataFrame:
    """
    Classify components as added, removed, updated, or unchanged.
    Match by component name; detect version changes.
    """
    merged = pd.merge(
        baseline_components, current_components,
        on='name', how='outer', suffixes=('_baseline', '_current')
    )
    
    conditions = [
        merged['version_baseline'].isna(),   # Added
        merged['version_current'].isna(),     # Removed
        merged['version_baseline'] != merged['version_current'],  # Updated
    ]
    choices = ['added', 'removed', 'updated']
    merged['change_type'] = np.select(conditions, choices, default='unchanged')
    
    return merged[merged['change_type'] != 'unchanged']
```

### Recipe Structure

```yaml
name: "Version Comparison"
description: "Full version and component changelog: progression across all versions with fixed/new findings and component churn per version pair"
category: assessment
template: "version_comparison.html"
execution_order: 50
auto_run: false

query:
  endpoint: "/public/v0/findings"
  params:
    limit: 10000

transform_function: version_comparison_transform

output:
  formats: ["csv", "xlsx", "html"]
  chart: bar
  table: true
  slide_title: "Version Comparison"
```

### CLI Parameters

- `--baseline-version <ID>` (required for this report): Version ID for the baseline
- `--current-version <ID>` (required for this report): Version ID for the current state
- Validation: Both must be provided when running this recipe

---

## 📋 Output Requirements

### CSV Output
- **Version Comparison.csv**: Summary — one row per version (Project, Version, Date, Total/Critical/High/Medium/Low, Fixed vs prev, New vs prev, Components)
- **Version Comparison_Detail_Findings.csv**: One row per finding per version (Project, Version, Date, ID, Severity, Component Name/Version, Risk, Title)
- **Version Comparison_Detail_Findings_Churn.csv**: One row per finding that was fixed or new in some version pair (Project, From Version, To Version, Change Type Fixed/New, ID, Severity, Component, Risk, Title)
- **Version Comparison_Detail_Component_Churn.csv**: One row per component change across version pairs (Project, From Version, To Version, Change Type, Component Name, Version Baseline/Current, Findings Impact). Detail files are written only when data exists.

### XLSX Output
- **Single workbook** with sheets:
  - **Summary**: One row per version (same as summary CSV)
  - **Findings Detail**: One row per finding per version
  - **Findings Churn**: Fixed/new findings per version pair (Change Type Fixed/New)
  - **Component Churn**: Component additions, removals, updates with findings impact
- Sheets omitted if empty. Formatted headers and column widths.

### HTML Output
- **Report header**: Project name, baseline version name/date, current version name/date
- **KPI delta cards**: Four cards with before/after values
- **Severity grouped bar chart**: Baseline vs current per severity
- **Changes (latest pair)**: Fixed and New findings tables side by side with severity summaries
- **Component Changes (latest pair)**: Added, removed, updated components with findings impact
- **Version changelog**: One collapsible entry per version pair (e.g. 3.14 → 3.15) with Fixed | New findings tables and Component changes for that pair; first entry expanded by default

---

## 🎯 Success Criteria

- [ ] Report accurately classifies findings as fixed, new, or unchanged
- [ ] Component matching correctly detects added, removed, and updated components
- [ ] KPI delta cards show correct before/after values and percentage changes
- [ ] All visualizations render correctly in HTML output with Chart.js
- [ ] CSV/XLSX contain consistent data matching the HTML view
- [ ] Report provides clear version names in headers and legends
- [ ] Color scheme is colorblind-safe
- [ ] Both `--baseline-version` and `--current-version` are validated before execution

---

## 🚨 Edge Cases

### Invalid Version IDs
- Display clear error message if either version doesn't exist or is inaccessible
- Suggest using `fs-report list-versions <project>` to find valid IDs

### Identical Versions
- Handle case where both version IDs are the same
- Show "No changes — versions are identical" with current state summary

### No Common Findings
- If no findings match between versions, show all as fixed (from baseline) and all as new (in current)
- Note in the report that the versions may represent very different products

### Large Version Differences
- Handle cases where versions have very different finding/component counts
- Ensure tables are paginated or truncated with "show more" in HTML

### Missing CVE IDs
- Fall back to finding ID for matching when CVE ID is not available
- Log a warning about reduced matching accuracy

### No Findings in One Version
- If baseline has findings but current has none: all classified as fixed (great progress!)
- If current has findings but baseline has none: all classified as new

---

*Last Updated: 2026-02-10*
*Status: Requirements Definition*
