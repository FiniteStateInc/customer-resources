# Scan Analysis Report – Requirements for Cursor

## 📌 Purpose

Define the specifications for generating a **Scan Analysis** report. This report will provide insights into scan activity, scan durations, failure rates, and queue status, enabling organizations to monitor scanning efficiency and identify bottlenecks.

No implementation should begin until all requirements are clarified and approved.

---

## 🧭 Narrative Context

The Scan Analysis report gives a **comprehensive overview of scan operations** to help organizations:
- **Monitor scan throughput** and platform utilization
- **Track scan durations** to identify performance issues
- **Analyze scan failure rates** for reliability
- **Understand scan queue status** to detect bottlenecks or delays
- **Plan resource allocation** and optimize scanning workflows

The report focuses on **operational metrics** for scans, providing actionable insights for platform administrators and security teams.

---

## ✅ Current State Summary

* No existing report provides detailed scan operation analytics
* Current reports focus on scan results, not operational efficiency
* Need for operational analytics to optimize scanning workflows

---

## 🔗 API Specification

All data for this report must be sourced using the official **Finite State API**, as defined in the project's **`swagger.json`** file.

Cursor developers must:
* Use the `swagger.json` spec as the **source of truth** for field names, endpoints, and capabilities
* Respect filtering, sorting, and pagination semantics as defined in the spec
* Use endpoints including:
  * `/public/v0/scans` – Primary data source for scan activity and status

### 🛠 Data Access Strategy

* Use server-side filtering for date ranges (`created>=${start_date}`)
* Pull full datasets and perform aggregation client-side
* Handle pagination for large scan datasets
* For queue analysis, filter scans by status (`INITIAL`, `STARTED`)

---

## 📊 Data Requirements

### Core Data Fields

| Field         | Source         | Description                                 | Required |
|---------------|----------------|---------------------------------------------|----------|
| id            | scans.id       | Unique scan identifier                      | Yes      |
| created       | scans.created  | Timestamp when scan was created             | Yes      |
| completed     | scans.completed| Timestamp when scan was completed           | Yes      |
| status        | scans.status   | Scan status (INITIAL, STARTED, COMPLETED, ERROR) | Yes      |
| type          | scans.type     | Scan type (SCA, SAST, etc.)                 | Yes      |
| project.name  | scans.project.name | Project name for context                | Yes      |
| projectVersion.name | scans.projectVersion.name | Version name for context | Yes      |
| errorMessage  | scans.errorMessage | Error details if scan failed            | No       |

### Data Scope

- **Time Range**: Configurable via CLI parameters (--start, --end, --period)
- **Scan Status**: All statuses (INITIAL, STARTED, COMPLETED, ERROR)
- **Projects/Versions**: All unless filtered

### Queue Analysis

- **Waiting Scans**: Scans with status `INITIAL` or `STARTED` and no `completed` timestamp
- **Queue Age**: Time since `created` for waiting scans
- **Queue Size**: Number of scans currently in queue

---

## 📊 Visualization Strategy

### 1. 📈 Scan Throughput Over Time — Line Chart
* **X-axis**: Time periods (daily/weekly/monthly)
* **Y-axis**: Number of scans started/completed
* **Lines**: Separate for started and completed
* **Goal**: Show scan production and completion rates

### 2. ⏱️ Scan Duration Analysis — Box Plot
* **X-axis**: Time periods or scan types
* **Y-axis**: Scan duration (completed - created)
* **Goal**: Show distribution and outliers in scan durations

### 3. ❌ Scan Failure Rate — Stacked Bar Chart
* **X-axis**: Time periods
* **Y-axis**: Number of scans
* **Bars**: Stacked by status (COMPLETED, ERROR)
* **Goal**: Show failure rates and trends

### 4. 🕒 Queue Status — Table/Bar Chart
* **Columns**: Scan ID, Project, Type, Status, Age (time since created)
* **Goal**: Show current queue, oldest scans, and queue size

All charts must:
- Be limited to **Top 12 time periods** by default (configurable)
- Include **clear legends** and **axis labels**
- Use **colorblind-safe** color schemes
- Support **interactive features** in HTML output
- Be **exportable** for inclusion in reports

---

## 🔧 Technical Requirements

### Transform Function
- **Approach**: Pandas-based transform
- **Function Name**: `scan_analysis_transform`
- **Location**: `fs_report/transforms/pandas/scan_analysis.py`

### Data Processing Logic
1. **Fetch scans** from the scans endpoint with date filtering
2. **Parse and validate** created and completed timestamps
3. **Calculate scan duration** (completed - created) for completed scans
4. **Group by time periods** for throughput and failure analysis
5. **Aggregate by status and type**
6. **Identify failed scans** (status == ERROR)
7. **Queue analysis**: filter scans with status INITIAL/STARTED and no completed timestamp
8. **Sort by time period and queue age**
9. **Prepare data for visualization**

### Scan Duration Logic
```python
def calculate_scan_duration(created: str, completed: str) -> Optional[float]:
    if not created or not completed:
        return None
    try:
        created_dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
        completed_dt = datetime.fromisoformat(completed.replace('Z', '+00:00'))
        duration = (completed_dt - created_dt).total_seconds() / 60  # minutes
        return duration
    except (ValueError, TypeError):
        return None
```

### Recipe Structure
```yaml
name: "Scan Analysis"
description: "Analyze scan throughput, durations, failures, and queue status"
template: "scan_analysis.html"
queries:
  - endpoint: "/public/v0/scans"
    params:
      filter: "created>=${start_date}"
      sort: "created:asc"
transform_function: scan_analysis_transform
output:
  formats: [csv, xlsx, html]
  chart: bar
  table: true
```

---

## 📋 Output Requirements

### CSV Output
- **Time Period**: Aggregated time period (date range)
- **Total Scans**: Number of scans started
- **Completed Scans**: Number of scans completed
- **Failed Scans**: Number of scans with status ERROR
- **Average Duration**: Average scan duration (minutes)
- **Median Duration**: Median scan duration
- **Queue Size**: Number of scans in queue at report time

### XLSX Output
- **Multiple Sheets**: 
  - Summary (throughput and failure overview)
  - Duration Analysis (detailed scan durations)
  - Queue Status (current queue details)
  - Charts (embedded visualizations)
- **Formatted**: Proper date and number formatting, conditional formatting
- **Charts**: Embedded Excel charts for all visualizations

### HTML Output
- **Responsive Design**: Works on desktop and mobile
- **Interactive Charts**: Chart.js or similar for interactive visualizations
- **Summary Statistics**: Key metrics and insights
- **Queue Table**: Live queue status
- **Export Options**: Download links for CSV and XLSX

---

## 🎯 Success Criteria

- [ ] Report generates accurate scan throughput, duration, and failure metrics
- [ ] All visualizations render correctly and provide actionable insights
- [ ] Queue analysis is accurate and up-to-date
- [ ] Report performance is acceptable for large scan datasets
- [ ] All output formats (CSV, XLSX, HTML) contain consistent data
- [ ] Color scheme is colorblind-safe and follows accessibility guidelines
- [ ] Report provides clear insights about scan operations and bottlenecks

---

## 🚨 Edge Cases

### No Data
- Display appropriate "No scan data available" message
- Show empty charts with explanatory text
- Provide suggestions for date range adjustments

### Long-Running Scans
- Highlight scans with unusually long durations
- Provide warnings for scans exceeding threshold

### Queue Overload
- Highlight when queue size exceeds threshold
- Provide recommendations for queue management

### Missing Timestamps
- Log warnings for scans with missing created/completed dates
- Exclude from duration analysis with clear documentation

---

*Last Updated: 2025-01-27*  
*Status: Requirements Definition* 