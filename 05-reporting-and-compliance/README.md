# 05 - Reporting and Compliance

This section covers generating reports, maintaining compliance, and using reporting tools.

## Available Scripts

- **[fs-report](./fs-report/)** - Reporting system that generates HTML, CSV, and XLSX reports with customizable recipes for executive summaries, component vulnerability analysis, findings by project, scan analysis, and the **Component List** (software inventory + license analysis)
- **[fs-reporter](./fs-reporter/)** - PDF report generator for creating detailed vulnerability and risk reports
- **[vex-vdr](./vex-vdr/)** - Standalone CycloneDX **VEX** export (Vulnerability Disclosure Report) — vulnerability and triage data with no SBOM component inventory, for consumers that require a VEX file rather than a full SBOM; optional triaged-only filter
- **[fs-csv-export](./fs-csv-export/)** - Findings and components CSV export that adds each row's **unique ID** as the first column (the platform export omits it, so rows can't be joined back to the API for triage automation, ticket linking, or version diffing), plus the CVSS vector string

