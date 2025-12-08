# Report Recipes

This directory contains YAML recipe files that define the available reports in the Finite State Reporting Kit.

## Available Recipes

- `component_vulnerability_analysis.yaml` — Component Vulnerability Analysis report
- `executive_summary.yaml` — Executive Summary Dashboard
- `findings_by_project.yaml` — Findings by Project report
- `scan_analysis.yaml` — Scan Analysis report

## Usage

To generate a report, use the CLI and specify the recipe name. For example:

```bash
python -m fs_report.cli --recipe "Component Vulnerability Analysis" --output output/
```

Replace the recipe name with any of the available options above. The output will be saved in the specified directory.

For more details, see the main project README or documentation. 