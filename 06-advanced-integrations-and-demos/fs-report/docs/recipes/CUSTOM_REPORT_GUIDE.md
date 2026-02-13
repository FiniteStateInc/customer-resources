# Creating Custom Reports with Recipes

A comprehensive guide to creating custom security reports using the Finite State Reporting Kit's YAML recipe system.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Introduction](#introduction)
3. [Recipe Basics](#recipe-basics)
4. [Recipe Structure](#recipe-structure)
5. [Creating Your First Recipe](#creating-your-first-recipe)
6. [Data Queries](#data-queries)
7. [Data Transformations](#data-transformations)
8. [Output Configuration](#output-configuration)
9. [Advanced Features](#advanced-features)
10. [Template Column Reference](#template-column-reference)
11. [Best Practices](#best-practices)
12. [Troubleshooting](#troubleshooting)
13. [Examples](#examples)

## Quick Start

Get started in 4 steps:

1. **Copy the template**: `cp recipes/_TEMPLATE.yaml recipes/my_report.yaml`
2. **Edit the recipe**: Configure query, transform, and output
3. **Test locally**: `fs-report --recipe "My Report" --verbose`
4. **View output**: Reports appear in `./output/My Report/`

## Introduction

The Finite State Reporting Kit uses a powerful YAML-based recipe system that allows you to create custom security reports without writing code. Recipes define:

- **What data to fetch** from the Finite State API
- **How to transform and analyze** the data
- **How to visualize** the results

This guide will teach you how to create, customize, and deploy your own recipes for generating tailored security reports.

## Recipe Basics

### What is a Recipe?

A recipe is a YAML file that defines a complete report generation workflow. It contains:

- **Metadata**: Name, description, and purpose
- **Query Configuration**: API endpoints and parameters
- **Transformations**: Data processing and calculations
- **Output Settings**: Chart types and formatting

### Recipe File Naming

- Use descriptive names: `vulnerability_trends.yaml`, `project_health_dashboard.yaml`
- Use lowercase with underscores: `license_compliance_analysis.yaml`
- Include the `.yaml` extension

### Recipe Location

Place your recipes in the `recipes/` directory (or specify a custom directory with `--recipes`).

## Recipe Structure

Every recipe follows this basic structure:

```yaml
name: "Your Recipe Name"
description: "What this recipe analyzes and why it's useful"

query:
  endpoint: "/public/v0/findings"
  params:
    filter: "your-filter-expression"
    limit: 1000
    sort: "field:direction"

transform:
  - group_by: [field1, field2]
  - calc:
      name: calculated_field
      expr: "calculation_expression"
  - sort:
      sort: [field1]
      ascending: true

output:
  chart: bar|line|pie|scatter
  table: true
  slide_title: "Report Title"
  description: "Report description"
```

## Creating Your First Recipe

### Step 1: Define Your Objective

Start by clearly defining what you want to analyze:

- **What question** are you trying to answer?
- **What data** do you need to answer it?
- **How** do you want to visualize the results?

### Step 2: Choose Your Data Source

Select the appropriate API endpoint:

| Endpoint | Purpose | Key Fields |
|----------|---------|------------|
| `/public/v0/findings` | Security findings and vulnerabilities | `severity`, `status`, `detected`, `risk` |
| `/public/v0/components` | Software components | `name`, `version`, `license`, `risk`, `project`, `projectVersion` |
| `/public/v0/projects` | Project information | `name`, `health_score`, `security_score` |
| `/public/v0/cves` | CVE-specific data | `cve_id`, `risk`, `exploitability` |
| `/public/v0/audit` | Audit trail events | `user`, `type`, `time`, `extra` |

### Step 3: Create the Recipe File

Create a new YAML file in your recipes directory:

```yaml
name: "My Custom Analysis"
description: "Analyzes security findings by severity and project"

query:
  endpoint: "/public/v0/findings"
  params:
    filter: "detected>=${start};detected<=${end}"
    limit: 1000
    sort: "detected:desc"

transform:
  - group_by: [project, severity]
  - calc:
      name: finding_count
      expr: "count(*)"
  - sort:
      sort: [project, severity]
      ascending: true

output:
  chart: bar
  stacked: true
  table: true
  slide_title: "Findings by Project and Severity"
  description: "Distribution of security findings across projects"
```

### Step 4: Test Your Recipe

Run your recipe to test it:

```bash
# Test with default date range
fs-report --recipe "My Custom Analysis"

# Test with specific date range
fs-report --recipe "My Custom Analysis" --start 2025-01-01 --end 2025-01-31

# Test with verbose output
fs-report --recipe "My Custom Analysis" --verbose
```

## Data Queries

### Basic Query Structure

```yaml
query:
  endpoint: "/public/v0/findings"
  params:
    filter: "your-filter-expression"
    limit: 1000
    sort: "field:direction"
    offset: 0
```

### Filtering with RSQL

Use RSQL (RESTful Service Query Language) for powerful filtering:

#### Basic Filters
```yaml
# Exact match
filter: "severity==HIGH"

# Multiple values
filter: "severity=in=(HIGH,CRITICAL)"

# Numeric comparison
filter: "risk>50"

# Date range
filter: "detected>=2025-01-01;detected<=2025-01-31"
```

#### Complex Filters
```yaml
# Multiple conditions with AND (use semicolons, not 'and')
filter: "severity==HIGH;risk>50;status=in=(OPEN,IN_TRIAGE)"

# Pattern matching
filter: "component=like=spring*"

# Null checks
filter: "resolved_time=isnull=true"

# Date ranges with variables
filter: "detected>=${start};detected<=${end}"
```

#### Common Filter Patterns

| Filter Type | Example | Description |
|-------------|---------|-------------|
| Severity | `severity=in=(HIGH,CRITICAL)` | High and critical findings |
| Status | `status=in=(OPEN,IN_TRIAGE)` | Unresolved findings |
| Date Range | `detected>=${start};detected<=${end}` | Date range with variables |
| Risk Score | `risk>75` | High-risk findings |
| Project | `project==my-project` | Specific project |
| Component | `component=like=log4j*` | Components matching pattern |

### Sorting

```yaml
# Single field
sort: "detected:desc"

# Multiple fields
sort: "project:asc,severity:desc,detected:desc"
```

### Pagination

```yaml
# Limit results
limit: 1000

# Offset for pagination
offset: 0
```

## Data Transformations

Transformations process and analyze your data. Apply them in sequence:

### Group By

Group data by one or more fields:

```yaml
transform:
  - group_by: [severity]
  - group_by: [project, severity]
  - group_by: [component, license]
```

**Note**: Each transform should contain only one operation. The examples above show separate transform entries.

### Calculations

Perform calculations on your data:

```yaml
transform:
  - calc:
      name: finding_count
      expr: "count(*)"
  - calc:
      name: avg_risk
      expr: "avg(risk)"
  - calc:
      name: total_risk
      expr: "sum(risk)"
  - calc:
      name: resolution_rate
      expr: "count(status='RESOLVED') / count(*) * 100"
```

**Note**: Each transform should contain only one operation. The examples above show separate transform entries.

#### Common Calculation Expressions

| Expression | Purpose | Example |
|------------|---------|---------|
| `count(*)` | Count records | `finding_count: "count(*)"` |
| `avg(field)` | Average value | `avg_risk: "avg(risk)"` |
| `sum(field)` | Sum values | `total_risk: "sum(risk)"` |
| `min(field)` | Minimum value | `min_risk: "min(risk)"` |
| `max(field)` | Maximum value | `max_risk: "max(risk)"` |
| `count(field='value')` | Count specific values | `high_severity: "count(severity='HIGH')"` |

### Filtering

Apply additional filters after grouping:

```yaml
transform:
  - group_by: [severity]
  - filter: "severity=in=(HIGH,CRITICAL)"
  - calc:
      name: finding_count
      expr: "count(*)"
```

**Note**: Each transform should contain only one operation. The examples above show separate transform entries.

### Sorting

Sort your results:

```yaml
transform:
  - group_by: [severity]
  - calc:
      name: finding_count
      expr: "count(*)"
  - sort:
      sort: [finding_count]
      ascending: false
```

**Note**: Each transform should contain only one operation. The examples above show separate transform entries.

### Pivot Tables

Create pivot tables for cross-tabulation:

```yaml
transform:
  - group_by: [project, severity]
  - calc:
      name: finding_count
      expr: "count(*)"
  - pivot:
      index: project
      columns: severity
      values: finding_count
```

**Note**: Each transform should contain only one operation. The examples above show separate transform entries.

### Joins

Combine data from multiple queries:

```yaml
# Main query
query:
  endpoint: "/public/v0/findings"
  params:
    filter: "detected>=${start};detected<=${end}"

# Additional queries
additional_queries:
  component_data:
    endpoint: "/public/v0/components"
    params:
      filter: "risk>50"

# Join the data
transform:
  - join:
      right: component_data
      left_on: [component]
      right_on: [name]
      how: left
```

**Note**: Each transform should contain only one operation. The examples above show separate transform entries.

### Built-in Transform Functions

For complex reports, use pre-built Python transform functions instead of YAML transforms:

| Function | Report | Description |
|----------|--------|-------------|
| `scan_analysis_transform` | Scan Analysis | Daily metrics, durations, failure rates |
| `component_vulnerability_analysis_pandas_transform` | CVA | Component risk scoring across portfolio |
| `findings_by_project_pandas_transform` | Findings by Project | Groups findings with severity details |
| `component_list_pandas_transform` | Component List | Component inventory with license info |
| `user_activity_pandas_transform` | User Activity | Audit log analysis, login tracking |

Reference these in your recipe with:

```yaml
transform_function: scan_analysis_transform
```

## Output Configuration

### Basic Output

```yaml
output:
  chart: bar
  table: true
  slide_title: "My Report Title"
  description: "Description of what this report shows"
```

### Chart Types

Choose the appropriate chart type for your data:

| Chart Type | Best For | Example Use Cases |
|------------|----------|-------------------|
| `bar` | Comparing categories | Severity distribution, project comparison |
| `line` | Time series data | Trends over time, MTTR analysis |
| `pie` | Proportions | Status distribution, severity breakdown |
| `scatter` | Correlations | Risk vs. time, component analysis |

### Multiple Charts

Create reports with multiple visualizations:

```yaml
output:
  charts:
    - name: "severity_distribution"
      chart: pie
      title: "Findings by Severity"
      description: "Distribution of findings across severity levels"
    
    - name: "trends_over_time"
      chart: line
      title: "Findings Over Time"
      description: "Number of findings detected per month"
    
    - name: "project_comparison"
      chart: bar
      title: "Findings by Project"
      description: "Comparison of findings across projects"
  
  table: true
  slide_title: "Comprehensive Security Analysis"
```

**Note**: Multiple charts require additional queries and specific transform names. See the "Advanced Features" section for details on supported transform names like `open_issues_transform` and `scan_frequency_transform`.

### Stacked Charts

For bar charts, enable stacking:

```yaml
output:
  chart: bar
  stacked: true
  table: true
```

## Advanced Features

### Date Variables

Use `${start}` and `${end}` for dynamic date ranges:

```yaml
query:
  endpoint: "/public/v0/findings"
  params:
    filter: "detected>=${start};detected<=${end}"
```

### Supported Transform Names for Multiple Charts

For recipes with multiple charts, you can use specific transform names that correspond to additional queries:

```yaml
# Additional queries
additional_queries:
  open_issues:
    endpoint: "/public/v0/findings"
    params:
      filter: "status=in=(IN_TRIAGE,EXPLOITABLE)"

# Supported transform names
open_issues_transform:
  - group_by: [severity]
  - calc:
      name: finding_count
      expr: "count(*)"

scan_frequency_transform:
  - calc:
      name: month_year
      expr: "strftime('%Y-%m', detected)"
  - group_by: [month_year]
  - calc:
      name: finding_count
      expr: "count(*)"
```

**Currently Supported Transform Names:**
- `open_issues_transform`: For open issues analysis
- `scan_frequency_transform`: For time-based frequency analysis

### Complex Transformations

Chain multiple transformations:

```yaml
transform:
  # Group by project and severity
  - group_by: [project, severity]
  
  # Calculate metrics
  - calc:
      name: finding_count
      expr: "count(*)"
  - calc:
      name: avg_risk
      expr: "avg(risk)"
  - calc:
      name: total_risk
      expr: "sum(risk)"
  
  # Filter for high-risk findings
  - filter: "avg_risk>50"
  
  # Sort by total risk
  - sort:
      sort: [total_risk]
      ascending: false
```

**Note**: Each transform should contain only one operation. The examples above show separate transform entries.

### Conditional Calculations

Use SQL-like expressions for conditional logic:

```yaml
transform:
  - calc:
      name: resolution_category
      expr: "CASE WHEN status IN ('RESOLVED', 'RESOLVED_WITH_PEDIGREE') THEN 'Resolved' WHEN status IN ('IN_TRIAGE', 'EXPLOITABLE') THEN 'Open' ELSE 'Other' END"
```

### Time-based Analysis

Analyze trends over time:

```yaml
transform:
  - calc:
      name: month_year
      expr: "strftime('%Y-%m', detected)"
  - group_by: [month_year]
  - calc:
      name: finding_count
      expr: "count(*)"
  - sort:
      sort: [month_year]
      ascending: true
```

**Note**: Each transform should contain only one operation. The examples above show separate transform entries.

## Template Column Reference

When creating custom HTML templates, use these column names for named access (`row.column_name`):

### Scan Analysis - daily_metrics

```python
row.period                      # Date period (YYYY-MM-DD)
row.date                        # Same as period
row.total_scans_started         # Count of scans started
row.unique_projects             # Distinct projects
row.new_projects                # Projects with first scan
row.existing_projects           # Projects with prior scans
row.unique_versions             # Distinct versions scanned
row.total_completed_scans       # Successfully completed
row.failed_scans                # Error count
row.success_rate                # Percentage (0-100)
row.avg_duration_minutes        # Average completion time
row.sca_scans                   # SCA scan count
row.sast_scans                  # SAST scan count
row.config_scans                # CONFIG scan count
```

### Component Vulnerability Analysis - portfolio_data

```python
row.name                        # Component name
row.version                     # Component version
row.project_count               # Projects affected
row.portfolio_composite_risk    # Aggregate risk score
row.normalized_risk_score       # Per-project risk
row.findings_count              # Total findings
row.has_kev                     # In CISA KEV (boolean)
row.has_exploits                # Known exploits (boolean)
```

### Findings by Project

```python
row['Project Name']             # Project name
row['CVE ID']                   # CVE identifier
row['Component']                # Affected component
row['CVSS']                     # CVSS score
row['# of known exploits']      # Exploit count
```

## Best Practices

### Recipe Design

1. **Start Simple**: Begin with basic queries and add complexity gradually
2. **Use Descriptive Names**: Make recipe names clear and meaningful
3. **Include Descriptions**: Document what each recipe does
4. **Test Incrementally**: Test each transformation step
5. **Optimize Performance**: Use appropriate limits and filters

### Data Quality

1. **Validate Filters**: Ensure RSQL syntax is correct
2. **Handle Missing Data**: Use appropriate null handling
3. **Check Data Types**: Ensure calculations work with your data
4. **Test Edge Cases**: Verify behavior with empty or large datasets

### Performance

1. **Limit Data**: Use appropriate `limit` values
2. **Filter Early**: Apply filters in the query, not just transforms
3. **Use Indexes**: Sort by indexed fields when possible
4. **Avoid Large Joins**: Keep joins manageable
5. **Optimize Execution Order**: Use `execution_order` to maximize cache reuse

#### Execution Order for Cache Optimization

Reports are automatically sorted by `execution_order` to maximize cache reuse:

```yaml
execution_order: 10  # Lower = runs first
```

| Order | Reports | Why |
|-------|---------|-----|
| 10 | Scan Analysis | Fetches scans - cached for other reports |
| 20 | CVA, Executive Summary, Findings by Project | Reuse cached scans |
| 30 | Component List | Independent - fetches components |
| 40 | User Activity | Independent - fetches audit data |
| 50 | (default) | New recipes without explicit order |

Reports that share data sources benefit when the first report caches that data.

### Maintenance

1. **Version Control**: Track recipe changes in git
2. **Documentation**: Keep recipes well-documented
3. **Testing**: Test recipes regularly
4. **Backup**: Keep backups of working recipes

## Troubleshooting

### Common Issues

#### Recipe Not Found
```bash
# Check recipe name spelling
fs-report list-recipes

# Verify recipe file exists
ls recipes/your_recipe.yaml
```

#### Invalid Filter Syntax
```yaml
# ❌ Wrong - mixing operators
filter: "severity==HIGH and risk>50"

# ✅ Correct - use semicolons
filter: "severity==HIGH;risk>50"
```

#### Empty Results
```yaml
# Check your date range
filter: "detected>=2025-01-01;detected<=2025-01-31"

# Verify field names
filter: "severity=in=(HIGH,CRITICAL)"
```

#### Calculation Errors
```yaml
# ❌ Wrong - invalid field reference
expr: "count(severity)"

# ✅ Correct - count all records
expr: "count(*)"

# ✅ Correct - count specific values
expr: "count(severity='HIGH')"
```

### Debugging Tips

1. **Use Verbose Mode**: `fs-report --verbose`
2. **Test Queries**: Verify API responses manually
3. **Check Data Types**: Ensure calculations match data types
4. **Simplify**: Remove complex transforms to isolate issues
5. **Check Logs**: Review error messages carefully

### Getting Help

1. **Check Examples**: Review existing recipes in `recipes/`
2. **Validate Syntax**: Use YAML validators
3. **Test Incrementally**: Build recipes step by step
4. **Review Documentation**: Check this guide and API docs

## Examples

### Example 1: MTTR Analysis

```yaml
name: "Mean Time to Remediate"
description: "Analysis of how quickly findings are resolved"

query:
  endpoint: "/public/v0/findings"
  params:
    filter: "detected>=${start};detected<=${end};status=in=(RESOLVED,RESOLVED_WITH_PEDIGREE)"
    limit: 1000

transform:
  - calc:
      name: resolution_days
      expr: "(resolved_time - detected) / 86400"
  - group_by: [severity]
  - calc:
      name: avg_mttr
      expr: "avg(resolution_days)"
  - calc:
      name: finding_count
      expr: "count(*)"
  - sort:
      sort: [avg_mttr]
      ascending: false

output:
  chart: bar
  table: true
  slide_title: "Mean Time to Remediate by Severity"
  description: "Average time to resolve findings by severity level"
```

### Example 2: Project Health Dashboard

```yaml
name: "Project Health Overview"
description: "Comprehensive health metrics across all projects"

query:
  endpoint: "/public/v0/projects"
  params:
    limit: 1000

transform:
  - calc:
      name: health_category
      expr: "CASE WHEN health_score >= 80 THEN 'Excellent' WHEN health_score >= 60 THEN 'Good' WHEN health_score >= 40 THEN 'Fair' ELSE 'Poor' END"
  - group_by: [health_category]
  - calc:
      name: project_count
      expr: "count(*)"
  - calc:
      name: avg_health
      expr: "avg(health_score)"
  - sort:
      sort: [avg_health]
      ascending: false

output:
  charts:
    - name: "health_distribution"
      chart: pie
      title: "Projects by Health Category"
      description: "Distribution of projects across health categories"
    
    - name: "health_scores"
      chart: bar
      title: "Average Health Scores"
      description: "Average health scores by category"
  
  table: true
  slide_title: "Project Health Dashboard"
  description: "Overview of project health and security posture"
```

### Example 3: Component Vulnerability Analysis

```yaml
name: "Component Vulnerability Analysis"
description: "Identify the most vulnerable software components"

query:
  endpoint: "/public/v0/components"
  params:
    filter: "risk>25"
    limit: 1000
    sort: "risk:desc"

transform:
  - calc:
      name: risk_category
      expr: "CASE WHEN risk >= 75 THEN 'Critical' WHEN risk >= 50 THEN 'High' WHEN risk >= 25 THEN 'Medium' ELSE 'Low' END"
  - group_by: [risk_category]
  - calc:
      name: component_count
      expr: "count(*)"
  - calc:
      name: avg_risk
      expr: "avg(risk)"
  - sort:
      sort: [avg_risk]
      ascending: false

output:
  chart: bar
  stacked: true
  table: true
  slide_title: "Component Vulnerability Analysis"
  description: "Analysis of vulnerable components by risk category"
```

## Security Considerations

**Important**: Recipes are code. Treat them with the same security practices you would apply to any executable script.

### Why This Matters

Recipes can contain arbitrary expressions in their `calc` transforms:

```yaml
transform:
  - calc:
      name: result
      expr: "count(*)"  # This expression is evaluated by pandas
```

These expressions are executed using pandas' eval functionality, which provides significant flexibility but also means malicious recipes could potentially:
- Access system information
- Cause denial of service through resource-intensive calculations
- Leak data through carefully crafted expressions

### Best Practices

1. **Review Before Running**: Always review custom recipes before execution, especially from external sources
2. **Version Control**: Store recipes in version control and require code review for changes
3. **CI/CD Security**: In automated pipelines, only use recipes from trusted, version-controlled sources
4. **Never Download and Execute**: Do not download recipes from untrusted URLs and execute them directly
5. **Principle of Least Privilege**: Run the reporting tool with minimal necessary permissions

### For CI/CD Pipelines

```yaml
# Good: Recipes from version control
- name: Generate reports
  run: fs-report --recipes ./recipes  # Recipes checked into repo

# Bad: Recipes from external source
- name: Generate reports
  run: |
    curl -o recipe.yaml https://untrusted-source.com/recipe.yaml
    fs-report --recipes ./  # Don't do this!
```

---

## Next Steps

Now that you understand how to create custom recipes:

1. **Start with Simple Recipes**: Create basic analyses first
2. **Experiment with Different Chart Types**: Try various visualizations
3. **Combine Multiple Queries**: Use joins for complex analyses
4. **Create Reusable Templates**: Build recipes you can customize
5. **Share with Your Team**: Collaborate on recipe development

Remember, the recipe system is designed to be flexible and powerful. Don't hesitate to experiment and iterate on your recipes to get the insights you need! 