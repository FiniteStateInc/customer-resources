# Recipe Quick Reference

A concise reference guide for creating custom reports with the Finite State Reporting Kit.

## Basic Recipe Template

```yaml
name: "Recipe Name"
description: "What this recipe does"

query:
  endpoint: "/public/v0/findings"
  params:
    filter: "detected>=${start};detected<=${end}"
    limit: 1000
    sort: "detected:desc"

transform:
  - group_by: [field1, field2]
  - calc:
      name: metric_name
      expr: "calculation_expression"
  - sort:
      sort: [field1]
      ascending: true

output:
  chart: bar|line|pie|scatter
  table: true
  slide_title: "Report Title"
```

## API Endpoints

| Endpoint | Purpose | Key Fields |
|----------|---------|------------|
| `/public/v0/findings` | Security findings | `severity`, `status`, `detected`, `risk`, `project` |
| `/public/v0/components` | Software components | `name`, `version`, `license`, `risk`, `project`, `projectVersion` |
| `/public/v0/projects` | Project information | `name`, `health_score`, `security_score` |
| `/public/v0/cves` | CVE data | `cve_id`, `risk`, `exploitability` |
| `/public/v0/audit` | Audit trail events | `user`, `type`, `time`, `extra` |

## Filter Syntax (RSQL)

### Basic Filters
```yaml
# Exact match
filter: "severity==HIGH"

# Multiple values
filter: "severity=in=(HIGH,CRITICAL)"

# Numeric comparison
filter: "risk>50"

# Date range
filter: "detected>=2025-01-01;detected<=2025-01-31"

# Pattern matching
filter: "component=like=spring*"

# Null check
filter: "resolved_time=isnull=true"
```

### Complex Filters
```yaml
# Multiple conditions (use semicolons, not 'and')
filter: "severity==HIGH;risk>50;status=in=(OPEN,IN_TRIAGE)"

# Date range with variables
filter: "detected>=${start};detected<=${end}"
```

## Transformations

### Group By
```yaml
transform:
  - group_by: [severity]
  - group_by: [project, severity]
```

**Note**: Each transform should contain only one operation. The examples above show separate transform entries.

### Calculations
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

### Common Calculation Expressions
| Expression | Purpose |
|------------|---------|
| `count(*)` | Count all records |
| `avg(field)` | Average value |
| `sum(field)` | Sum values |
| `min(field)` | Minimum value |
| `max(field)` | Maximum value |
| `count(field='value')` | Count specific values |

### Filtering
```yaml
transform:
  - group_by: [severity]
  - filter: "severity=in=(HIGH,CRITICAL)"
```

**Note**: Each transform should contain only one operation. The examples above show separate transform entries.

### Sorting
```yaml
transform:
  - sort:
      sort: [finding_count]
      ascending: false
```

**Note**: Each transform should contain only one operation. The examples above show separate transform entries.

### Pivot Tables
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
```yaml
# Additional queries
additional_queries:
  component_data:
    endpoint: "/public/v0/components"
    params:
      filter: "risk>50"

# Join in transform
transform:
  - join:
      right: component_data
      left_on: [component]
      right_on: [name]
      how: left
```

**Note**: Each transform should contain only one operation. The examples above show separate transform entries.

## Output Configuration

### Single Chart
```yaml
output:
  chart: bar
  stacked: true
  table: true
  slide_title: "Report Title"
```

### Multiple Charts
```yaml
output:
  charts:
    - name: "chart1"
      chart: pie
      title: "Chart Title"
    - name: "chart2"
      chart: bar
      title: "Chart Title 2"
  table: true
  slide_title: "Report Title"
```

## Chart Types

| Type | Best For | Example |
|------|----------|---------|
| `bar` | Comparing categories | Severity distribution |
| `line` | Time series | Trends over time |
| `pie` | Proportions | Status breakdown |
| `scatter` | Correlations | Risk vs. time |

## Common Patterns

### Time-based Analysis
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

### Conditional Categories
```yaml
transform:
  - calc:
      name: risk_category
      expr: "CASE WHEN risk >= 75 THEN 'Critical' WHEN risk >= 50 THEN 'High' WHEN risk >= 25 THEN 'Medium' ELSE 'Low' END"
  - group_by: [risk_category]
```

## CLI Commands

```bash
# List available recipes
fs-report list-recipes

# Run specific recipe
fs-report --recipe "Recipe Name"

# Run with custom date range
fs-report --recipe "Recipe Name" --start 2025-01-01 --end 2025-01-31

# Run with verbose output
fs-report --recipe "Recipe Name" --verbose

# Use custom recipes directory
fs-report --recipes ./my-recipes --recipe "Recipe Name"

# Use custom output directory
fs-report --output ./my-reports --recipe "Recipe Name"
```

## Troubleshooting

### Common Issues
- **Recipe not found**: Check spelling with `fs-report list-recipes`
- **Invalid filter**: Use semicolons (`;`) not `and` for multiple conditions
- **Empty results**: Check date range and field names
- **Calculation errors**: Use `count(*)` not `count(field)` for record counts

### Debugging
```bash
# Enable verbose logging
fs-report --verbose --recipe "Recipe Name"

# Test with sample data
fs-report --data-file test_data.json --recipe "Recipe Name"
```

## Field Reference

### Findings Fields
- `severity`: HIGH, MEDIUM, LOW, CRITICAL
- `status`: OPEN, IN_TRIAGE, RESOLVED, RESOLVED_WITH_PEDIGREE, NOT_AFFECTED, FALSE_POSITIVE
- `detected`: Detection timestamp
- `resolved_time`: Resolution timestamp
- `risk`: Risk score (0-100)
- `project`: Project name
- `component`: Component name

### Component Fields
- `name`: Component name
- `version`: Component version
- `license`: License type
- `risk`: Risk score (0-100)

### Project Fields
- `name`: Project name
- `health_score`: Health score (0-100)
- `security_score`: Security score (0-100) 