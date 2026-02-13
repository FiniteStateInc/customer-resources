# Recipe Tutorial: Creating Custom Security Reports

This tutorial walks you through creating comprehensive security reports using the Finite State Reporting Kit. We'll cover both DuckDB (legacy) and Pandas (recommended) approaches.

## What We'll Build

We'll create several recipes that demonstrate different capabilities:

1. **Findings by Project**: A comprehensive inventory report using Pandas transforms
2. **Security Dashboard**: Traditional analysis using DuckDB transforms
3. **Data Comparison**: Using the XLSX comparison utility

## Prerequisites

- Finite State Reporting Kit installed
- API access configured
- Basic understanding of YAML syntax
- Python knowledge (for custom transforms)

## Step 1: Understanding Transformers

The reporting kit supports two data transformation engines:

### DuckDB Transformer (Legacy)
- SQL-like syntax for data manipulation
- Good for simple aggregations and calculations
- Use with `--transformer duckdb` or omit the flag

### Pandas Transformer (Recommended)
- Python-based transforms for complex logic
- Better debugging and extensibility
- Use with `--transformer pandas`
- Supports custom transform functions

## Step 2: Create a Pandas-Based Recipe

Let's start with a modern approach using the Pandas transformer.

### Create the Recipe File

Create `findings_by_project.yaml` in your `recipes/` directory:

```yaml
name: "Findings by Project"
description: "Comprehensive inventory of all findings across active projects"

query:
  endpoint: "/public/v0/findings"
  params:
    limit: 1000
    filter: "detected>=${start};detected<=${end}"

transform_function: findings_by_project_pandas_transform

output:
  formats: [csv, xlsx]  # Control which formats to generate
  table: true
  charts: []
```

### Create the Custom Transform Function

Create `fs_report/transforms/pandas/findings_by_project.py`:

```python
import pandas as pd
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

def findings_by_project_pandas_transform(data: List[Dict[str, Any]], **kwargs) -> pd.DataFrame:
    """
    Transform findings data into a comprehensive project inventory.
    
    Args:
        data: Raw findings data from API
        **kwargs: Additional parameters
        
    Returns:
        Processed DataFrame with findings by project
    """
    try:
        # Convert to DataFrame
        df = pd.DataFrame(data)
        logger.info(f"Processing {len(df)} findings")
        
        # Add your custom logic here
        # Example: Filter active projects, calculate metrics, etc.
        
        return df
        
    except Exception as e:
        logger.error(f"Error in findings_by_project_pandas_transform: {e}")
        return pd.DataFrame()
```

### Test Your Pandas Recipe

```bash
# Run with pandas transformer
fs-report --recipe "Findings by Project" --transformer pandas --verbose

# Check the output
ls output/Findings\ by\ Project/
```

## Step 3: Create a DuckDB-Based Recipe

For comparison, let's create a traditional DuckDB recipe.

### Create Security Dashboard Recipe

Create `security_dashboard.yaml`:

```yaml
name: "Security Dashboard"
description: "Traditional security analysis using DuckDB transforms"

query:
  endpoint: "/public/v0/findings"
  params:
    filter: "detected>=${start};detected<=${end}"
    limit: 1000
    sort: "detected:desc"

transform:
  - group_by: [severity]
  - calc:
      name: finding_count
      expr: "count(*)"
  - sort:
      sort: [finding_count]
      ascending: false

output:
  chart: pie
  table: true
  slide_title: "Security Dashboard"
  description: "Distribution of security findings by severity level"
```

### Test Your DuckDB Recipe

```bash
# Run with DuckDB transformer (default)
fs-report --recipe "Security Dashboard" --verbose

# Or explicitly specify DuckDB
fs-report --recipe "Security Dashboard" --transformer duckdb --verbose
```

## Step 4: Advanced Pandas Recipe with Complex Logic

Let's create a more sophisticated recipe that demonstrates the power of custom transforms.

### Create Component Risk Analysis Recipe

Create `component_risk_analysis.yaml`:

```yaml
name: "Component Risk Analysis"
description: "Advanced component analysis with custom risk scoring"

query:
  endpoint: "/public/v0/findings"
  params:
    limit: 1000
    filter: "detected>=${start};detected<=${end}"

transform_function: component_risk_analysis_transform

output:
  formats: [csv, xlsx, html]
  table: true
  charts: []
```

### Create Advanced Transform Function

Create `fs_report/transforms/pandas/component_risk_analysis.py`:

```python
import pandas as pd
import numpy as np
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

def component_risk_analysis_transform(data: List[Dict[str, Any]], **kwargs) -> pd.DataFrame:
    """
    Advanced component risk analysis with custom scoring.
    """
    try:
        df = pd.DataFrame(data)
        logger.info(f"Processing {len(df)} findings for component risk analysis")
        
        # Handle missing data
        df['risk'] = df['risk'].fillna(0)
        df['severity'] = df['severity'].fillna('MEDIUM')
        df['exploitability'] = df['exploitability'].fillna('UNKNOWN')
        
        # Custom risk scoring logic
        def calculate_risk_score(row):
            try:
                base_score = float(row.get('risk', 0))
                severity_multiplier = {
                    'CRITICAL': 2.0,
                    'HIGH': 1.5,
                    'MEDIUM': 1.0,
                    'LOW': 0.5
                }.get(row.get('severity', 'MEDIUM'), 1.0)
                
                exploit_bonus = 1.5 if row.get('exploitability') == 'KNOWN_EXPLOIT' else 1.0
                
                return base_score * severity_multiplier * exploit_bonus
            except (ValueError, TypeError):
                return 0.0
        
        # Apply custom scoring
        df['custom_risk_score'] = df.apply(calculate_risk_score, axis=1)
        
        # Group by component and aggregate
        result = df.groupby('component').agg({
            'custom_risk_score': ['mean', 'max', 'sum'],
            'findingId': 'count'
        }).round(2)
        
        # Flatten column names
        result.columns = ['avg_risk', 'max_risk', 'total_risk', 'finding_count']
        result = result.reset_index()
        
        # Add risk category
        result['risk_category'] = pd.cut(
            result['avg_risk'], 
            bins=[0, 25, 50, 75, 100], 
            labels=['Low', 'Medium', 'High', 'Critical']
        )
        
        logger.info(f"Generated risk analysis for {len(result)} components")
        return result.sort_values('avg_risk', ascending=False)
        
    except Exception as e:
        logger.error(f"Error in component_risk_analysis_transform: {e}")
        return pd.DataFrame()
```

## Step 5: Output Format Control

Modern recipes support precise control over output formats:

### CSV and XLSX Only (No HTML)
```yaml
output:
  formats: [csv, xlsx]
  table: true
  charts: []
```

### HTML Only (No Data Files)
```yaml
output:
  formats: [html]
  chart: pie
  table: true
```

### All Formats
```yaml
output:
  formats: [csv, xlsx, html]
  chart: bar
  table: true
```

## Step 6: Data Comparison and Analysis

### Using the XLSX Comparison Utility

Compare your generated reports with external data:

```bash
# Compare with customer data
python scripts/compare_xlsx_files.py \
  customer_data.xlsx \
  "output/Findings by Project/Findings by Project.xlsx" \
  I421GLGD \
  --output comparison_report.xlsx

# With custom column names
python scripts/compare_xlsx_files.py \
  customer_data.xlsx \
  generated_data.xlsx \
  I421GLGD \
  --cve-column "CVE_ID" \
  --project-column "Project_ID"
```

### Understanding Comparison Results

The comparison tool generates:
- **Summary statistics** showing differences
- **CVEs only in customer file** (missing from your data)
- **CVEs only in generated file** (new findings)
- **Side-by-side comparison** of matching CVEs

## Step 7: Testing and Validation

### Test Your Recipes

```bash
# Test with different transformers
fs-report --recipe "Your Recipe" --transformer pandas --verbose
fs-report --recipe "Your Recipe" --transformer duckdb --verbose

# Test with different date ranges
fs-report --recipe "Your Recipe" --start 2025-01-01 --end 2025-01-31

# Test with specific output formats
# (Check the generated files match your formats specification)
```

### Validate Output

```bash
# Check CSV output
head -5 "output/Your Recipe/Your Recipe.csv"

# Check XLSX output
# Open the file and verify columns and data

# Check HTML output (if generated)
# Open in browser and verify charts
```

## Step 8: Troubleshooting

### Common Issues and Solutions

#### Problem: Transform Function Not Found
**Solution**: Check function name and file location
```python
# Make sure function name matches recipe
transform_function: my_function_name  # Must match function name in Python file
```

**Note**: Transform functions should be placed in `fs_report/transforms/pandas/` directory and the function name in the recipe must exactly match the function name in the Python file.

#### Problem: Output Formats Not Working
**Solution**: Check formats specification
```yaml
# Correct format
output:
  formats: [csv, xlsx]  # Must be a list

# Incorrect format  
output:
  formats: csv, xlsx    # Missing brackets
```

#### Problem: Data Not Filtering Correctly
**Solution**: Check your transform logic
```python
# Add debugging
logger.info(f"Input data shape: {df.shape}")
logger.info(f"Columns: {df.columns.tolist()}")
logger.info(f"Sample data: {df.head()}")
```

#### Problem: Missing Dependencies
**Solution**: Ensure required packages are installed
```bash
# Install required packages
poetry add pandas numpy

# Or if using pip
pip install pandas numpy
```

## Step 9: Automation and Scheduling

### Create Automated Scripts

Create `run_reports.sh`:

```bash
#!/bin/bash

# Set environment variables
export FINITE_STATE_AUTH_TOKEN="your-token"
export FINITE_STATE_DOMAIN="your-domain.finitestate.io"

# Create output directory with timestamp
OUTPUT_DIR="./reports/$(date +%Y-%m-%d)"
mkdir -p "$OUTPUT_DIR"

# Run reports with pandas transformer
fs-report --transformer pandas --output "$OUTPUT_DIR" --recipe "Findings by Project"
fs-report --transformer pandas --output "$OUTPUT_DIR" --recipe "Component Risk Analysis"

# Run traditional reports with DuckDB
fs-report --transformer duckdb --output "$OUTPUT_DIR" --recipe "Security Dashboard"

echo "Reports generated in $OUTPUT_DIR"
```

**Note**: Make sure to replace `"your-token"` and `"your-domain.finitestate.io"` with your actual credentials, or set them as environment variables in your system.

### Schedule with Cron

```bash
# Edit crontab
crontab -e

# Run daily at 9 AM
0 9 * * * /path/to/run_reports.sh
```

## Step 10: Best Practices

### Recipe Design
- **Use descriptive names** for recipes and transform functions
- **Include clear descriptions** explaining what the recipe does
- **Test with small datasets** before running on large data
- **Use appropriate output formats** for your use case

### Transform Functions
- **Handle missing data** gracefully
- **Add logging** for debugging
- **Validate input data** structure
- **Return clean DataFrames** with proper column names

### Performance
- **Use appropriate limits** in API queries
- **Leverage data caching** for multiple recipes
- **Monitor memory usage** with large datasets
- **Consider chunking** for very large datasets

## Next Steps

Now that you've mastered the basics:

1. **Create custom transforms** for your specific use cases
2. **Build comprehensive dashboards** combining multiple recipes
3. **Automate your reporting** with scheduled scripts
4. **Share recipes** with your team
5. **Contribute** to the recipe library

## Tips for Success

- **Start with Pandas transforms** for complex logic
- **Use DuckDB transforms** for simple aggregations
- **Test thoroughly** before deploying to production
- **Document your transforms** with clear comments
- **Monitor performance** and optimize as needed
- **Use the comparison tools** to validate your data

The recipe system is designed to be flexible and powerful. Experiment with different approaches to find what works best for your specific needs! 