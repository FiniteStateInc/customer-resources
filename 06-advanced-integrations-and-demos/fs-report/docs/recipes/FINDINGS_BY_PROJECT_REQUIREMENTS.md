# Findings by Project Report - Requirements Document

## Report Overview
**Report Name**: Findings by Project  
**Purpose**: Generate a comprehensive inventory of all findings across all active projects or filtered by specific projects, organized by project and sorted by CVSS score.  
**Target Audience**: Security teams, project managers, and stakeholders needing detailed finding inventories for compliance, risk assessment, and remediation planning.

## Data Requirements

### Core Data Fields
| Field | Source | Description | Required |
|-------|--------|-------------|----------|
| CVE ID | findings.cve_id | CVE identifier | Yes |
| CVSS | findings.cvss_score | CVSS base score | Yes |
| # of known exploits | findings.exploit_count | Count of known exploits | Yes |
| # of known weaponization | findings.weaponization_count | Count of weaponization instances | Yes |
| Component | findings.component.name | Component name only | Yes |
| CWE | findings.cwe_id | CWE identifier (e.g., CWE-476) | Yes |
| Project Name | findings.project.name | Project name | Yes |
| Project Version | findings.project.version | Project version (e.g., 1.02) | Yes |

### Data Scope
- **Status Filter**: All findings regardless of status (IN_TRIAGE, EXPLOITABLE, RESOLVED, etc.)
- **Project Filter**: 
  - **Default**: All non-archived projects (using `archived=false` parameter)
  - **Optional**: Filter by specific project(s) using name, ID, or version ID
- **Date Range**: Configurable via CLI parameters (--start, --end)
- **Deduplication**: None - each finding appears once per project/component combination

### Data Sources
1. **Primary**: `/public/v0/findings` endpoint
2. **Secondary**: `/public/v0/projects` endpoint (for active project validation and project listing)
3. **Additional**: Any other endpoints needed for complete CWE information

## Project Filtering Requirements

### Filter Types
The report supports filtering by multiple project identifier types:

1. **Project Name** (case-insensitive, exact match)
   - Example: `--project "Reachability Demo"`
   - Matches: `findings.project.name` (case-insensitive)

2. **Project ID** (exact match, integer format)
   - Example: `--project "4276528361006159502"` or `--project "-4276528361006159502"`
   - Matches: `findings.project.id`

3. **Version ID** (exact match, integer format)
   - Example: `--project "3434155612106342937"` or `--project "-3434155612106342937"`
   - Matches: `findings.project.version_id`

### Filter Behavior
- **Single Project**: Filter to specific project only
- **Multiple Projects**: Support comma-separated list (e.g., `--project "proj1,proj2,proj3"`)
- **No Filter**: Include all active projects (default behavior)
- **Invalid Filter**: Clear error message with available options and similar name suggestions

### Project Discovery
- **List Projects**: `--project list` shows available projects with IDs and names
- **Interactive Selection**: Future enhancement for guided project selection
- **Autocomplete**: Future enhancement for project name suggestions
- **Similar Name Suggestions**: When invalid project name provided, suggest similar names

### API-Level Filtering
- **Strategy**: Apply project filtering at the API level when possible to reduce data transfer
- **Implementation**: Use RSQL filters in the findings endpoint query
- **Fallback**: Apply filtering at application level if API-level filtering is not supported

## Technical Requirements

### Transform Function
- **Approach**: Pandas-based transform (not DuckDB)
- **Function Name**: `findings_by_project_pandas_transform`
- **Location**: `fs_report/transforms/pandas/findings_by_project.py`

### Data Processing Logic
1. **Fetch all findings** from the findings endpoint with appropriate filters
2. **Apply project filtering** if specified (name, ID, or version ID)
3. **Filter for active projects** by cross-referencing with projects endpoint using `archived=false` (when no specific filter)
4. **Flatten nested data** (component, project objects)
5. **Remove unwanted columns** (detected, component_version, cwe_name, etc.)
6. **Sort by CVSS score** (descending - highest first)
7. **Group by project** for organized output
8. **Handle missing data** gracefully (None values for optional fields)

### Project Filtering Logic
```python
def apply_project_filter(df: pd.DataFrame, project_filter: str) -> pd.DataFrame:
    """
    Apply project filtering based on filter type detection.
    
    Args:
        df: Findings DataFrame
        project_filter: Filter string (project name, ID, or version ID)
    
    Returns:
        Filtered DataFrame
    """
    if not project_filter or project_filter == "all":
        return df
    
    # Handle multiple projects (comma-separated)
    if "," in project_filter:
        project_list = [p.strip() for p in project_filter.split(",")]
        filtered_dfs = []
        for project in project_list:
            filtered_df = apply_single_project_filter(df, project)
            filtered_dfs.append(filtered_df)
        return pd.concat(filtered_dfs, ignore_index=True)
    
    return apply_single_project_filter(df, project_filter)

def apply_single_project_filter(df: pd.DataFrame, project_filter: str) -> pd.DataFrame:
    """
    Apply filtering for a single project identifier.
    """
    # Try to parse as integer (project ID or version ID)
    try:
        project_id = int(project_filter)
        # Check if it's a project ID
        project_match = df[df['project.id'] == project_id]
        if not project_match.empty:
            return project_match
        
        # Check if it's a version ID
        version_match = df[df['project.version_id'] == project_id]
        if not version_match.empty:
            return version_match
        
        # If no matches found, return empty DataFrame
        return pd.DataFrame()
        
    except ValueError:
        # Not an integer, treat as project name (case-insensitive)
        return df[df['project.name'].str.lower() == project_filter.lower()]
```

### Performance Considerations
- **Expected Volume**: Thousands of findings
- **Pagination**: Implement proper pagination for large datasets
- **Caching**: Use ephemeral project list cache during single report generation (no persistence)
- **Memory Management**: Process data in chunks if necessary
- **Filter Optimization**: Apply project filters at API level when possible to reduce data transfer
- **API-Level Filtering**: Use RSQL filters in findings endpoint to minimize data transfer

## Output Requirements

### Format
- **Primary**: XLSX (to match existing Excel format)
- **Secondary**: CSV (for data portability)
- **Tertiary**: HTML (for web viewing)

### Table Structure
- **No charts** - table-only report
- **Columns**: All required fields listed above
- **Sorting**: Primary sort by CVSS score (descending), secondary by Project Name
- **Grouping**: Visual grouping by project (if possible in output format)

### File Naming
- **Pattern**: 
  - No filter: `Findings by Project_{start_date}_{end_date}.{extension}`
  - With filter: `Findings by Project_{project_filter}_{start_date}_{end_date}.{extension}`
- **Examples**: 
  - `Findings by Project_2025-01-01_2025-01-31.xlsx`
  - `Findings by Project_Reachability_Demo_2025-01-01_2025-01-31.xlsx`
  - `Findings by Project_4276528361006159502_2025-01-01_2025-01-31.xlsx`
  - `Findings by Project_proj1_proj2_proj3_2025-01-01_2025-01-31.xlsx` (multiple projects)

## Recipe Configuration

### YAML Structure
```yaml
name: Findings by Project
template: findings_by_project.html
description: Comprehensive inventory of findings across projects with optional filtering

query:
  endpoint: /public/v0/findings
  params:
    limit: 1000
    filter: "detected>=${start};detected<=${end}"

# Project list query for discovery
project_list_query:
  endpoint: /public/v0/projects
  params:
    limit: 1000
    archived: false

transform_function: findings_by_project_pandas_transform
output:
  table: true
  charts: []
```

### Template Requirements
- **HTML Template**: `templates/findings_by_project.html`
- **Responsive Design**: Works on various screen sizes
- **Print-Friendly**: Optimized for PDF export
- **Sortable Columns**: JavaScript-enabled sorting if possible
- **Filter Indicator**: Show applied project filter in report header

## CLI Integration

### New Parameters
```python
project_filter: Union[str, None] = typer.Option(
    None,
    "--project",
    "-pr",
    help="Filter by project (name, ID, or version ID). Use 'list' to see available projects.",
)
```

### Usage Examples
```bash
# All projects (default)
fs-report --recipe "Findings by Project" --period "1m"

# Filter by project name (case-insensitive)
fs-report --recipe "Findings by Project" --project "Reachability Demo" --period "1m"

# Filter by project ID
fs-report --recipe "Findings by Project" --project "4276528361006159502" --period "1m"

# Filter by version ID
fs-report --recipe "Findings by Project" --project "3434155612106342937" --period "1m"

# Multiple projects (comma-separated)
fs-report --recipe "Findings by Project" --project "proj1,proj2,proj3" --period "1m"

# List available projects
fs-report --recipe "Findings by Project" --project list
```

## Error Handling

### Data Quality Issues
- **Missing CVE IDs**: Handle gracefully, mark as "N/A" or similar
- **Missing CVSS Scores**: Default to 0 or "Unknown"
- **Missing Component Data**: Show "Unknown" for name/version
- **Missing CWE Data**: Show "Unknown" for ID/name

### Project Filter Issues
- **Invalid Project Name**: Clear error with available project names
- **Invalid Project ID**: Clear error with available project IDs
- **Invalid Version ID**: Clear error with available version IDs
- **No Matching Projects**: Informative message about filter criteria

### API Issues
- **Rate Limiting**: Implement retry logic with exponential backoff
- **Authentication Failures**: Clear error messages
- **Network Issues**: Graceful degradation

## Testing Requirements

### Test Data
- **Location**: `tests/fixtures/sample_data/findings_by_project_data.json`
- **Coverage**: Include various edge cases (missing data, different statuses, etc.)
- **Volume**: Test with both small and large datasets
- **Project Filters**: Test data with different project identifier types

### Test Scenarios
1. **Basic Functionality**: Normal data with all fields populated
2. **Missing Data**: Records with missing CVE, CVSS, or component data
3. **Large Dataset**: Performance testing with thousands of records
4. **API Errors**: Rate limiting and authentication failure scenarios
5. **Output Formats**: Verify XLSX, CSV, and HTML outputs
6. **Project Filtering**: Test all filter types (name, ID, version ID)
7. **Case Sensitivity**: Test project name filtering with different cases
8. **Invalid Filters**: Test error handling for invalid project identifiers

## Success Criteria

### Functional Requirements
- [ ] Generates complete finding inventory for all active projects (default)
- [ ] Supports filtering by project name (case-insensitive, exact match)
- [ ] Supports filtering by project ID (integer format, exact match)
- [ ] Supports filtering by version ID (integer format, exact match)
- [ ] Supports multiple project filtering (comma-separated list)
- [ ] Applies filtering at API level when possible
- [ ] Includes all required fields with proper data types
- [ ] Sorts correctly by CVSS score (descending)
- [ ] Handles missing data gracefully
- [ ] Produces XLSX output matching existing format
- [ ] Updates file naming to reflect applied filters (underscore sanitization)
- [ ] Provides similar name suggestions for invalid project names

### Performance Requirements
- [ ] Handles thousands of findings without memory issues
- [ ] Completes within reasonable time (< 5 minutes for typical datasets)
- [ ] Implements proper pagination and caching
- [ ] Applies project filters efficiently to reduce data processing

### Quality Requirements
- [ ] 90%+ test coverage
- [ ] Passes all linting and type checking
- [ ] Follows project coding standards
- [ ] Includes comprehensive error handling
- [ ] Provides clear error messages for invalid filters

## Implementation Plan

### Phase 1: Core Implementation
1. Create pandas transform function with project filtering
2. Implement data fetching and processing logic
3. Create HTML template with filter indicators
4. Add recipe configuration with project list query

### Phase 2: CLI Integration
1. Add `--project` parameter to CLI
2. Implement project filter type detection
3. Add project listing functionality
4. Update file naming logic

### Phase 3: Testing & Validation
1. Create test data and test cases for all filter types
2. Implement unit tests for filtering logic
3. Performance testing with large datasets
4. Output format validation

### Phase 4: Integration & Documentation
1. Integrate with main report engine
2. Update documentation with usage examples
3. Create example outputs for different filter scenarios
4. Final testing and validation

## Dependencies
- **pandas**: For data manipulation and transformation
- **openpyxl**: For XLSX output generation
- **jinja2**: For HTML template rendering
- **requests**: For API calls (via existing api_client)

## Notes
- This report is designed to replace or supplement existing Excel-based finding inventories
- The pandas approach provides better debugging and extensibility compared to DuckDB
- Project filtering enhances usability for customers with multiple projects
- Case-insensitive project name matching improves user experience
- Future enhancements could include multiple project selection and interactive project discovery 