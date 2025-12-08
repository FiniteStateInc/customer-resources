# Finite State Autotriage REST Script

A comprehensive Python script for managing vulnerability triage decisions using the Finite State REST API. Supports VEX (Vulnerability Exploitability eXchange) compliance with subcommand-based interface for better usability.

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Set Environment Variables

Create a `.env` file or export:

```bash
export FINITE_STATE_AUTH_TOKEN="your-api-token-here"
export FINITE_STATE_DOMAIN="your-org.finitestate.io"
```

### 3. Run the Script

```bash
# Show VEX information
python3 autotriage.py vex-info

# View findings for a project/version
python3 autotriage.py view <version_id>

# Replicate triage from one artifact to another
python3 autotriage.py replicate <source_id> <target_id> --dry-run

# Apply triage from CSV file
python3 autotriage.py apply -c cves.csv -v <version_id> --dry-run
```

## 📋 Commands

The script uses a subcommand-based interface for better organization:

### `vex-info`

Display VEX information and requirements.

```bash
python3 autotriage.py vex-info
```

### `view`

View findings for a project version. Accepts version ID, project ID, or project name.

```bash
# View by version ID
python3 autotriage.py view <version_id>

# View by project ID (shows latest version)
python3 autotriage.py view <project_id>

# View by project name (shows latest version)
python3 autotriage.py view "Project Name"

# With filters
python3 autotriage.py view <version_id> --severity HIGH --component spring-core

# With debug output
python3 autotriage.py view <version_id> --debug
```

**Options:**

- `--component <name>` - Filter by component name
- `--version <version>` - Filter by component version
- `--severity <level>` - Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, NONE, INFO)
- `--risk-min <score>` - Minimum risk score filter
- `--risk-max <score>` - Maximum risk score filter
- `--archived` - Include archived findings
- `--debug` - Enable debug output

### `replicate`

Replicate VEX triage decisions from a source artifact to a target artifact.

```bash
# Basic replication
python3 autotriage.py replicate <source_id> <target_id>

# Dry run (see what would change)
python3 autotriage.py replicate <source_id> <target_id> --dry-run

# With filtering
python3 autotriage.py replicate <source_id> <target_id> --severity HIGH --component spring-core

# Overwrite existing decisions
python3 autotriage.py replicate <source_id> <target_id> --overwrite
```

**Options:**

- `--component <name>` - Filter by component name
- `--version <version>` - Filter by component version
- `--severity <level>` - Filter by severity
- `--risk-min <score>` - Minimum risk score
- `--risk-max <score>` - Maximum risk score
- `--archived` - Include archived findings
- `--overwrite` - Overwrite existing status/justification
- `--skip-verification` - Skip project version verification
- `--dry-run` - Show what would change without making changes
- `--debug` - Enable debug output

### `apply`

Apply triage decisions from a CSV file or CVE list to one or more artifacts.

```bash
# Apply CSV to a specific version
python3 autotriage.py apply -c cves.csv -v <version_id> --dry-run

# Apply CSV to all versions in a project
python3 autotriage.py apply -c cves.csv -p <project_id> --dry-run

# Apply CSV organization-wide (requires confirmation)
python3 autotriage.py apply -c cves.csv --all-projects --dry-run

# Apply same status to multiple CVEs
python3 autotriage.py apply --cve "CVE-2023-12345,CVE-2023-12346" -v <version_id> -s NOT_AFFECTED --dry-run
```

**CSV Format:**

```csv
CVE,Status,Justification,Response,Reason
CVE-2023-12345,NOT_AFFECTED,CODE_NOT_PRESENT,WILL_NOT_FIX,Not in our codebase
CVE-2023-12346,FALSE_POSITIVE,CODE_NOT_PRESENT,WILL_NOT_FIX,False positive
```

**Options:**

- `-c, --cve-list <file>` - CSV file with CVEs and triage data
- `--cve <list>` - Comma-separated list of CVEs (requires `-s`)
- `-s, --apply-status <status>` - Status to apply (required for text format)
- `--apply-justification <value>` - Justification to apply
- `--apply-response <value>` - Response to apply
- `--apply-reason <text>` - Reason/comment to apply
- `-v, --version-id <id>` - Target version ID
- `--target-list <file>` - File with list of version IDs (one per line)
- `-p, --project-id <id>` - Apply to all versions in project
- `--all-projects` - Apply to all accessible projects (requires confirmation)
- `--overwrite` - Overwrite existing status
- `--dry-run` - Show what would change without making changes
- `--debug` - Enable debug output

### `rollback`

Restore findings from a backup file.

```bash
python3 autotriage.py rollback backups/backup_<id>_<timestamp>.json
```

Backups are automatically created before making changes (when not in dry-run mode).

## 📊 VEX Status Values

- **NOT_AFFECTED**: Vulnerability does not affect this component
- **FALSE_POSITIVE**: Finding is incorrect or not applicable
- **IN_TRIAGE**: Under investigation
- **RESOLVED_WITH_PEDIGREE**: Fixed with documented changes
- **RESOLVED**: Fixed
- **EXPLOITABLE**: Confirmed exploitable

## 🎯 VEX Justification Values

- **CODE_NOT_PRESENT**: Vulnerable code not in this version
- **CODE_NOT_REACHABLE**: Code present but not accessible
- **REQUIRES_CONFIGURATION**: Needs specific config to exploit
- **REQUIRES_DEPENDENCY**: Needs specific dependency to exploit
- **REQUIRES_ENVIRONMENT**: Needs specific environment to exploit
- **PROTECTED_BY_COMPILER**: Compiler protection prevents exploit
- **PROTECTED_AT_RUNTIME**: Runtime protection prevents exploit
- **PROTECTED_AT_PERIMETER**: Network/security controls prevent exploit
- **PROTECTED_BY_MITIGATING_CONTROL**: Other controls prevent exploit

## 🔄 VEX Response Values

- **CAN_NOT_FIX**: Unable to fix the vulnerability
- **WILL_NOT_FIX**: Decision not to fix
- **UPDATE**: Will update to fix
- **ROLLBACK**: Will rollback to previous version
- **WORKAROUND_AVAILABLE**: Alternative mitigation exists

## 📝 Examples

### View Findings

```bash
# View findings for a version
python3 autotriage.py view 1234567890123456789

# View latest version of a project
python3 autotriage.py view -9193618121057357350

# View by project name
python3 autotriage.py view "My Project"

# View with filters
python3 autotriage.py view 1234567890123456789 --severity HIGH --component spring-core --debug
```

### Replicate Triage

```bash
# Basic replication (dry-run first!)
python3 autotriage.py replicate 1234567890123456789 9876543210987654321 --dry-run

# Replication with filtering
python3 autotriage.py replicate 1234567890123456789 9876543210987654321 --severity HIGH --component spring-core --dry-run

# Overwrite mode
python3 autotriage.py replicate 1234567890123456789 9876543210987654321 --overwrite --dry-run
```

### Apply CSV Triage

```bash
# Apply to a version
python3 autotriage.py apply -c test_cves.csv -v 1234567890123456789 --dry-run

# Apply to all versions in a project
python3 autotriage.py apply -c test_cves.csv -p -9193618121057357350 --dry-run

# Apply to multiple versions from file
python3 autotriage.py apply -c test_cves.csv --target-list versions.txt --dry-run
```

### Rollback

```bash
# Restore from backup
python3 autotriage.py rollback backups/backup_1234567890123456789_20251126_142150.json
```

## 🔒 Backup and Restore

The script automatically creates backups before making changes (when not in `--dry-run` mode):

- Backups are saved in `backups/` directory
- Filename format: `backup_<artifact_id>_<timestamp>.json`
- Contains all findings that will be modified
- Use `rollback` command to restore

**Note:** Findings with `null` or `UNTRIAGED` status are skipped during rollback (API limitation).

## ⚠️ Important Notes

### VEX Compliance

- Status is **required** by the API
- Justification and Response are **recommended** by VEX standards
- The script applies sensible defaults when justification/response are missing
- Defaults ensure VEX compliance while allowing status-only updates

### Default VEX Values

When justification/response are missing, defaults are applied:

- `NOT_AFFECTED` → `CODE_NOT_PRESENT` + `WILL_NOT_FIX`
- Other statuses get appropriate defaults

### Environment Setup

- Requires Python 3.6+ (recommended: 3.8+)
- Only external dependency: `requests` library
- API token must have appropriate permissions
- Project versions must exist and be accessible

### Dry-Run Mode

**Always use `--dry-run` first** to see what would change:

```bash
python3 autotriage.py replicate <source> <target> --dry-run
python3 autotriage.py apply -c cves.csv -v <version_id> --dry-run
```

## 🛠️ Troubleshooting

### Common Issues

1. **"Could not resolve to a valid project or version"**

   - Verify the identifier exists
   - Check if you're pointing to the correct Finite State instance
   - Try using `--debug` to see resolution details
2. **"No findings found"**

   - Verify the version ID exists
   - Check if scans have been completed
   - Ensure you have access to the project
3. **"Missing justification/response"**

   - Source findings should have complete VEX information
   - Use `--debug` to see which findings are incomplete
   - Defaults are applied automatically if missing

### Debug Mode

Always use `--debug` when troubleshooting:

```bash
python3 autotriage.py view <version_id> --debug
python3 autotriage.py replicate <source> <target> --debug --dry-run
```

## 📦 Requirements

### Minimal (Production)

```txt
requests>=2.25.0
```

### Install with:

```bash
pip install -r requirements.txt
```


## 🔄 Project/Version Resolution

The `view` command can resolve:

- **Version IDs**: Used directly
- **Project IDs**: Resolved to latest version (by `created` date)
- **Project Names**: Case-insensitive lookup, resolved to latest version

Both positive and negative IDs are supported (unsigned integers).

## 📄 Related Files

- `autotriage.py` - Main script
- `requirements.txt` - Full requirements
- `test_cves.csv` - Example CSV file

## 📞 Support

For issues or questions:

1. Check the debug output for detailed error information
2. Verify your environment variables are set correctly
3. Ensure your API token has the necessary permissions]
4. Contact your Finite State support team at support@finitestate.io

## 🔄 Version History

- **v2.0**: Subcommand-based interface, CSV import, backup/restore, project resolution
- **v1.0**: Initial release with VEX compliance
