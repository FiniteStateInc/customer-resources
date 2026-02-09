# Common Workflows

This guide covers common use cases and workflows for FS-Smartsheet.

## Table of Contents

- [Initial Setup](#initial-setup)
- [Daily Sync Workflow](#daily-sync-workflow)
- [VEX Workflow (Vulnerability Triage)](#vex-workflow-vulnerability-triage)
- [Executive Reporting](#executive-reporting)
- [Automated CI/CD Integration](#automated-cicd-integration)

---

## Initial Setup

### Step 1: Get API Credentials

**Finite State:**
1. Log in to your Finite State instance
2. Go to **Settings → API Tokens**
3. Click **Create Token**
4. Copy the token (you won't see it again!)

**Smartsheet:**
1. Log in to Smartsheet
2. Go to **Account → Personal Settings → API Access**
3. Click **Generate new access token**
4. Copy the token

### Step 2: Configure Environment

```bash
# Add to your shell profile (~/.zshrc or ~/.bashrc)
export FINITE_STATE_DOMAIN="your-org.finitestate.io"
export FINITE_STATE_AUTH_TOKEN="your-fs-token"
export SMARTSHEET_ACCESS_TOKEN="your-ss-token"

# Reload shell
source ~/.zshrc
```

### Step 3: Verify Setup

```bash
cd fs-smartsheet
uv run fs-smartsheet verify
```

Expected output:
```
Verifying API connections...

┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Service        ┃ Status       ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ Finite State   │ ✓ Connected  │
│ Smartsheet     │ ✓ Connected  │
└────────────────┴──────────────┘
```

### Step 4: Create Sheets

```bash
uv run fs-smartsheet init
```

This creates the workspace and folder hierarchy, plus the FS Projects sheet:
- **FS Projects** - Project overview (always at workspace root)
- **FS Findings** - Security findings (supports status updates, created per-project on sync)
- **FS Components** - Software components (created per-project on sync)

To use a different workspace name:
```bash
uv run fs-smartsheet init --workspace "My Security Data"
```

#### Keeping Hierarchy in Sync

When your Finite State folder structure changes (projects moved, renamed, or deleted):

```bash
# Detect what's changed (dry-run)
uv run fs-smartsheet init --refresh

# Delete orphaned Smartsheet folders/sheets
uv run fs-smartsheet init --refresh --clean
```

This compares the current FS folder tree with the Smartsheet workspace and reports new, matched, and orphaned paths. With `--clean`, orphaned items are removed (sheets first, then folders deepest-first).

### Step 5: Initial Sync

```bash
# Full sync to populate all data
uv run fs-smartsheet sync all --full

# Or sync only a specific project (auto-mirrors FS folder hierarchy in Smartsheet)
uv run fs-smartsheet sync all --full --project "My Product"

# Sync with persistent cache (second run within 4 hours is instant)
uv run fs-smartsheet sync all --full --project "My Product" --cache-ttl 4

# Sync into a specific Smartsheet folder (bypasses hierarchy)
uv run fs-smartsheet sync findings --project "My Product" --target-folder 1234567890

# Include file-type components/findings (excluded by default)
uv run fs-smartsheet sync all --full --include-files
```

When using `--project`, the tool automatically mirrors the FS folder hierarchy in Smartsheet:
- If the project is in FS folder path `Automotive / ECU Team`, sheets are created at `Workspace / Automotive / ECU Team /` (directly in the FS folder — no per-project subfolder).
- If the project has no FS folder, sheets go at the workspace root.
- The **FS Projects** sheet always stays at the workspace root.

---

## Daily Sync Workflow

For ongoing synchronization, run incremental syncs:

```bash
# Quick incremental sync (only changes)
uv run fs-smartsheet sync all

# Sync a specific project (mirrors FS folder hierarchy in Smartsheet)
uv run fs-smartsheet sync all --project "My Product"

# Sync with cache (repeat syncs within 4 hours skip API calls)
uv run fs-smartsheet sync all --project "My Product" --cache-ttl 4

# Force fresh data (ignore cache)
uv run fs-smartsheet sync all --project "My Product" --no-cache

# Sync to a specific folder (bypasses hierarchy)
uv run fs-smartsheet sync findings --target-folder 1234567890

# Check sync status
uv run fs-smartsheet status
```

> **Note on file filtering:** By default, components and findings with `type = "file"` are excluded to keep sheets focused on libraries and known vulnerability types. Use `--include-files` to include them.

### Using the API Cache

For large deployments where syncing takes minutes, use `--cache-ttl` to avoid re-fetching data from the FS API on every run:

```bash
# Cache API responses for 4 hours — repeat syncs are instant
uv run fs-smartsheet sync findings --project "Router-FW" --cache-ttl 4

# View cache stats
uv run fs-smartsheet cache stats

# Clear stale cache data
uv run fs-smartsheet cache clear
```

The cache is stored in `~/.fs-smartsheet/{domain}.db` (separate from `fs-report`). It only caches read operations — write-backs and status updates always go to the live API.

### Automating with Cron

```bash
# Edit crontab
crontab -e

# Add line for hourly sync (with 4-hour cache to reduce API load)
0 * * * * cd /path/to/fs-smartsheet && /path/to/.venv/bin/fs-smartsheet sync all --cache-ttl 4 >> /var/log/fs-sync.log 2>&1
```

### Automating with AWS Lambda

1. Deploy Lambda function (see README)
2. Create CloudWatch Event rule:
   - Schedule: `rate(1 hour)`
   - Target: Your Lambda function

---

## VEX Workflow (Vulnerability Triage)

The VEX (Vulnerability Exploitability eXchange) workflow allows security teams to triage findings in Smartsheet and sync decisions back to Finite State.

### Overview

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Analyst   │    │ Smartsheet  │    │FS-Smartsheet│    │Finite State │
│   Reviews   │───►│   Updates   │───►│  Writeback  │───►│   Updated   │
│   Finding   │    │   Status    │    │  (validates │    │             │
└─────────────┘    └─────────────┘    │  & batches) │    └─────────────┘
                                      └─────────────┘
```

### Step 1: Review Findings in Smartsheet

Open the **FS Findings** sheet. Key columns for triage:

| Column | Use |
|--------|-----|
| CVE ID | Vulnerability identifier |
| Severity | Priority for review |
| Risk Score | Finite State's risk assessment |
| EPSS Score | Exploit probability |
| In KEV | Is it actively exploited? |
| Component | Affected component |
| **Status** | Your triage decision (editable) |
| **Response** | Required for EXPLOITABLE status |
| **Justification** | Required for NOT_AFFECTED status |
| **Reason** | Optional comment/explanation |

### Step 2: Update Status

For each finding, set the **Status** column to one of:

| Status | Required Field | Meaning |
|--------|----------------|---------|
| `EXPLOITABLE` | Response + Justification | Vulnerability is exploitable, action needed |
| `NOT_AFFECTED` | Justification | Component not actually affected |
| `IN_TRIAGE` | - | Currently being analyzed |
| `RESOLVED` | - | Vulnerability has been remediated |
| `RESOLVED_WITH_PEDIGREE` | - | Resolved with tracking history |
| `FALSE_POSITIVE` | - | Not a real vulnerability |
| *(blank)* | - | Clear the status (reset to unset) |

**Response Values (for EXPLOITABLE):**
- `Can Not Fix` - Cannot be fixed due to constraints
- `Will Not Fix` - Decision not to fix
- `Update` - Will update the component
- `Rollback` - Will rollback to safe version
- `Workaround Available` - Mitigation in place

**Justification Values (for NOT_AFFECTED):**
- `Code Not Present` - Vulnerable code doesn't exist
- `Code Not Reachable` - Code exists but can't be reached
- `Requires Configuration` - Only vulnerable with specific config
- `Requires Dependency` - Missing required dependency
- `Requires Environment` - Environment doesn't support exploit
- `Protected By Compiler` - Compiler mitigations prevent exploit
- `Protected At Runtime` - Runtime protections in place
- `Protected At Perimeter` - Network protections block exploit
- `Protected By Mitigating Control` - Other mitigations in place

**Validation:** The writeback command validates that required fields are set before sending to Finite State. Invalid rows are skipped with clear error messages.

### Step 3: Sync Back to Finite State

Run the `sync` command — it automatically detects VEX edits you made in Smartsheet and pushes them back to Finite State:

```bash
uv run fs-smartsheet sync findings -p "My App" -w "My Workspace"
```

The sync results table shows a **Write-back** column. When edits are detected, you will see output like:

```
Write-back=1; Status: (empty) -> IN_TRIAGE
```

The sync command:
1. Detects changed writeback fields (Status, Response, Justification, Reason) in Smartsheet
2. Validates each change (e.g. EXPLOITABLE requires Response)
3. Pushes valid changes to Finite State in parallel
4. Reports results in the sync summary

### Step 4: Bulk Updates from CLI

For mass-updates without editing Smartsheet, use the `writeback` command to
apply a VEX status directly to the Finite State API:

```bash
# Mark all critical findings as IN_TRIAGE
uv run fs-smartsheet writeback --status IN_TRIAGE --severity critical

# Mark a project's findings as NOT_AFFECTED
uv run fs-smartsheet writeback --status NOT_AFFECTED \
    --justification "Code Not Reachable" --project "My App"

# Preview first
uv run fs-smartsheet writeback --status IN_TRIAGE \
    --severity critical --dry-run
```

### Step 5: Verify in Finite State

Log in to Finite State and verify the finding statuses were updated.

### Recommended Triage Process

1. **Filter by severity:** Focus on Critical/High first
2. **Check EPSS:** High EPSS score = higher priority
3. **Check KEV:** If `In KEV = true`, prioritize immediately
4. **Review component:** Is this component actually used?
5. **Set status:** Select appropriate VEX status
6. **Add required fields:** Response for EXPLOITABLE, Justification for NOT_AFFECTED
7. **Add reason:** Document your reasoning in the Reason column
8. **Sync changes:** Run `sync findings` to push edits back to Finite State

---

## Executive Reporting

Use the synced Smartsheet data for executive dashboards and reports.

### Findings Summary for Leadership

Use the **FS Findings** sheets for executive reporting:

1. Open a project's Findings sheet
2. Create a Smartsheet Report or Dashboard
3. Key metrics to highlight:
   - Total Critical/High findings
   - Findings in CISA KEV
   - EPSS scores above threshold
   - Trending (detected this week)

### Automated Reports

Use Smartsheet's automation to:
1. Send weekly email summaries
2. Alert on new Critical findings
3. Notify when high-risk findings are detected

---

## Automated CI/CD Integration

Integrate FS-Smartsheet into your CI/CD pipeline.

### GitHub Actions Example

```yaml
# .github/workflows/sync-security-data.yml
name: Sync Security Data

on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours
  workflow_dispatch:  # Manual trigger

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install UV
        uses: astral-sh/setup-uv@v1
        
      - name: Install dependencies
        run: uv sync
        
      - name: Run sync
        env:
          FINITE_STATE_DOMAIN: ${{ secrets.FS_DOMAIN }}
          FINITE_STATE_AUTH_TOKEN: ${{ secrets.FS_TOKEN }}
          SMARTSHEET_ACCESS_TOKEN: ${{ secrets.SS_TOKEN }}
        run: uv run fs-smartsheet sync all
```

### Jenkins Pipeline Example

```groovy
pipeline {
    agent any
    
    environment {
        FINITE_STATE_DOMAIN = credentials('fs-domain')
        FINITE_STATE_AUTH_TOKEN = credentials('fs-token')
        SMARTSHEET_ACCESS_TOKEN = credentials('ss-token')
    }
    
    triggers {
        cron('H */6 * * *')
    }
    
    stages {
        stage('Sync') {
            steps {
                sh 'uv run fs-smartsheet sync all'
            }
        }
    }
}
```

### Post-Build Sync

After scanning new firmware:

```bash
#!/bin/bash
# post-scan-sync.sh

# Wait for Finite State to process the scan
sleep 300  # 5 minutes

# Sync latest findings to Smartsheet
uv run fs-smartsheet sync findings --full

# Notify team
echo "Security data synced to Smartsheet"
```

---

## Troubleshooting Workflows

### Column Mismatch Errors

If the schema has changed (new columns added), existing sheets may fail to sync. Use the `reset` command to delete and recreate them:

```bash
# Reset all sheets (prompts for confirmation)
uv run fs-smartsheet reset all

# Reset just findings
uv run fs-smartsheet reset findings

# Reset sheets for a specific project (uses hierarchy resolution)
uv run fs-smartsheet reset findings --project "My Product"

# Reset into a specific folder (bypasses hierarchy)
uv run fs-smartsheet reset findings --target-folder 1234567890

# Skip confirmation
uv run fs-smartsheet reset all --yes
```

The `reset` command uses the same hierarchy resolution as `sync`. After deleting sheets it clears all workspace and folder caches, so if Smartsheet auto-deleted an empty folder the recreation step will create a fresh one.

After reset, run a full sync to repopulate:
```bash
uv run fs-smartsheet sync all --full
```

### Sync Not Picking Up Changes

```bash
# Force a full sync
uv run fs-smartsheet sync all --full

# Or reset state
rm .fs-smartsheet-state.json
uv run fs-smartsheet sync all --full
```

### Writeback Not Working

1. **Missing project_version_id:** Re-sync findings to populate the state file
   ```bash
   uv run fs-smartsheet sync findings --project "Your Project"
   ```

2. **Validation errors:** Check that required fields are set
   - `EXPLOITABLE` requires `Response` AND `Justification`
   - `NOT_AFFECTED` requires `Justification`
   - Clearing a status (setting to blank) is supported and clears all VEX fields

3. **Lock file stuck:** Remove the lock file if a previous run crashed
   ```bash
   rm ~/.fs-smartsheet/.writeback.lock
   ```

4. **Check writeback columns exist:**
   ```bash
   uv run fs-smartsheet config-show
   ```

5. **Run with verbose output:**
   ```bash
   uv run fs-smartsheet writeback --verbose
   ```

### Rate Limiting

If you see 429 errors:

1. Reduce sync frequency
2. Increase batch size to reduce calls
3. Use incremental syncs instead of full

```bash
# Set larger batch size
export SYNC_BATCH_SIZE=200
```

### Connection Timeouts

For large datasets:

```python
# Increase timeout in code
client = FiniteStateClient(
    domain=domain,
    auth_token=token,
    timeout=120.0  # 2 minutes
)
```
