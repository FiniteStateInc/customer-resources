# FS-Smartsheet

An abstraction layer that synchronizes data between the **Finite State** firmware security platform and **Smartsheet**, enabling teams to manage security findings, track components, and monitor projects using familiar spreadsheet workflows.

## Overview

FS-Smartsheet bridges the gap between security engineering and project management by:

- **Exporting security data** from Finite State to Smartsheet for visibility and collaboration
- **Enabling VEX workflow** by allowing status updates in Smartsheet to sync back to Finite State
- **Automating reporting** through scheduled syncs and real-time webhooks

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FS-Smartsheet Architecture                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────┐         ┌──────────────────┐         ┌─────────────┐      │
│   │   Finite    │  HTTP   │                  │  HTTP   │             │      │
│   │   State     │◄───────►│   Sync Engine    │◄───────►│  Smartsheet │      │
│   │   API       │         │                  │         │     API     │      │
│   └─────────────┘         └────────┬─────────┘         └─────────────┘      │
│         │                          │                          │             │
│         │                          │                          │             │
│   ┌─────▼─────┐            ┌───────▼───────┐          ┌───────▼───────┐     │
│   │ Projects  │            │  State File   │          │   Sheets:     │     │
│   │ Findings  │            │  (JSON cache  │          │  - Projects   │     │
│   │ Components│            │   for delta   │          │  - Findings   │     │
│   └───────────┘            │   sync)       │          │  - Components │     │
│                            └───────────────┘          └───────────────┘     │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Features

| Feature | Description |
|---------|-------------|
| **Bidirectional Sync** | Pull data from Finite State → Smartsheet; push status updates back |
| **Multiple Data Types** | Projects, Findings, and Components |
| **Incremental Sync** | State tracking enables efficient delta syncs (only changed data) |
| **Full Sync** | Complete data refresh when needed |
| **VEX Workflow** | Update finding status in Smartsheet, sync back to Finite State |
| **Flexible Deployment** | CLI for ad-hoc use or scripted automation |
| **Configurable Mappings** | Customize field mappings via YAML configuration |

## Quick Start

### 1. Installation

```bash
# Install UV if you don't have it (https://docs.astral.sh/uv/)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone https://github.com/FiniteStateInc/customer-resources.git
cd customer-resources/06-advanced-integrations-and-demos/fs-smartsheet

# Install dependencies
uv sync
```

### 2. Configuration

Set environment variables:

```bash
# Finite State API (get token from Settings → API Tokens)
export FINITE_STATE_DOMAIN="your-org.finitestate.io"
export FINITE_STATE_AUTH_TOKEN="your-api-token"

# Smartsheet API (get token from Account → Personal Settings → API Access)
export SMARTSHEET_ACCESS_TOKEN="your-smartsheet-token"
```

### 3. Verify Connections

```bash
uv run fs-smartsheet verify
```

### 4. Initialize Workspace and Folder Hierarchy

```bash
uv run fs-smartsheet init
```

This connects to both APIs and sets up the Smartsheet workspace:

1. **Creates the workspace** (default: "Finite State", override with `--workspace`)
2. **Creates the FS Projects sheet** at the workspace root
3. **Fetches all projects** from Finite State and mirrors the FS folder structure as Smartsheet folders

After init, your workspace will mirror the Finite State folder hierarchy.  Only FS folders are created — project sheets are placed directly inside their folder when you sync:

```
Finite State (workspace)
├── FS Projects                    (sheet, at workspace root)
├── Automotive/                    (top-level FS folder)
│   └── ECU Team/                  (nested FS subfolder)
├── Medical/
└── Sensors/
```

The folders are empty until you run `sync` — that's when data sheets like `Router-FW Findings` and `Router-FW Components` are created inside the appropriate FS folder.  Projects without an FS folder get their sheets at the workspace root.

#### Keeping the Hierarchy in Sync

When your Finite State folder structure changes (projects moved, folders renamed or deleted), run `init --refresh` to detect and report differences:

```bash
# See what's changed (dry-run)
uv run fs-smartsheet init --refresh

# Also delete orphaned Smartsheet folders/sheets
uv run fs-smartsheet init --refresh --clean
```

`--refresh` compares the current FS folder tree with the Smartsheet workspace and reports:
- **New paths**: FS folders not yet in Smartsheet (created automatically)
- **Orphaned folders**: Smartsheet folders with no matching FS folder
- **Orphaned sheets**: Sheets inside orphaned folders

`--clean` actually deletes the orphaned items (sheets first, then folders deepest-first).

### 5. Sync Data

```bash
# Sync a project (findings + components, placed in the project's FS folder)
uv run fs-smartsheet sync --project "My Product"

# Sync just findings for a project
uv run fs-smartsheet sync findings --project "My Product"

# Sync critical/high findings from the last 30 days
uv run fs-smartsheet sync findings --severity critical,high --since 30d

# Sync with persistent cache (second run within 4 hours is instant)
uv run fs-smartsheet sync --project "My Product" --cache-ttl 4
```

> **Tip:** When you omit the sheet type (or use `all`), `--project` automatically syncs findings and components for that project. Without `--project`, it syncs all three sheet types (projects, findings, components).

### API Response Caching

For large deployments, repeatedly syncing can be slow because every run re-fetches data from the Finite State API. Use `--cache-ttl` to cache API responses in a local SQLite database:

```bash
# Cache for 4 hours (bare number = hours)
uv run fs-smartsheet sync findings --project "My Product" --cache-ttl 4

# Cache for 30 minutes
uv run fs-smartsheet sync findings --project "My Product" --cache-ttl 30m

# Cache for 1 day
uv run fs-smartsheet sync findings --project "My Product" --cache-ttl 1d

# Combined: 1 hour 30 minutes
uv run fs-smartsheet sync findings --project "My Product" --cache-ttl 1h30m

# Force fresh data (bypass any existing cache)
uv run fs-smartsheet sync findings --project "My Product" --no-cache
```

The cache is stored in `~/.fs-smartsheet/{domain}.db` (separate from `fs-report`'s `~/.fs-report/` cache). Key behaviors:

- **Default:** Caching is **disabled** (every run fetches fresh data)
- **TTL checked at session start:** The cache cannot expire mid-sync
- **Crash recovery:** Incomplete fetches from crashed runs are automatically discarded
- **Works with init too:** `uv run fs-smartsheet init --cache-ttl 4` caches folder/project data

```bash
# View cache stats
uv run fs-smartsheet cache stats

# Clear all cached data
uv run fs-smartsheet cache clear
```

#### When to use caching

| Scenario | Recommendation |
|----------|---------------|
| Iterating on filters or sheet layout | `--cache-ttl 4` — avoids re-fetching while you experiment |
| Scheduled/cron sync | `--cache-ttl 1` (1 hour) — reduces API load between runs |
| After making changes in Finite State | `--no-cache` — ensures you see the latest data |
| After running `writeback` | No action needed — the next `sync` will fetch fresh data |
| First sync of a new project | Omit the flag (or `--no-cache`) — there's nothing to cache yet |

**Things to know:**

- **Different filters produce different cache entries.** A cached `sync findings -p "Router"` will *not* speed up `sync findings -p "Router" -s critical` — that's a separate query with its own cache key. If you plan to run several filter variations, the first run of each combination will still hit the API.
- **The TTL is how stale you're willing to tolerate.** If a new scan completes in Finite State 5 minutes after your last cached sync, you won't see those results until the TTL expires or you run with `--no-cache`.
- **`cache clear` wipes everything.** There is no way to selectively evict one project or query — it deletes the entire SQLite database.

## Filtering (Essential for Large Deployments)

For enterprise deployments with thousands of projects and millions of findings, **always use filters** to scope your sync:

### Filter Options

| Filter | Flag | Example |
|--------|------|---------|
| **Project** | `--project, -p` | `--project "Product-A"` or `-p "id1,id2"` |
| **Severity** | `--severity, -s` | `-s critical,high` |
| **VEX Status** | `--status` | `--status null` (unreviewed only) |
| **Time Range** | `--since` | `--since 30d` or `--since 2024-01-01` |
| **Finding Type** | `--type, -t` | `-t cve,binary-sast` |
| **Row Limit** | `--max-rows` | `--max-rows 5000` |

### Examples

```bash
# Sync all critical findings across all projects
uv run fs-smartsheet sync findings --severity critical

# Sync findings for specific projects only
uv run fs-smartsheet sync findings --project "Product-A,Product-B"

# Sync unreviewed findings from the last week
uv run fs-smartsheet sync findings --status null --since 7d

# Sync high/critical CVE-type findings for a project
uv run fs-smartsheet sync findings -p "My Product" -s critical,high -t cve

# Limit to 5000 rows
uv run fs-smartsheet sync findings --max-rows 5000
```

### Recommended Patterns for Enterprise

| Use Case | Command |
|----------|---------|
| **Daily triage** | `sync findings -s critical,high --status null --since 1d` |
| **Weekly report** | `sync findings -p "Product-X" --since 7d` |
| **Project review** | `sync findings --project "Release-2024"` |
| **CVE tracking** | `sync findings --severity critical,high -t cve` |

## Data Flow

### Read Flow (Finite State → Smartsheet)

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  FS API     │───►│  FS Client  │───►│  Mapper     │───►│  Smartsheet │
│  Response   │    │  (Parse)    │    │  (Transform)│    │  (Write)    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
     JSON              Pydantic           Dict with          Rows
     Data              Models             SS columns         Added/Updated
```

### Write-back Flow (Smartsheet → Finite State)

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Smartsheet │───►│  Change     │───►│  Mapper     │───►│  FS API     │
│  Row Change │    │  Detection  │    │  (Reverse)  │    │  PUT Status │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
     User edits        Compare           Extract           Update
     Status column     with state        FS fields         finding VEX
```

## Smartsheet Hierarchy

When syncing project-specific data, FS-Smartsheet mirrors the Finite State **folder** hierarchy inside a Smartsheet workspace.  Only FS folders become Smartsheet folders — project sheets are placed directly inside their FS folder:

```
Smartsheet Workspace: "Finite State"
├── FS Projects                          (always at workspace root)
├── Automotive/                          (top-level FS folder)
│   ├── ECU Team/                        (nested FS subfolder)
│   │   ├── Infotainment-FW Findings     (sheet — directly in folder)
│   │   └── Infotainment-FW Components
│   └── Sensors/
│       ├── Lidar-Module Findings
│       └── Lidar-Module Components
├── Medical/
│   ├── Router-Firmware Findings
│   ├── Router-Firmware Components
│   ├── Gateway-Firmware Findings
│   └── Gateway-Firmware Components
├── Standalone-Project Findings          (no FS folder → workspace root)
└── Standalone-Project Components
```

**Rules:**

| Scenario | Sheet location |
|----------|---------------|
| `--project "X"` where X is in FS folder path `A / B / C` | `Workspace / A / B / C / sheets` |
| `--project "X"` where X has no FS folder | Workspace root |
| `projects` sheet type | Always at workspace root |
| No project filter | Workspace root |
| `--target-folder <id>` | Specified folder (bypasses hierarchy) |
| `--sheet-name "Custom"` | Workspace root with custom name |

The `--target-folder` flag accepts a Smartsheet folder ID and places sheets directly in that folder, bypassing all automatic hierarchy logic. This is useful for one-off syncs or custom organizational structures.

## Synced Data Types

### Projects Sheet

Provides an overview of all projects in Finite State.

| Column | FS Field | Description |
|--------|----------|-------------|
| Project ID | `id` | Unique identifier (primary key) |
| Name | `name` | Project name |
| Description | `description` | Project description |
| Created | `created` | Creation timestamp |
| Type | `type` | Project type (application, etc.) |
| Created By | `createdBy` | Creator email |
| Findings | `defaultBranch.latestVersion.findings` | Finding count |
| Components | `defaultBranch.latestVersion.components` | Component count |
| Violations | `defaultBranch.latestVersion.violations` | Violation count |
| Warnings | `defaultBranch.latestVersion.warnings` | Warning count |

### Findings Sheet

Security findings with vulnerability data. **Supports write-back for Status, Response, Justification, and Reason.**

| Column | FS Field | Description | Write-back |
|--------|----------|-------------|------------|
| Finding ID | `id` | Internal identifier (primary key) | No |
| CVE ID | `findingId` | CVE ID or FS finding ID | No |
| Title | `title` | Finding title | No |
| Severity | `severity` | critical/high/medium/low | No |
| **Status** | `status` | VEX status | **Yes** |
| **Response** | `response` | Response action (for EXPLOITABLE) | **Yes** |
| **Justification** | `justification` | Justification (for NOT_AFFECTED) | **Yes** |
| **Reason** | `reason` | Optional comment/reason | **Yes** |
| Risk Score | `risk` | Risk score (0-100) | No |
| EPSS Score | `epssScore` | EPSS probability | No |
| EPSS Percentile | `epssPercentile` | EPSS percentile | No |
| In KEV | `inKev` | In CISA KEV catalog | No |
| Component | `component.name` | Affected component | No |
| Component Version | `component.version` | Component version | No |
| Project | `project.name` | Parent project | No |
| Project Version | `projectVersion.version` | Project version | No |
| Detected | `detected` | Detection date | No |
| Attack Vector | `attackVector` | Attack vector classification | No |
| Finding Type | `type` | Finding type (cve, binary-sast, etc.) | No |

**VEX Status Values:**

| Status | Required Fields | Description |
|--------|-----------------|-------------|
| `EXPLOITABLE` | Response, Justification | Vulnerability is exploitable |
| `RESOLVED` | - | Vulnerability has been resolved |
| `RESOLVED_WITH_PEDIGREE` | - | Resolved with tracking |
| `IN_TRIAGE` | - | Under investigation |
| `FALSE_POSITIVE` | - | Not a real vulnerability |
| `NOT_AFFECTED` | Justification | Component not affected |

> **Note:** The Finite State API currently requires `response` and `justification` for all statuses. For statuses where these aren't semantically meaningful (e.g., `IN_TRIAGE`), the integration auto-fills default values. You only need to set the fields listed above.

**Response Values (for EXPLOITABLE):**
- `Can Not Fix`
- `Will Not Fix`
- `Update`
- `Rollback`
- `Workaround Available`

**Justification Values (for NOT_AFFECTED):**
- `Code Not Present`
- `Code Not Reachable`
- `Requires Configuration`
- `Requires Dependency`
- `Requires Environment`
- `Protected By Compiler`
- `Protected At Runtime`
- `Protected At Perimeter`
- `Protected By Mitigating Control`

### Components Sheet

Software components discovered in analyzed binaries/SBOMs. File-type components are excluded by default (use `--include-files` to include them).

| Column | FS Field | Description |
|--------|----------|-------------|
| Component ID | `id` | Unique identifier |
| Name | `name` | Component name |
| Component Version | `version` | Component version |
| Type | `type` | file, library, etc. |
| Supplier | `supplier` | Component supplier |
| Declared Licenses | `declaredLicenses` | Declared license information |
| Concluded Licenses | `concludedLicenses` | Concluded license information |
| Findings | `findings` | Associated finding count |
| Violations | `violations` | Violation count |
| Warnings | `warnings` | Warning count |
| Project | `project.name` | Parent project |
| Project Version | `projectVersion.version` | Project version |
| Source | `source` | Component source(s) |

## CLI Reference

### `fs-smartsheet verify`

Test connections to both APIs.

```bash
uv run fs-smartsheet verify
```

### `fs-smartsheet init`

Initialize the Smartsheet workspace, create the FS Projects sheet at the workspace root, and build the full folder hierarchy by mirroring the Finite State folder tree (including nested subfolders) and project structure.

```bash
# Initialize with default workspace name ("Finite State")
uv run fs-smartsheet init

# Initialize with a custom workspace name
uv run fs-smartsheet init --workspace "My Security Data"

# Detect hierarchy differences (dry-run)
uv run fs-smartsheet init --refresh

# Detect and clean up orphaned folders/sheets
uv run fs-smartsheet init --refresh --clean
```

**Options:**

| Option | Description |
|--------|-------------|
| `--workspace, -w` | Smartsheet workspace name (default: "Finite State", created if not exists) |
| `--refresh` | Compare FS hierarchy with Smartsheet and report differences |
| `--clean` | Delete orphaned folders/sheets (requires `--refresh`) |
| `--cache-ttl` | Cache FS API responses with TTL (e.g. `4`, `30m`, `1d`). Default: disabled |
| `--no-cache` | Force fresh data (ignore any existing cache) |

### `fs-smartsheet cache`

Manage the local SQLite API cache.

```bash
# Show cache statistics
uv run fs-smartsheet cache stats

# Clear all cached data
uv run fs-smartsheet cache clear
```

### `fs-smartsheet sync`

Synchronize data from Finite State to Smartsheet.

```bash
# Sync specific sheet type with filters (recommended)
uv run fs-smartsheet sync findings --project "My Project" --severity critical,high

# Sync all sheets (uses default 10K row limit)
uv run fs-smartsheet sync all

# Sync with time filter
uv run fs-smartsheet sync findings --since 30d

# Sync unreviewed findings only
uv run fs-smartsheet sync findings --status null

# Override row limits (use with caution)
uv run fs-smartsheet sync findings --force

# Sync to a specific Smartsheet folder by ID (bypasses hierarchy)
uv run fs-smartsheet sync findings --target-folder 1234567890
```

**Options:**

| Option | Description |
|--------|-------------|
| `--full, -f` | Full sync (refresh all data) |
| `--project, -p` | Filter by project ID(s) or name(s) |
| `--severity, -s` | Filter by severity level(s) |
| `--status` | Filter by VEX status |
| `--since` | Filter by detection date (e.g., `30d`, `2024-01-01`) |
| `--type, -t` | Filter by finding type |
| `--workspace, -w` | Smartsheet workspace name (created if not exists) |
| `--sheet-name` | Custom sheet name (overrides default naming) |
| `--include-files` | Include file-type components/findings (excluded by default) |
| `--max-rows` | Maximum rows to sync |
| `--force` | Bypass safety limits |
| `--target-folder` | Smartsheet folder ID to place sheets in (bypasses hierarchy) |
| `--cache-ttl` | Cache FS API responses with TTL (e.g. `4`, `30m`, `1d`). Default: disabled |
| `--no-cache` | Force fresh data (ignore any existing cache) |

### `fs-smartsheet writeback`

Bulk-update VEX status on findings in Finite State directly via the API.

> **Note:** To sync VEX edits made in the Smartsheet UI back to Finite State,
> use `sync findings` instead — it detects and pushes writeback changes automatically.

```bash
# Mark all critical findings as IN_TRIAGE
uv run fs-smartsheet writeback --status IN_TRIAGE --severity critical

# Mark findings as NOT_AFFECTED with justification
uv run fs-smartsheet writeback --status NOT_AFFECTED \
    --justification "Code Not Reachable" --project "MyApp"

# Mark EXPLOITABLE with required response and justification
uv run fs-smartsheet writeback --status EXPLOITABLE \
    --response "Update" --justification "Code Not Reachable" --project "MyApp"

# Preview first
uv run fs-smartsheet writeback --status IN_TRIAGE --severity critical --dry-run
```

**Options:**

| Option | Description |
|--------|-------------|
| `--status, -s` | Target VEX status (required) |
| `--response, -r` | Response value (required for EXPLOITABLE) |
| `--justification, -j` | Justification (required for EXPLOITABLE, NOT_AFFECTED) |
| `--reason` | Optional reason/comment |
| `--project, -p` | Filter by project name |
| `--severity` | Filter by severity |
| `--type, -t` | Filter by finding type |
| `--max-rows` | Maximum findings to update (default: 1000) |
| `--batch-size` | Concurrent API calls (default: 50) |
| `--dry-run` | Show what would be updated without making changes |
| `--verbose, -v` | Enable debug output |

### `fs-smartsheet status`

Show current sync state.

```bash
uv run fs-smartsheet status
```

### `fs-smartsheet reset`

Delete and recreate sheets. Useful for fixing column mismatch errors after schema changes.

The reset command uses the same hierarchy resolution as `sync` (see [Smartsheet Hierarchy](#smartsheet-hierarchy)). After deleting sheets, it clears all workspace/folder caches to handle cases where Smartsheet auto-deletes empty folders.

```bash
# Reset all sheets (prompts for confirmation)
uv run fs-smartsheet reset all

# Reset just findings sheet
uv run fs-smartsheet reset findings

# Reset sheets for a specific project (uses hierarchy)
uv run fs-smartsheet reset findings --project "My Product"

# Reset into a specific folder (bypasses hierarchy)
uv run fs-smartsheet reset findings --target-folder 1234567890

# Skip confirmation
uv run fs-smartsheet reset all --yes
```

**Options:**

| Option | Description |
|--------|-------------|
| `--project, -p` | Project name (resets project-specific sheets) |
| `--workspace, -w` | Smartsheet workspace name |
| `--target-folder` | Smartsheet folder ID (bypasses hierarchy) |
| `--yes, -y` | Skip confirmation prompt |

### `fs-smartsheet config-show`

Display current configuration (secrets masked).

```bash
uv run fs-smartsheet config-show
```

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `FINITE_STATE_DOMAIN` | Yes | Your Finite State domain |
| `FINITE_STATE_AUTH_TOKEN` | Yes | API token from FS settings |
| `SMARTSHEET_ACCESS_TOKEN` | Yes | Smartsheet API token |
| `SMARTSHEET_WORKSPACE_ID` | No | Target workspace ID (numeric) |
| `SMARTSHEET_WORKSPACE_NAME` | No | Workspace name, created if not exists (default: `Finite State`) |
| `SYNC_INTERVAL_MINUTES` | No | Sync interval (default: 60) |
| `SYNC_BATCH_SIZE` | No | Records per batch (default: 100) |

### Custom Field Mappings

Edit `config/mappings.yaml` to customize field mappings:

```yaml
sync:
  sheets:
    findings:
      fs_endpoint: "/findings"
      columns:
        - fs_field: "id"
          ss_column: "Finding ID"
          type: "string"
          primary: true
        - fs_field: "severity"
          ss_column: "Severity"
          type: "picklist"
          options: ["critical", "high", "medium", "low"]
        - fs_field: "status"
          ss_column: "Status"
          type: "picklist"
          writeback: true  # Enable write-back for this field
          options:
            - "EXPLOITABLE"
            - "RESOLVED"
            - "RESOLVED_WITH_PEDIGREE"
            - "IN_TRIAGE"
            - "FALSE_POSITIVE"
            - "NOT_AFFECTED"
```

## Programmatic Usage

### Using the Sync Engine

```python
import asyncio
from fs_smartsheet.config import AppConfig
from fs_smartsheet.sync import SyncEngine

async def main():
    config = AppConfig()
    engine = SyncEngine(config)
    
    try:
        # Verify connections
        status = await engine.verify_connections()
        print(f"FS Connected: {status['finite_state']}")
        print(f"SS Connected: {status['smartsheet']}")
        
        # Run full sync
        results = await engine.sync_all(full=True)
        for r in results:
            print(f"{r.sheet_name}: +{r.added} ~{r.updated} -{r.deleted}")
    finally:
        await engine.close()

asyncio.run(main())
```

### Using the FS Client Directly

```python
from fs_smartsheet.fs_client import FiniteStateClient

async with FiniteStateClient(
    domain="your-org.finitestate.io",
    auth_token="your-token"
) as client:
    # Get all projects
    projects = await client.get_projects()
    
    # Iterate findings with filters
    async for finding in client.iter_findings(severity="critical"):
        print(f"{finding.finding_id}: {finding.title}")
    
    # Update finding status (VEX)
    await client.update_finding_status(
        project_version_id="123456",
        finding_id="CVE-2024-1234",
        status="not_affected",
        justification="component_not_present"
    )
```

### Using the Smartsheet Client Directly

```python
from fs_smartsheet.smartsheet_client import SmartsheetClient
from fs_smartsheet.smartsheet_client.schemas import FINDINGS_SCHEMA

client = SmartsheetClient(access_token="your-token")

# Create sheet from schema
sheet = client.get_or_create_sheet(FINDINGS_SCHEMA)

# Add rows
client.add_rows(sheet.id, [
    {
        "Finding ID": "123",
        "CVE ID": "CVE-2024-1234",
        "Severity": "high",
        "Status": "IN_TRIAGE"
    }
])

# Update rows
client.update_rows(sheet.id, [
    {"_row_id": 456, "Status": "fixed"}
])
```

## State Management

The sync engine maintains state in `.fs-smartsheet-state.json`:

```json
{
  "version": "1.0",
  "last_modified": "2024-01-15T10:30:00Z",
  "sheets": {
    "FS Findings": {
      "ss_sheet_id": 1234567890,
      "last_full_sync": "2024-01-15T10:00:00Z",
      "rows": {
        "finding-id-1": {
          "primary_key": "finding-id-1",
          "ss_row_id": 9876543210,
          "data_hash": "abc123...",
          "writeback_fields": {"Status": "affected"}
        }
      }
    }
  }
}
```

This enables:
- **Incremental sync**: Only sync changed records
- **Change detection**: Compare current state with previous
- **Write-back tracking**: Detect user changes in Smartsheet

## Troubleshooting

### Connection Issues

```bash
# Check if environment variables are set
uv run fs-smartsheet config-show

# Test API connections
uv run fs-smartsheet verify
```

### Sync Failures

```bash
# Check sync status
uv run fs-smartsheet status

# Run with verbose output
uv run fs-smartsheet sync all --full 2>&1 | tee sync.log
```

### Reset State

```bash
# Delete state file to force full re-sync
rm .fs-smartsheet-state.json
uv run fs-smartsheet sync all --full
```

## Development

```bash
# Install dev dependencies
uv sync

# Run tests
uv run pytest -v

# Run linter
uv run ruff check src/

# Run type checker
uv run mypy src/
```

## Release Promotion

Code moves through three GitHub repos:

```
Engineer Repo  ──(tag)──►  Staging Repo  ──(manual trigger)──►  Customer Resources
(full tree)                (full tree)                          (06-advanced-integrations-and-demos/fs-smartsheet/)
```

### CI

Every push and PR runs lint, type-check, and tests automatically via `.github/workflows/ci.yml`.

### Promote to Staging

Tag a release and push the tag — CI runs first, then the full tree is pushed to the staging repo:

```bash
git tag v0.2.0
git push origin v0.2.0
```

### Promote to Customer

From the GitHub **Actions** tab, select **Promote to Customer**, enter the tag (e.g. `v0.2.0`), and click **Run workflow**. The workflow:

1. Checks out the tagged commit
2. Removes files listed in `.customer-exclude` (tests, internal docs, CI configs, scripts)
3. Copies the sanitized files into the `06-advanced-integrations-and-demos/fs-smartsheet/` subdirectory of the customer-resources monorepo
4. Commits and pushes

### Local Promotion (optional)

The same logic is available as a standalone script:

```bash
# Push to staging
./scripts/promote.sh --target git@github.com:FiniteStateInc/fs-smartsheet.git --tag v0.2.0

# Push sanitized build to customer repo subdirectory
./scripts/promote.sh --target git@github.com:FiniteStateInc/customer-resources.git \
    --tag v0.2.0 --sanitize --subdirectory 06-advanced-integrations-and-demos/fs-smartsheet

# Dry run (shows what would happen without pushing)
./scripts/promote.sh --target git@github.com:FiniteStateInc/customer-resources.git \
    --tag v0.2.0 --sanitize --subdirectory 06-advanced-integrations-and-demos/fs-smartsheet --dry-run
```

### GitHub Secrets Setup

Configure these in the engineer repo under **Settings → Secrets and variables → Actions**:

| Secret / Variable | Value | Used by |
|---|---|---|
| `STAGING_REPO` | `FiniteStateInc/fs-smartsheet` | promote-staging |
| `STAGING_DEPLOY_KEY` | SSH private key with write access to staging repo | promote-staging |
| `CUSTOMER_REPO` | `git@github.com:FiniteStateInc/customer-resources.git` | promote-customer |
| `CUSTOMER_DEPLOY_KEY` | SSH private key with write access to customer repo | promote-customer |
| `CUSTOMER_SUBDIRECTORY` (variable) | `06-advanced-integrations-and-demos/fs-smartsheet` | promote-customer |

**Generating deploy keys (one-time per target repo):**

```bash
# Generate a key pair for the staging repo
ssh-keygen -t ed25519 -f staging_deploy_key -N "" -C "fs-smartsheet-staging-deploy"

# Generate a key pair for the customer repo
ssh-keygen -t ed25519 -f customer_deploy_key -N "" -C "fs-smartsheet-customer-deploy"
```

Then:
1. Add the **public** key (`*.pub`) to the target repo: **Settings → Deploy keys → Add deploy key** (check "Allow write access")
2. Add the **private** key contents to the engineer repo: **Settings → Secrets → New repository secret**

## License

MIT
