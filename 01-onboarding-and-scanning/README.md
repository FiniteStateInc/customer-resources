# IDP Group Sync

Synchronize IDP group memberships to the Finite State platform via the REST API.

This script reads a mapping file (YAML or CSV) that defines how your Identity Provider
groups map to Finite State groups, then reconciles group state — creating groups,
setting org roles, and adding or removing members.

## Prerequisites

- **Python 3.11+**
- **[uv](https://docs.astral.sh/uv/)** — for dependency management

## Quick Start

1. **Install dependencies:**

   ```bash
   uv sync
   ```

2. **Set environment variables:**

   ```bash
   export FINITE_STATE_AUTH_TOKEN="your-api-token"
   export FINITE_STATE_DOMAIN="acme.finitestate.io"
   ```

3. **Create your mapping file** — copy and edit one of the examples:

   ```bash
   cp mapping.example.yaml mapping.yaml
   # Edit mapping.yaml with your IDP groups, Finite State groups, and members
   ```

4. **Preview changes (dry run):**

   ```bash
   uv run python idp_group_sync.py --mapping mapping.yaml --dry-run
   ```

5. **Apply changes:**

   ```bash
   uv run python idp_group_sync.py --mapping mapping.yaml
   ```

## CLI Reference

```
uv run python idp_group_sync.py \
  --mapping mapping.yaml \
  --dry-run \
  --create-missing-users \
  --max-new-users 100 \
  --remove-unlisted-members \
  --verbose
```

| Flag | Description |
|------|-------------|
| `--domain` | Finite State domain (e.g. `acme.finitestate.io`). Falls back to `FINITE_STATE_DOMAIN` env var. |
| `--allow-custom-domain` | Bypass `.finitestate.io` domain validation. |
| `--mapping` | **(required)** Path to mapping file (`.yaml`, `.yml`, or `.csv`). |
| `--dry-run` | Preview changes without applying them. |
| `--create-missing-users` | Invite users not yet in Finite State (default: skip with warning). **Each invited user will receive an email prompting them to set up their credentials.** |
| `--max-new-users N` | Safety limit for `--create-missing-users` (default: 50). |
| `--remove-unlisted-members` | Remove users from groups if not in the mapping file (default: additive only). |
| `--verbose` | Enable detailed debug logging. |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `FINITE_STATE_AUTH_TOKEN` | **(required)** API token. Not accepted as a CLI flag for security reasons. |
| `FINITE_STATE_DOMAIN` | Customer domain (e.g. `acme.finitestate.io`). Can be overridden with `--domain`. |

## Mapping File Formats

The script accepts either YAML or CSV, auto-detected by file extension.

### YAML Format

```yaml
groups:
  - idp_group: "Engineering"
    # fs_group is optional — defaults to idp_group name
    description: "Engineering team"
    org_roles:
      - "Projects Admin"
    members:
      - email: alice@example.com
        first_name: Alice
        last_name: Smith
      - email: bob@example.com

  - idp_group: "Security-Analysts"
    fs_group: "Security Analysts"
    description: "Security analysis team"
    org_roles:
      - "Global admin"
    members:
      - email: alice@example.com
```

### CSV Format

One row per user-group assignment:

```csv
user_email,first_name,last_name,idp_group,fs_group,description,org_roles
alice@example.com,Alice,Smith,Engineering,,Engineering team,Projects Admin
bob@example.com,Bob,Jones,Engineering,,Engineering team,Projects Admin
alice@example.com,Alice,Smith,Security-Analysts,Security Analysts,Security analysis team,Global admin
```

**CSV notes:**

- `first_name`, `last_name` — optional (can be blank)
- `fs_group` — optional; if blank, defaults to `idp_group` value
- `org_roles` — multiple values separated by `|` (e.g. `Role A|Role B`)
- Group config is taken from the first row seen for each `idp_group`; conflicts produce a warning

## Behavior

### Default (safe)

- **Additive only:** Users are added to groups but never removed
- **No user creation:** Users not found in Finite State are skipped with a warning
- **Idempotent:** Running twice with the same input produces no changes the second time

### With flags

- `--remove-unlisted-members`: Users in a Finite State group but NOT in the mapping file for that group are removed from the group (the user account is NOT deleted)
- `--create-missing-users`: Users in the mapping file but NOT in Finite State are invited. Subject to the `--max-new-users` safety limit. **Note:** Each invited user will receive an email prompting them to set up their credentials — use `--dry-run` first to review who will be invited.

## Security

- The API token is never accepted as a CLI flag (avoiding exposure in `ps`, shell history, CI logs)
- The API token is never written to log output, even in verbose mode
- Domain validation ensures the token is only sent to `.finitestate.io` servers (override with `--allow-custom-domain` for non-standard domains)
- YAML files are parsed with `yaml.safe_load()` to prevent code execution

## Example Output

```
Loading mapping file: mapping.yaml
  3 group mapping(s), 4 unique user(s)

Fetching Finite State users...
  Found 150 users
Fetching Finite State groups...
  Found 5 groups

[Engineering] Group exists (id: 8837291038472)
  Org roles: ['Projects Admin'] (no change)
  Current members: 5, Desired members: 2
  Adding 0 members
  Removing 3 member(s): dave@example.com, eve@example.com, frank@example.com

[Security Analysts] Group does not exist, creating...
  Created group (id: 9928371625184)
  Setting org roles: ['Global admin']
  Current members: 0, Desired members: 1
  Adding 1 member(s): alice@example.com

Summary:
  Groups processed: 2 (1 created, 1 existing)
  Members added: 1
  Members removed: 3
  Warnings: 0
```
