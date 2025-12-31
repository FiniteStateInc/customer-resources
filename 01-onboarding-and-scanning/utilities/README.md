# Utilities

This directory contains utility scripts for managing Finite State platform operations.

## Available Scripts

- **[manage_users.py](./manage_users.py)** - Script to manage users during maintenance windows (deactivate/reactivate)

---

## manage_users.py

A Python script for managing users during maintenance windows. Supports deactivating and reactivating users with configurable exclusions and safety features.

### Features

- Fetches all users with pagination
- Configurable exclusions (email domains, full emails, or user IDs)
- Deactivates users by setting status to "DISABLED"
- Stores deactivated user data for reactivation
- Reactivates users from saved data or all currently disabled users
- Safety features: `--list-only`, `--dry-run`, and confirmation prompts

### Requirements

- Python 3.6+ (recommended: 3.8+)
- `requests` library

```bash
pip install requests
```

### Authentication

The script requires authentication via API token and domain. These must be provided via environment variables:

```bash
export FINITE_STATE_AUTH_TOKEN="your-api-token-here"
export FINITE_STATE_DOMAIN="your-org.finitestate.io"
```

**Note:** The domain should be the full FQDN (e.g., `acme.finitestate.io`), not just the subdomain.

### Usage

#### Deactivate Users

Deactivate users (except those matching exclusion patterns):

```bash
# List which users would be deactivated (safe preview)
python3 manage_users.py deactivate --list-only

# Dry run deactivation (no actual changes)
python3 manage_users.py deactivate --dry-run -o deactivated_users.json

# Actually deactivate users (will prompt for confirmation)
python3 manage_users.py deactivate -o deactivated_users.json

# Deactivate with custom exclusions
python3 manage_users.py deactivate --exclude '@finitestate.io' --exclude 'admin@example.com' -o deactivated_users.json
```

#### Reactivate Users

Reactivate users from a saved file or all currently disabled users:

```bash
# Reactivate users from saved file
python3 manage_users.py reactivate -i deactivated_users.json

# Reactivate all currently disabled users
python3 manage_users.py reactivate --all-disabled

# Reactivate all disabled users, excluding specific patterns
python3 manage_users.py reactivate --all-disabled --exclude '@finitestate.io' --exclude 'admin@example.com'
```

### Commands

#### `deactivate`

Deactivate users (except those matching exclusion patterns).

**Options:**

- `-d, --domain <domain>` - Finite State domain (default: from `FINITE_STATE_DOMAIN` env var)
- `-t, --token <token>` - API token (default: from `FINITE_STATE_AUTH_TOKEN` env var)
- `-o, --output <file>` - Output file to save deactivated user data (default: `deactivated_users.json`)
- `--exclude <pattern>` - Exclude users matching this pattern (can be specified multiple times)
  - Patterns can be: email domain (e.g., `@finitestate.io`), full email (e.g., `admin@example.com`), or user ID (e.g., `user123`)
- `--list-only` - Only list users that would be deactivated, don't make changes
- `--dry-run` - Dry run mode: show what would be done without actually making changes

#### `reactivate`

Reactivate users from saved file or all currently disabled users.

**Options:**

- `-d, --domain <domain>` - Finite State domain (default: from `FINITE_STATE_DOMAIN` env var)
- `-t, --token <token>` - API token (default: from `FINITE_STATE_AUTH_TOKEN` env var)
- `-i, --input <file>` - Input file containing deactivated user data (if not provided, reactivates all currently disabled users)
- `--all-disabled` - Reactivate all currently disabled users (alternative to `--input`)
- `--exclude <pattern>` - Exclude users matching this pattern (can be specified multiple times)
- `--list-only` - Only list users that would be reactivated, don't make changes
- `--dry-run` - Dry run mode: show what would be done without actually making changes

### Exclusion Patterns

Exclusion patterns can be specified multiple times using `--exclude`. The script supports three types of patterns:

1. **Email Domain**: Exclude all users with emails ending in the specified domain
   ```bash
   --exclude '@finitestate.io'
   --exclude '@example.com'
   ```

2. **Full Email**: Exclude a specific user by their email address
   ```bash
   --exclude 'admin@example.com'
   --exclude 'user@company.com'
   ```

3. **User ID**: Exclude a specific user by their user ID
   ```bash
   --exclude 'user123'
   --exclude 'admin-user'
   ```

**Examples:**

```bash
# Exclude multiple patterns
python3 manage_users.py deactivate \
  --exclude '@finitestate.io' \
  --exclude 'admin@example.com' \
  --exclude 'user123' \
  -o deactivated_users.json
```

### Safety Features

The script includes several safety features to prevent accidental changes:

1. **`--list-only`**: Preview which users would be affected without making any changes
2. **`--dry-run`**: Simulate the operation without actually making API calls
3. **Confirmation prompts**: Interactive confirmation before deactivating or reactivating users
4. **User data backup**: Automatically saves user data to a JSON file before deactivation

### Examples

#### Example 1: Preview Deactivation

```bash
# See which users would be deactivated
python3 manage_users.py deactivate --list-only
```

#### Example 2: Deactivate with Exclusions

```bash
# Deactivate all users except those with @finitestate.io or admin@example.com emails
python3 manage_users.py deactivate \
  --exclude '@finitestate.io' \
  --exclude 'admin@example.com' \
  -o deactivated_users.json
```

#### Example 3: Dry Run Before Deactivation

```bash
# Test the deactivation process without making changes
python3 manage_users.py deactivate --dry-run -o deactivated_users.json
```

#### Example 4: Reactivate from Saved File

```bash
# Reactivate users from a previously saved file
python3 manage_users.py reactivate -i deactivated_users.json
```

#### Example 5: Reactivate All Disabled Users

```bash
# Reactivate all currently disabled users (sets status to ENABLED)
python3 manage_users.py reactivate --all-disabled
```

#### Example 6: Reactivate with Exclusions

```bash
# Reactivate all disabled users except those matching exclusion patterns
python3 manage_users.py reactivate \
  --all-disabled \
  --exclude '@finitestate.io' \
  --exclude 'admin@example.com'
```

### Output Files

When deactivating users, the script saves user data to a JSON file (default: `deactivated_users.json`). The file contains:

```json
{
  "timestamp": "2024-01-15T10:30:00.000000Z",
  "count": 5,
  "users": [
    {
      "id": "1234567890123456789",
      "userId": "user123",
      "email": "user@example.com",
      "status": "ENABLED",
      ...
    }
  ]
}
```

This file can be used later to reactivate users with their original status preserved.

### Important Notes

1. **User Status**: When reactivating from `--all-disabled`, users are set to `ENABLED` status (original status is unknown). When reactivating from a saved file, the original status is preserved.

2. **Exclusions**: Exclusion patterns are case-insensitive and match:
   - Email domains: Users with emails ending in the specified domain
   - Full emails: Exact email address match
   - User IDs: Exact user ID match

3. **Pagination**: The script automatically handles pagination when fetching users from the API.

4. **Error Handling**: The script continues processing even if individual user updates fail, and provides a summary at the end.

5. **Permissions**: Your API token must have appropriate permissions to read and update user information.

### Troubleshooting

#### "Missing required environment variables"

Ensure both environment variables are set:

```bash
export FINITE_STATE_AUTH_TOKEN="your-token"
export FINITE_STATE_DOMAIN="your-org.finitestate.io"
```

#### "Permission denied to update user"

Your API token may not have sufficient permissions. Contact your Finite State administrator to ensure your token has user management permissions.

#### "No users to deactivate/reactivate"

- For deactivation: All users may already be disabled or match exclusion patterns
- For reactivation: No disabled users found, or all disabled users match exclusion patterns

Use `--list-only` to preview which users would be affected.

### Related Files

- `manage_users.py` - Main script
- `deactivated_users.json` - Example output file (created when deactivating users)
