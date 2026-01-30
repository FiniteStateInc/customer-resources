# Bulk User Creation Script

This script allows you to create multiple users in Finite State from a CSV file.

## Features

- ✓ Create users with email, role, first name, and last name
- ✓ Automatically add users to groups
- ✓ Dry run mode to preview actions
- ✓ Progress indication and timing
- ✓ Detailed logging
- ✓ Handles existing users gracefully
- ✓ Support for group names with spaces

## CSV Format

A template CSV file (`user_template.csv`) is provided for your convenience.

The CSV file should have the following columns:

| Column     | Required | Description                                               |
|------------|----------|-----------------------------------------------------------|
| email      | Yes      | User's email address (used for both email and userId)    |
| role       | No       | Organization role (see valid roles below)                 |
| groups     | No       | Pipe-separated ('|') or semicolon-separated (';') groups (case-sensitive) |
| first_name | No       | User's first name                                         |
| last_name  | No       | User's last name                                          |

### Valid Organization Roles

The `role` column accepts one of these values (case-insensitive):

- `Integrator`
- `Projects Admin`
- `Global Components Editor`
- `Portfolio Viewer`
- `Compliance Manager`
- `Global admin`
- `System manager`

**Note**: 
- Roles are **case-insensitive** - you can use "Global Admin" or "global admin" and it will be normalized to the correct format
- Leave the `role` column empty if you don't want to assign an organization role to the user
- Invalid roles will be logged as warnings and the user will be created without a role

### Example CSV

```csv
email,role,groups,first_name,last_name
john.doe@example.com,Integrator,Engineering|QA,John,Doe
jane.smith@example.com,Global admin,Engineering,Jane,Smith
bob.johnson@example.com,,Security,Bob,Johnson
alice.williams@example.com,Projects Admin,,Alice,Williams
```

## Prerequisites

1. Python 3.6+
2. `requests` library: `pip install requests`
3. Environment variables set:
   - `FINITE_STATE_DOMAIN`: Your Finite State domain (e.g., `jermaine.finitestate.io`)
   - `FINITE_STATE_AUTH_TOKEN`: Your API token

## Usage

### Dry Run (Preview Only)

Test the script without making any changes:

```bash
python3 bulk_create_users.py sample_users.csv --dry-run
```

### Create Users

Run the script to create users:

```bash
python3 bulk_create_users.py sample_users.csv
```

### Verbose Logging

Enable detailed debug logging:

```bash
python3 bulk_create_users.py sample_users.csv --verbose
```

## How It Works

1. **Reads CSV**: Parses the CSV file and validates that the `email` column exists
2. **Loads Groups**: Fetches all available groups from the API and caches them
3. **Creates Users**: For each row:
   - Generates a `userId` from the email (e.g., `john.doe@example.com` → `john_doe`)
   - Creates the user with optional role, first name, and last name
   - If user already exists, logs a warning and continues
4. **Adds to Groups**: For each group specified:
   - Looks up the group ID by name
   - Adds the user to the group
   - Logs success or failure
5. **Reports Statistics**: Shows summary of:
   - Users created
   - Users skipped (already exist)
   - Users failed
   - Group assignments
   - Total time and rate

## Group Delimiter

Groups can be separated by:
- **Pipe** (`|`): `Engineering|QA|Security`
- **Semicolon** (`;`): `Engineering;QA;Security`

Use pipe for group names that might contain commas.

**Important**: Group names are **case-sensitive** and must match exactly as they appear in your Finite State organization. For example, `Engineering` is different from `engineering`.

## Error Handling

- **Missing email**: Row is skipped with a warning
- **User already exists**: Logged as skipped, script continues
- **Group not found**: Logged as warning, user is still created
- **API errors**: Logged with details, script continues with next user

## Output Example

```
2025-01-30 15:00:00 - INFO - Starting bulk user creation
2025-01-30 15:00:00 - INFO - Domain: jermaine.finitestate.io
2025-01-30 15:00:00 - INFO - Processing CSV file: sample_users.csv
2025-01-30 15:00:00 - INFO - Dry run mode: False
2025-01-30 15:00:00 - INFO - --------------------------------------------------------------------------------
2025-01-30 15:00:00 - INFO - CSV columns detected: email, role, groups, first_name, last_name
2025-01-30 15:00:00 - INFO - --------------------------------------------------------------------------------
2025-01-30 15:00:01 - INFO - Loading groups from API...
2025-01-30 15:00:01 - INFO - Loaded 15 groups
2025-01-30 15:00:01 - INFO - Row 2: Processing john.doe@example.com
2025-01-30 15:00:02 - INFO - Created user: john.doe@example.com (ID: 123456789)
2025-01-30 15:00:02 - INFO -   Added john.doe@example.com to group: Engineering
2025-01-30 15:00:02 - INFO -   Added john.doe@example.com to group: QA
...
2025-01-30 15:00:10 - INFO - ================================================================================
2025-01-30 15:00:10 - INFO - SUMMARY
2025-01-30 15:00:10 - INFO - ================================================================================
2025-01-30 15:00:10 - INFO - Total rows processed: 5
2025-01-30 15:00:10 - INFO - Users created: 4
2025-01-30 15:00:10 - INFO - Users failed: 0
2025-01-30 15:00:10 - INFO - Users skipped (already exist): 1
2025-01-30 15:00:10 - INFO - Group assignments successful: 3
2025-01-30 15:00:10 - INFO - Group assignments failed: 0
2025-01-30 15:00:10 - INFO - Total time: 9.52 seconds
2025-01-30 15:00:10 - INFO - Average time per row: 1.90 seconds
2025-01-30 15:00:10 - INFO - ================================================================================
```

## Tips

1. **Always test with `--dry-run` first** to preview what will happen
2. **Start with a small CSV** to test the script before running large batches
3. **Check group names** in the Finite State UI to ensure they match exactly
4. **Keep the CSV simple** - only include columns you need
5. **Both name fields required** - If you want to set names, provide both `first_name` AND `last_name`

## Troubleshooting

### "Invalid role" warning
- The role spelling must match one of the valid organization roles (case-insensitive)
- Valid roles: `Integrator`, `Projects Admin`, `Global Components Editor`, `Portfolio Viewer`, `Compliance Manager`, `Global admin`, `System manager`
- If an invalid role is detected, the user will still be created but without a role assignment
- Leave the role column empty if you don't want to assign a role

### "Group not found"
- Check the group name spelling in your CSV
- Use `--verbose` to see all available groups
- Group names are case-sensitive

### "User already exists"
- This is expected if re-running the script
- The script will skip existing users and continue

### "Authentication required"
- Check that your environment variables are set correctly
- Verify your API token is valid and hasn't expired

### Rate limiting
- The script processes users sequentially to avoid rate limits
- If you hit rate limits, add a small delay between users (modify the script)
