#!/usr/bin/env python3
"""
Script to manage users during maintenance windows.

Features:
- Fetches all users with pagination
- Configurable exclusions (email domains, full emails, or user IDs)
- Deactivates users by setting status to "DISABLED"
- Stores deactivated user data for reactivation
- Reactivates users from saved data or all currently disabled users

SAFETY FEATURES:
- --list-only: Preview which users would be affected
- --dry-run: Simulate the operation without making changes
- Confirmation prompt before deactivation/reactivation
- Saves user state before any changes
- Flexible exclusion patterns for both deactivation and reactivation
"""

import argparse
import json
import os
import sys
from datetime import datetime
from typing import List, Optional, Tuple

import requests


def get_environment_vars():
    """
    Get environment variables (if set).
    Returns a tuple of (auth_token, domain) - may be None values.
    """
    auth_token = os.getenv('FINITE_STATE_AUTH_TOKEN')
    domain = os.getenv('FINITE_STATE_DOMAIN')
    return auth_token, domain


def fetch_all_users(domain: str, token: str) -> List[dict]:
    """Fetch all users from the API with pagination.

    Args:
        domain: Finite State domain (e.g., 'acme.finitestate.io')
        token: API token

    Returns:
        List of user objects with all fields
    """
    url = f"https://{domain}/api/public/v0/users/"
    headers = {
        "X-Authorization": token,
        "Content-Type": "application/json",
    }

    users = []
    offset = 0
    limit = 5000  # Max page size

    print(f"Fetching users from API...")

    while True:
        params = {"offset": offset, "limit": limit}

        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()

            # API returns array directly
            if isinstance(data, list):
                batch = data
            else:
                # Fallback if response structure changes
                batch = data.get("items", [])

            if not batch:
                break

            users.extend(batch)
            print(f"  Fetched {len(users)} users so far...")

            # If we got fewer than limit, we're done
            if len(batch) < limit:
                break
            offset += limit

        except requests.exceptions.RequestException as e:
            print(f"Error fetching users from API: {e}", file=sys.stderr)
            sys.exit(1)

    print(f"Retrieved {len(users)} total users from API")
    return users


def user_matches_exclusion(user: dict, exclusions: List[str]) -> bool:
    """Check if a user matches any exclusion pattern.

    Args:
        user: User dictionary
        exclusions: List of exclusion patterns. Can be:
            - Email domain (e.g., "@finitestate.io", "@example.com")
            - Full email address (e.g., "admin@example.com")
            - User ID (e.g., "user123")

    Returns:
        True if user matches any exclusion pattern, False otherwise
    """
    if not exclusions:
        return False

    email = user.get("email", "").lower()
    user_id = user.get("userId", "").lower()

    for exclusion in exclusions:
        exclusion_lower = exclusion.lower().strip()
        
        # Check full email match
        if exclusion_lower == email:
            return True
        
        # Check email domain match (starts with @)
        if exclusion_lower.startswith("@"):
            if email.endswith(exclusion_lower):
                return True
        
        # Check user ID match
        if exclusion_lower == user_id:
            return True

    return False


def filter_users_for_deactivation(users: List[dict], exclusions: Optional[List[str]] = None) -> Tuple[List[dict], List[dict]]:
    """Filter users to identify which should be deactivated.

    Args:
        users: List of all users
        exclusions: List of exclusion patterns (email domains, emails, or user IDs)

    Returns:
        Tuple of (users_to_deactivate, excluded_users)
    """
    if exclusions is None:
        exclusions = []
    
    users_to_deactivate = []
    excluded_users = []

    for user in users:
        email = user.get("email", "")
        status = user.get("status", "")
        user_id = user.get("userId", "")

        # Skip users that are already disabled
        if status == "DISABLED":
            continue

        # Check if user matches any exclusion pattern
        if user_matches_exclusion(user, exclusions):
            excluded_users.append(user)
        else:
            users_to_deactivate.append(user)

    return users_to_deactivate, excluded_users


def filter_disabled_users(users: List[dict], exclusions: Optional[List[str]] = None) -> List[dict]:
    """Filter users to find all currently disabled users, excluding those matching exclusion patterns.

    Args:
        users: List of all users
        exclusions: List of exclusion patterns (email domains, emails, or user IDs)

    Returns:
        List of users with status "DISABLED" (excluding those matching exclusion patterns)
    """
    if exclusions is None:
        exclusions = []
    
    disabled_users = []
    for user in users:
        status = user.get("status", "")
        if status == "DISABLED":
            # Skip users that match exclusion patterns
            if user_matches_exclusion(user, exclusions):
                continue
            
            # Set status to ENABLED for reactivation (we don't know original status)
            user_copy = user.copy()
            user_copy["status"] = "ENABLED"
            disabled_users.append(user_copy)
    return disabled_users


def clean_user_data(user_data: dict) -> dict:
    """Clean user data by removing null values and fields that cause validation errors.

    The API doesn't accept null values for typed fields like eulaAccepted (boolean)
    and eulaAcceptedAt (string). We remove these to avoid validation errors.
    """
    cleaned = {}
    for key, value in user_data.items():
        # Skip null values entirely
        if value is None:
            continue
        cleaned[key] = value
    return cleaned


def update_user_status(
    domain: str,
    token: str,
    user_id: str,
    user_data: dict,
    new_status: str,
    dry_run: bool = False
) -> Tuple[bool, str, int]:
    """Update a user's status.

    Args:
        domain: Finite State domain (e.g., 'acme.finitestate.io')
        token: API token
        user_id: User ID (primary key, not userId field)
        user_data: Full user object to update
        new_status: New status ("DISABLED" or "ENABLED")
        dry_run: If True, don't actually make the request

    Returns:
        Tuple of (success: bool, message: str, status_code: int)
    """
    url = f"https://{domain}/api/public/v0/users/{user_id}"
    headers = {
        "X-Authorization": token,
        "Content-Type": "application/json",
    }

    if dry_run:
        return True, f"[DRY RUN] Would set status to {new_status}", 0

    # Clean the user data to remove null values that cause validation errors
    updated_user = clean_user_data(user_data.copy())
    updated_user["status"] = new_status

    try:
        response = requests.put(url, headers=headers, json=updated_user)
        status_code = response.status_code

        if status_code == 200:
            return True, f"Successfully updated status to {new_status} (HTTP {status_code})", status_code
        elif status_code == 403:
            return False, f"Permission denied to update user", status_code
        elif status_code == 404:
            return False, f"User not found", status_code
        else:
            error_msg = response.text or f"Status {status_code}"
            return False, f"Failed to update user (HTTP {status_code}): {error_msg}", status_code
    except requests.exceptions.RequestException as e:
        return False, f"Error updating user: {e}", 0


def save_users_to_file(users: List[dict], filename: str):
    """Save user data to a JSON file for later reactivation."""
    data = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "count": len(users),
        "users": users
    }

    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"\n✓ Saved {len(users)} user records to: {filename}")
    except Exception as e:
        print(f"\n✗ Error saving users to file: {e}", file=sys.stderr)
        sys.exit(1)


def load_users_from_file(filename: str) -> List[dict]:
    """Load user data from a JSON file."""
    try:
        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)

        users = data.get("users", [])
        timestamp = data.get("timestamp", "Unknown")
        print(f"Loaded {len(users)} users from {filename} (saved at {timestamp})")
        return users
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in file '{filename}': {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file '{filename}': {e}", file=sys.stderr)
        sys.exit(1)


def deactivate_users(domain: str, token: str, users: List[dict], dry_run: bool = False) -> Tuple[int, int]:
    """Deactivate a list of users.

    Args:
        domain: Finite State domain (e.g., 'acme.finitestate.io')
        token: API token
        users: List of users to deactivate
        dry_run: If True, don't actually make changes

    Returns:
        Tuple of (success_count, failure_count)
    """
    success_count = 0
    failure_count = 0
    status_codes = {}

    for i, user in enumerate(users, 1):
        user_id = user.get("id", "")
        user_identifier = user.get("userId", "Unknown")
        email = user.get("email", "Unknown")

        print(f"[{i}/{len(users)}] Deactivating: {user_identifier} ({email})")
        success, message, status_code = update_user_status(
            domain, token, user_id, user, "DISABLED", dry_run=dry_run
        )

        # Track status codes
        if status_code > 0:
            status_codes[status_code] = status_codes.get(status_code, 0) + 1

        if success:
            print(f"  ✓ {message}")
            success_count += 1
        else:
            print(f"  ✗ {message}", file=sys.stderr)
            failure_count += 1

    print()
    if status_codes:
        print(f"Response codes received: {dict(sorted(status_codes.items()))}")

    return success_count, failure_count


def reactivate_users(domain: str, token: str, users: List[dict], dry_run: bool = False) -> Tuple[int, int]:
    """Reactivate a list of users.

    Args:
        domain: Finite State domain (e.g., 'acme.finitestate.io')
        token: API token
        users: List of users to reactivate
        dry_run: If True, don't actually make changes

    Returns:
        Tuple of (success_count, failure_count)
    """
    success_count = 0
    failure_count = 0
    status_codes = {}

    for i, user in enumerate(users, 1):
        user_id = user.get("id", "")
        user_identifier = user.get("userId", "Unknown")
        email = user.get("email", "Unknown")
        original_status = user.get("status", "ENABLED")

        print(f"[{i}/{len(users)}] Reactivating: {user_identifier} ({email}) to status: {original_status}")
        success, message, status_code = update_user_status(
            domain, token, user_id, user, original_status, dry_run=dry_run
        )

        # Track status codes
        if status_code > 0:
            status_codes[status_code] = status_codes.get(status_code, 0) + 1

        if success:
            print(f"  ✓ {message}")
            success_count += 1
        else:
            print(f"  ✗ {message}", file=sys.stderr)
            failure_count += 1

    print()
    if status_codes:
        print(f"Response codes received: {dict(sorted(status_codes.items()))}")

    return success_count, failure_count


def main():
    """Main function."""
    # Get environment variables (may be None)
    env_token, env_domain = get_environment_vars()
    
    parser = argparse.ArgumentParser(
        description="Manage users during maintenance windows",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List which users would be deactivated (safe preview)
  python3 manage_users.py deactivate --list-only

  # Dry run deactivation (no actual changes)
  python3 manage_users.py deactivate --dry-run -o deactivated_users.json

  # Actually deactivate users (will prompt for confirmation)
  python3 manage_users.py deactivate -o deactivated_users.json

  # Deactivate with custom exclusions (exclude multiple domains/emails)
  python3 manage_users.py deactivate --exclude '@finitestate.io' --exclude 'admin@example.com' --exclude 'user123'

  # Reactivate users from saved file
  python3 manage_users.py reactivate -i deactivated_users.json

  # Reactivate all currently disabled users
  python3 manage_users.py reactivate --all-disabled

  # Reactivate all disabled users, excluding specific patterns
  python3 manage_users.py reactivate --all-disabled --exclude '@finitestate.io' --exclude 'admin@example.com'

Environment Variables:
  FINITE_STATE_AUTH_TOKEN: Your authentication token from the Finite State app
  FINITE_STATE_DOMAIN: Your organization's domain (e.g., 'your-org.finitestate.io')
        """
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Command to execute")

    # Deactivate command
    deactivate_parser = subparsers.add_parser("deactivate", help="Deactivate users (with optional exclusions)")
    deactivate_parser.add_argument(
        "-d", "--domain",
        default=env_domain,
        help="Finite State domain (default: from FINITE_STATE_DOMAIN env var)"
    )
    deactivate_parser.add_argument(
        "-t", "--token",
        default=env_token,
        help="Finite State API token (default: from FINITE_STATE_AUTH_TOKEN env var)"
    )
    deactivate_parser.add_argument(
        "-o", "--output", default="deactivated_users.json",
        help="Output file to save deactivated user data (default: deactivated_users.json)"
    )
    deactivate_parser.add_argument(
        "--exclude", action="append", default=[],
        help="Exclude users matching this pattern (can be specified multiple times). "
             "Patterns can be: email domain (e.g., '@finitestate.io'), "
             "full email (e.g., 'admin@example.com'), or user ID (e.g., 'user123')"
    )
    deactivate_parser.add_argument(
        "--list-only", action="store_true",
        help="Only list users that would be deactivated, don't make changes"
    )
    deactivate_parser.add_argument(
        "--dry-run", action="store_true",
        help="Dry run mode: show what would be done without actually making changes"
    )

    # Reactivate command
    reactivate_parser = subparsers.add_parser("reactivate", help="Reactivate users from saved file or all currently disabled users")
    reactivate_parser.add_argument(
        "-d", "--domain",
        default=env_domain,
        help="Finite State domain (default: from FINITE_STATE_DOMAIN env var)"
    )
    reactivate_parser.add_argument(
        "-t", "--token",
        default=env_token,
        help="Finite State API token (default: from FINITE_STATE_AUTH_TOKEN env var)"
    )
    reactivate_parser.add_argument(
        "-i", "--input",
        help="Input file containing deactivated user data (if not provided, reactivates all currently disabled users)"
    )
    reactivate_parser.add_argument(
        "--all-disabled", action="store_true",
        help="Reactivate all currently disabled users (alternative to --input)"
    )
    reactivate_parser.add_argument(
        "--exclude", action="append", default=[],
        help="Exclude users matching this pattern (can be specified multiple times). "
             "Patterns can be: email domain (e.g., '@finitestate.io'), "
             "full email (e.g., 'admin@example.com'), or user ID (e.g., 'user123')"
    )
    reactivate_parser.add_argument(
        "--list-only", action="store_true",
        help="Only list users that would be reactivated, don't make changes"
    )
    reactivate_parser.add_argument(
        "--dry-run", action="store_true",
        help="Dry run mode: show what would be done without actually making changes"
    )

    args = parser.parse_args()

    # Validate that token and domain are provided (either from env or args)
    token = args.token
    domain = args.domain
    
    if not token:
        print("Error: API token is required.", file=sys.stderr)
        print("  Set FINITE_STATE_AUTH_TOKEN environment variable or use --token", file=sys.stderr)
        sys.exit(1)
    if not domain:
        print("Error: Domain is required.", file=sys.stderr)
        print("  Set FINITE_STATE_DOMAIN environment variable or use --domain", file=sys.stderr)
        print("  Example: export FINITE_STATE_DOMAIN='your-org.finitestate.io'", file=sys.stderr)
        sys.exit(1)

    if args.command == "deactivate":
        # Get exclusions (if any)
        exclusions = args.exclude if args.exclude else []
        
        # Fetch all users
        all_users = fetch_all_users(domain, token)
        print()

        # Filter users
        users_to_deactivate, excluded_users = filter_users_for_deactivation(
            all_users, exclusions
        )

        print(f"Total users fetched: {len(all_users)}")
        if exclusions:
            exclusion_str = ", ".join(exclusions)
            print(f"Exclusion patterns: {exclusion_str}")
        print(f"Excluded users: {len(excluded_users)}")
        print(f"Users to deactivate: {len(users_to_deactivate)}")
        print()

        if not users_to_deactivate:
            print("No users to deactivate.")
            sys.exit(0)

        # Show sample of users to be deactivated
        print("Sample of users to be deactivated:")
        for user in users_to_deactivate[:10]:
            print(f"  - {user.get('userId', 'Unknown')} ({user.get('email', 'Unknown')}) [Status: {user.get('status', 'Unknown')}]")

        if len(users_to_deactivate) > 10:
            print(f"  ... and {len(users_to_deactivate) - 10} more")
        print()

        if args.list_only:
            print("List-only mode: No users will be deactivated.")
            sys.exit(0)

        if args.dry_run:
            print("🔍 DRY RUN MODE - No users will actually be deactivated")
            print()

        # Save user data before deactivation
        if not args.dry_run:
            save_users_to_file(users_to_deactivate, args.output)

        # Confirm before deactivation (unless dry-run)
        if not args.dry_run:
            confirm = input(f"\n⚠️  Are you sure you want to DEACTIVATE {len(users_to_deactivate)} user(s)? [y/N]: ")
            if confirm.lower() not in ["y", "yes"]:
                print("Aborted.")
                sys.exit(0)
            print()

        # Deactivate users
        success_count, failure_count = deactivate_users(
            domain, token, users_to_deactivate, dry_run=args.dry_run
        )

        # Summary
        print()
        if args.dry_run:
            print(f"Summary (DRY RUN): {success_count} would be deactivated, {failure_count} would fail")
        else:
            print(f"Summary: {success_count} deactivated, {failure_count} failed")
            print(f"\n✓ User data saved to: {args.output}")
            print(f"  To reactivate these users, run:")
            print(f"  python3 manage_users.py reactivate -i {args.output}")

        if failure_count > 0:
            sys.exit(1)

    elif args.command == "reactivate":
        # Determine source of users to reactivate
        if args.all_disabled and args.input:
            print("Error: Cannot specify both --input and --all-disabled. Choose one.", file=sys.stderr)
            sys.exit(1)
        
        # Get exclusions (if any)
        exclusions = args.exclude if args.exclude else []
        
        if args.all_disabled or not args.input:
            # Fetch all users and filter for disabled ones
            print("Fetching all users to find disabled ones...")
            all_users = fetch_all_users(domain, token)
            print()
            
            users_to_reactivate = filter_disabled_users(all_users, exclusions)
            
            if not users_to_reactivate:
                print("No disabled users found to reactivate.")
                if exclusions:
                    print(f"(Excluding users matching: {', '.join(exclusions)})")
                sys.exit(0)
            
            print(f"Found {len(users_to_reactivate)} disabled user(s) to reactivate")
            if exclusions:
                print(f"Exclusion patterns: {', '.join(exclusions)}")
            print("Note: These users will be reactivated with status 'ENABLED' (original status unknown)")
            print()
        else:
            # Load users from file
            users_to_reactivate = load_users_from_file(args.input)
            
            # Apply exclusions to file-loaded users if specified
            if exclusions:
                original_count = len(users_to_reactivate)
                users_to_reactivate = [
                    user for user in users_to_reactivate
                    if not user_matches_exclusion(user, exclusions)
                ]
                excluded_count = original_count - len(users_to_reactivate)
                if excluded_count > 0:
                    print(f"Excluded {excluded_count} user(s) matching exclusion patterns: {', '.join(exclusions)}")
            print()

        if not users_to_reactivate:
            print("No users to reactivate.")
            sys.exit(0)

        # Show sample of users to be reactivated
        print("Sample of users to be reactivated:")
        for user in users_to_reactivate[:10]:
            print(f"  - {user.get('userId', 'Unknown')} ({user.get('email', 'Unknown')}) [Will restore to: {user.get('status', 'ENABLED')}]")

        if len(users_to_reactivate) > 10:
            print(f"  ... and {len(users_to_reactivate) - 10} more")
        print()

        if args.list_only:
            print("List-only mode: No users will be reactivated.")
            sys.exit(0)

        if args.dry_run:
            print("🔍 DRY RUN MODE - No users will actually be reactivated")
            print()

        # Confirm before reactivation (unless dry-run)
        if not args.dry_run:
            confirm = input(f"\n⚠️  Are you sure you want to REACTIVATE {len(users_to_reactivate)} user(s)? [y/N]: ")
            if confirm.lower() not in ["y", "yes"]:
                print("Aborted.")
                sys.exit(0)
            print()

        # Reactivate users
        success_count, failure_count = reactivate_users(
            domain, token, users_to_reactivate, dry_run=args.dry_run
        )

        # Summary
        print()
        if args.dry_run:
            print(f"Summary (DRY RUN): {success_count} would be reactivated, {failure_count} would fail")
        else:
            print(f"Summary: {success_count} reactivated, {failure_count} failed")

        if failure_count > 0:
            sys.exit(1)


if __name__ == "__main__":
    main()

