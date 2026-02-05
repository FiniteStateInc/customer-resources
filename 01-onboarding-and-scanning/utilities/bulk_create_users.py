#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = ["requests>=2.25.0"]
# ///
"""
Bulk User Creation Script for Finite State

This script reads a CSV file and creates users in Finite State, optionally
adding them to groups.

CSV Format (see user_template.csv for a template):
    email,role,groups,first_name,last_name
    
    - email: Required. User's email address (used for both email and userId)
    - role: Optional. Organization role (case-insensitive) - valid values:
            Integrator, Projects Admin, Global Components Editor,
            Portfolio Viewer, Compliance Manager, Global admin, System manager
    - groups: Optional. Pipe-separated list of group names (case-sensitive, e.g., "Engineering|QA")
    - first_name: Optional. User's first name
    - last_name: Optional. User's last name

Environment Variables:
    FINITE_STATE_DOMAIN: Full domain (e.g., jermaine.finitestate.io)
    FINITE_STATE_AUTH_TOKEN: API token

Example Usage:
    # Dry run to preview actions
    python3 bulk_create_users.py users.csv --dry-run
    
    # Create users for real
    python3 bulk_create_users.py users.csv
    
    # Verbose logging
    python3 bulk_create_users.py users.csv --verbose
"""

import argparse
import csv
import os
import sys
import time
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone

import requests


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class FiniteStateUserManager:
    """Manages user creation and group assignments in Finite State."""
    
    # Valid organization roles (case-insensitive mapping)
    VALID_ROLES = {
        "integrator": "Integrator",
        "projects admin": "Projects Admin",
        "global components editor": "Global Components Editor",
        "portfolio viewer": "Portfolio Viewer",
        "compliance manager": "Compliance Manager",
        "global admin": "Global admin",
        "system manager": "System manager",
    }
    
    def __init__(self, subdomain: str, token: str, dry_run: bool = False):
        self.subdomain = subdomain
        self.token = token
        self.base_url = f"https://{subdomain}.finitestate.io/api"
        self.dry_run = dry_run
        self.headers = {
            "X-Authorization": token,
            "Content-Type": "application/json",
        }
        self.groups_cache: Optional[Dict[str, str]] = None
        
        # Statistics
        self.stats = {
            "total_rows": 0,
            "users_created": 0,
            "users_failed": 0,
            "users_skipped": 0,
            "groups_added": 0,
            "groups_failed": 0,
        }
    
    def get_auth_from_env(self) -> Tuple[str, str]:
        """Get authentication details from environment variables."""
        domain = os.environ.get("FINITE_STATE_DOMAIN")
        token = os.environ.get("FINITE_STATE_AUTH_TOKEN")
        
        if not domain or not token:
            logger.error("Missing required environment variables:")
            if not domain:
                logger.error("  - FINITE_STATE_DOMAIN")
            if not token:
                logger.error("  - FINITE_STATE_AUTH_TOKEN")
            sys.exit(1)
        
        # Extract subdomain from full domain
        subdomain = domain.replace(".finitestate.io", "").replace("https://", "").replace("http://", "")
        
        return subdomain, token
    
    def normalize_role(self, role: str) -> Optional[str]:
        """Normalize role to match API expectations (case-insensitive)."""
        if not role:
            return None
        
        # Try exact match first
        if role in self.VALID_ROLES.values():
            return role
        
        # Try case-insensitive match
        role_lower = role.lower().strip()
        normalized = self.VALID_ROLES.get(role_lower)
        
        if normalized:
            if role != normalized:
                logger.info(f"  Normalized role '{role}' to '{normalized}'")
            return normalized
        else:
            logger.warning(f"  Invalid role '{role}' - must be one of: {', '.join(self.VALID_ROLES.values())}")
            return None
    
    def load_groups(self) -> Dict[str, str]:
        """Load all groups and create a name-to-ID mapping."""
        if self.groups_cache is not None:
            return self.groups_cache
        
        logger.info("Loading groups from API...")
        url = f"{self.base_url}/public/v0/groups"
        
        groups = {}
        offset = 0
        limit = 1000
        
        while True:
            params = {"offset": offset, "limit": limit}
            
            try:
                response = requests.get(url, headers=self.headers, params=params)
                response.raise_for_status()
                batch = response.json()
                
                if not isinstance(batch, list):
                    logger.error(f"Unexpected response format from groups API: {type(batch)}")
                    break
                
                for group in batch:
                    group_name = group.get("name")
                    group_id = group.get("id")
                    if group_name and group_id:
                        groups[group_name] = group_id
                
                if len(batch) < limit:
                    break
                offset += limit
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Error loading groups: {e}")
                sys.exit(1)
        
        logger.info(f"Loaded {len(groups)} groups")
        self.groups_cache = groups
        return groups
    
    def create_user(self, email: str, role: Optional[str] = None,
                    first_name: Optional[str] = None, last_name: Optional[str] = None) -> Optional[Dict]:
        """Create a new user."""
        # Use email for both userId and email fields
        user_data = {
            "userId": email,
            "email": email,
        }
        
        # Add optional fields
        if first_name:
            user_data["firstName"] = first_name
        if last_name:
            user_data["lastName"] = last_name
        if role:
            # Normalize role (case-insensitive)
            normalized_role = self.normalize_role(role)
            if normalized_role:
                user_data["orgRoles"] = [normalized_role]
        
        if self.dry_run:
            logger.info(f"[DRY RUN] Would create user: {email} (userId: {email})")
            if "orgRoles" in user_data:
                logger.info(f"  Role: {user_data['orgRoles'][0]}")
            if first_name or last_name:
                logger.info(f"  Name: {first_name or ''} {last_name or ''}")
            return {"id": f"dry_run_{email}", "userId": email, "email": email}
        
        url = f"{self.base_url}/public/v0/users/"
        
        try:
            response = requests.post(url, headers=self.headers, json=user_data)
            response.raise_for_status()
            user = response.json()
            logger.info(f"Created user: {email} (ID: {user.get('id')})")
            return user
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 409:
                logger.warning(f"User already exists: {email}")
                self.stats["users_skipped"] += 1
                return None
            else:
                logger.error(f"Failed to create user {email}: {e}")
                if e.response.text:
                    logger.error(f"  Response: {e.response.text}")
                self.stats["users_failed"] += 1
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create user {email}: {e}")
            self.stats["users_failed"] += 1
            return None
    
    def add_user_to_groups(self, user_id: str, email: str, group_names: List[str]) -> None:
        """Add a user to one or more groups."""
        if not group_names:
            return
        
        groups = self.load_groups()
        
        for group_name in group_names:
            group_name = group_name.strip()
            if not group_name:
                continue
            
            group_id = groups.get(group_name)
            if not group_id:
                logger.warning(f"  Group not found: '{group_name}' (skipping)")
                self.stats["groups_failed"] += 1
                continue
            
            if self.dry_run:
                logger.info(f"  [DRY RUN] Would add {email} to group: {group_name}")
                self.stats["groups_added"] += 1
                continue
            
            url = f"{self.base_url}/public/v0/groups/{group_id}/members"
            
            try:
                response = requests.post(url, headers=self.headers, json=[user_id])
                response.raise_for_status()
                logger.info(f"  Added {email} to group: {group_name}")
                self.stats["groups_added"] += 1
                
            except requests.exceptions.RequestException as e:
                logger.error(f"  Failed to add {email} to group {group_name}: {e}")
                if hasattr(e, 'response') and e.response and e.response.text:
                    logger.error(f"    Response: {e.response.text}")
                self.stats["groups_failed"] += 1
    
    def process_csv(self, csv_file: str) -> None:
        """Process CSV file and create users."""
        logger.info(f"Processing CSV file: {csv_file}")
        logger.info(f"Dry run mode: {self.dry_run}")
        logger.info("-" * 80)
        
        start_time = time.time()
        
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                # Validate CSV headers
                if 'email' not in reader.fieldnames:
                    logger.error("CSV file must have an 'email' column")
                    sys.exit(1)
                
                logger.info(f"CSV columns detected: {', '.join(reader.fieldnames)}")
                logger.info("-" * 80)
                
                for row_num, row in enumerate(reader, start=2):  # Start at 2 (1 is header)
                    self.stats["total_rows"] += 1
                    
                    # Get required field
                    email = row.get('email', '').strip()
                    if not email:
                        logger.warning(f"Row {row_num}: Missing email address (skipping)")
                        self.stats["users_skipped"] += 1
                        continue
                    
                    # Get optional fields
                    role = row.get('role', '').strip() or None
                    first_name = row.get('first_name', '').strip() or None
                    last_name = row.get('last_name', '').strip() or None
                    groups_str = row.get('groups', '').strip()
                    
                    logger.info(f"Row {row_num}: Processing {email}")
                    
                    # Create user
                    user = self.create_user(email, role, first_name, last_name)
                    
                    if user:
                        self.stats["users_created"] += 1
                        
                        # Add to groups if specified
                        if groups_str:
                            # Support pipe (|) or semicolon (;) as group delimiters
                            if '|' in groups_str:
                                group_names = groups_str.split('|')
                            elif ';' in groups_str:
                                group_names = groups_str.split(';')
                            else:
                                group_names = [groups_str]
                            
                            # Use the internal ID (not userId/email) for group membership
                            user_id = user.get('id')
                            self.add_user_to_groups(user_id, email, group_names)
                    
                    # Progress indication
                    if self.stats["total_rows"] % 10 == 0:
                        elapsed = time.time() - start_time
                        rate = self.stats["total_rows"] / elapsed if elapsed > 0 else 0
                        logger.info(f"Progress: {self.stats['total_rows']} rows processed "
                                  f"({rate:.1f} rows/sec)")
                    
                    logger.info("")  # Blank line between users
        
        except FileNotFoundError:
            logger.error(f"CSV file not found: {csv_file}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error processing CSV: {e}")
            sys.exit(1)
        
        # Calculate total time
        elapsed = time.time() - start_time
        
        # Print summary
        logger.info("=" * 80)
        logger.info("SUMMARY")
        logger.info("=" * 80)
        logger.info(f"Total rows processed: {self.stats['total_rows']}")
        logger.info(f"Users created: {self.stats['users_created']}")
        logger.info(f"Users failed: {self.stats['users_failed']}")
        logger.info(f"Users skipped (already exist): {self.stats['users_skipped']}")
        logger.info(f"Group assignments successful: {self.stats['groups_added']}")
        logger.info(f"Group assignments failed: {self.stats['groups_failed']}")
        logger.info(f"Total time: {elapsed:.2f} seconds")
        if self.stats['total_rows'] > 0:
            logger.info(f"Average time per row: {elapsed / self.stats['total_rows']:.2f} seconds")
        logger.info("=" * 80)


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Bulk create users from a CSV file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
CSV Format (see user_template.csv for a template):
  email,role,groups,first_name,last_name
  
  - email: Required. User's email address (used for both email and userId)
  - role: Optional. Organization role (case-insensitive) - valid values:
          Integrator, Projects Admin, Global Components Editor,
          Portfolio Viewer, Compliance Manager, Global admin, System manager
  - groups: Optional. Pipe-separated (|) or semicolon-separated (;) list of group names (case-sensitive)
  - first_name: Optional. User's first name
  - last_name: Optional. User's last name

Environment Variables (Required):
  FINITE_STATE_DOMAIN        Full domain (e.g., jermaine.finitestate.io)
  FINITE_STATE_AUTH_TOKEN    API token

Examples:
  # Dry run to preview actions
  python3 bulk_create_users.py users.csv --dry-run
  
  # Create users for real
  python3 bulk_create_users.py users.csv
  
  # Verbose logging
  python3 bulk_create_users.py users.csv --verbose
        """
    )
    
    parser.add_argument(
        "csv_file",
        help="Path to CSV file containing user data"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview actions without making changes"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Get authentication from environment
    domain = os.environ.get("FINITE_STATE_DOMAIN")
    token = os.environ.get("FINITE_STATE_AUTH_TOKEN")
    
    if not domain or not token:
        logger.error("Missing required environment variables:")
        if not domain:
            logger.error("  - FINITE_STATE_DOMAIN")
        if not token:
            logger.error("  - FINITE_STATE_AUTH_TOKEN")
        sys.exit(1)
    
    # Extract subdomain
    subdomain = domain.replace(".finitestate.io", "").replace("https://", "").replace("http://", "")
    
    logger.info("Starting bulk user creation")
    logger.info(f"Domain: {subdomain}.finitestate.io")
    logger.info("")
    
    # Create manager and process CSV
    manager = FiniteStateUserManager(subdomain, token, dry_run=args.dry_run)
    manager.process_csv(args.csv_file)


if __name__ == "__main__":
    main()
