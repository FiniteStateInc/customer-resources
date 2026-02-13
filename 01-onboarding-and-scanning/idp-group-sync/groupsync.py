#!/usr/bin/env python3
"""IDP Group Sync — Sync IDP group memberships to the Finite State platform.

Reads a mapping file (YAML or CSV) that defines how IDP groups map to Finite State
groups, then reconciles group state via the Finite State REST API: creating groups,
setting org roles, and adding/removing members.

Usage:
    export FINITE_STATE_AUTH_TOKEN="<your-api-token>"

    # Minimal — domain from env var or --domain flag (required)
    uv run python groupsync.py --domain acme.finitestate.io --mapping mapping.yaml

    # Preview changes without applying them
    uv run python groupsync.py --domain acme.finitestate.io --mapping mapping.yaml --dry-run

    # Create users that don't exist yet (they will receive an invitation email)
    uv run python groupsync.py --domain acme.finitestate.io --mapping mapping.yaml \
        --create-missing-users --max-new-users 100

    # Remove group members not present in the mapping file
    uv run python groupsync.py --domain acme.finitestate.io --mapping mapping.csv \
        --remove-unlisted-members

    # Verbose output
    uv run python groupsync.py --domain acme.finitestate.io --mapping mapping.yaml --verbose

CLI options:
    --domain                  Finite State domain (e.g. acme.finitestate.io).
                              Falls back to FINITE_STATE_DOMAIN env var.
    --mapping                 Path to the mapping file (YAML or CSV, auto-detected).
    --dry-run                 Preview changes without applying them.
    --create-missing-users    Invite users not yet in Finite State.
    --max-new-users N         Safety limit for user creation (default: 50).
    --remove-unlisted-members Remove members not present in the mapping file.
    --allow-custom-domain     Bypass .finitestate.io domain validation.
    --verbose                 Enable debug logging.

Environment variables:
    FINITE_STATE_AUTH_TOKEN  API token (required)
    FINITE_STATE_DOMAIN     Customer domain, e.g. acme.finitestate.io (or use --domain)
"""

from __future__ import annotations

import argparse
import csv
import io
import logging
import os
import sys
from dataclasses import dataclass, field
from typing import Any

import requests
import yaml
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("groupsync")


def setup_logging(verbose: bool = False) -> None:
    """Configure logging with a clean format."""
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    fmt = logging.Formatter("%(message)s")
    handler.setFormatter(fmt)
    logger.setLevel(level)
    logger.addHandler(handler)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class MemberInfo:
    """User info from the mapping file."""

    email: str
    first_name: str = ""
    last_name: str = ""


@dataclass
class GroupMapping:
    """A single IDP-to-Finite-State group mapping entry."""

    idp_group: str
    fs_group: str
    description: str = ""
    org_roles: list[str] = field(default_factory=list)
    members: list[MemberInfo] = field(default_factory=list)


@dataclass
class MappingData:
    """Parsed mapping file: group definitions + user detail lookup."""

    groups: list[GroupMapping]
    user_details: dict[str, MemberInfo]  # email (lowercase) -> MemberInfo


# ---------------------------------------------------------------------------
# Finite State API Client
# ---------------------------------------------------------------------------

# Redacting filter for debug logging — prevents token leakage
_REDACTED_HEADERS = {"X-Authorization", "x-authorization"}


class FiniteStateClient:
    """REST API client for the Finite State platform."""

    def __init__(self, base_url: str, api_token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-Authorization": api_token,
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )
        # Retry strategy for transient errors
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
    ) -> requests.Response:
        """Make an API request with error handling."""
        url = self._url(path)
        safe_headers = {
            k: ("***REDACTED***" if k in _REDACTED_HEADERS else v)
            for k, v in self.session.headers.items()
        }
        logger.debug("API %s %s params=%s headers=%s", method, url, params, safe_headers)

        resp = self.session.request(method, url, params=params, json=json_body)

        if resp.status_code == 401:
            logger.error("Authentication failed (HTTP 401). Check your FINITE_STATE_AUTH_TOKEN.")
            sys.exit(1)

        if resp.status_code >= 400:
            logger.debug(
                "API error: %s %s -> %d: %s",
                method,
                url,
                resp.status_code,
                resp.text[:500],
            )
        return resp

    def _paginate(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """Fetch all pages from a paginated list endpoint."""
        all_items: list[dict[str, Any]] = []
        offset = 0
        if params is None:
            params = {}
        params["limit"] = page_size

        while True:
            params["offset"] = offset
            resp = self._request("GET", path, params=dict(params))
            resp.raise_for_status()
            items: list[dict[str, Any]] = resp.json()
            all_items.extend(items)

            total_str = resp.headers.get("X-Total-Count")
            if total_str is not None:
                total = int(total_str)
                if offset + len(items) >= total:
                    break
            else:
                # No total count header — stop when we get fewer items than page size
                if len(items) < page_size:
                    break

            offset += len(items)

        return all_items

    # -- Users ----------------------------------------------------------------

    def list_users(self, rsql_filter: str | None = None) -> list[dict[str, Any]]:
        """Fetch all users, optionally filtered by RSQL."""
        params: dict[str, Any] = {}
        if rsql_filter:
            params["filter"] = rsql_filter
        return self._paginate("/users/", params=params)

    def create_user(
        self,
        email: str,
        first_name: str = "",
        last_name: str = "",
    ) -> dict[str, Any]:
        """Create/invite a new user. Returns the created user object.

        Handles 409 (already exists) gracefully by returning an empty dict.
        """
        body: dict[str, Any] = {"email": email, "userId": email}
        if first_name:
            body["firstName"] = first_name
        if last_name:
            body["lastName"] = last_name

        resp = self._request("POST", "/users/", json_body=body)
        if resp.status_code == 409:
            logger.warning("  User %s already exists, skipping creation", email)
            return {}
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        return result

    # -- Groups ---------------------------------------------------------------

    def list_groups(self, rsql_filter: str | None = None) -> list[dict[str, Any]]:
        """Fetch all groups, optionally filtered by RSQL."""
        params: dict[str, Any] = {}
        if rsql_filter:
            params["filter"] = rsql_filter
        return self._paginate("/groups", params=params)

    def create_group(
        self,
        name: str,
        description: str = "",
        org_roles: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a new group. Returns the created group object."""
        body: dict[str, Any] = {"name": name, "description": description}
        if org_roles:
            body["orgRoles"] = org_roles
        resp = self._request("POST", "/groups", json_body=body)
        if resp.status_code == 409:
            logger.warning("  Group '%s' already exists", name)
            return {}
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        return result

    def update_group(
        self,
        group_id: str,
        name: str,
        description: str = "",
        org_roles: list[str] | None = None,
    ) -> dict[str, Any]:
        """Update an existing group."""
        body: dict[str, Any] = {"name": name, "description": description}
        if org_roles is not None:
            body["orgRoles"] = org_roles
        resp = self._request("PUT", f"/groups/{group_id}", json_body=body)
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        return result

    # -- Group Members --------------------------------------------------------

    def get_group_members(self, group_id: str) -> list[dict[str, Any]]:
        """Fetch all members of a group."""
        return self._paginate(f"/groups/{group_id}/members")

    def add_group_members(self, group_id: str, user_ids: list[str]) -> list[str]:
        """Add members to a group. Returns list of successfully added user IDs."""
        if not user_ids:
            return []
        resp = self._request("POST", f"/groups/{group_id}/members", json_body=user_ids)
        resp.raise_for_status()
        result: list[str] = resp.json()
        return result

    def remove_group_members(self, group_id: str, user_ids: list[str]) -> None:
        """Remove members from a group."""
        if not user_ids:
            return
        resp = self._request("DELETE", f"/groups/{group_id}/members", json_body=user_ids)
        resp.raise_for_status()


# ---------------------------------------------------------------------------
# Config Loading
# ---------------------------------------------------------------------------


class ConfigError(Exception):
    """Raised when the mapping file has validation errors."""


def load_mapping(path: str) -> MappingData:
    """Load a mapping file (YAML or CSV) and return normalized MappingData.

    Auto-detects format by file extension (.yaml/.yml for YAML, .csv for CSV).
    """
    lower_path = path.lower()
    if lower_path.endswith((".yaml", ".yml")):
        return _load_yaml_mapping(path)
    elif lower_path.endswith(".csv"):
        return _load_csv_mapping(path)
    else:
        raise ConfigError(f"Unsupported mapping file extension: {path!r}. Use .yaml, .yml, or .csv")


def _load_yaml_mapping(path: str) -> MappingData:
    """Parse a YAML mapping file."""
    with open(path) as f:
        # Security: always use safe_load to prevent arbitrary code execution
        data = yaml.safe_load(f)

    if not isinstance(data, dict) or "groups" not in data:
        raise ConfigError(f"YAML mapping must contain a top-level 'groups' key: {path}")

    raw_groups = data["groups"]
    if not isinstance(raw_groups, list):
        raise ConfigError(f"'groups' must be a list in {path}")

    groups: list[GroupMapping] = []
    user_details: dict[str, MemberInfo] = {}

    for i, entry in enumerate(raw_groups):
        if not isinstance(entry, dict):
            raise ConfigError(f"Group entry {i} must be a mapping in {path}")

        idp_group = entry.get("idp_group")
        if not idp_group:
            raise ConfigError(f"Group entry {i} missing required 'idp_group' in {path}")

        fs_group = str(entry.get("fs_group") or idp_group)
        description = entry.get("description", "")
        org_roles = entry.get("org_roles", [])
        if not isinstance(org_roles, list):
            raise ConfigError(f"Group '{idp_group}' org_roles must be a list in {path}")

        members: list[MemberInfo] = []
        raw_members = entry.get("members", [])
        if not isinstance(raw_members, list):
            raise ConfigError(f"Group '{idp_group}' members must be a list in {path}")

        for j, mem in enumerate(raw_members):
            if isinstance(mem, dict):
                email = mem.get("email", "")
            elif isinstance(mem, str):
                email = mem
            else:
                raise ConfigError(
                    f"Group '{idp_group}' member {j} must be a string or mapping in {path}"
                )

            if not email:
                raise ConfigError(f"Group '{idp_group}' member {j} missing 'email' in {path}")

            email_lower = email.strip().lower()
            first_name = mem.get("first_name", "") if isinstance(mem, dict) else ""
            last_name = mem.get("last_name", "") if isinstance(mem, dict) else ""

            member = MemberInfo(
                email=email_lower,
                first_name=str(first_name),
                last_name=str(last_name),
            )
            members.append(member)

            # Track user details (first occurrence wins)
            if email_lower not in user_details:
                user_details[email_lower] = member
            else:
                existing = user_details[email_lower]
                if first_name and existing.first_name and str(first_name) != existing.first_name:
                    logger.warning(
                        "Warning: conflicting first_name for %s: '%s' vs '%s' "
                        "(using first occurrence)",
                        email_lower,
                        existing.first_name,
                        first_name,
                    )

        groups.append(
            GroupMapping(
                idp_group=idp_group,
                fs_group=fs_group,
                description=description,
                org_roles=org_roles,
                members=members,
            )
        )

    return MappingData(groups=groups, user_details=user_details)


def _load_csv_mapping(path: str) -> MappingData:
    """Parse a CSV mapping file."""
    with open(path, newline="") as f:
        content = f.read()

    reader = csv.DictReader(io.StringIO(content))
    if reader.fieldnames is None:
        raise ConfigError(f"CSV file is empty or has no header: {path}")

    required_cols = {"user_email", "idp_group"}
    header_set = set(reader.fieldnames)
    missing = required_cols - header_set
    if missing:
        raise ConfigError(f"CSV missing required columns {missing} in {path}")

    # Collect data: group_name -> {config, member_emails}
    group_configs: dict[str, dict[str, Any]] = {}
    group_members: dict[str, list[MemberInfo]] = {}
    user_details: dict[str, MemberInfo] = {}

    for row_num, row in enumerate(reader, start=2):
        email_raw = (row.get("user_email") or "").strip()
        idp_group = (row.get("idp_group") or "").strip()

        if not email_raw or not idp_group:
            logger.warning("Skipping CSV row %d: missing user_email or idp_group", row_num)
            continue

        email_lower = email_raw.lower()
        first_name = (row.get("first_name") or "").strip()
        last_name = (row.get("last_name") or "").strip()

        member = MemberInfo(
            email=email_lower,
            first_name=first_name,
            last_name=last_name,
        )

        # Track user details (first occurrence wins, warn on conflict)
        if email_lower not in user_details:
            user_details[email_lower] = member
        else:
            existing = user_details[email_lower]
            if first_name and existing.first_name and first_name != existing.first_name:
                logger.warning(
                    "Warning: conflicting first_name for %s at row %d: '%s' vs '%s' "
                    "(using first occurrence)",
                    email_lower,
                    row_num,
                    existing.first_name,
                    first_name,
                )

        # Track group config (first occurrence wins, warn on conflict)
        fs_group = (row.get("fs_group") or "").strip()
        description = (row.get("description") or "").strip()
        org_roles_raw = (row.get("org_roles") or "").strip()
        org_roles = (
            [r.strip() for r in org_roles_raw.split("|") if r.strip()] if org_roles_raw else []
        )

        if idp_group not in group_configs:
            group_configs[idp_group] = {
                "fs_group": fs_group or idp_group,
                "description": description,
                "org_roles": org_roles,
            }
            group_members[idp_group] = []
        else:
            # Warn if group config differs from first occurrence
            existing_cfg = group_configs[idp_group]
            effective_fs_group = fs_group or idp_group
            if effective_fs_group != existing_cfg["fs_group"]:
                logger.warning(
                    "Warning: conflicting fs_group for idp_group '%s' at row %d: "
                    "'%s' vs '%s' (using first occurrence)",
                    idp_group,
                    row_num,
                    existing_cfg["fs_group"],
                    effective_fs_group,
                )
            if org_roles and org_roles != existing_cfg["org_roles"]:
                logger.warning(
                    "Warning: conflicting org_roles for idp_group '%s' at row %d "
                    "(using first occurrence)",
                    idp_group,
                    row_num,
                )

        group_members[idp_group].append(member)

    # Build GroupMapping list
    groups: list[GroupMapping] = []
    for idp_group, cfg in group_configs.items():
        groups.append(
            GroupMapping(
                idp_group=idp_group,
                fs_group=cfg["fs_group"],
                description=cfg["description"],
                org_roles=cfg["org_roles"],
                members=group_members[idp_group],
            )
        )

    return MappingData(groups=groups, user_details=user_details)


# ---------------------------------------------------------------------------
# Reconciliation Engine
# ---------------------------------------------------------------------------


@dataclass
class SyncSummary:
    """Accumulates sync statistics for the final report."""

    groups_processed: int = 0
    groups_created: int = 0
    groups_existing: int = 0
    members_added: int = 0
    members_removed: int = 0
    users_created: int = 0
    warnings: int = 0


def sync_groups(
    client: FiniteStateClient,
    mapping: MappingData,
    dry_run: bool = False,
    create_missing_users: bool = False,
    max_new_users: int = 50,
    remove_unlisted: bool = False,
) -> SyncSummary:
    """Reconcile Finite State groups to match the mapping file."""
    summary = SyncSummary()
    prefix = "[DRY RUN] " if dry_run else ""

    if dry_run:
        logger.info("[DRY RUN] No changes will be made.\n")

    # Step 0: Build email -> user_id lookup
    logger.info("Fetching Finite State users...")
    all_users = client.list_users()
    logger.info("  Found %d users", len(all_users))
    email_to_user: dict[str, dict[str, Any]] = {}
    for u in all_users:
        email = (u.get("email") or "").lower()
        if email:
            email_to_user[email] = u

    # Step 0b: Fetch all existing groups
    logger.info("Fetching Finite State groups...")
    all_groups = client.list_groups()
    logger.info("  Found %d groups\n", len(all_groups))
    name_to_group: dict[str, dict[str, Any]] = {}
    for g in all_groups:
        name_to_group[g["name"]] = g

    # Pre-check: count missing users for safety limit
    if create_missing_users:
        missing_emails: set[str] = set()
        for gm in mapping.groups:
            for member in gm.members:
                if member.email not in email_to_user:
                    missing_emails.add(member.email)
        if len(missing_emails) > max_new_users:
            logger.error(
                "ERROR: --create-missing-users would invite %d new users, "
                "which exceeds the safety limit of %d.\n"
                "To proceed, set --max-new-users %d (or higher).",
                len(missing_emails),
                max_new_users,
                len(missing_emails),
            )
            sys.exit(1)
        if missing_emails:
            logger.info(
                "%sWill invite %d new user(s) to Finite State",
                prefix,
                len(missing_emails),
            )
            logger.info(
                "  NOTE: Each invited user will receive an email prompting "
                "them to set up their credentials.\n"
            )

    # Step 1-5: Process each group mapping
    for gm in mapping.groups:
        logger.info("[%s]", gm.fs_group)

        # 1. Resolve member emails to user IDs
        desired_user_ids: set[str] = set()
        desired_email_to_id: dict[str, str] = {}
        for member in gm.members:
            user = email_to_user.get(member.email)
            if user:
                uid = user["id"]
                desired_user_ids.add(uid)
                desired_email_to_id[member.email] = uid
            elif create_missing_users:
                if dry_run:
                    logger.info("  %sWould invite user: %s", prefix, member.email)
                    summary.users_created += 1
                else:
                    logger.info("  Inviting user: %s", member.email)
                    details = mapping.user_details.get(member.email)
                    first = details.first_name if details else ""
                    last = details.last_name if details else ""
                    new_user = client.create_user(member.email, first, last)
                    if new_user and "id" in new_user:
                        uid = new_user["id"]
                        desired_user_ids.add(uid)
                        desired_email_to_id[member.email] = uid
                        email_to_user[member.email] = new_user
                        summary.users_created += 1
                    else:
                        logger.warning("  Warning: failed to create user %s", member.email)
                        summary.warnings += 1
            else:
                logger.warning(
                    "  Warning: user %s not found in Finite State (skipping)",
                    member.email,
                )
                summary.warnings += 1

        # 2. Find or create the group
        existing_group = name_to_group.get(gm.fs_group)
        if existing_group:
            group_id = existing_group["id"]
            logger.info("  Group exists (id: %s)", group_id)
            summary.groups_existing += 1
        else:
            if dry_run:
                logger.info("  %sWould create group '%s'", prefix, gm.fs_group)
                group_id = "<new>"
                summary.groups_created += 1
            else:
                logger.info("  Group does not exist, creating...")
                created = client.create_group(gm.fs_group, gm.description, gm.org_roles)
                if created and "id" in created:
                    group_id = created["id"]
                    logger.info("  Created group (id: %s)", group_id)
                    name_to_group[gm.fs_group] = created
                    summary.groups_created += 1
                else:
                    logger.error("  ERROR: failed to create group '%s', skipping", gm.fs_group)
                    summary.warnings += 1
                    continue

        # 3. Sync org roles
        if existing_group:
            current_org_roles = sorted(existing_group.get("orgRoles") or [])
            desired_org_roles = sorted(gm.org_roles)
            if current_org_roles != desired_org_roles:
                if dry_run:
                    logger.info(
                        "  %sWould update org roles: %s -> %s",
                        prefix,
                        current_org_roles,
                        desired_org_roles,
                    )
                else:
                    logger.info("  Updating org roles: %s", desired_org_roles)
                    client.update_group(group_id, gm.fs_group, gm.description, gm.org_roles)
            else:
                logger.info("  Org roles: %s (no change)", current_org_roles)
        else:
            if gm.org_roles:
                logger.info("  Setting org roles: %s", gm.org_roles)

        # 4. Fetch current members, compute diff (skip for dry-run new groups)
        if group_id == "<new>":
            to_add = desired_user_ids
            to_remove: set[str] = set()
            current_member_ids: set[str] = set()
        else:
            current_members = client.get_group_members(group_id)
            current_member_ids = {m["id"] for m in current_members}
            to_add = desired_user_ids - current_member_ids
            to_remove = (current_member_ids - desired_user_ids) if remove_unlisted else set()

        logger.info(
            "  Current members: %d, Desired members: %d",
            len(current_member_ids),
            len(desired_user_ids),
        )

        # Build reverse lookup for readable log output
        id_to_email: dict[str, str] = {}
        for u in all_users:
            uid = u.get("id", "")
            em = (u.get("email") or "").lower()
            if uid and em:
                id_to_email[uid] = em
        # Include newly created users
        for em, uid in desired_email_to_id.items():
            id_to_email[uid] = em

        # 5. Apply member changes
        if to_add:
            add_emails = [id_to_email.get(uid, uid) for uid in to_add]
            if dry_run:
                logger.info(
                    "  %sWould add %d member(s): %s",
                    prefix,
                    len(to_add),
                    ", ".join(sorted(add_emails)),
                )
            else:
                logger.info(
                    "  Adding %d member(s): %s",
                    len(to_add),
                    ", ".join(sorted(add_emails)),
                )
                client.add_group_members(group_id, list(to_add))
            summary.members_added += len(to_add)
        else:
            logger.info("  Adding 0 members")

        if to_remove:
            remove_emails = [id_to_email.get(uid, uid) for uid in to_remove]
            if dry_run:
                logger.info(
                    "  %sWould remove %d member(s): %s",
                    prefix,
                    len(to_remove),
                    ", ".join(sorted(remove_emails)),
                )
            else:
                logger.info(
                    "  Removing %d member(s): %s",
                    len(to_remove),
                    ", ".join(sorted(remove_emails)),
                )
                client.remove_group_members(group_id, list(to_remove))
            summary.members_removed += len(to_remove)
        elif remove_unlisted:
            logger.info("  Removing 0 members")

        summary.groups_processed += 1
        logger.info("")

    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def validate_domain(domain: str, allow_custom: bool) -> str:
    """Validate and return the domain.

    Ensures the domain ends with '.finitestate.io' unless --allow-custom-domain is set.
    """
    domain = domain.strip().rstrip("/")
    if not allow_custom and not domain.endswith(".finitestate.io"):
        logger.error(
            "ERROR: Domain '%s' does not end with '.finitestate.io'.\n"
            "This check prevents accidentally sending your API token "
            "to a non-Finite State server.\n"
            "If this is a dev/staging environment, use --allow-custom-domain to bypass.",
            domain,
        )
        sys.exit(1)
    return domain


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="groupsync",
        description=(
            "Sync IDP group memberships to the Finite State platform. "
            "Reads a mapping file (YAML or CSV) and reconciles group state via the REST API."
        ),
    )
    parser.add_argument(
        "--domain",
        default=os.environ.get("FINITE_STATE_DOMAIN", ""),
        help=(
            "Finite State domain (e.g. acme.finitestate.io). "
            "Falls back to FINITE_STATE_DOMAIN env var."
        ),
    )
    parser.add_argument(
        "--allow-custom-domain",
        action="store_true",
        default=False,
        help="Bypass .finitestate.io domain validation.",
    )
    parser.add_argument(
        "--mapping",
        required=True,
        help="Path to the mapping file (YAML or CSV, auto-detected by extension).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Preview changes without applying them.",
    )
    parser.add_argument(
        "--create-missing-users",
        action="store_true",
        default=False,
        help=(
            "Invite users not yet in Finite State (default: skip with warning). "
            "NOTE: Invited users will receive an email prompting them to set up "
            "their credentials."
        ),
    )
    parser.add_argument(
        "--max-new-users",
        type=int,
        default=50,
        help=(
            "Safety limit for --create-missing-users. "
            "Abort if more than this many users would be created (default: 50)."
        ),
    )
    parser.add_argument(
        "--remove-unlisted-members",
        action="store_true",
        default=False,
        help=(
            "Remove users from Finite State groups if they are not in the mapping "
            "file for that group (default: additive only)."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose/debug logging.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    setup_logging(verbose=args.verbose)

    # Validate domain
    if not args.domain:
        logger.error(
            "ERROR: No domain specified. "
            "Set --domain or the FINITE_STATE_DOMAIN environment variable."
        )
        sys.exit(1)
    domain = validate_domain(args.domain, args.allow_custom_domain)
    base_url = f"https://{domain}/api/public/v0"

    # Get API token from env var only (security: no CLI flag)
    api_token = os.environ.get("FINITE_STATE_AUTH_TOKEN", "")
    if not api_token:
        logger.error(
            "ERROR: No API token found. Set the FINITE_STATE_AUTH_TOKEN environment variable."
        )
        sys.exit(1)

    # Load mapping file
    logger.info("Loading mapping file: %s", args.mapping)
    try:
        mapping = load_mapping(args.mapping)
    except ConfigError as e:
        logger.error("ERROR: %s", e)
        sys.exit(1)
    except FileNotFoundError:
        logger.error("ERROR: Mapping file not found: %s", args.mapping)
        sys.exit(1)

    logger.info(
        "  %d group mapping(s), %d unique user(s)\n",
        len(mapping.groups),
        len(mapping.user_details),
    )

    # Create API client and run sync
    client = FiniteStateClient(base_url, api_token)

    summary = sync_groups(
        client=client,
        mapping=mapping,
        dry_run=args.dry_run,
        create_missing_users=args.create_missing_users,
        max_new_users=args.max_new_users,
        remove_unlisted=args.remove_unlisted_members,
    )

    # Print summary
    prefix = "[DRY RUN] " if args.dry_run else ""
    logger.info("%sSummary:", prefix)
    logger.info(
        "  Groups processed: %d (%d created, %d existing)",
        summary.groups_processed,
        summary.groups_created,
        summary.groups_existing,
    )
    if summary.users_created:
        logger.info("  Users invited: %d", summary.users_created)
    logger.info("  Members added: %d", summary.members_added)
    logger.info("  Members removed: %d", summary.members_removed)
    logger.info("  Warnings: %d", summary.warnings)


if __name__ == "__main__":
    main()
