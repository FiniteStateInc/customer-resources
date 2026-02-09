"""Sync engine for bidirectional data synchronization."""

import asyncio
import logging
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from ..cache import SQLiteCache
from ..config import AppConfig
from ..fs_client import FiniteStateClient
from ..mapper import DataMapper
from ..smartsheet_client import SmartsheetClient
from ..smartsheet_client.client import SmartsheetError
from ..smartsheet_client.schemas import (
    DEFAULT_API_JUSTIFICATION,
    DEFAULT_API_RESPONSE,
    STANDARD_SCHEMAS,
    VEX_JUSTIFICATION_TO_API,
    VEX_JUSTIFICATIONS,
    VEX_RESPONSE_TO_API,
    VEX_RESPONSES,
    VEX_STATUSES,
    SheetSchema,
)
from .filters import SyncFilters
from .state import SyncState, compute_data_hash

# Progress callback: (phase, current_count, total_or_none, detail)
# Phases:
#   "start"     - new sheet starting (detail=sheet_name)
#   "fetch"     - items fetched from FS (current=count, total=None)
#   "write"     - rows written to Smartsheet (current=count, total=None)
#   "writeback" - write-back ops (current=completed, total=total)
#   "done"      - sync complete (current=total_processed, total=None)
ProgressCallback = Callable[[str, int, int | None, str], None]

logger = logging.getLogger(__name__)


@dataclass
class SyncResult:
    """Result of a sync operation."""

    sheet_name: str
    added: int = 0
    updated: int = 0
    deleted: int = 0
    unchanged: int = 0
    skipped: int = 0
    writeback_ok: int = 0
    writeback_failed: int = 0
    writeback_validation_errors: int = 0
    writeback_details: list[dict[str, Any]] = field(
        default_factory=list
    )  # Details of each writeback
    updated_rows: list[dict[str, Any]] = field(default_factory=list)  # Details of updated rows
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    filters_applied: str = ""
    row_limit_hit: bool = False

    @property
    def total_processed(self) -> int:
        return self.added + self.updated + self.deleted + self.unchanged

    @property
    def success(self) -> bool:
        return len(self.errors) == 0


@dataclass
class WritebackResult:
    """Result of a write-back operation."""

    sheet_name: str
    total: int = 0
    successful: int = 0
    failed: int = 0
    skipped: int = 0
    validation_errors: list[tuple[str, list[str]]] = field(default_factory=list)
    api_errors: list[tuple[str, str]] = field(default_factory=list)
    dry_run: bool = False

    @property
    def success(self) -> bool:
        return self.failed == 0 and len(self.validation_errors) == 0


@dataclass
class BulkUpdateResult:
    """Result of a bulk update operation."""

    total: int = 0
    successful: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.failed == 0


@dataclass
class HierarchyDiff:
    """Result of comparing expected FS hierarchy with actual Smartsheet workspace."""

    expected_paths: list[str] = field(default_factory=list)
    """All folder paths expected from FS (root → leaf)."""

    matched: list[str] = field(default_factory=list)
    """Smartsheet folders that match an expected FS path."""

    orphaned_folders: list[dict[str, Any]] = field(default_factory=list)
    """Smartsheet folders with no matching FS path (candidates for cleanup)."""

    orphaned_sheets: list[dict[str, Any]] = field(default_factory=list)
    """Sheets inside orphaned folders."""

    new_in_fs: list[str] = field(default_factory=list)
    """FS paths that don't yet exist as Smartsheet folders."""

    @property
    def has_orphans(self) -> bool:
        return bool(self.orphaned_folders or self.orphaned_sheets)

    @property
    def has_new(self) -> bool:
        return bool(self.new_in_fs)


class SyncEngine:
    """
    Orchestrates bidirectional sync between Finite State and Smartsheet.

    Supports:
    - Full sync (complete data refresh)
    - Incremental sync (only changes)
    - Filtered sync (scoped to projects, severity, etc.)
    - Write-back (Smartsheet changes to FS)
    """

    def __init__(
        self,
        config: AppConfig,
        state_path: Path | None = None,
        cache_ttl: int = 0,
    ):
        """
        Initialize the sync engine.

        Args:
            config: Application configuration
            state_path: Path to sync state file (defaults to config value)
            cache_ttl: Persistent cache TTL in seconds.  0 = disabled (default).
        """
        self.config = config
        self.state_path = state_path or config.sync.state_file
        self.state = SyncState.load(self.state_path)
        self.cache_ttl = cache_ttl

        # Build SQLiteCache when TTL is active
        self._cache: SQLiteCache | None = None
        if cache_ttl > 0:
            self._cache = SQLiteCache(
                default_ttl=cache_ttl,
                domain=config.finite_state.domain,
                cache_dir=config.sync.cache_dir,
            )

        self._fs_client: FiniteStateClient | None = None
        self._ss_client: SmartsheetClient | None = None

    @property
    def fs_client(self) -> FiniteStateClient:
        """Get or create Finite State client."""
        if self._fs_client is None:
            self._fs_client = FiniteStateClient(
                domain=self.config.finite_state.domain,
                auth_token=self.config.finite_state.auth_token,
                cache=self._cache,
            )
        return self._fs_client

    @property
    def ss_client(self) -> SmartsheetClient:
        """Get or create Smartsheet client."""
        if self._ss_client is None:
            self._ss_client = SmartsheetClient(
                access_token=self.config.smartsheet.access_token,
                workspace_id=self.config.smartsheet.workspace_id,
                workspace_name=self.config.smartsheet.workspace_name,
            )
        return self._ss_client

    async def close(self) -> None:
        """Clean up resources."""
        if self._fs_client:
            await self._fs_client.close()
            self._fs_client = None

    def save_state(self) -> None:
        """Save current sync state."""
        self.state.save(self.state_path)

    # ==================== Sync Operations ====================

    async def sync_all(
        self,
        full: bool = False,
        filters: SyncFilters | None = None,
        force: bool = False,
        progress: ProgressCallback | None = None,
    ) -> list[SyncResult]:
        """
        Sync all standard sheets.

        Args:
            full: If True, force full sync even if incremental is possible
            filters: Optional filters to scope the sync
            force: If True, bypass safety limits
            progress: Optional callback for progress updates

        Returns:
            List of SyncResult for each sheet
        """
        results = []

        # Per-project sync: only findings + components (projects is redundant)
        sheet_types = ["projects", "findings", "components"]
        if filters and filters.project_names:
            sheet_types = ["findings", "components"]

        for sheet_type in sheet_types:
            try:
                result = await self.sync_sheet(
                    sheet_type,
                    full=full,
                    filters=filters,
                    force=force,
                    progress=progress,
                )
                results.append(result)
            except Exception as e:
                logger.error(f"Error syncing {sheet_type}: {e}")
                results.append(
                    SyncResult(
                        sheet_name=sheet_type,
                        errors=[str(e)],
                    )
                )

        self.save_state()
        return results

    async def sync_sheet(
        self,
        sheet_type: str,
        schema: SheetSchema | None = None,
        full: bool = False,
        filters: SyncFilters | None = None,
        force: bool = False,
        sheet_name: str | None = None,
        progress: ProgressCallback | None = None,
    ) -> SyncResult:
        """
        Sync a specific sheet type.

        Args:
            sheet_type: Type of sheet ('projects', 'findings', 'components')
            schema: Custom schema (uses standard if not provided)
            full: Force full sync
            filters: Optional filters to scope the sync
            force: If True, bypass safety limits
            sheet_name: Custom sheet name (overrides default naming)

        Returns:
            SyncResult with statistics
        """
        start_time = datetime.utcnow()
        base_schema = schema or STANDARD_SCHEMAS.get(sheet_type)
        if not base_schema:
            raise ValueError(f"Unknown sheet type: {sheet_type}")

        filters = filters or SyncFilters()

        # Determine sheet name and folder
        effective_sheet_name, folder_id = await self._resolve_sheet_location(
            sheet_type, base_schema, filters, sheet_name
        )

        # Create schema with effective name
        schema = base_schema.with_name(effective_sheet_name)

        result = SyncResult(
            sheet_name=schema.name,
            filters_applied=filters.get_description(),
        )

        if progress:
            progress("start", 0, None, schema.name)

        # Determine effective max rows
        max_rows = self._get_effective_max_rows(filters, force)

        try:
            # Ensure sheet exists (in folder if specified).
            # Smartsheet may auto-delete empty folders, so the folder_id
            # from _resolve_sheet_location can be stale.  If creation
            # fails with "not found", clear the folder cache, re-resolve
            # the location (which recreates the folder), and retry once.
            logger.info(f"Getting or creating sheet: {schema.name}")
            try:
                sheet = self.ss_client.get_or_create_sheet(schema, folder_id=folder_id)
            except SmartsheetError as sse:
                if folder_id and "not found" in str(sse).lower():
                    logger.warning(
                        "Folder %s gone (auto-deleted?). Re-resolving sheet location...",
                        folder_id,
                    )
                    self.ss_client._folder_cache.clear()
                    effective_sheet_name, folder_id = await self._resolve_sheet_location(
                        sheet_type, base_schema, filters, sheet_name
                    )
                    schema = base_schema.with_name(effective_sheet_name)
                    result.sheet_name = schema.name
                    sheet = self.ss_client.get_or_create_sheet(schema, folder_id=folder_id)
                else:
                    raise
            logger.info(f"Sheet ID: {sheet.id}, Columns: {[c.title for c in sheet.columns]}")
            self.state.set_sheet_id(schema.name, sheet.id)

            # Create mapper
            mapper = DataMapper(schema)

            # Fetch data from FS with filters
            fs_data = self._fetch_fs_data(sheet_type, filters)

            # Build index of existing rows
            sheet = self.ss_client.get_sheet(sheet.id, use_cache=False)
            existing_rows = self.ss_client.build_row_index(sheet, schema)

            # Track what we've seen
            seen_keys: set[str] = set()
            rows_to_add: list[dict[str, Any]] = []
            rows_to_update: list[dict[str, Any]] = []
            row_count = 0
            batch_size = 500  # Write to Smartsheet in batches
            pending_writebacks: list[dict[str, Any]] = []

            def flush_adds() -> None:
                """Write pending adds to Smartsheet."""
                nonlocal rows_to_add, total_written  # type: ignore[misc]
                if rows_to_add:
                    batch_count = len(rows_to_add)
                    added_rows = self.ss_client.add_rows(sheet.id, rows_to_add, schema)
                    for row, row_data in zip(added_rows, rows_to_add, strict=True):
                        primary_col = schema.get_primary_column()
                        if primary_col:
                            pk = row_data.get(primary_col.title)
                            if pk:
                                # Extract stored metadata
                                pv_id = row_data.pop("_project_version_id", None)
                                wb_fields = row_data.pop("_writeback_fields", {})
                                self.state.update_row_state(
                                    schema.name,
                                    str(pk),
                                    ss_row_id=row.id,
                                    project_version_id=pv_id,
                                    data_hash=compute_data_hash(row_data),
                                    writeback_fields=wb_fields,
                                )
                    total_written += batch_count
                    if progress:
                        progress("write", total_written, None, "")
                    rows_to_add = []

            def flush_updates() -> None:
                """Write pending updates to Smartsheet."""
                nonlocal rows_to_update, total_written  # type: ignore[misc]
                if rows_to_update:
                    batch_count = len(rows_to_update)
                    self.ss_client.update_rows(sheet.id, rows_to_update, schema)
                    total_written += batch_count
                    if progress:
                        progress("write", total_written, None, "")
                    rows_to_update = []

            total_written = 0

            try:
                async for item in fs_data:
                    row_count += 1
                    if progress and (row_count % 50 == 0 or row_count == 1):
                        progress("fetch", row_count, None, "")

                    # Check row limit
                    if max_rows and row_count > max_rows:
                        result.row_limit_hit = True
                        result.warnings.append(
                            f"Row limit ({max_rows}) reached. "
                            f"Increase --max-rows or remove it to sync all data."
                        )
                        break

                    try:
                        row_data = mapper.fs_to_smartsheet(item)
                        primary_key = mapper.get_primary_key_value(item)

                        if not primary_key:
                            result.skipped += 1
                            continue

                        seen_keys.add(primary_key)
                        data_hash = compute_data_hash(row_data)

                        # Check if row exists
                        existing_row = existing_rows.get(primary_key)
                        row_state = self.state.get_row_state(schema.name, primary_key)

                        # Extract project_version_id for findings (for writeback)
                        project_version_id: str | None = None
                        if sheet_type == "findings" and hasattr(item, "project_version"):
                            pv = item.project_version
                            if pv is not None:
                                project_version_id = pv.id

                        # Extract writeback field values for state tracking
                        writeback_values: dict[str, Any] = {}
                        for col in schema.get_writeback_columns():
                            if col.title in row_data:
                                writeback_values[col.title] = row_data[col.title]

                        if existing_row:
                            # Get current Smartsheet data for comparison
                            existing_data = self.ss_client.get_row_data(sheet, existing_row)

                            # Detect user's writeback field edits in Smartsheet
                            # and preserve them (+ queue for writeback to FS).
                            wb_columns = {c.title for c in schema.get_writeback_columns()}
                            if wb_columns and row_state:
                                changed_fields: dict[str, tuple[Any, Any]] = {}
                                for col_title in wb_columns:
                                    ss_val = existing_data.get(col_title)
                                    last_synced_val = row_state.writeback_fields.get(col_title)
                                    # Normalize empty values for comparison
                                    # (None, "", and missing all mean "empty")
                                    norm_ss = ss_val or None
                                    norm_last = last_synced_val or None
                                    if norm_ss != norm_last:
                                        # User changed this in Smartsheet — keep their value
                                        row_data[col_title] = ss_val
                                        changed_fields[col_title] = (last_synced_val, ss_val)

                                # Queue writeback to FS if user made changes
                                if changed_fields and sheet_type == "findings":
                                    pv_id = project_version_id or (
                                        row_state.project_version_id if row_state else None
                                    )
                                    if pv_id:
                                        # Get the finding title for display
                                        title_col = next(
                                            (c for c in schema.columns if c.primary),
                                            None,
                                        )
                                        finding_title = (
                                            existing_data.get(title_col.title, primary_key)
                                            if title_col
                                            else primary_key
                                        )
                                        pending_writebacks.append(
                                            {
                                                "finding_id": primary_key,
                                                "project_version_id": pv_id,
                                                "status": existing_data.get("Status"),
                                                "response": existing_data.get("Response"),
                                                "justification": existing_data.get("Justification"),
                                                "reason": existing_data.get("Reason"),
                                                "_title": finding_title,
                                                "_changes": changed_fields,
                                            }
                                        )

                            # Update if changed or full sync
                            if full or not row_state or row_state.data_hash != data_hash:
                                row_data["_row_id"] = existing_row.id
                                rows_to_update.append(row_data)
                                result.updated += 1

                                # Capture what changed for display
                                field_diffs: dict[str, tuple[Any, Any]] = {}
                                for col in schema.columns:
                                    title = col.title
                                    if title.startswith("_"):
                                        continue
                                    old_val = existing_data.get(title)
                                    new_val = row_data.get(title)
                                    # Normalize for comparison
                                    if (old_val or None) != (new_val or None):
                                        field_diffs[title] = (old_val, new_val)
                                result.updated_rows.append(
                                    {
                                        "key": primary_key,
                                        "changes": field_diffs,
                                    }
                                )
                            else:
                                result.unchanged += 1

                            # Update writeback state from the *final* row_data values.
                            # After writeback detection (above), row_data[col] is:
                            #   • the SS value – if the user edited it in Smartsheet
                            #   • the FS API value – if no user edit was detected
                            # This is the value that will actually live in SS after
                            # flush, so it's the correct baseline for next-run
                            # change detection.  Using existing_data (the pre-update
                            # SS value) would cause false writebacks when FS changes
                            # a writeback field (e.g. clearing a VEX status).
                            for col_title in wb_columns:
                                writeback_values[col_title] = row_data.get(col_title)

                            self.state.update_row_state(
                                schema.name,
                                primary_key,
                                ss_row_id=existing_row.id,
                                project_version_id=project_version_id,
                                data_hash=data_hash,
                                writeback_fields=writeback_values,
                            )
                        else:
                            # New row - store project_version_id for later state update
                            row_data["_project_version_id"] = project_version_id
                            row_data["_writeback_fields"] = writeback_values
                            rows_to_add.append(row_data)
                            result.added += 1

                        # Flush batches periodically
                        if len(rows_to_add) >= batch_size:
                            flush_adds()
                        if len(rows_to_update) >= batch_size:
                            flush_updates()

                    except Exception as item_error:
                        # Log and skip individual item errors
                        logger.warning(f"Skipping item due to error: {item_error}")
                        result.skipped += 1
                        continue

            except Exception as fetch_error:
                # Log fetch error but continue with what we have
                logger.warning(
                    f"Error during data fetch (continuing with {result.added} items): {fetch_error}"
                )
                result.warnings.append(f"Fetch interrupted: {str(fetch_error)[:100]}")

            # Final progress update for fetch count
            if progress and row_count > 0:
                progress("fetch", row_count, None, "")

            # Final flush of remaining rows
            flush_adds()
            flush_updates()

            # Bidirectional: write back user changes to Finite State
            if pending_writebacks:
                if progress:
                    progress("writeback", 0, len(pending_writebacks), "")
                logger.info(
                    f"Detected {len(pending_writebacks)} writeback change(s) — "
                    f"pushing to Finite State..."
                )
                valid_updates = []
                for wb in pending_writebacks:
                    status_val = wb.get("status")
                    errors = self._validate_vex_status_update(
                        status_val,
                        wb.get("response"),
                        wb.get("justification"),
                    )
                    if errors:
                        result.writeback_validation_errors += 1
                        result.warnings.append(
                            f"{wb['finding_id']}: skipped writeback — {'; '.join(errors)}"
                        )
                    else:
                        valid_updates.append(wb)

                # Store details for all attempted writebacks (valid + invalid)
                for wb in pending_writebacks:
                    result.writeback_details.append(
                        {
                            "finding_id": wb["finding_id"],
                            "title": wb.get("_title", wb["finding_id"]),
                            "changes": wb.get("_changes", {}),
                            "status": wb.get("status"),
                        }
                    )

                if valid_updates:
                    wb_result = await self._bulk_update_findings(valid_updates)
                    result.writeback_ok = wb_result.successful
                    result.writeback_failed = wb_result.failed
                    if wb_result.errors:
                        result.errors.extend(wb_result.errors)
                    if progress:
                        progress("writeback", len(pending_writebacks), len(pending_writebacks), "")

                    # Invalidate the findings cache so the next sync
                    # fetches fresh data reflecting the writeback changes.
                    if wb_result.successful and self._cache is not None:
                        self._cache.clear(endpoint="/findings")
                        logger.info(
                            "Cleared findings cache after %d successful writeback(s)",
                            wb_result.successful,
                        )

            if progress:
                progress("done", result.added + result.updated, None, "")

            # Remove "file" component rows when include_files is False
            # This ensures file components are cleaned up even on incremental sync
            if sheet_type == "components" and not filters.include_files:
                file_rows_to_delete = []
                for pk, row in existing_rows.items():
                    if pk in seen_keys:
                        continue  # Already handled above
                    row_data_existing = self.ss_client.get_row_data(sheet, row)
                    comp_type = row_data_existing.get("Type", "")
                    if comp_type and str(comp_type).lower() == "file":
                        file_rows_to_delete.append(row.id)
                        self.state.remove_row(schema.name, pk)
                        result.deleted += 1
                if file_rows_to_delete:
                    logger.info(
                        f"Removing {len(file_rows_to_delete)} file-type component "
                        f"row(s) (use --include-files to keep them)"
                    )
                    self.ss_client.delete_rows(sheet.id, file_rows_to_delete)

            # Handle deletions (rows in sheet but not in FS)
            # Only delete if full sync AND no filters (filters mean partial data)
            if full and filters.is_empty():
                rows_to_delete = []
                for pk, row in existing_rows.items():
                    if pk not in seen_keys:
                        rows_to_delete.append(row.id)
                        self.state.remove_row(schema.name, pk)
                        result.deleted += 1

                if rows_to_delete:
                    self.ss_client.delete_rows(sheet.id, rows_to_delete)
            elif full and not filters.is_empty():
                result.warnings.append(
                    "Deletions skipped: filters are active. "
                    "Use unfiltered full sync to remove stale rows."
                )

            if full:
                self.state.mark_full_sync(schema.name)
            else:
                self.state.mark_incremental_sync(schema.name)

        except Exception as e:
            logger.error(f"Error syncing {schema.name}: {e}")
            result.errors.append(str(e))

        result.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
        return result

    def _get_effective_max_rows(self, filters: SyncFilters, force: bool) -> int | None:
        """Determine the effective max rows limit."""
        # Only apply a limit if the user explicitly set --max-rows
        return filters.max_rows

    async def _resolve_sheet_location(
        self,
        sheet_type: str,
        base_schema: SheetSchema,
        filters: SyncFilters,
        custom_sheet_name: str | None = None,
    ) -> tuple[str, int | None]:
        """
        Determine sheet name and folder location based on filters.

        Hierarchy rules:
        - ``--target-folder`` overrides everything.
        - ``projects`` sheet always goes at workspace root.
        - Single-project filter: sheets are placed in the project's
          FS folder (not a project-specific subfolder):
              Workspace / {Folder A} / {Folder B} / ... / sheets
          If the project has no FS folder, sheets go at workspace root.
        - No project filter / multiple projects: workspace root.

        Args:
            sheet_type: Type of sheet (findings, components, etc.)
            base_schema: Base schema for the sheet type
            filters: Active filters
            custom_sheet_name: User-specified sheet name override

        Returns:
            Tuple of (sheet_name, folder_id or None)
        """
        # Map sheet types to human-readable suffixes
        type_suffix_map = {
            "findings": "Findings",
            "components": "Components",
            "projects": "Projects",
        }
        suffix = type_suffix_map.get(sheet_type, sheet_type.title())

        # --target-folder bypasses all hierarchy logic
        if filters.target_folder:
            name = custom_sheet_name or base_schema.name
            return name, filters.target_folder

        # If custom name provided, use it (no folder organization)
        if custom_sheet_name:
            return custom_sheet_name, None

        # Projects sheet always sits at workspace root
        if sheet_type == "projects":
            return base_schema.name, None

        # If single project filter, place sheets in the FS folder
        if len(filters.project_names) == 1:
            project_name = filters.project_names[0]
            sheet_name = f"{project_name} {suffix}"

            workspace_id = self.ss_client.workspace_id
            if workspace_id:
                # Look up the project's FS folder path (folders only, no project subfolder)
                folder_path = await self._get_project_folder_path(project_name)

                if folder_path:
                    # Create the FS folder chain and place sheets there
                    folder_id = self._create_smartsheet_folder_chain(workspace_id, folder_path)
                    return sheet_name, folder_id

                # No FS folder → workspace root
                return sheet_name, None

            return sheet_name, None

        # If single project ID filter, we'd need to resolve the name
        # For now, just use the ID in the name
        if len(filters.project_ids) == 1:
            project_id = filters.project_ids[0]
            sheet_name = f"Project {project_id} {suffix}"
            return sheet_name, None

        # No project filter or multiple projects - use default name at workspace root
        return base_schema.name, None

    async def _ensure_folder_tree(self) -> None:
        """
        Fetch all FS folders and cache them for tree lookups.

        Populates ``_folder_tree`` (dict[folder_id, FolderDetail]).
        """
        if not hasattr(self, "_folder_tree") or self._folder_tree is None:  # type: ignore[has-type]
            self._folder_tree = await self.fs_client.get_folder_tree()

    def _get_folder_path(self, folder_id: str) -> list[str]:
        """
        Walk up the parentFolderId chain to build the full path.

        Returns:
            List of folder names from root to leaf, e.g. ["Top", "Middle", "Leaf"].
            Empty list if folder_id is not found.
        """
        if not hasattr(self, "_folder_tree") or self._folder_tree is None:
            return []

        path: list[str] = []
        current_id: str | None = folder_id
        seen: set[str] = set()  # cycle protection

        while current_id and current_id not in seen:
            seen.add(current_id)
            folder = self._folder_tree.get(current_id)
            if folder is None:
                break
            path.append(folder.name)
            current_id = folder.parent_folder_id

        path.reverse()  # root → leaf
        return path

    async def _get_project_folder_path(self, project_name: str) -> list[str]:
        """
        Look up the full folder path for a project by name.

        Returns:
            List of folder names from root to leaf, e.g. ["Customers", "Acme"].
            Empty list if the project has no folder.
        """
        # Check local cache first
        if not hasattr(self, "_project_folder_path_cache"):
            self._project_folder_path_cache: dict[str, list[str]] = {}

        if project_name in self._project_folder_path_cache:
            return self._project_folder_path_cache[project_name]

        # Ensure folder tree is loaded
        await self._ensure_folder_tree()

        # Find the project's folder ID
        try:
            async for project in self.fs_client.iter_projects():
                if project.name == project_name:
                    if project.folder:
                        path = self._get_folder_path(project.folder.id)
                    else:
                        path = []
                    self._project_folder_path_cache[project_name] = path
                    return path
        except Exception:
            logger.debug(f"Could not look up FS folder for project '{project_name}'")

        self._project_folder_path_cache[project_name] = []
        return []

    def _create_smartsheet_folder_chain(self, workspace_id: int, folder_names: list[str]) -> int:
        """
        Create a chain of nested Smartsheet folders, returning the leaf folder ID.

        Args:
            workspace_id: Smartsheet workspace ID (top-level container)
            folder_names: Folder names from root to leaf, e.g. ["Top", "Middle", "Leaf"]

        Returns:
            The Smartsheet folder ID of the deepest (leaf) folder.
        """
        if not folder_names:
            return workspace_id

        # First level is a direct child of the workspace
        current_folder = self.ss_client.get_or_create_folder(workspace_id, folder_names[0])

        # Subsequent levels are subfolders
        for name in folder_names[1:]:
            current_folder = self.ss_client.get_or_create_subfolder(current_folder.id, name)

        return current_folder.id

    async def refresh_hierarchy(self) -> "HierarchyDiff":
        """
        Compare the expected FS folder hierarchy with the actual Smartsheet
        workspace contents and return a diff.

        Returns:
            HierarchyDiff describing new, orphaned, and matched paths.
        """
        workspace_id = self.ss_client.workspace_id
        if not workspace_id:
            raise SmartsheetError("No workspace configured")

        # --- 1. Build expected FS folder paths (no project subfolders) ---
        await self._ensure_folder_tree()

        expected_paths: set[str] = set()
        async for project in self.fs_client.iter_projects():
            if project.folder:
                folder_path = self._get_folder_path(project.folder.id)
                if folder_path:
                    # Add the full folder path
                    expected_paths.add("/".join(folder_path))
                    # Also add all intermediate folder paths
                    for i in range(1, len(folder_path)):
                        expected_paths.add("/".join(folder_path[:i]))
            # Projects without an FS folder go at workspace root — no folder expected

        # --- 2. Walk actual Smartsheet workspace ---
        actual_items = self.ss_client.walk_workspace(workspace_id)

        actual_folder_paths: dict[str, dict[str, Any]] = {}  # path → item dict
        actual_sheet_paths: dict[str, dict[str, Any]] = {}
        for item in actual_items:
            if item["type"] == "folder":
                actual_folder_paths[item["path"]] = item
            else:
                actual_sheet_paths[item["path"]] = item

        # --- 3. Diff ---
        # Known non-project items at root (e.g. "FS Projects" sheet)
        known_root_sheets = {"FS Projects"}

        orphaned_folders: list[dict[str, Any]] = []
        orphaned_sheets: list[dict[str, Any]] = []
        matched_folders: list[str] = []
        new_in_fs: list[str] = []

        for path, item in actual_folder_paths.items():
            if path in expected_paths:
                matched_folders.append(path)
            else:
                orphaned_folders.append(item)

        for path, item in actual_sheet_paths.items():
            # Root sheets like "FS Projects" are always expected
            if item["parent_folder_id"] is None and item["name"] in known_root_sheets:
                continue
            # A sheet inside an orphaned folder is also orphaned
            parent_path = "/".join(path.split("/")[:-1])
            if parent_path and parent_path not in expected_paths:
                orphaned_sheets.append(item)

        for path in expected_paths:
            if path not in actual_folder_paths:
                new_in_fs.append(path)

        return HierarchyDiff(
            expected_paths=sorted(expected_paths),
            matched=sorted(matched_folders),
            orphaned_folders=orphaned_folders,
            orphaned_sheets=orphaned_sheets,
            new_in_fs=sorted(new_in_fs),
        )

    def clean_orphans(self, diff: "HierarchyDiff") -> int:
        """
        Delete orphaned folders and sheets identified by a HierarchyDiff.

        Deletes sheets first, then folders (deepest first to avoid errors).

        Returns:
            Number of items deleted.
        """
        deleted = 0

        # Delete orphaned sheets first
        for item in diff.orphaned_sheets:
            logger.info(f"Deleting orphaned sheet: {item['path']} (ID: {item['id']})")
            self.ss_client.delete_sheet(item["id"])
            deleted += 1

        # Delete orphaned folders (deepest first so parents are deleted after children)
        sorted_folders = sorted(
            diff.orphaned_folders,
            key=lambda f: f["path"].count("/"),
            reverse=True,
        )
        for item in sorted_folders:
            logger.info(f"Deleting orphaned folder: {item['path']} (ID: {item['id']})")
            self.ss_client.delete_folder(item["id"])
            deleted += 1

        return deleted

    async def _fetch_fs_data(
        self, sheet_type: str, filters: SyncFilters
    ) -> AsyncIterator[BaseModel]:
        """Fetch data from Finite State API based on sheet type and filters."""
        if sheet_type == "projects":
            async for project in self._fetch_projects(filters):
                yield project

        elif sheet_type == "findings":
            async for finding in self._fetch_findings(filters):
                yield finding

        elif sheet_type == "components":
            async for component in self._fetch_components(filters):
                yield component

        else:
            raise ValueError(f"Unknown sheet type: {sheet_type}")

    async def _fetch_projects(self, filters: SyncFilters) -> AsyncIterator[BaseModel]:
        """Fetch projects, optionally filtered."""
        async for project in self.fs_client.iter_projects():
            # Apply project name filter
            if filters.project_names:
                if project.name not in filters.project_names:
                    continue

            # Apply project ID filter
            if filters.project_ids:
                if project.id not in filters.project_ids:
                    continue

            yield project

    async def _resolve_version_ids(self, filters: SyncFilters) -> list[str]:
        """Resolve project/version filters to a list of project version IDs.

        The sync should only fetch data for the *current* (latest) version of
        each project.  The current version is determined by:

        1. ``--version <id>`` — user-supplied override, used as-is.
        2. ``project.default_branch.latest_version.id`` — the current version
           reported by the Finite State project object.

        Returns:
            List of project-version IDs to fetch findings/components from.
        """
        # Explicit version override — use as-is
        if filters.version_id:
            logger.info(f"Using explicit version ID: {filters.version_id}")
            return [filters.version_id]

        # Collect target project IDs and names
        target_ids = set(filters.project_ids) if filters.project_ids else set()
        target_names = set(filters.project_names) if filters.project_names else set()

        version_ids: list[str] = []

        # If we only have IDs (no names to resolve), fetch each project directly
        if target_ids and not target_names:
            for pid in target_ids:
                project = await self.fs_client.get_project(pid)
                vid = self._get_current_version_id(project)
                if vid:
                    version_ids.append(vid)
                    logger.info(f"Project '{project.name}' ({pid}) → current version {vid}")
                else:
                    logger.warning(
                        f"Project '{project.name}' ({pid}) has no current version — skipping"
                    )
            return version_ids

        # Need to iterate all projects (name resolution or discovery)
        has_filter = bool(target_ids or target_names)
        if not has_filter:
            logger.info("No project filter — discovering all projects for per-version fetch")

        async for project in self.fs_client.iter_projects():
            if has_filter:
                if project.name not in target_names and project.id not in target_ids:
                    continue

            vid = self._get_current_version_id(project)
            if vid:
                version_ids.append(vid)
                logger.info(f"Project '{project.name}' → current version {vid}")
            else:
                logger.warning(f"Project '{project.name}' has no current version — skipping")

        logger.info(f"Resolved {len(version_ids)} current version(s)")
        return version_ids

    @staticmethod
    def _get_current_version_id(project: Any) -> str | None:
        """Extract the current (latest) version ID from a Project object."""
        branch = getattr(project, "default_branch", None)
        if branch is None:
            return None
        latest = getattr(branch, "latest_version", None)
        if latest is None:
            return None
        return latest.id

    async def _fetch_findings(self, filters: SyncFilters) -> AsyncIterator[BaseModel]:
        """Fetch findings with filters.

        Only fetches findings from the *current* version of each project
        (or a user-specified ``--version``).  This avoids pulling in stale
        findings from older versions.
        """
        # Build API filter params
        severity = filters.severities[0] if len(filters.severities) == 1 else None
        status = filters.statuses[0] if len(filters.statuses) == 1 else None
        finding_type = filters.finding_types[0] if len(filters.finding_types) == 1 else None

        version_ids = await self._resolve_version_ids(filters)
        logger.info(f"Will fetch findings from {len(version_ids)} version(s)")

        seen_finding_ids: set[str] = set()
        for version_id in version_ids:
            async for finding in self.fs_client.iter_findings(
                project_version_id=version_id,
                severity=severity,
                status=status,
                finding_type=finding_type,
            ):
                # Deduplicate — a finding can appear in multiple versions
                if finding.id in seen_finding_ids:
                    continue
                seen_finding_ids.add(finding.id)

                # Apply additional client-side filters
                if self._finding_matches_filters(finding, filters):
                    yield finding

    async def _resolve_project_names(self, names: list[str]) -> list[str]:
        """Resolve project names to project IDs."""
        resolved: list[str] = []
        name_set = set(names)

        async for project in self.fs_client.iter_projects():
            if project.name in name_set:
                resolved.append(project.id)
                name_set.remove(project.name)
                if not name_set:  # Found all
                    break

        if name_set:
            logger.warning(f"Could not find projects: {name_set}")

        return resolved

    def _finding_matches_filters(self, finding: Any, filters: SyncFilters) -> bool:
        """Check if a finding matches client-side filters."""
        # Exclude "file" type findings by default (same logic as components)
        if not filters.include_files:
            finding_type = getattr(finding, "type", None)
            if finding_type and str(finding_type).lower() == "file":
                return False

        # Multi-value severity filter
        if len(filters.severities) > 1:
            finding_severity = (finding.severity or "").lower()
            if finding_severity not in filters.severities:
                return False

        # Multi-value status filter
        if len(filters.statuses) > 1:
            finding_status = (finding.status or "").lower()
            if finding_status not in filters.statuses:
                return False

        # Multi-value finding type filter
        if len(filters.finding_types) > 1:
            finding_type_val = (finding.type or "").lower()
            if finding_type_val not in filters.finding_types:
                return False

        # Project name filter (for findings)
        if filters.project_names and finding.project:
            if finding.project.name not in filters.project_names:
                return False

        # Time-based filter
        since = filters.get_since_datetime()
        if since and finding.detected:
            if finding.detected < since:
                return False

        return True

    async def _fetch_components(self, filters: SyncFilters) -> AsyncIterator[BaseModel]:
        """Fetch components with filters.

        Only fetches components from the *current* version of each project
        (or a user-specified ``--version``).  This avoids pulling in stale
        components from older versions.
        """
        version_ids = await self._resolve_version_ids(filters)
        logger.info(f"Will fetch components from {len(version_ids)} version(s)")

        for version_id in version_ids:
            async for component in self.fs_client.iter_components(
                project_version_id=version_id,
            ):
                if self._component_matches_filters(component, filters):
                    yield component

    def _component_matches_filters(self, component: Any, filters: SyncFilters) -> bool:
        """Check if a component matches client-side filters."""
        # Project name filter
        if filters.project_names and component.project:
            if component.project.name not in filters.project_names:
                return False

        # Exclude "file" component types by default
        if not filters.include_files:
            comp_type = getattr(component, "type", None)
            if comp_type and str(comp_type).lower() == "file":
                return False

        return True

    # ==================== Validation ====================

    def _validate_vex_status_update(
        self,
        status: str | None,
        response: str | None,
        justification: str | None,
    ) -> list[str]:
        """
        Validate VEX status update fields.

        Args:
            status: The VEX status
            response: The response field (required for EXPLOITABLE)
            justification: The justification field (required for NOT_AFFECTED)

        Returns:
            List of validation error messages (empty if valid)
        """
        errors: list[str] = []

        if not status:
            # Blank status = clear operation (supported via /status/clear endpoint)
            return errors

        # Validate status value
        if status not in VEX_STATUSES:
            errors.append(
                f"Invalid status value: {status}. Valid values: {', '.join(VEX_STATUSES)}"
            )
            return errors

        # Accept both display names ("Will Not Fix") and API values ("WILL_NOT_FIX")
        valid_responses = set(VEX_RESPONSES) | set(VEX_RESPONSE_TO_API.values())
        valid_justifications = set(VEX_JUSTIFICATIONS) | set(VEX_JUSTIFICATION_TO_API.values())

        # EXPLOITABLE requires Response AND Justification
        if status == "EXPLOITABLE":
            if not response:
                errors.append("EXPLOITABLE status requires Response field")
            elif response not in valid_responses:
                errors.append(
                    f"Invalid response value: {response}. Valid values: {', '.join(VEX_RESPONSES)}"
                )
            if not justification:
                errors.append("EXPLOITABLE status requires Justification field")
            elif justification not in valid_justifications:
                errors.append(
                    f"Invalid justification value: {justification}. "
                    f"Valid values: {', '.join(VEX_JUSTIFICATIONS)}"
                )

        # NOT_AFFECTED requires Justification
        if status == "NOT_AFFECTED":
            if not justification:
                errors.append("NOT_AFFECTED status requires Justification field")
            elif justification not in valid_justifications:
                errors.append(
                    f"Invalid justification value: {justification}. "
                    f"Valid values: {', '.join(VEX_JUSTIFICATIONS)}"
                )

        return errors

    # ==================== Write-back ====================

    async def _bulk_update_findings(
        self,
        updates: list[dict[str, Any]],
        batch_size: int = 5,
    ) -> BulkUpdateResult:
        """
        Process finding updates in batches with concurrency limit.

        Processes updates in batches to avoid overwhelming the API.
        Within each batch, requests run in parallel.

        Args:
            updates: List of update dictionaries
            batch_size: Number of concurrent requests per batch

        Returns:
            BulkUpdateResult with statistics
        """
        result = BulkUpdateResult(total=len(updates))

        if not updates:
            return result

        async def update_one(update: dict[str, Any]) -> tuple[str, bool, str | None]:
            try:
                status_val = update.get("status")

                # Blank status = clear operation
                if not status_val:
                    await self.fs_client.clear_finding_status(
                        project_version_id=update["project_version_id"],
                        finding_id=update["finding_id"],
                    )
                    return (update["finding_id"], True, None)

                # Convert Smartsheet display values to API enum values
                response_val = update.get("response")
                if response_val:
                    response_val = VEX_RESPONSE_TO_API.get(response_val, response_val)

                justification_val = update.get("justification")
                if justification_val:
                    justification_val = VEX_JUSTIFICATION_TO_API.get(
                        justification_val, justification_val
                    )

                # API workaround: all statuses require response + justification
                # even when not semantically meaningful. Auto-fill defaults.
                if not response_val:
                    response_val = DEFAULT_API_RESPONSE
                if not justification_val:
                    justification_val = DEFAULT_API_JUSTIFICATION

                await self.fs_client.update_finding_status(
                    project_version_id=update["project_version_id"],
                    finding_id=update["finding_id"],
                    status=status_val,
                    justification=justification_val,
                    response=response_val,
                    reason=update.get("reason"),
                )
                return (update["finding_id"], True, None)
            except Exception as e:
                # Ensure we always have a useful error message
                error_msg = str(e) or f"{type(e).__name__} (no details)"
                logger.debug(f"Writeback failed for {update['finding_id']}: {error_msg}")
                return (update["finding_id"], False, error_msg)

        # Process in batches to avoid overwhelming the API
        for i in range(0, len(updates), batch_size):
            batch = updates[i : i + batch_size]
            tasks = [update_one(u) for u in batch]
            batch_results = await asyncio.gather(*tasks)

            for finding_id, success, error in batch_results:
                if success:
                    result.successful += 1
                else:
                    result.failed += 1
                    result.errors.append(f"{finding_id}: {error}")

            # Small delay between batches to be kind to the API
            if i + batch_size < len(updates):
                await asyncio.sleep(0.5)

        return result

    async def writeback_with_filters(
        self,
        target_status: str,
        response: str | None = None,
        justification: str | None = None,
        reason: str | None = None,
        filters: SyncFilters | None = None,
        max_rows: int = 1000,
        dry_run: bool = False,
        batch_size: int = 50,
    ) -> WritebackResult:
        """
        Apply status updates to findings matching filters (bypass Smartsheet).

        This is for programmatic mass-updates from CLI, not from Smartsheet changes.

        Args:
            target_status: The VEX status to set
            response: Response value (required for EXPLOITABLE)
            justification: Justification value (required for NOT_AFFECTED)
            reason: Optional reason/comment
            filters: Filters to select findings
            max_rows: Maximum findings to update
            dry_run: If True, show what would be updated
            batch_size: Concurrent API calls

        Returns:
            WritebackResult with statistics
        """
        result = WritebackResult(sheet_name="findings", dry_run=dry_run)
        filters = filters or SyncFilters()

        # Validate the target status update
        errors = self._validate_vex_status_update(target_status, response, justification)
        if errors:
            result.validation_errors.append(("CLI", errors))
            return result

        # Collect findings matching filters
        pending_updates: list[dict[str, Any]] = []
        count = 0

        async for finding in self._fetch_findings(filters):
            if count >= max_rows:
                break
            count += 1

            if not finding.project_version:  # type: ignore[attr-defined]
                continue

            pending_updates.append(
                {
                    "finding_id": finding.id,  # type: ignore[attr-defined]
                    "project_version_id": finding.project_version.id,  # type: ignore[attr-defined]
                    "status": target_status,
                    "response": response,
                    "justification": justification,
                    "reason": reason,
                }
            )

        result.total = len(pending_updates)

        if dry_run:
            result.successful = len(pending_updates)
            return result

        if not pending_updates:
            return result

        # Process updates
        bulk_result = await self._bulk_update_findings(pending_updates, batch_size)
        result.successful = bulk_result.successful
        result.failed = bulk_result.failed
        for error in bulk_result.errors:
            parts = error.split(": ", 1)
            if len(parts) == 2:
                result.api_errors.append((parts[0], parts[1]))
            else:
                result.api_errors.append(("", error))

        return result

    # ==================== Utility Methods ====================

    async def verify_connections(self) -> dict[str, bool]:
        """
        Verify connections to both APIs.

        Returns:
            Dict with 'finite_state' and 'smartsheet' connection status
        """
        results = {"finite_state": False, "smartsheet": False}

        # Test FS connection
        try:
            user = await self.fs_client.get_authenticated_user()
            logger.info(f"Connected to Finite State as {user.user}")
            results["finite_state"] = True
        except Exception as e:
            logger.error(f"Finite State connection failed: {e}")

        # Test Smartsheet connection
        try:
            sheets = self.ss_client.list_sheets()
            logger.info(f"Connected to Smartsheet, found {len(sheets)} sheets")
            results["smartsheet"] = True
        except Exception as e:
            logger.error(f"Smartsheet connection failed: {e}")

        return results

    def get_sync_status(self) -> dict[str, Any]:
        """Get current sync status for all sheets."""
        last_mod = self.state.last_modified
        status: dict[str, Any] = {
            "state_file": str(self.state_path),
            "last_modified": last_mod.isoformat() if last_mod else None,
            "sheets": {},
        }

        for name, sheet_state in self.state.sheets.items():
            full_sync = sheet_state.last_full_sync
            incr_sync = sheet_state.last_incremental_sync
            status["sheets"][name] = {
                "sheet_id": sheet_state.ss_sheet_id,
                "last_full_sync": full_sync.isoformat() if full_sync else None,
                "last_incremental_sync": incr_sync.isoformat() if incr_sync else None,
                "row_count": len(sheet_state.rows),
            }

        return status
