"""Smartsheet client wrapper."""

import logging
import time
import warnings
from datetime import datetime
from typing import Any

import smartsheet
from smartsheet.exceptions import ApiError
from smartsheet.models import Cell, Column, Folder, Row, Sheet, Workspace

from .schemas import ColumnSchema, ColumnType, SheetSchema

# Suppress DeprecationWarnings from the Smartsheet SDK only (not all libraries)
warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"smartsheet\b")

logger = logging.getLogger(__name__)


class SmartsheetError(Exception):
    """Base exception for Smartsheet errors."""

    pass


def _is_not_found(exc: ApiError) -> bool:
    """Return True if *exc* is a Smartsheet 1006 Not Found error.

    The Smartsheet SDK exposes error details on either ``exc.error``
    or ``exc.result`` depending on the SDK version and API call.
    Check both to be robust.
    """
    for attr in ("error", "result"):
        obj = getattr(exc, attr, None)
        if obj is not None:
            code = getattr(obj, "code", None) or getattr(obj, "error_code", None)
            if code == 1006:
                return True
    return False


class SmartsheetClient:
    """Wrapper around the Smartsheet SDK with schema-aware operations."""

    def __init__(
        self,
        access_token: str,
        workspace_id: int | None = None,
        workspace_name: str | None = None,
    ):
        """
        Initialize the Smartsheet client.

        Args:
            access_token: Smartsheet API access token
            workspace_id: Optional workspace ID for sheet operations
            workspace_name: Optional workspace name (will create if not exists)
        """
        self.client = smartsheet.Smartsheet(access_token)
        self.client.errors_as_exceptions(True)
        # Suppress noisy SDK "ImportError! Could not load api or model class" messages
        logging.getLogger("smartsheet").setLevel(logging.WARNING)
        self._workspace_id = workspace_id
        self._workspace_name = workspace_name
        self._sheet_cache: dict[str, Sheet] = {}
        self._column_map_cache: dict[int, dict[str, int]] = {}
        self._folder_cache: dict[str, Folder] = {}

    def _get_column_map(self, sheet: Sheet) -> dict[str, int]:
        """Get a mapping of column titles to column IDs."""
        sheet_id = sheet.id
        if sheet_id not in self._column_map_cache:
            self._column_map_cache[sheet_id] = {col.title: col.id for col in sheet.columns}
        return self._column_map_cache[sheet_id]

    def _clear_cache(self, sheet_id: int | None = None) -> None:
        """Clear cached data."""
        if sheet_id:
            self._sheet_cache.pop(str(sheet_id), None)
            self._column_map_cache.pop(sheet_id, None)
        else:
            self._sheet_cache.clear()
            self._column_map_cache.clear()
            self._folder_cache.clear()

    # ==================== Workspace Operations ====================

    def get_or_create_workspace(self, name: str) -> Workspace:
        """
        Get existing workspace by name or create it.

        Includes two guards against Smartsheet API eventual consistency:
        1. Pre-creation retry: if the first list misses a recently created
           workspace, waits 2 s and re-checks before creating a new one.
        2. Post-creation dedup: after creating, waits 2 s, re-lists, and
           deletes any duplicates (keeps the oldest by ID).

        Args:
            name: Workspace name

        Returns:
            Workspace object
        """
        # Check existing workspaces
        response = self.client.Workspaces.list_workspaces()
        for ws in response.data or []:
            if ws.name == name:
                logger.info(f"Found existing workspace: {name} (ID: {ws.id})")
                return ws

        # Retry after brief delay — another CLI invocation may have just
        # created this workspace and it hasn't propagated yet.
        logger.debug(
            f"Workspace {name!r} not found; retrying after 2 s (eventual-consistency guard)"
        )
        time.sleep(2)
        response = self.client.Workspaces.list_workspaces()
        for ws in response.data or []:
            if ws.name == name:
                logger.info(f"Found workspace on retry: {name} (ID: {ws.id})")
                return ws

        # Still not found — create new workspace
        logger.info(f"Creating workspace: {name}")
        new_workspace = smartsheet.models.Workspace({"name": name})
        response = self.client.Workspaces.create_workspace(new_workspace)
        created = response.result

        # Post-creation dedup: another process may have created the same
        # name concurrently.  Wait for propagation before checking.
        time.sleep(2)
        all_ws = self.client.Workspaces.list_workspaces()
        matches = [ws for ws in (all_ws.data or []) if ws.name == name]
        if len(matches) > 1:
            # Keep the oldest (lowest ID), delete the rest
            matches.sort(key=lambda w: w.id)
            keeper = matches[0]
            for dup in matches[1:]:
                logger.warning(
                    f"Deleting duplicate workspace: {dup.name} "
                    f"(ID: {dup.id}), keeping ID: {keeper.id}"
                )
                self.client.Workspaces.delete_workspace(dup.id)
            return keeper

        return created

    def get_workspace(self, workspace_id: int) -> Workspace:
        """Get a workspace by ID with metadata."""
        return self.client.Workspaces.get_workspace_metadata(workspace_id)

    @property
    def workspace_id(self) -> int | None:
        """Get the current workspace ID, creating workspace if needed."""
        if self._workspace_id:
            return self._workspace_id
        if self._workspace_name:
            ws = self.get_or_create_workspace(self._workspace_name)
            self._workspace_id = ws.id
            return self._workspace_id
        return None

    # ==================== Folder Operations ====================

    def get_or_create_folder(self, workspace_id: int, name: str) -> Folder:
        """
        Get or create a folder within a workspace.

        Handles stale workspace IDs: if the workspace has been deleted,
        clears the cached ID, re-resolves the workspace, and retries.

        Args:
            workspace_id: The workspace ID
            name: Folder name

        Returns:
            Folder object
        """
        cache_key = f"{workspace_id}/{name}"
        if cache_key in self._folder_cache:
            return self._folder_cache[cache_key]

        try:
            return self._get_or_create_folder_inner(workspace_id, name, cache_key)
        except ApiError as exc:
            if not _is_not_found(exc):
                raise
            # Stale workspace ID – re-resolve and retry once
            logger.warning(f"Workspace {workspace_id} not found (stale ID). Re-resolving...")
            self._workspace_id = None
            self._folder_cache.clear()
            new_ws_id = self.workspace_id
            if new_ws_id is None:
                raise SmartsheetError(
                    "Cannot re-resolve workspace: no workspace_name configured"
                ) from exc
            new_cache_key = f"{new_ws_id}/{name}"
            return self._get_or_create_folder_inner(new_ws_id, name, new_cache_key)

    def _get_or_create_folder_inner(self, workspace_id: int, name: str, cache_key: str) -> Folder:
        """Inner helper for get_or_create_folder (no retry logic)."""
        # Get workspace folders via non-deprecated children API
        children = self.client.Workspaces.get_workspace_children(
            workspace_id, children_resource_types=["folders"]
        )
        for folder in children.data or []:
            if folder.name == name:
                logger.info(f"Found existing folder: {name} (ID: {folder.id})")
                self._folder_cache[cache_key] = folder
                return folder

        # Create new folder
        logger.info(f"Creating folder: {name} in workspace {workspace_id}")
        new_folder = smartsheet.models.Folder({"name": name})
        response = self.client.Workspaces.create_folder_in_workspace(workspace_id, new_folder)
        self._folder_cache[cache_key] = response.result
        return response.result

    def get_or_create_subfolder(self, parent_folder_id: int, name: str) -> Folder:
        """
        Get or create a folder within another folder.

        Args:
            parent_folder_id: The parent folder ID
            name: Subfolder name

        Returns:
            Folder object
        """
        cache_key = f"folder:{parent_folder_id}/{name}"
        if cache_key in self._folder_cache:
            return self._folder_cache[cache_key]

        # List child folders of the parent (non-deprecated API)
        try:
            children = self.client.Folders.get_folder_children(
                parent_folder_id, children_resource_types=["folders"]
            )
            for folder in children.data or []:
                if folder.name == name:
                    logger.info(f"Found existing subfolder: {name} (ID: {folder.id})")
                    self._folder_cache[cache_key] = folder
                    return folder
        except ApiError as exc:
            if _is_not_found(exc):
                raise SmartsheetError(f"Parent folder {parent_folder_id} not found.") from exc
            raise

        # Create new subfolder
        logger.info(f"Creating subfolder: {name} in folder {parent_folder_id}")
        new_folder = smartsheet.models.Folder({"name": name})
        response = self.client.Folders.create_folder_in_folder(parent_folder_id, new_folder)
        self._folder_cache[cache_key] = response.result
        return response.result

    def get_folder(self, folder_id: int) -> Folder:
        """Get a folder by ID with metadata."""
        return self.client.Folders.get_folder_metadata(folder_id)

    def delete_folder(self, folder_id: int) -> None:
        """Delete a folder and all its contents."""
        self.client.Folders.delete_folder(folder_id)
        # Invalidate any cached entries referencing this folder
        stale_keys = [k for k in self._folder_cache if str(folder_id) in k]
        for k in stale_keys:
            del self._folder_cache[k]

    def walk_workspace(self, workspace_id: int) -> list[dict[str, Any]]:
        """
        Recursively walk a workspace to list all folders and sheets.

        Returns a flat list of entries, each with:
            - ``type``: "folder" or "sheet"
            - ``id``: Smartsheet object ID
            - ``name``: Object name
            - ``path``: Full path from workspace root (e.g. "FolderA/FolderB/SheetName")
            - ``parent_folder_id``: Parent folder ID (None for workspace-root items)
        """
        entries: list[dict[str, Any]] = []

        # Get top-level children (both folders and sheets)
        children = self.client.Workspaces.get_workspace_children(
            workspace_id, children_resource_types=["folders", "sheets"]
        )
        for item in children.data or []:
            # Distinguish Folder vs Sheet by checking the model type
            if isinstance(item, Folder):
                entries.append(
                    {
                        "type": "folder",
                        "id": item.id,
                        "name": item.name,
                        "path": item.name,
                        "parent_folder_id": None,
                    }
                )
                # Recurse into this folder
                self._walk_folder(item.id, item.name, entries)
            else:
                entries.append(
                    {
                        "type": "sheet",
                        "id": item.id,
                        "name": item.name,
                        "path": item.name,
                        "parent_folder_id": None,
                    }
                )

        return entries

    def _walk_folder(
        self,
        folder_id: int,
        parent_path: str,
        entries: list[dict[str, Any]],
    ) -> None:
        """Recursively walk a folder, appending children to *entries*."""
        children = self.client.Folders.get_folder_children(
            folder_id, children_resource_types=["folders", "sheets"]
        )
        for item in children.data or []:
            item_path = f"{parent_path}/{item.name}"
            if isinstance(item, Folder):
                entries.append(
                    {
                        "type": "folder",
                        "id": item.id,
                        "name": item.name,
                        "path": item_path,
                        "parent_folder_id": folder_id,
                    }
                )
                self._walk_folder(item.id, item_path, entries)
            else:
                entries.append(
                    {
                        "type": "sheet",
                        "id": item.id,
                        "name": item.name,
                        "path": item_path,
                        "parent_folder_id": folder_id,
                    }
                )

    # ==================== Sheet Operations ====================

    def list_sheets(self) -> list[Sheet]:
        """List all sheets accessible to the user."""
        response = self.client.Sheets.list_sheets(include_all=True)
        return list(response.data)

    def get_sheet(self, sheet_id: int, use_cache: bool = True) -> Sheet:
        """
        Get a sheet by ID.

        Args:
            sheet_id: The sheet ID
            use_cache: Whether to use cached data
        """
        cache_key = str(sheet_id)
        if use_cache and cache_key in self._sheet_cache:
            return self._sheet_cache[cache_key]

        sheet = self.client.Sheets.get_sheet(sheet_id)
        self._sheet_cache[cache_key] = sheet
        return sheet

    def get_sheet_by_name(self, name: str, folder_id: int | None = None) -> Sheet | None:
        """
        Find a sheet by name.

        Search order:
        1. If *folder_id* is given, search that folder first.
        2. If a workspace is configured, search the entire workspace
           (root + subfolders) — **never** falls through to a global search,
           which would risk finding identically-named sheets in other
           workspaces.
        3. Otherwise fall back to a global ``list_sheets`` search.

        Args:
            name: Sheet name to find
            folder_id: Optional folder ID to search within

        Returns:
            Sheet if found, None otherwise
        """
        if folder_id:
            # Search within specific folder using non-deprecated children API
            try:
                children = self.client.Folders.get_folder_children(
                    folder_id, children_resource_types=["sheets"]
                )
                for sheet in children.data or []:
                    if sheet.name == name:
                        return self.get_sheet(sheet.id)
            except Exception:
                # Folder may not exist (deleted or not created yet)
                logger.debug(f"Folder {folder_id} not found, falling back to broader search")

        # Workspace-scoped search (avoids cross-workspace name collisions).
        # Use the property (not _workspace_id) so the workspace is resolved
        # even when no earlier call has triggered resolution yet.
        ws_id = self.workspace_id
        if ws_id:
            for entry in self.walk_workspace(ws_id):
                if entry["type"] == "sheet" and entry["name"] == name:
                    return self.get_sheet(entry["id"])
            return None

        # No workspace configured — global search (fallback)
        sheets = self.list_sheets()
        for sheet in sheets:
            if sheet.name == name:
                return self.get_sheet(sheet.id)
        return None

    def _build_sheet_spec(self, schema: SheetSchema) -> smartsheet.models.Sheet:
        """Build a Smartsheet Sheet spec from a schema."""
        return smartsheet.models.Sheet(
            {
                "name": schema.name,
                "columns": [self._column_schema_to_spec(col) for col in schema.columns],
            }
        )

    def create_sheet(self, schema: SheetSchema, folder_id: int | None = None) -> Sheet:
        """
        Create a new sheet from a schema definition.

        Handles stale IDs: if a folder or workspace has been deleted by
        Smartsheet (e.g. auto-deleted empty folder), catches the 1006 Not
        Found and either re-resolves the workspace or raises a clear error
        so the caller can re-obtain the folder.

        Args:
            schema: Sheet schema defining structure
            folder_id: Optional folder ID to create sheet in

        Returns:
            Created Sheet object
        """
        sheet_spec = self._build_sheet_spec(schema)
        logger.info(f"Creating sheet: {schema.name}")

        if folder_id:
            # Create in specific folder
            try:
                response = self.client.Folders.create_sheet_in_folder(folder_id, sheet_spec)
            except ApiError as exc:
                if _is_not_found(exc):
                    raise SmartsheetError(
                        f"Folder {folder_id} not found (may have been auto-deleted). "
                        f"Re-obtain the folder and retry."
                    ) from exc
                raise
        elif self.workspace_id:
            # Create directly in workspace (not in a folder)
            try:
                response = self.client.Workspaces.create_sheet_in_workspace(
                    self.workspace_id, sheet_spec
                )
            except ApiError as exc:
                if not _is_not_found(exc):
                    raise
                # Stale workspace – re-resolve and retry once
                logger.warning("Workspace not found (stale ID). Re-resolving...")
                self._workspace_id = None
                new_ws_id = self.workspace_id
                if new_ws_id is None:
                    raise SmartsheetError(
                        "Cannot re-resolve workspace: no workspace_name configured"
                    ) from exc
                response = self.client.Workspaces.create_sheet_in_workspace(new_ws_id, sheet_spec)
        else:
            # Create at Home level (deprecated but still works)
            response = self.client.Home.create_sheet(sheet_spec)

        return response.result

    def _column_schema_to_spec(self, col_schema: ColumnSchema) -> Column:
        """Convert a ColumnSchema to a Smartsheet Column spec."""
        col_dict: dict[str, Any] = {
            "title": col_schema.title,
            "type": col_schema.type.value,
            "primary": col_schema.primary,
            "width": col_schema.width,
        }

        if col_schema.options and col_schema.type == ColumnType.PICKLIST:
            # Filter out empty strings - Smartsheet doesn't accept them
            valid_options = [opt for opt in col_schema.options if opt]
            if valid_options:
                col_dict["options"] = valid_options

        return Column(col_dict)

    def get_or_create_sheet(self, schema: SheetSchema, folder_id: int | None = None) -> Sheet:
        """
        Get an existing sheet or create it if it doesn't exist.

        Args:
            schema: Sheet schema defining structure
            folder_id: Optional folder ID to search/create in

        Returns:
            Sheet object (existing or newly created)
        """
        existing = self.get_sheet_by_name(schema.name, folder_id=folder_id)
        if existing:
            logger.info(f"Found existing sheet: {schema.name} (ID: {existing.id})")
            return existing

        # Create and return directly - don't re-fetch by name
        # This avoids race conditions from API propagation delays
        created = self.create_sheet(schema, folder_id=folder_id)
        logger.info(f"Created sheet: {schema.name} (ID: {created.id})")
        return created

    def delete_sheet(self, sheet_id: int) -> None:
        """Delete a sheet."""
        self.client.Sheets.delete_sheet(sheet_id)
        self._clear_cache(sheet_id)

    # ==================== Row Operations ====================

    def get_rows(self, sheet_id: int) -> list[Row]:
        """Get all rows from a sheet."""
        sheet = self.get_sheet(sheet_id, use_cache=False)
        return list(sheet.rows) if sheet.rows else []

    def get_row_data(self, sheet: Sheet, row: Row) -> dict[str, Any]:
        """
        Convert a row to a dictionary mapping column titles to values.

        Args:
            sheet: The sheet containing the row
            row: The row to convert
        """
        column_map = self._get_column_map(sheet)
        id_to_title = {v: k for k, v in column_map.items()}

        data: dict[str, Any] = {"_row_id": row.id}
        for cell in row.cells:
            title = id_to_title.get(cell.column_id)
            if title:
                data[title] = cell.value
        return data

    def add_rows(
        self,
        sheet_id: int,
        rows_data: list[dict[str, Any]],
        schema: SheetSchema | None = None,
        batch_size: int = 500,
    ) -> list[Row]:
        """
        Add multiple rows to a sheet.

        Args:
            sheet_id: The sheet ID
            rows_data: List of dictionaries mapping column titles to values
            schema: Optional schema for type conversion
            batch_size: Max rows per API call (Smartsheet limit is 500)
        """
        sheet = self.get_sheet(sheet_id)
        column_map = self._get_column_map(sheet)

        # Identify primary key column so we can set strict=True on it.
        # Smartsheet TEXT_NUMBER columns silently coerce numeric strings
        # to floats, which causes precision loss for large IDs (>15 digits)
        # and breaks row-index lookups on subsequent syncs.
        primary_col_title = None
        if schema:
            primary_col = schema.get_primary_column()
            if primary_col:
                primary_col_title = primary_col.title

        rows_to_add = []
        for row_data in rows_data:
            cells = []
            for title, value in row_data.items():
                if title.startswith("_"):  # Skip internal fields
                    continue
                col_id = column_map.get(title)
                if col_id is None:
                    continue

                # Get column schema for type hints
                col_schema = schema.get_column_by_title(title) if schema else None
                cell_value = self._convert_value_for_smartsheet(value, col_schema)

                # Skip cells with None values - Smartsheet requires cell.value to be present
                if cell_value is None:
                    continue

                cell_dict: dict[str, Any] = {
                    "column_id": col_id,
                    "value": cell_value,
                }
                # Prevent Smartsheet from coercing the primary key to a
                # number.  strict=True tells the API to store the value
                # exactly as provided (string stays a string).
                if title == primary_col_title and isinstance(cell_value, str):
                    cell_dict["strict"] = True

                cells.append(Cell(cell_dict))

            if cells:
                rows_to_add.append(
                    Row(
                        {
                            "to_bottom": True,
                            "cells": cells,
                        }
                    )
                )

        if not rows_to_add:
            return []

        # Batch rows to respect Smartsheet API limits
        all_added: list[Row] = []
        for i in range(0, len(rows_to_add), batch_size):
            batch = rows_to_add[i : i + batch_size]
            response = self.client.Sheets.add_rows(sheet_id, batch)
            all_added.extend(response.result)

        self._clear_cache(sheet_id)
        return all_added

    def update_rows(
        self,
        sheet_id: int,
        updates: list[dict[str, Any]],
        schema: SheetSchema | None = None,
        batch_size: int = 500,
    ) -> list[Row]:
        """
        Update multiple rows in a sheet.

        Args:
            sheet_id: The sheet ID
            updates: List of dicts with '_row_id' and column values to update
            schema: Optional schema for type conversion
            batch_size: Max rows per API call (Smartsheet limit is 500)
        """
        sheet = self.get_sheet(sheet_id)
        column_map = self._get_column_map(sheet)

        # Identify primary key column for strict mode (same rationale as add_rows).
        primary_col_title = None
        if schema:
            primary_col = schema.get_primary_column()
            if primary_col:
                primary_col_title = primary_col.title

        rows_to_update = []
        for update in updates:
            row_id = update.get("_row_id")
            if not row_id:
                continue

            cells = []
            for title, value in update.items():
                if title.startswith("_"):
                    continue
                col_id = column_map.get(title)
                if col_id is None:
                    continue

                col_schema = schema.get_column_by_title(title) if schema else None
                cell_value = self._convert_value_for_smartsheet(value, col_schema)

                # For updates, send "" to clear cells (unlike add_rows which skips None)
                if cell_value is None:
                    cell_value = ""

                cell_dict: dict[str, Any] = {
                    "column_id": col_id,
                    "value": cell_value,
                }
                if title == primary_col_title and isinstance(cell_value, str):
                    cell_dict["strict"] = True

                cells.append(Cell(cell_dict))

            if cells:
                rows_to_update.append(
                    Row(
                        {
                            "id": row_id,
                            "cells": cells,
                        }
                    )
                )

        if not rows_to_update:
            return []

        # Batch updates to respect Smartsheet API limits
        all_updated: list[Row] = []
        for i in range(0, len(rows_to_update), batch_size):
            batch = rows_to_update[i : i + batch_size]
            response = self.client.Sheets.update_rows(sheet_id, batch)
            all_updated.extend(response.result)

        self._clear_cache(sheet_id)
        return all_updated

    def delete_rows(self, sheet_id: int, row_ids: list[int]) -> None:
        """Delete multiple rows from a sheet."""
        if not row_ids:
            return
        self.client.Sheets.delete_rows(sheet_id, row_ids)
        self._clear_cache(sheet_id)

    def _convert_value_for_smartsheet(self, value: Any, col_schema: ColumnSchema | None) -> Any:
        """Convert a Python value to a Smartsheet-compatible value."""
        if value is None:
            return None

        if col_schema:
            if col_schema.type == ColumnType.CHECKBOX:
                return bool(value)
            if col_schema.type == ColumnType.DATE:
                if isinstance(value, datetime):
                    return value.isoformat()
                if isinstance(value, str):
                    return value
            if col_schema.type == ColumnType.PICKLIST:
                return str(value) if value else ""

        # Default conversions
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value
        if isinstance(value, list):
            return ", ".join(str(v) for v in value)

        return str(value) if value is not None else None

    # ==================== Sync Helpers ====================

    @staticmethod
    def _normalize_cell_key(value: Any) -> str | None:
        """Normalize a Smartsheet cell value to a stable string key.

        Smartsheet TEXT_NUMBER columns silently convert numeric-looking
        strings (e.g. ``"12345"``) to floats (``12345.0``).  A naïve
        ``str()`` then produces ``"12345.0"`` which doesn't match the
        original ``"12345"`` from the API.  This helper strips the
        spurious ``.0`` so row-index lookups work correctly.
        """
        if value is None:
            return None
        if isinstance(value, float) and value == int(value):
            return str(int(value))
        return str(value)

    def find_row_by_primary_key(
        self,
        sheet: Sheet,
        schema: SheetSchema,
        key_value: str,
    ) -> Row | None:
        """
        Find a row by its primary key value.

        Args:
            sheet: The sheet to search
            schema: Sheet schema with primary column defined
            key_value: The primary key value to find
        """
        primary_col = schema.get_primary_column()
        if not primary_col:
            return None

        column_map = self._get_column_map(sheet)
        primary_col_id = column_map.get(primary_col.title)
        if not primary_col_id:
            return None

        norm_target = self._normalize_cell_key(key_value)
        for row in sheet.rows or []:
            for cell in row.cells:
                if (
                    cell.column_id == primary_col_id
                    and self._normalize_cell_key(cell.value) == norm_target
                ):
                    return row

        return None

    def build_row_index(
        self,
        sheet: Sheet,
        schema: SheetSchema,
    ) -> dict[str, Row]:
        """
        Build an index of rows by their primary key.

        Args:
            sheet: The sheet to index
            schema: Sheet schema with primary column defined

        Returns:
            Dictionary mapping primary key values to rows
        """
        primary_col = schema.get_primary_column()
        if not primary_col:
            return {}

        column_map = self._get_column_map(sheet)
        primary_col_id = column_map.get(primary_col.title)
        if not primary_col_id:
            return {}

        index: dict[str, Row] = {}
        for row in sheet.rows or []:
            for cell in row.cells:
                if cell.column_id == primary_col_id and cell.value:
                    key = self._normalize_cell_key(cell.value)
                    if key:
                        index[key] = row
                    break

        return index

    def get_changed_rows(
        self,
        sheet: Sheet,
        schema: SheetSchema,
        since: datetime | None = None,
    ) -> list[tuple[Row, dict[str, Any]]]:
        """
        Get rows that have changed, with their data.

        Note: Smartsheet doesn't track cell-level changes easily,
        so this returns all rows and relies on the sync engine
        to compare with previous state.

        Args:
            sheet: The sheet to check
            schema: Sheet schema
            since: Optional timestamp (not used currently)

        Returns:
            List of (row, data_dict) tuples
        """
        changed = []
        for row in sheet.rows or []:
            data = self.get_row_data(sheet, row)
            changed.append((row, data))
        return changed
