"""Sync state tracking for change detection."""

import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from .._compat import secure_file

logger = logging.getLogger(__name__)


class RowState(BaseModel):
    """State of a single synced row."""

    primary_key: str
    ss_row_id: int | None = None
    project_version_id: str | None = None  # For writeback API calls
    last_sync: datetime
    data_hash: str = ""
    writeback_fields: dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}


class SheetState(BaseModel):
    """State of a synced sheet."""

    sheet_name: str
    ss_sheet_id: int | None = None
    last_full_sync: datetime | None = None
    last_incremental_sync: datetime | None = None
    rows: dict[str, RowState] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}


class SyncState(BaseModel):
    """Overall sync state across all sheets."""

    version: str = "1.0"
    created: datetime = Field(default_factory=datetime.utcnow)
    last_modified: datetime = Field(default_factory=datetime.utcnow)
    sheets: dict[str, SheetState] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}

    @classmethod
    def load(cls, path: Path) -> "SyncState":
        """
        Load sync state from a file with corruption detection and recovery.

        Args:
            path: Path to state file

        Returns:
            Loaded state or new empty state if file doesn't exist or is corrupted
        """
        if not path.exists():
            return cls()

        try:
            with open(path) as f:
                data = json.load(f)
            return cls.model_validate(data)
        except (json.JSONDecodeError, ValidationError) as e:
            logger.error(f"State file corrupted: {e}")

            # Try backup recovery
            backup_path = path.with_suffix(".json.backup")
            if backup_path.exists():
                logger.info("Attempting recovery from backup...")
                try:
                    with open(backup_path) as f:
                        data = json.load(f)
                    state = cls.model_validate(data)
                    logger.info("Recovery from backup successful")
                    return state
                except (json.JSONDecodeError, ValidationError) as backup_err:
                    logger.error(f"Backup also corrupted: {backup_err}")

            logger.warning("Starting with fresh state")
            return cls()

    def save(self, path: Path) -> None:
        """
        Save sync state to a file with atomic write and backup.

        Args:
            path: Path to state file
        """
        self.last_modified = datetime.utcnow()
        path.parent.mkdir(parents=True, exist_ok=True)

        # Backup existing state before overwriting
        if path.exists():
            backup_path = path.with_suffix(".json.backup")
            try:
                shutil.copy2(path, backup_path)
            except OSError as e:
                logger.warning(f"Failed to create backup: {e}")

        # Write to temp file first (atomic write)
        temp_path = path.with_suffix(".json.tmp")
        try:
            with open(temp_path, "w") as f:
                json.dump(self.model_dump(mode="json"), f, indent=2, default=str)
            # Atomic rename (Path.replace works on all platforms;
            # Path.rename raises FileExistsError on Windows)
            temp_path.replace(path)
            secure_file(path)
        except OSError:
            # Fallback to direct write
            with open(path, "w") as f:
                json.dump(self.model_dump(mode="json"), f, indent=2, default=str)
            secure_file(path)

    def get_sheet_state(self, sheet_name: str) -> SheetState:
        """
        Get or create state for a sheet.

        Args:
            sheet_name: Name of the sheet

        Returns:
            SheetState for the sheet
        """
        if sheet_name not in self.sheets:
            self.sheets[sheet_name] = SheetState(sheet_name=sheet_name)
        return self.sheets[sheet_name]

    def set_sheet_id(self, sheet_name: str, sheet_id: int) -> None:
        """Set the Smartsheet ID for a sheet."""
        state = self.get_sheet_state(sheet_name)
        state.ss_sheet_id = sheet_id

    def get_row_state(self, sheet_name: str, primary_key: str) -> RowState | None:
        """
        Get state for a specific row.

        Args:
            sheet_name: Name of the sheet
            primary_key: Primary key value

        Returns:
            RowState or None if not found
        """
        sheet_state = self.sheets.get(sheet_name)
        if not sheet_state:
            return None
        return sheet_state.rows.get(primary_key)

    def update_row_state(
        self,
        sheet_name: str,
        primary_key: str,
        ss_row_id: int | None = None,
        project_version_id: str | None = None,
        data_hash: str = "",
        writeback_fields: dict[str, Any] | None = None,
    ) -> RowState:
        """
        Update or create state for a row.

        Args:
            sheet_name: Name of the sheet
            primary_key: Primary key value
            ss_row_id: Smartsheet row ID
            project_version_id: Finite State project version ID (for writeback)
            data_hash: Hash of row data for change detection
            writeback_fields: Current values of writeback fields

        Returns:
            Updated RowState
        """
        sheet_state = self.get_sheet_state(sheet_name)

        if primary_key in sheet_state.rows:
            row_state = sheet_state.rows[primary_key]
            row_state.last_sync = datetime.utcnow()
            if ss_row_id is not None:
                row_state.ss_row_id = ss_row_id
            if project_version_id is not None:
                row_state.project_version_id = project_version_id
            if data_hash:
                row_state.data_hash = data_hash
            if writeback_fields is not None:
                row_state.writeback_fields = writeback_fields
        else:
            row_state = RowState(
                primary_key=primary_key,
                ss_row_id=ss_row_id,
                project_version_id=project_version_id,
                last_sync=datetime.utcnow(),
                data_hash=data_hash,
                writeback_fields=writeback_fields or {},
            )
            sheet_state.rows[primary_key] = row_state

        return row_state

    def remove_row(self, sheet_name: str, primary_key: str) -> None:
        """Remove a row from state."""
        sheet_state = self.sheets.get(sheet_name)
        if sheet_state and primary_key in sheet_state.rows:
            del sheet_state.rows[primary_key]

    def mark_full_sync(self, sheet_name: str) -> None:
        """Mark that a full sync was completed for a sheet."""
        state = self.get_sheet_state(sheet_name)
        state.last_full_sync = datetime.utcnow()

    def mark_incremental_sync(self, sheet_name: str) -> None:
        """Mark that an incremental sync was completed for a sheet."""
        state = self.get_sheet_state(sheet_name)
        state.last_incremental_sync = datetime.utcnow()

    def get_known_row_ids(self, sheet_name: str) -> dict[str, int]:
        """
        Get mapping of primary keys to Smartsheet row IDs.

        Args:
            sheet_name: Name of the sheet

        Returns:
            Dict mapping primary key -> row ID
        """
        sheet_state = self.sheets.get(sheet_name)
        if not sheet_state:
            return {}

        return {
            pk: row.ss_row_id for pk, row in sheet_state.rows.items() if row.ss_row_id is not None
        }

    def detect_writeback_changes(
        self,
        sheet_name: str,
        primary_key: str,
        current_values: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Detect changes in writeback fields.

        Args:
            sheet_name: Name of the sheet
            primary_key: Primary key value
            current_values: Current values from Smartsheet

        Returns:
            Dict of changed fields with their new values
        """
        row_state = self.get_row_state(sheet_name, primary_key)
        if not row_state:
            return {}

        changes: dict[str, Any] = {}
        for field, current_value in current_values.items():
            previous_value = row_state.writeback_fields.get(field)
            if current_value != previous_value:
                changes[field] = current_value

        return changes


def compute_data_hash(data: dict[str, Any]) -> str:
    """
    Compute a hash of row data for change detection.

    Args:
        data: Row data dictionary

    Returns:
        Hash string
    """
    import hashlib

    # Sort keys for consistent hashing
    sorted_items = sorted(
        (k, str(v) if v is not None else "") for k, v in data.items() if not k.startswith("_")
    )
    content = json.dumps(sorted_items, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()[:16]
