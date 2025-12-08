"""Data models for component injection script."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ComponentRecord:
    """Represents a component from the components CSV."""
    component_name: str
    component_version: str
    supplier_name: str
    swid_tag_id: str

    def __hash__(self) -> int:
        """Make hashable for deduplication."""
        return hash((self.component_name, self.component_version, 
                     self.supplier_name, self.swid_tag_id))

    def __eq__(self, other) -> bool:
        """Equality comparison for deduplication."""
        if not isinstance(other, ComponentRecord):
            return False
        return (self.component_name == other.component_name and
                self.component_version == other.component_version and
                self.supplier_name == other.supplier_name and
                self.swid_tag_id == other.swid_tag_id)


@dataclass
class TargetVersion:
    """Represents a target from the targets CSV (may have IDs or names)."""
    project_id: Optional[int] = None
    project_version_id: Optional[int] = None
    project_name: Optional[str] = None
    project_version_name: Optional[str] = None

    def has_ids(self) -> bool:
        """Check if this target has both IDs."""
        return self.project_id is not None and self.project_version_id is not None

    def has_names(self) -> bool:
        """Check if this target has both names."""
        return (self.project_name is not None and 
                self.project_name.strip() != "" and
                self.project_version_name is not None and 
                self.project_version_name.strip() != "")

    def is_valid(self) -> bool:
        """Check if target is valid (has either IDs or names)."""
        return self.has_ids() or self.has_names()


@dataclass
class ResolvedTarget:
    """Final target with resolved names for CLI upload."""
    project_name: str
    project_version_name: str

    def __hash__(self) -> int:
        """Make hashable for deduplication."""
        return hash((self.project_name, self.project_version_name))

    def __eq__(self, other) -> bool:
        """Equality comparison for deduplication."""
        if not isinstance(other, ResolvedTarget):
            return False
        return (self.project_name == other.project_name and
                self.project_version_name == other.project_version_name)


@dataclass
class ScriptConfig:
    """Configuration from CLI arguments."""
    components_csv: str
    targets_csv: str
    fs_cli_jar: str
    java_path: str
    component_type: str
    output_dir: str
    dry_run: bool
    log_level: str
    log_file: Optional[str] = None

