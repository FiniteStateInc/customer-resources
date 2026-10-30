"""SBOM export: CycloneDX/SPDX documents built from platform data."""

from fs_report.sbom_export.options import SbomOptions, SbomOptionsError
from fs_report.sbom_export.resolve import (
    AmbiguousProjectError,
    resolve_unique_project,
    resolve_version_id,
)

__all__ = [
    "AmbiguousProjectError",
    "SbomOptions",
    "SbomOptionsError",
    "resolve_unique_project",
    "resolve_version_id",
]
