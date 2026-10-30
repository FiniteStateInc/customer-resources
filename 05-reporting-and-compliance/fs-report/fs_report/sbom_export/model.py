"""Neutral SBOM document model shared by the builder and the format writers.

Keys: ProjectNode.key = version_id; Component.key = f"{version_id}:{component_id}".
Writers derive bom-refs / SPDXIDs from keys so they are unique per project instance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# How the version was scanned; None = unknown, so no lifecycle is claimed.
Lifecycle = Literal["pre-build", "build", "post-build"] | None


@dataclass
class Rating:
    source: str
    score: float | None = None
    severity: str | None = None
    method: str | None = None
    vector: str | None = None


@dataclass
class Vuln:
    id: str
    source_name: str
    source_url: str | None = None
    affects: list[str] = field(default_factory=list)  # component keys
    ratings: list[Rating] = field(default_factory=list)
    cwes: list[int] = field(default_factory=list)
    description: str | None = None
    state: str | None = None
    justification: str | None = None
    response: list[str] = field(default_factory=list)
    detail: str | None = None
    # Exploit intelligence (finding fields; absent = not emitted).
    in_kev: bool = False  # CISA KEV
    in_vulncheck_kev: bool = False
    epss_score: float | None = None
    epss_percentile: float | None = None
    exploit_maturity: str | None = None  # "poc" | "weaponized"


@dataclass
class Component:
    key: str
    project_key: str
    name: str
    version: str | None = None
    type: str = "library"
    group: str | None = None
    purl: str | None = None
    cpes: list[str] = field(default_factory=list)
    hashes: list[tuple[str, str]] = field(default_factory=list)
    supplier: str | None = None
    description: str | None = None
    homepage: str | None = None
    external_refs: list[tuple[str, str]] = field(default_factory=list)  # (type, url)
    # SPDX ids/expressions or raw text; NONE = the SPDX keyword.
    declared_licenses: list[str] = field(default_factory=list)
    concluded_licenses: list[str] = field(default_factory=list)
    author: str | None = None
    eol_date: str | None = None
    comment: str | None = None
    summary: str | None = None
    properties: list[tuple[str, str]] = field(default_factory=list)
    # The component a user edit replaced: (name, version) from the platform's
    # ``replaced`` record (CycloneDX pedigree ancestor).
    replaced: tuple[str, str | None] | None = None


@dataclass
class ProjectNode:
    key: str
    project_id: str
    project_name: str
    version_id: str
    version_name: str
    project_type: str
    folder: str | None = None
    purl: str | None = None
    cpes: list[str] = field(default_factory=list)
    children: list[str] = field(default_factory=list)  # child project keys
    # From the platform's image record folded into this node (collect).
    hashes: list[tuple[str, str]] = field(default_factory=list)
    properties: list[tuple[str, str]] = field(default_factory=list)
    # From this version's uniqueTestTypes (collect); a split document's own.
    lifecycle: Lifecycle = None  # no claim unless collect makes one


@dataclass
class Author:
    name: str
    email: str | None = None
    is_org: bool = False


@dataclass
class Supplier:
    """User-asserted supplier of the described product (--sbom-supplier*)."""

    name: str
    url: str | None = None
    email: str | None = None


@dataclass
class SbomDoc:
    root: str
    projects: dict[str, ProjectNode]
    components: list[Component]
    vulns: list[Vuln]
    author: Author
    serial: str
    timestamp: str
    lifecycle: Lifecycle = None  # no claim unless collect makes one
    # User-asserted (SbomOptions); defaults emit nothing / "unknown".
    supplier: Supplier | None = None
    data_license: str | None = None
    completeness: Literal["complete", "incomplete", "unknown"] = "unknown"
    primary_license: str | None = None  # SPDX expression, concluded by the user
    primary_copyright: str | None = None
