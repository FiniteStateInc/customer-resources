"""Pydantic models for Finite State API entities."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class Scan(BaseModel):
    """Scan information."""

    id: str
    type: str
    status: str
    fsan_id: str | None = Field(default=None, alias="fsanId")
    org_id: str | None = Field(default=None, alias="orgId")
    completed: datetime | None = None
    created: datetime | None = None
    mechanism: str | None = None
    initiated_by: str | None = Field(default=None, alias="initiatedBy")
    bss_message: str | None = Field(default=None, alias="bssMessage")

    model_config = {"populate_by_name": True}


class BranchRef(BaseModel):
    """Minimal branch reference."""

    id: str
    name: str

    model_config = {"populate_by_name": True}


class ProjectRef(BaseModel):
    """Minimal project reference."""

    id: str
    name: str

    model_config = {"populate_by_name": True}


class VersionRef(BaseModel):
    """Minimal version reference."""

    id: str
    name: str | None = Field(default=None, alias="version")
    created: datetime | None = None
    updated: datetime | None = None

    model_config = {"populate_by_name": True}


class ProjectVersion(BaseModel):
    """Project version with full details."""

    id: str
    name: str
    created: datetime
    components: int = 0
    findings: int = 0
    violations: int = 0
    warnings: int = 0
    project: ProjectRef | None = None
    branch: BranchRef | None = None
    latest_scan: Scan | None = Field(default=None, alias="latestScan")

    model_config = {"populate_by_name": True}


class Branch(BaseModel):
    """Branch information."""

    id: str
    name: str
    latest_version: ProjectVersion | None = Field(default=None, alias="latestVersion")

    model_config = {"populate_by_name": True}


class Folder(BaseModel):
    """Folder reference (as embedded in a Project response)."""

    id: str
    name: str

    model_config = {"populate_by_name": True}


class FolderDetail(BaseModel):
    """Full folder object from GET /folders (includes parent info for tree building)."""

    id: str
    name: str
    description: str | None = None
    project_count: int = Field(default=0, alias="projectCount")
    parent_folder_id: str | None = Field(default=None, alias="parentFolderId")
    created_at: datetime | None = Field(default=None, alias="createdAt")
    created_by: str | None = Field(default=None, alias="createdBy")
    actions: list[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


class Project(BaseModel):
    """Finite State project."""

    id: str
    name: str
    description: str = ""
    created: datetime
    type: str
    created_by: str = Field(alias="createdBy")
    default_branch: Branch | None = Field(default=None, alias="defaultBranch")
    priorities: list[str] = Field(default_factory=list)
    flag_conflicts: bool = Field(default=False, alias="flagConflicts")
    software_identifiers: Any | None = Field(default=None, alias="softwareIdentifiers")
    folder: Folder | None = None
    actions: list[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


class ComponentRef(BaseModel):
    """Component reference within a finding."""

    app_id: str | None = Field(default=None, alias="appId")
    id: str
    name: str
    vc_id: str | None = Field(default=None, alias="vcId")
    version: str = ""

    model_config = {"populate_by_name": True}


class Factor(BaseModel):
    """Reachability factor for a finding."""

    entity_type: str
    entity_name: str
    summary: str
    details: dict[str, Any] | None = None
    score_change: float = 0.0

    model_config = {"populate_by_name": True}


class ProjectVersionRef(BaseModel):
    """Project version reference in finding context."""

    id: str
    version: str
    created: datetime
    updated: datetime | None = None

    model_config = {"populate_by_name": True}


class Finding(BaseModel):
    """Security finding from Finite State."""

    id: str
    finding_id: str = Field(default="", alias="findingId")
    title: str = ""
    type: str = ""
    severity: str | None = None
    status: str | None = None
    justification: str | None = None
    response: str | None = None
    risk: int | None = None
    location: str = ""
    description: str | None = None
    detected: datetime | None = None

    # EPSS data
    epss_score: float | None = Field(default=None, alias="epssScore")
    epss_percentile: float | None = Field(default=None, alias="epssPercentile")

    # Exploit data
    exploit_maturity: str | None = Field(default=None, alias="exploitMaturity")
    exploit_info: list[str] = Field(default_factory=list, alias="exploitInfo")
    in_kev: bool = Field(default=False, alias="inKev")
    in_vc_kev: bool = Field(default=False, alias="inVcKev")

    # Relationships
    cwes: list[str] = Field(default_factory=list)
    cve_references: list[str] | None = Field(default=None, alias="cveReferences")
    component: ComponentRef | None = None
    project: ProjectRef | None = None
    project_version: ProjectVersionRef | None = Field(default=None, alias="projectVersion")

    # Analysis data
    attack_vector: str | None = Field(default=None, alias="attackVector")
    reachability_score: float | None = Field(default=None, alias="reachabilityScore")
    factors: list[Factor] | None = None
    vuln_in_dataset: bool | None = Field(default=None, alias="vulnInDataset")

    # Metadata
    comments: str | None = None
    reason: str | None = None
    violations: int = 0
    warnings: int = 0

    model_config = {"populate_by_name": True}


class Component(BaseModel):
    """Software component from Finite State."""

    id: str
    gc_id: str | None = Field(default=None, alias="gcId")
    name: str
    version: str | None = ""
    type: str | None = ""
    created: datetime | None = None
    release_date: datetime | None = Field(default=None, alias="releaseDate")

    # Supplier and licensing
    supplier: str | None = ""
    declared_licenses: str | None = Field(default=None, alias="declaredLicenses")
    concluded_licenses: str | None = Field(default=None, alias="concludedLicenses")
    declared_license_details: list[Any] = Field(
        default_factory=list, alias="declaredLicenseDetails"
    )
    concluded_license_details: list[Any] = Field(
        default_factory=list, alias="concludedLicenseDetails"
    )

    # Counts
    findings: int = 0
    warnings: int = 0
    violations: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict, alias="severityCounts")

    # Source information
    source: list[str] = Field(default_factory=list)
    origin: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    bom_ref: str | None = Field(default=None, alias="bomRef")

    # Status
    project_module: bool = Field(default=False, alias="projectModule")
    excluded: bool = False
    include_in_future_versions: bool = Field(default=False, alias="includeInFutureVersions")
    status: str | None = None
    status_comment: str | None = Field(default=None, alias="statusComment")
    edited: bool = False
    last_modified_at: datetime | None = Field(default=None, alias="lastModifiedAt")
    last_modified_by: str | None = Field(default=None, alias="lastModifiedBy")
    replaced: Any | None = None

    # Relationships
    project: ProjectRef | None = None
    branch: BranchRef | None = None
    project_version: VersionRef | None = Field(default=None, alias="projectVersion")

    model_config = {"populate_by_name": True}


class FindingStatusUpdate(BaseModel):
    """Request body for updating finding VEX status."""

    status: str
    justification: str | None = None  # API enum value (e.g., CODE_NOT_REACHABLE)
    response: str | None = None  # API enum value (e.g., WILL_NOT_FIX)
    reason: str | None = None  # Optional reason/comment text

    model_config = {"populate_by_name": True}


class User(BaseModel):
    """Authenticated user information."""

    user: str  # email
    new: bool = False
    last_login: datetime | None = Field(default=None, alias="lastLogin")
    org_actions: list[str] = Field(default_factory=list, alias="orgActions")
    organization: dict[str, Any] | None = None

    model_config = {"populate_by_name": True}
