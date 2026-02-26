# Copyright (c) 2024 Finite State, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
CycloneDX SBOM parser for remediation package generation.

Parses CycloneDX 1.4+ JSON SBOMs and extracts:
- Component inventory with PURLs
- Dependency graph (adjacency list)
- VEX vulnerability assessments

See: https://cyclonedx.org/specification/overview/
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class SBOMComponent:
    """A single component extracted from a CycloneDX SBOM."""

    bom_ref: str
    name: str
    version: str
    purl: str = ""
    group: str = ""  # Maven groupId, npm scope, etc.
    component_type: str = ""  # library, framework, application, etc.
    scope: str = "required"  # required, optional, excluded
    description: str = ""
    licenses: list[str] = field(default_factory=list)
    hashes: dict[str, str] = field(default_factory=dict)
    external_references: list[dict[str, str]] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        """Full name including group/namespace."""
        if self.group:
            return f"{self.group}/{self.name}"
        return self.name

    @property
    def display_name(self) -> str:
        """Human-readable name with version."""
        return f"{self.full_name}@{self.version}" if self.version else self.full_name


@dataclass
class VexEntry:
    """A VEX (Vulnerability Exploitability eXchange) assessment from the SBOM."""

    vuln_id: str  # CVE ID or other identifier
    state: str = ""  # exploitable, not_affected, fixed, in_triage, etc.
    justification: str = ""  # code_not_reachable, requires_configuration, etc.
    response: list[str] = field(default_factory=list)  # update, will_not_fix, etc.
    detail: str = ""
    recommendation: str = ""
    affected_refs: list[str] = field(
        default_factory=list
    )  # bom-refs of affected components
    source: str = ""  # NVD, GHSA, etc.
    ratings: list[dict[str, Any]] = field(default_factory=list)  # CVSS ratings
    cwes: list[int] = field(default_factory=list)
    advisories: list[dict[str, str]] = field(default_factory=list)
    # Structured version info from affects[].versions[]
    fixed_versions: list[str] = field(default_factory=list)


@dataclass
class DependencyInfo:
    """Describes the dependency relationship from root to a component."""

    is_direct: bool
    path: list[str]  # List of bom-refs from root to target
    depth: int  # 1 = direct, 2+ = transitive
    direct_dependency: str | None = None  # bom-ref of the first hop (if transitive)


@dataclass
class SBOMData:
    """Parsed CycloneDX SBOM with components, dependency graph, and VEX data."""

    # Spec metadata
    spec_version: str = ""
    serial_number: str = ""
    bom_version: int = 1

    # Root component (the application/firmware itself)
    root_ref: str = ""
    root_name: str = ""
    root_version: str = ""

    # Component inventory: bom_ref -> SBOMComponent
    components: dict[str, SBOMComponent] = field(default_factory=dict)

    # Dependency graph: bom_ref -> list of bom_refs it depends on
    dependency_graph: dict[str, list[str]] = field(default_factory=dict)

    # VEX assessments: vuln_id -> VexEntry
    vulnerabilities: dict[str, VexEntry] = field(default_factory=dict)

    # Lookup indexes (built during parsing)
    _purl_to_ref: dict[str, str] = field(default_factory=dict)
    _name_version_to_ref: dict[str, str] = field(default_factory=dict)

    def component_by_purl(self, purl: str) -> SBOMComponent | None:
        """Look up a component by PURL."""
        ref = self._purl_to_ref.get(purl)
        return self.components.get(ref) if ref else None

    def component_by_name_version(
        self, name: str, version: str
    ) -> SBOMComponent | None:
        """Look up a component by name + version (fallback when PURL is unavailable)."""
        key = f"{name}:{version}"
        ref = self._name_version_to_ref.get(key)
        if ref:
            return self.components.get(ref)

        # Try case-insensitive match
        key_lower = key.lower()
        for k, r in self._name_version_to_ref.items():
            if k.lower() == key_lower:
                return self.components.get(r)
        return None

    def vex_for_cve(self, cve_id: str) -> VexEntry | None:
        """Look up VEX assessment for a CVE."""
        return self.vulnerabilities.get(cve_id)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def parse_cyclonedx(data: dict[str, Any]) -> SBOMData:
    """Parse a CycloneDX JSON SBOM into structured data.

    Handles CycloneDX spec versions 1.4 through 1.6.

    Args:
        data: Raw CycloneDX JSON (as a Python dict).

    Returns:
        Parsed SBOM with components, dependency graph, and VEX data.
    """
    sbom = SBOMData(
        spec_version=str(data.get("specVersion", "")),
        serial_number=str(data.get("serialNumber", "")),
        bom_version=int(data.get("version", 1)),
    )

    # Parse root component from metadata
    metadata = data.get("metadata", {})
    root_component = metadata.get("component", {})
    if root_component:
        sbom.root_ref = str(root_component.get("bom-ref", ""))
        sbom.root_name = str(root_component.get("name", ""))
        sbom.root_version = str(root_component.get("version", ""))

    # Parse components
    for comp_data in data.get("components", []):
        comp = _parse_component(comp_data)
        if comp.bom_ref:
            sbom.components[comp.bom_ref] = comp
            if comp.purl:
                sbom._purl_to_ref[comp.purl] = comp.bom_ref
            # Build name:version index (use full_name for disambiguation)
            for key in [
                f"{comp.name}:{comp.version}",
                f"{comp.full_name}:{comp.version}",
            ]:
                sbom._name_version_to_ref[key] = comp.bom_ref

    # Parse dependency graph
    for dep_entry in data.get("dependencies", []):
        ref = str(dep_entry.get("ref", ""))
        depends_on = [str(d) for d in dep_entry.get("dependsOn", [])]
        sbom.dependency_graph[ref] = depends_on

    # Parse vulnerabilities (VEX)
    for vuln_data in data.get("vulnerabilities", []):
        vex = _parse_vulnerability(vuln_data)
        if vex.vuln_id:
            sbom.vulnerabilities[vex.vuln_id] = vex

    logger.info(
        f"Parsed CycloneDX SBOM: {len(sbom.components)} components, "
        f"{len(sbom.dependency_graph)} dependency entries, "
        f"{len(sbom.vulnerabilities)} vulnerabilities"
    )

    return sbom


def _parse_component(data: dict[str, Any]) -> SBOMComponent:
    """Parse a single CycloneDX component object."""
    # Extract licenses
    licenses = []
    for lic_entry in data.get("licenses", []):
        lic = lic_entry.get("license", {})
        if isinstance(lic, dict):
            lic_id = lic.get("id", "")
            if lic_id:
                licenses.append(lic_id)
            elif lic.get("name"):
                licenses.append(lic["name"])
        elif isinstance(lic_entry, dict) and lic_entry.get("expression"):
            licenses.append(lic_entry["expression"])

    # Extract hashes
    hashes = {}
    for h in data.get("hashes", []):
        alg = h.get("alg", "")
        content = h.get("content", "")
        if alg and content:
            hashes[alg] = content

    # Extract external references
    ext_refs = []
    for ref in data.get("externalReferences", []):
        ref_type = ref.get("type", "")
        url = ref.get("url", "")
        if ref_type and url:
            ext_refs.append({"type": ref_type, "url": url})

    return SBOMComponent(
        bom_ref=str(data.get("bom-ref", "")),
        name=str(data.get("name", "")),
        version=str(data.get("version", "")),
        purl=str(data.get("purl", "")),
        group=str(data.get("group", "")),
        component_type=str(data.get("type", "")),
        scope=str(data.get("scope", "required")),
        description=str(data.get("description", "")),
        licenses=licenses,
        hashes=hashes,
        external_references=ext_refs,
    )


def _parse_vulnerability(data: dict[str, Any]) -> VexEntry:
    """Parse a single CycloneDX vulnerability/VEX entry."""
    vuln_id = str(data.get("id", ""))

    # Parse analysis (VEX core)
    analysis = data.get("analysis", {})
    state = str(analysis.get("state", ""))
    justification = str(analysis.get("justification", ""))
    response = [str(r) for r in analysis.get("response", [])]
    detail = str(analysis.get("detail", ""))

    # Parse source
    source = data.get("source", {})
    source_name = str(source.get("name", "")) if isinstance(source, dict) else ""

    # Parse ratings
    ratings = []
    for r in data.get("ratings", []):
        rating = {
            "score": r.get("score"),
            "severity": str(r.get("severity", "")),
            "method": str(r.get("method", "")),
            "vector": str(r.get("vector", "")),
        }
        rating_source = r.get("source", {})
        if isinstance(rating_source, dict):
            rating["source"] = str(rating_source.get("name", ""))
        ratings.append(rating)

    # Parse CWEs
    cwes = [int(c) for c in data.get("cwes", []) if isinstance(c, (int, float))]

    # Parse advisories
    advisories = []
    for adv in data.get("advisories", []):
        entry = {}
        if adv.get("title"):
            entry["title"] = str(adv["title"])
        if adv.get("url"):
            entry["url"] = str(adv["url"])
        if entry:
            advisories.append(entry)

    # Parse affected component refs and fixed versions
    affected_refs = []
    fixed_versions = []
    for affect in data.get("affects", []):
        ref = str(affect.get("ref", ""))
        if ref:
            affected_refs.append(ref)

        # Extract fixed versions from versions array
        for ver_entry in affect.get("versions", []):
            status = str(ver_entry.get("status", ""))
            if status == "unaffected":
                version = ver_entry.get("version", "")
                if version:
                    fixed_versions.append(str(version))
                # Also try to parse from range
                ver_range = ver_entry.get("range", "")
                if ver_range and not version:
                    # Try to extract version from vers: format
                    extracted = _extract_version_from_vers(str(ver_range))
                    if extracted:
                        fixed_versions.append(extracted)

    return VexEntry(
        vuln_id=vuln_id,
        state=state,
        justification=justification,
        response=response,
        detail=detail,
        recommendation=str(data.get("recommendation", "")),
        affected_refs=affected_refs,
        source=source_name,
        ratings=ratings,
        cwes=cwes,
        advisories=advisories,
        fixed_versions=fixed_versions,
    )


def _extract_version_from_vers(vers_range: str) -> str:
    """Try to extract a minimum fixed version from a vers: range string.

    Examples:
        "vers:semver/>=2.0.0|<5.0.0" → ""  (upper bound is still affected)
        "vers:maven/>=2.10.5.1" → "2.10.5.1"  (lower bound of unaffected range)
    """
    # Simple heuristic: if the range starts with >=, the first version is the fix
    import re

    m = re.search(r">=\s*([\d][\d.]*[\d])", vers_range)
    if m:
        return m.group(1)
    return ""


# ---------------------------------------------------------------------------
# Dependency graph operations
# ---------------------------------------------------------------------------


def find_dependency_path(
    sbom: SBOMData,
    target_ref: str,
    root_ref: str | None = None,
) -> list[str] | None:
    """Find the shortest path from root to a target component in the dependency graph.

    Uses BFS for shortest-path guarantees.

    Args:
        sbom: Parsed SBOM data with dependency graph.
        target_ref: The bom-ref of the target (vulnerable) component.
        root_ref: Override for the root bom-ref. Uses sbom.root_ref if not specified.

    Returns:
        List of bom-refs from root to target (inclusive), or None if no path exists.
    """
    root = root_ref or sbom.root_ref
    if not root or not target_ref:
        return None
    if root == target_ref:
        return [root]

    # BFS
    visited: set[str] = {root}
    queue: deque[list[str]] = deque([[root]])

    while queue:
        path = queue.popleft()
        current = path[-1]

        for neighbor in sbom.dependency_graph.get(current, []):
            if neighbor in visited:
                continue
            new_path = path + [neighbor]
            if neighbor == target_ref:
                return new_path
            visited.add(neighbor)
            queue.append(new_path)

    return None


def classify_dependency(
    sbom: SBOMData,
    target_ref: str,
    root_ref: str | None = None,
) -> DependencyInfo:
    """Classify a component's dependency relationship to the root.

    Args:
        sbom: Parsed SBOM data.
        target_ref: The bom-ref of the target component.
        root_ref: Override for root bom-ref.

    Returns:
        DependencyInfo with path, depth, and direct/transitive classification.
    """
    path = find_dependency_path(sbom, target_ref, root_ref)

    if path is None:
        # Component not found in dependency graph — treat as direct
        return DependencyInfo(
            is_direct=True,
            path=[target_ref],
            depth=1,
            direct_dependency=None,
        )

    depth = len(path) - 1  # root doesn't count
    is_direct = depth <= 1

    return DependencyInfo(
        is_direct=is_direct,
        path=path,
        depth=max(depth, 1),
        direct_dependency=path[1] if len(path) > 2 else None,
    )


def get_direct_dependencies(sbom: SBOMData) -> list[str]:
    """Return bom-refs of direct dependencies (first hop from root)."""
    return list(sbom.dependency_graph.get(sbom.root_ref, []))


def format_dependency_path(
    sbom: SBOMData,
    path: list[str],
) -> str:
    """Format a dependency path as a human-readable string.

    Resolves bom-refs to display names where possible.

    Example output: ``my-app → express@4.16.0 → lodash@4.17.4``
    """
    parts = []
    for ref in path:
        comp = sbom.components.get(ref)
        if comp:
            parts.append(comp.display_name)
        elif ref == sbom.root_ref:
            parts.append(sbom.root_name or ref)
        else:
            parts.append(ref)
    return " → ".join(parts)


def match_component_to_sbom(
    sbom: SBOMData,
    component_name: str,
    component_version: str,
) -> SBOMComponent | None:
    """Match a finding's component to an SBOM component.

    Tries multiple matching strategies:
    1. Exact name:version match
    2. Name-only match (if only one component with that name)
    3. Case-insensitive match

    Args:
        sbom: Parsed SBOM.
        component_name: Component name from the finding.
        component_version: Component version from the finding.

    Returns:
        Matched SBOMComponent, or None if no match found.
    """
    # Strategy 1: exact match via index
    comp = sbom.component_by_name_version(component_name, component_version)
    if comp:
        return comp

    # Strategy 2: match by name only (if unambiguous)
    name_lower = component_name.lower()
    candidates = [
        c
        for c in sbom.components.values()
        if c.name.lower() == name_lower and c.version == component_version
    ]
    if len(candidates) == 1:
        return candidates[0]

    # Strategy 3: partial name match (handles group prefix differences)
    candidates = [
        c
        for c in sbom.components.values()
        if (
            c.name.lower() == name_lower
            or c.full_name.lower().endswith(f"/{name_lower}")
        )
        and c.version == component_version
    ]
    if len(candidates) == 1:
        return candidates[0]

    # Strategy 4: version-relaxed match (component name matches, version close)
    candidates = [c for c in sbom.components.values() if c.name.lower() == name_lower]
    if len(candidates) == 1:
        logger.debug(
            f"Relaxed match: {component_name}:{component_version} → "
            f"{candidates[0].display_name} (version mismatch)"
        )
        return candidates[0]

    logger.debug(
        f"No SBOM match for {component_name}:{component_version} "
        f"({len(candidates)} candidates)"
    )
    return None
