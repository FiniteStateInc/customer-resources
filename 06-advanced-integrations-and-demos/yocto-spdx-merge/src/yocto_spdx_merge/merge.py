"""Merge multiple SPDX package documents into a single flat document."""

from __future__ import annotations

import re
import sys
import uuid
from datetime import datetime, timezone

from yocto_spdx_merge import __version__
from yocto_spdx_merge.enrich import load_cpe_map, enrich_package
from yocto_spdx_merge.licenses import resolve_license_expression


_cpe_map_cache: dict | None = None

def _get_cpe_map() -> dict:
    global _cpe_map_cache
    if _cpe_map_cache is None:
        _cpe_map_cache = load_cpe_map()
    return _cpe_map_cache


def filter_package_refs(external_doc_refs: list[dict]) -> list[dict]:
    """Filter externalDocumentRefs to only package docs (skip runtime-*, recipe-*)."""
    filtered = []
    for ref in external_doc_refs:
        doc_id = ref["externalDocumentId"]
        # Skip runtime and recipe references
        if doc_id.startswith("DocumentRef-runtime-") or doc_id.startswith("DocumentRef-recipe-"):
            continue
        filtered.append(ref)
    return filtered


def _sanitize_spdx_id(name: str) -> str:
    """Sanitize a package name for use in an SPDX ID (letters, numbers, . and -)."""
    return re.sub(r"[^a-zA-Z0-9.\-]", "-", name)


def extract_packages(
    refs: list[dict],
    namespace_index: dict[str, dict],
    all_external_doc_refs: list[dict] | None = None,
) -> tuple[list[dict], list[str]]:
    """Extract package records from referenced SPDX documents.

    Returns (packages, warnings). Warnings are logged for missing refs.
    """
    cpe_map = _get_cpe_map()
    packages = []
    warnings = []
    seen_ids: set[str] = set()

    for ref in refs:
        ns = ref["spdxDocument"]
        doc = namespace_index.get(ns)

        if doc is None:
            warnings.append(f"Missing referenced document: {ref['externalDocumentId']} ({ns})")
            continue

        for pkg in doc.get("packages", []):
            # Remap SPDX ID to ensure uniqueness
            safe_name = _sanitize_spdx_id(pkg["name"])
            new_id = f"SPDXRef-Package-{safe_name}"

            # Handle collisions by appending a counter
            if new_id in seen_ids:
                counter = 2
                while f"{new_id}-{counter}" in seen_ids:
                    counter += 1
                new_id = f"{new_id}-{counter}"

            seen_ids.add(new_id)

            # Resolve cross-document license references
            license_declared = pkg.get("licenseDeclared", "NOASSERTION")
            license_declared = resolve_license_expression(
                license_declared, namespace_index, all_external_doc_refs
            )

            extracted = {
                "SPDXID": new_id,
                "name": pkg["name"],
                "versionInfo": pkg.get("versionInfo", ""),
                "downloadLocation": pkg.get("downloadLocation", "NOASSERTION"),
                "licenseConcluded": pkg.get("licenseConcluded", "NOASSERTION"),
                "licenseDeclared": license_declared,
                "copyrightText": pkg.get("copyrightText", "NOASSERTION"),
                "supplier": pkg.get("supplier", "NOASSERTION"),
            }

            # Preserve existing externalRefs from source and enrich
            if pkg.get("externalRefs"):
                extracted["externalRefs"] = list(pkg["externalRefs"])
            extracted = enrich_package(extracted, cpe_map)

            packages.append(extracted)

    return packages, warnings


def assemble_document(
    image_name: str,
    image_version: str,
    image_package: dict,
    component_packages: list[dict],
) -> dict:
    """Assemble a flat SPDX 2.3 document from the image and component packages."""
    doc_uuid = uuid.uuid4()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": image_package["SPDXID"],
        }
    ]

    for pkg in component_packages:
        relationships.append({
            "spdxElementId": image_package["SPDXID"],
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": pkg["SPDXID"],
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": image_name,
        "documentNamespace": f"http://spdx.org/spdxdocs/{image_name}-{doc_uuid}",
        "creationInfo": {
            "created": now,
            "creators": [
                f"Tool: yocto-spdx-merge-{__version__}",
                "Organization: Finite State",
            ],
            "licenseListVersion": "3.24",
        },
        "packages": [image_package] + component_packages,
        "relationships": relationships,
    }
