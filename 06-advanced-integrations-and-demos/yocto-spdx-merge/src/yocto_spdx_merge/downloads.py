"""Backfill package downloadLocation from Yocto recipe SPDX documents.

Yocto's create-spdx class leaves downloadLocation as NOASSERTION on runtime
package documents. The real SRC_URI-derived location lives in the recipe
document, on synthetic ``<pn>-source-N`` download packages
(``SPDXRef-Download-<pn>-N``). Each package document links back to its recipe
via a GENERATED_FROM relationship and a ``DocumentRef-recipe-*`` external
document ref, so the chain is resolvable entirely within the archive.
"""

from __future__ import annotations

import re

_DOWNLOAD_IDX_PATTERN = re.compile(r"-(\d+)$")


def _download_sort_key(spdx_id: str) -> int:
    """Sort download packages by their trailing SRC_URI index (Download-<pn>-N)."""
    match = _DOWNLOAD_IDX_PATTERN.search(spdx_id)
    return int(match.group(1)) if match else 0


def _is_real_location(value: str | None) -> bool:
    return bool(value) and value not in ("NOASSERTION", "NONE")


def resolve_download_location(
    package_spdxid: str,
    package_doc: dict,
    namespace_index: dict[str, dict],
) -> str | None:
    """Resolve a package's upstream download location from its recipe document.

    Returns the first real download URI (lowest SRC_URI index), or None when
    the chain cannot be resolved (no GENERATED_FROM relationship, recipe doc
    not in the archive, or a file://-only recipe with no download packages).
    """
    # 1. Find the GENERATED_FROM edge for this package
    recipe_target = None
    for rel in package_doc.get("relationships", []):
        if (
            rel.get("relationshipType") == "GENERATED_FROM"
            and rel.get("spdxElementId") == package_spdxid
        ):
            recipe_target = rel.get("relatedSpdxElement", "")
            break
    if not recipe_target or ":" not in recipe_target:
        return None
    doc_ref_id, recipe_spdxid = recipe_target.split(":", 1)

    # 2. Resolve the DocumentRef to the recipe doc via the package doc's own refs
    recipe_ns = None
    for ref in package_doc.get("externalDocumentRefs", []):
        if ref.get("externalDocumentId") == doc_ref_id:
            recipe_ns = ref.get("spdxDocument")
            break
    if not recipe_ns:
        return None
    recipe_doc = namespace_index.get(recipe_ns)
    if recipe_doc is None:
        return None

    # 3. Collect download packages: prefer BUILD_DEPENDENCY_OF edges to the
    #    recipe element, falling back to the SPDXRef-Download- ID convention.
    download_ids = [
        rel.get("spdxElementId")
        for rel in recipe_doc.get("relationships", [])
        if rel.get("relationshipType") == "BUILD_DEPENDENCY_OF"
        and rel.get("relatedSpdxElement") == recipe_spdxid
    ]
    if not download_ids:
        download_ids = [
            pkg["SPDXID"]
            for pkg in recipe_doc.get("packages", [])
            if pkg.get("SPDXID", "").startswith("SPDXRef-Download-")
        ]
    if not download_ids:
        return None

    # 4. Return the first real location by SRC_URI index
    by_id = {pkg.get("SPDXID"): pkg for pkg in recipe_doc.get("packages", [])}
    for download_id in sorted(download_ids, key=_download_sort_key):
        pkg = by_id.get(download_id)
        if pkg is None:
            continue
        location = pkg.get("downloadLocation")
        if _is_real_location(location):
            return location
    return None
