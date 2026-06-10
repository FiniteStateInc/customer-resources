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
_RECIPE_SPDXID_PREFIX = "SPDXRef-Recipe-"


def _download_sort_key(spdx_id: str) -> int:
    """Sort download packages by their trailing SRC_URI index (Download-<pn>-N)."""
    match = _DOWNLOAD_IDX_PATTERN.search(spdx_id)
    return int(match.group(1)) if match else 0


def _is_real_location(value) -> bool:
    return isinstance(value, str) and value not in ("", "NOASSERTION", "NONE")


def _find_recipe_target(package_spdxid: str, package_doc: dict) -> tuple[str, str] | None:
    """Return (doc_ref_id, recipe_spdxid) from the package's GENERATED_FROM edge."""
    for rel in package_doc.get("relationships", []):
        if (
            rel.get("relationshipType") == "GENERATED_FROM"
            and rel.get("spdxElementId") == package_spdxid
        ):
            target = rel.get("relatedSpdxElement", "")
            if isinstance(target, str) and ":" in target:
                return tuple(target.split(":", 1))
    return None


def _resolve_doc_ref(
    doc_ref_id: str,
    package_doc: dict,
    extra_doc_refs: list[dict] | None,
) -> str | None:
    """Map a DocumentRef ID to a namespace, preferring the package doc's own refs."""
    ref_lists = [package_doc.get("externalDocumentRefs", [])]
    if extra_doc_refs:
        ref_lists.append(extra_doc_refs)
    for refs in ref_lists:
        for ref in refs:
            if ref.get("externalDocumentId") == doc_ref_id:
                return ref.get("spdxDocument")
    return None


def resolve_download_location(
    package_spdxid: str,
    package_doc: dict,
    namespace_index: dict[str, dict],
    extra_doc_refs: list[dict] | None = None,
) -> str | None:
    """Resolve a package's upstream download location from its recipe document.

    Returns the first real download URI (lowest SRC_URI index), or None when
    the chain cannot be resolved (no GENERATED_FROM relationship, recipe doc
    not in the archive, or a file://-only recipe with no download packages).
    ``extra_doc_refs`` (e.g. the image doc's refs) are consulted when the
    package document lacks its own external ref for the recipe.
    """
    target = _find_recipe_target(package_spdxid, package_doc)
    if target is None:
        return None
    doc_ref_id, recipe_spdxid = target

    recipe_ns = _resolve_doc_ref(doc_ref_id, package_doc, extra_doc_refs)
    if not recipe_ns:
        return None
    recipe_doc = namespace_index.get(recipe_ns)
    if recipe_doc is None:
        return None

    # Collect download packages from BUILD_DEPENDENCY_OF edges to the recipe
    # element, unioned with the SPDXRef-Download-<pn>- ID convention (scoped
    # to this recipe) so incomplete relationship sets don't drop candidates.
    download_ids = {
        rel.get("spdxElementId")
        for rel in recipe_doc.get("relationships", [])
        if rel.get("relationshipType") == "BUILD_DEPENDENCY_OF"
        and rel.get("relatedSpdxElement") == recipe_spdxid
        and isinstance(rel.get("spdxElementId"), str)
    }
    if recipe_spdxid.startswith(_RECIPE_SPDXID_PREFIX):
        pn = recipe_spdxid[len(_RECIPE_SPDXID_PREFIX):]
        download_prefix = f"SPDXRef-Download-{pn}-"
        download_ids.update(
            pkg["SPDXID"]
            for pkg in recipe_doc.get("packages", [])
            if isinstance(pkg.get("SPDXID"), str) and pkg["SPDXID"].startswith(download_prefix)
        )

    by_id = {pkg.get("SPDXID"): pkg for pkg in recipe_doc.get("packages", [])}
    for download_id in sorted(download_ids, key=_download_sort_key):
        pkg = by_id.get(download_id)
        if pkg is None:
            continue
        location = pkg.get("downloadLocation")
        if _is_real_location(location):
            return location

    # Defensive fallback: some create-spdx variants may carry the location on
    # the recipe package itself.
    recipe_pkg = by_id.get(recipe_spdxid)
    if recipe_pkg is not None:
        location = recipe_pkg.get("downloadLocation")
        if _is_real_location(location):
            return location
    return None
