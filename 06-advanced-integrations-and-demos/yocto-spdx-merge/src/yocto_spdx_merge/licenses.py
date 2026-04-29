"""Resolve cross-document license references in SPDX expressions."""

from __future__ import annotations

import re


_DOC_REF_PATTERN = re.compile(r"DocumentRef-([^:]+):(\S+)")

# Deprecated SPDX license IDs that spdx-tools rejects.
# Map to their valid SPDX 2.3 equivalents.
_DEPRECATED_LICENSE_MAP = {
    "GPL-3.0-with-GCC-exception": "GPL-3.0-only WITH GCC-exception-3.1",
    "GPL-2.0-with-classpath-exception": "GPL-2.0-only WITH Classpath-exception-2.0",
    "GPL-2.0-with-font-exception": "GPL-2.0-only WITH Font-exception-2.0",
    "GPL-2.0-with-bison-exception": "GPL-2.0-only WITH Bison-exception-2.2",
    "GPL-2.0-with-autoconf-exception": "GPL-2.0-only WITH Autoconf-exception-2.0",
}


def resolve_license_expression(
    expression: str,
    namespace_index: dict[str, dict],
    external_doc_refs: list[dict] | None = None,
) -> str:
    """Resolve DocumentRef-* license references to plain license IDs.

    If a DocumentRef reference can be resolved via the namespace index,
    replace it with the bare LicenseRef-* ID. If not, return NOASSERTION.
    """
    if not expression or expression == "NOASSERTION":
        return expression

    # Normalize deprecated license IDs
    for deprecated, replacement in _DEPRECATED_LICENSE_MAP.items():
        if deprecated in expression:
            expression = expression.replace(deprecated, replacement)

    # Check if expression contains any DocumentRef references
    if "DocumentRef-" not in expression:
        return expression

    # Build a map from DocumentRef ID to namespace URI
    ref_to_ns: dict[str, str] = {}
    if external_doc_refs:
        for ref in external_doc_refs:
            ref_to_ns[ref["externalDocumentId"]] = ref["spdxDocument"]

    unresolvable_refs: list[str] = []

    def replace_ref(match: re.Match) -> str:
        full_ref_id = f"DocumentRef-{match.group(1)}"
        license_id = match.group(2)

        # Try to find the referenced document
        ns = ref_to_ns.get(full_ref_id)
        if ns and ns in namespace_index:
            # We found the doc — just use the bare LicenseRef ID
            return license_id

        # Unresolvable: record this and return a placeholder
        unresolvable_refs.append(match.group(0))
        return match.group(0)

    result = _DOC_REF_PATTERN.sub(replace_ref, expression)

    # If every token in the expression was unresolvable, return NOASSERTION
    if unresolvable_refs and result.strip() == expression.strip():
        return "NOASSERTION"

    return result
