"""Validate SPDX 2.3 documents using spdx-tools."""

from __future__ import annotations


def validate_spdx_file(path: str) -> list[str]:
    """Validate an SPDX JSON file and return a list of error messages.

    Returns an empty list if the document is valid.
    """
    from spdx_tools.spdx.parser.parse_anything import parse_file
    from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document

    try:
        document = parse_file(path)
    except Exception as e:
        return [f"Parse error: {e}"]

    messages = validate_full_spdx_document(document)
    return [
        f"[{msg.context.element_type}] {msg.validation_message}"
        for msg in messages
    ]
