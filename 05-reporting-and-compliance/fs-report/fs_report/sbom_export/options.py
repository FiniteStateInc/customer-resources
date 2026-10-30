"""SBOM export options and the standard/encoding/signing validity matrix."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, get_args
from urllib.parse import urlsplit

from cyclonedx.spdx import is_supported_id

from fs_report.sbom_export.mapping import is_spdx_expression

Standard = Literal["cyclonedx-1.6", "cyclonedx-1.7", "spdx-2.3", "spdx-3.0"]
Completeness = Literal["complete", "incomplete", "unknown"]
_EMAIL = re.compile(r"[^@\s()]+@[^@\s()]+")
_ASSERTED_TEXT = (
    "author",
    "supplier",
    "supplier_url",
    "supplier_email",
    "data_license",
    "primary_license",
    "primary_copyright",
)

# First entry is the default encoding for the standard.
VALID_ENCODINGS: dict[Standard, tuple[str, ...]] = {
    "cyclonedx-1.6": ("json", "xml", "protobuf"),
    "cyclonedx-1.7": ("json", "xml", "protobuf"),
    "spdx-2.3": ("json", "yaml", "xml", "rdf-xml", "tag-value"),
    "spdx-3.0": ("json-ld",),
}


class SbomOptionsError(ValueError):
    """Raised when an SBOM option combination is invalid."""


@dataclass(frozen=True)
class SbomOptions:
    standard: Standard = "cyclonedx-1.6"
    encoding: str | None = None  # None -> default for standard
    include_vex: bool = True
    include_dependencies: bool = True
    split: bool = False
    author: str | None = None
    sign_key: str | None = None
    sign_keyless: bool = False
    sign_identity_token: str | None = None
    sign_embedded: bool = False
    # User-asserted (never derived from platform data).
    supplier: str | None = None
    supplier_url: str | None = None
    supplier_email: str | None = None
    data_license: str | None = None
    completeness: Completeness = "unknown"
    # The described product's licence (SPDX expression) and copyright.
    primary_license: str | None = None
    primary_copyright: str | None = None

    def __post_init__(self) -> None:
        for f in _ASSERTED_TEXT:  # strip on every path (CLI, web, Config)
            v = getattr(self, f)
            if v is not None:
                object.__setattr__(self, f, v.strip())

    def resolved_encoding(self) -> str:
        return self.encoding or VALID_ENCODINGS[self.standard][0]

    def validate(self, *, web: bool = False) -> None:
        if self.standard not in VALID_ENCODINGS:
            raise SbomOptionsError(
                f"Unknown standard {self.standard!r}; valid: "
                + ", ".join(VALID_ENCODINGS)
            )
        enc = self.resolved_encoding()
        valid = VALID_ENCODINGS[self.standard]
        if enc not in valid:
            raise SbomOptionsError(
                f"Encoding {enc!r} is not valid for {self.standard}; "
                f"valid encodings: {', '.join(valid)}"
            )
        if self.sign_key and self.sign_keyless:
            raise SbomOptionsError("sign_key and sign_keyless are mutually exclusive")
        if self.sign_identity_token and not self.sign_keyless:
            raise SbomOptionsError("sign_identity_token requires sign_keyless")
        if web and self.sign_keyless:
            raise SbomOptionsError("sign_keyless is not available in the web UI")
        if self.sign_embedded:
            if not self.sign_key:
                raise SbomOptionsError("sign_embedded requires sign_key")
            if not (self.standard.startswith("cyclonedx-") and enc in ("json", "xml")):
                raise SbomOptionsError(
                    "sign_embedded is only supported for cyclonedx json or xml"
                )
        self._validate_assertions()

    def _validate_assertions(self) -> None:
        for f in _ASSERTED_TEXT:
            v = getattr(self, f)
            if v == "":
                raise SbomOptionsError(f"{f} is blank")
            if v and ("\n" in v or "\r" in v):
                raise SbomOptionsError(f"{f} must be a single line")
        if (self.supplier_url or self.supplier_email) and not self.supplier:
            raise SbomOptionsError("supplier_url / supplier_email require supplier")
        if self.supplier_url:
            try:
                u = urlsplit(self.supplier_url)
            except ValueError:  # e.g. an unclosed IPv6 bracket
                u = None
            if not u or u.scheme not in ("http", "https") or not u.netloc:
                raise SbomOptionsError("supplier_url must be an http(s) URL")
        if self.supplier_email and not _EMAIL.fullmatch(self.supplier_email):
            raise SbomOptionsError("supplier_email must look like local@domain")
        if (
            self.standard == "spdx-2.3"
            and self.supplier
            and self.supplier.endswith(")")
            and not self.supplier_email
        ):
            # "Organization: Acme (UK)" reads back as name Acme, email UK.
            raise SbomOptionsError(
                "SPDX 2.3 reads a supplier name ending in ')' as 'NAME (EMAIL)': "
                "add --sbom-supplier-email or drop the trailing parenthesis"
            )
        if self.standard == "spdx-2.3" and self.author and self.author.endswith(")"):
            # Same actor syntax for the creator line, which has no email.
            raise SbomOptionsError(
                "SPDX 2.3 reads an author ending in ')' as 'NAME (EMAIL)': "
                "drop the trailing parenthesis"
            )
        if self.data_license:
            if not is_supported_id(self.data_license):
                raise SbomOptionsError(
                    f"data_license {self.data_license!r} is not an SPDX licence id"
                )
            if self.standard.startswith("spdx-") and self.data_license != "CC0-1.0":
                raise SbomOptionsError(
                    "SPDX documents are licensed CC0-1.0 by the SPDX "
                    "specification; data_license must be CC0-1.0 (or unset)"
                )
        if self.primary_license and not is_spdx_expression(self.primary_license):
            raise SbomOptionsError(
                f"primary_license {self.primary_license!r} is not an SPDX licence "
                "expression (e.g. GPL-2.0-only, MIT OR Apache-2.0, LicenseRef-x)"
            )
        if self.completeness not in get_args(Completeness):
            raise SbomOptionsError(
                "completeness must be one of " + ", ".join(get_args(Completeness))
            )
