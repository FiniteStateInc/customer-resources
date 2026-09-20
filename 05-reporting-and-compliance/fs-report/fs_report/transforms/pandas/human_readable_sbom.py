"""
Pandas transform for the Human Readable SBOM report.

One project version's component inventory, laid out to be read rather than
parsed, and shareable by default: name, version, type, supplier, licenses,
release date, and the PURL/CPE identifiers NTIA asks for. Policy counts,
findings broken out by severity, review status and the platform component id
are all opt-in; with every group on it mirrors the platform's Components table.

Three things this module deliberately does NOT do:

1. **It does not truncate.** An SBOM that silently drops rows is not an SBOM.
   There is no top-N, no ranking, no cap.
2. **It does not chart.** The table is the deliverable. Charts on a 795-row
   inventory are decoration that pushes the actual content below the fold.
3. **It does not reimplement license resolution.** That lives in
   ``component_list`` and is imported, so an SBOM row and a Component List row
   resolve the same license from the same precedence chain. Copying it is how
   the two reports would start disagreeing about a component's license.

``severityCounts`` is the source for the per-severity columns. The API omits
zero counts, so a missing key means 0 — NOT missing data. It also carries NONE
and INFO, which are counted in ``findings`` but not broken out, so the four
severity columns are not guaranteed to sum to ``findings``; that gap is real and
is disclosed in the report rather than papered over by inventing an Other bucket
the platform UI does not show.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

import pandas as pd

# Imported, not reimplemented — see the module docstring. These are the same
# helpers Component List uses, so both reports resolve a component's license and
# license identically.
from fs_report.transforms.pandas.component_list import (
    _best_license_details,
    _map_source_labels,
    flatten_component_data,
)

logger = logging.getLogger(__name__)


#: Severity tiers broken out into their own columns, worst first. Deliberately
#: excludes NONE/INFO: the platform's Components table shows exactly these four,
#: and this report mirrors it.
SEVERITY_TIERS: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

#: Component ``type`` values that are SAST placeholders rather than real
#: software components. Excluded unless ``--include-file-components``.
FILE_TYPE = "file"

#: Columns present in every configuration, in render order. The identifiers sit
#: at the TAIL, not next to name/version: a PURL is routinely 60+ characters and
#: placing it third pushes type/supplier/licenses past readable width, breaking
#: this recipe's one contract (laid out to be read rather than parsed).
#: Identifiers are looked *up* when you need them, not read across.
BASE_COLUMNS: list[str] = [
    "component_name",
    "version",
    "component_type",
    "supplier",
    "licenses",
    "release_date",
    "purl",
    "cpe",
]

#: Inserted after ``version`` when policy columns are on, matching the position
#: of the platform's Policy Status column. OFF by default.
POLICY_COLUMNS: list[str] = ["violations", "warnings"]

#: The finding-count group, inserted before ``component_type``. Toggled as ONE
#: unit: the platform renders the total and the severity badges as a single
#: "Findings" column, and a total with no breakdown (or a breakdown with no
#: total) is a half-answer. OFF by default.
FINDING_COLUMNS: list[str] = ["findings", "critical", "high", "medium", "low"]

#: The component's review/triage status (NEEDS_REVIEW, IN_REVIEW, CONFIRMED,
#: FALSE_POSITIVE, UNKNOWN). OFF by default: the default artifact is a SHAREABLE
#: SBOM — what is in the build — and triage state is an internal judgement the
#: recipient has no context for.
STATUS_COLUMNS: list[str] = ["status"]

#: How the component was introduced (Binary SCA, Upload). OFF by default: it is
#: scan methodology rather than inventory, and a recipient of a shared SBOM has
#: no use for it. Restorable with ``--source-column`` for anyone whose pipeline
#: still reads it.
SOURCE_COLUMNS: list[str] = ["source"]

#: The platform's internal component UUID. OFF by default: it is meaningless
#: outside the tenant that issued it, so it is not the "other unique identifier"
#: NTIA asks for — ``purl``/``cpe`` are, and they are on by default. Kept behind
#: ``--component-ids`` for anyone cross-referencing back into the platform.
ID_COLUMNS: list[str] = ["component_id"]

#: The four optional groups and their defaults. The default report is a plain
#: shareable inventory: name, version, type, supplier, license, release date,
#: PURL, CPE. Everything internal — policy verdicts, finding counts,
#: review status, platform ids — is opt-in.
OPTION_DEFAULTS: dict[str, bool] = {
    "policy_status": False,
    "finding_counts": False,
    "component_status": False,
    "component_ids": False,
    "source_column": False,
}


def _columns_for(
    include_policy: bool = False,
    include_findings: bool = False,
    include_status: bool = False,
    include_ids: bool = False,
    include_source: bool = False,
) -> list[str]:
    """Render-order column list for the active options.

    Policy and findings sit between ``version`` and ``component_type``, in the
    order the platform's own table uses. Status and the platform id append at
    the very end, after the identifiers: inventory data first, internal platform
    metadata last.
    """
    cut = BASE_COLUMNS.index("component_type")
    middle: list[str] = []
    if include_policy:
        middle += POLICY_COLUMNS
    if include_findings:
        middle += FINDING_COLUMNS
    base = list(BASE_COLUMNS)
    if include_source:
        # Back where it was before it left the default set: after `source`'s old
        # neighbour `release_date`, ahead of the identifiers.
        at = base.index("purl")
        base[at:at] = SOURCE_COLUMNS
    tail: list[str] = []
    if include_status:
        tail += STATUS_COLUMNS
    if include_ids:
        tail += ID_COLUMNS
    return base[:cut] + middle + base[cut:] + tail


def _pretty_type(value: Any) -> str:
    """``operating-system`` -> ``Operating System``.

    The platform labels this column "CDX Type" and title-cases it for display;
    there is no separate cdxType field on the API. Unknown values pass through
    title-cased rather than being dropped.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    return text.replace("-", " ").replace("_", " ").title()


#: Appended to `notes` on EVERY run, populated or empty. NTIA's Minimum
#: Elements explicitly permit declaring a required element a "known unknown"
#: rather than omitting it silently, and dependency relationships are one here:
#: component-to-component edges come only from
#: /component-dependencies/{pvId}/{profCompId}, one level per call, in a
#: different ID space needing a per-component /lookup?vcId= bridge — 800+ calls
#: for a large image — and the edges carry no relationship type.
KNOWN_UNKNOWNS_NOTE = (
    "Dependency relationships between components are not included: the "
    "platform's component API does not expose them, so this inventory is a "
    "flat list. Per NTIA guidance this is declared as a known unknown rather "
    "than omitted silently. Identifier types other than PURL and CPE (SWID, "
    "UDI, UPC, GTIN, GMN) are likewise not surfaced."
)


def _provenance(config: Any, project_name: str, version_name: str) -> dict[str, str]:
    """NTIA's "Author of SBOM Data" and "Timestamp" elements.

    Computed ONCE per report, here, because the transform is the only layer
    that sees both the config and every renderer's input. Two ``now()`` calls
    would put two different timestamps in one compliance artifact.
    """
    from fs_report import __version__

    return {
        # %Y-%m-%dT%H:%M:%SZ, matching _metadata_block's own fallback and the
        # rest of the repo's timestamps. A compliance artifact whose selling
        # point is a disclosed timestamp should not render it two ways
        # depending on which code path produced it.
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generated_by": f"fs-report {__version__}",
        "source": "Finite State Platform",
        "tenant": str(getattr(config, "domain", "") or ""),
        "project": project_name,
        "version": version_name,
    }


def _as_dict(value: Any) -> dict[str, Any]:
    """Coerce a nested API field to a dict, accepting a JSON string.

    Both ``severityCounts`` and ``softwareIdentifiers`` arrive as dicts from the
    API and as JSON strings from an older cache row that predates the decode
    tuple. Anything else (None, a float NaN from a ragged frame, a scalar) reads
    as empty rather than raising.
    """
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return {}
    return value if isinstance(value, dict) else {}


def _identifiers(rec: Any) -> tuple[str, str]:
    """``(purl, cpe)`` for one component record.

    Two sources, in order:

    1. ``softwareIdentifiers`` — what ``GET /public/v0/components`` returns.
    2. ``sbom_purl`` / ``sbom_cpe`` — backfilled by the engine from the
       CycloneDX export on the ``--version`` path, where the endpoint is
       ``/versions/{id}/components`` and returns no identifiers at all.

    ``purl`` is singular because ``SoftwareIdentifiersV0.purls`` is
    ``maxItems: 1``. ``cpe`` joins every value with ``"; "`` — not ``", "``,
    because CPE 2.3 strings contain commas — deduped, order preserved, never
    truncated.

    Deliberately does NOT fall back to ``bomRef``: the two endpoints that could
    supply one are exactly the two that already supply ``softwareIdentifiers``
    or supply neither, so the branch is unreachable. Deliberately does NOT
    synthesise ``pkg:generic/<name>@<version>`` either — NTIA asks for the
    identifiers you have, and a fabricated identifier is a false claim where a
    blank is an honest known unknown.
    """
    identifiers = _as_dict(rec.get("softwareIdentifiers"))

    purls = identifiers.get("purls") or []
    purl = str(purls[0]).strip() if isinstance(purls, list) and purls else ""
    if not purl:
        purl = str(rec.get("sbom_purl") or "").strip()

    raw_cpes = identifiers.get("cpes") or []
    if not isinstance(raw_cpes, list):
        raw_cpes = []
    seen: dict[str, None] = {}
    for value in raw_cpes:
        text = str(value).strip()
        if text:
            seen.setdefault(text, None)
    cpe = "; ".join(seen)
    if not cpe:
        cpe = str(rec.get("sbom_cpe") or "").strip()

    return purl, cpe


def _severity_count(counts: Any, tier: str) -> int:
    """Read one tier out of ``severityCounts``, treating absent as 0.

    The API omits zero counts, and a cached row round-trips this as a JSON
    string, so both shapes are accepted. Anything unparseable reads as 0 — for
    a count column that is the honest floor, and the total ``findings`` column
    still carries the real number.
    """
    counts = _as_dict(counts)
    for key, value in counts.items():
        if str(key).strip().upper() == tier:
            try:
                return int(value)
            except (ValueError, TypeError):
                return 0
    return 0


#: A percent-escape: ``%`` followed by exactly two hex digits. A lone ``%`` is
#: not one, and must survive untouched — a version may legitimately contain it.
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")


def _decode_version(value: str) -> str:
    """Decode percent-escapes in a component version for display.

    Versions reach the platform from purl coordinates, and purl REQUIRES ``+``
    to be percent-encoded — ``pkg:deb/debian/libxml2@2.9.1%2Bdfsg1-5%2Bdeb8u6``.
    The escaped form is what gets stored, so Debian and ipk components arrive
    reading ``2.9.1%2Bdfsg1-5%2Bdeb8u6`` in a report whose entire purpose is
    being read by a person.

    Deliberately narrow:

    * Only when a real escape is present, so a value with a lone ``%`` is
      returned byte-identical rather than round-tripped through a decoder.
    * Exactly ONE decode pass. Decoding until stable would turn a version whose
      true text contains ``%2B`` (stored as ``%252B``) into a ``+``.
    * ``version`` only. It is the one purl-derived field; names, suppliers and
      licenses are not, so there is nothing there to decode and any change
      would be corruption rather than presentation.
    """
    if not value or not _PERCENT_ESCAPE.search(value):
        return value
    return unquote(value)


def _first_nonempty(row: pd.Series, *fields: str) -> str:
    """First field on the row with a non-blank value."""
    for field in fields:
        value = row.get(field)
        if value is None:
            continue
        text = str(value).strip()
        if text and text.lower() not in ("nan", "none"):
            return text
    return ""


def _as_int(value: Any) -> int:
    try:
        if value is None or (isinstance(value, float) and pd.isna(value)):
            return 0
        return int(value)
    except (ValueError, TypeError):
        return 0


def _date_only(value: Any) -> str:
    """``2024-05-01T00:00:00Z`` -> ``2024-05-01``.

    A release date's time component is never meaningful here and costs column
    width the table does not have.
    """
    text = str(value or "").strip()
    if not text or text.lower() in ("nan", "none", "nat"):
        return ""
    return text.split("T")[0]


def _license_text(rec: pd.Series) -> str:
    """Effective license for a component row.

    Precedence mirrors Component List: concluded (user-set) beats declared
    (auto-detected), and the flat legacy ``licenses`` field is last but is the
    ONLY place some components carry a license at all.

    Two shapes the plain string path got wrong:

    * a LIST value (``["MIT", "Apache-2.0"]``) rendered as a Python repr —
      ``"['MIT', 'Apache-2.0']"`` — in an SBOM's license column;
    * a component whose license lives only in ``*LicenseDetails`` rendered
      BLANK, which for a compliance artifact reads as "unlicensed" rather than
      "look in the structured field". Component List enriches from those arrays
      for exactly this reason, so the same fallback applies here.
    """
    for field in ("concludedLicenses", "declaredLicenses", "licenses"):
        value = rec.get(field)
        if isinstance(value, (list, tuple, set)):
            # A dict element is read through the same key precedence as the
            # detail arrays below rather than str()'d — `str({"spdx": "MIT"})`
            # would put a Python repr in a compliance artifact's license column,
            # which is the exact failure the list branch exists to prevent.
            parts: list[str] = []
            for item in value:
                text = (
                    _first_dict_value(item, "spdx", "spdxId", "spdxid", "license")
                    if isinstance(item, dict)
                    else str(item or "").strip()
                )
                if text and text.lower() not in ("nan", "none"):
                    parts.append(text)
            if parts:
                return ", ".join(dict.fromkeys(parts))
            continue
        text = str(value or "").strip()
        if text and text.lower() not in ("nan", "none"):
            return text

    # Structured fallback: concluded/declared/legacy detail arrays.
    details = _best_license_details(rec)
    if isinstance(details, list):
        names: list[str] = []
        for detail in details:
            if not isinstance(detail, dict):
                continue
            # `spdx` is the API's actual key (LicenseDetail.spdx) and is what
            # Component List reads. `license` is the FULL DISPLAY NAME ("GNU
            # General Public License v2.0"), so it is a last resort — preferring
            # it would put prose in a column that should carry SPDX ids.
            name = _first_dict_value(detail, "spdx", "spdxId", "spdxid", "license")
            if name and name not in names:
                names.append(name)
        if names:
            return ", ".join(names)
    return ""


def _first_dict_value(detail: dict, *keys: str) -> str:
    for key in keys:
        text = str(detail.get(key) or "").strip()
        if text and text.lower() not in ("nan", "none"):
            return text
    return ""


def _distinct_version_ids(df: pd.DataFrame) -> list[str]:
    """Distinct non-blank ``projectVersion.id`` values present in the frame.

    Used only by the single-version guard. The version-scoped endpoint omits
    projectVersion per row (the engine backfills it), so an empty result means
    "cannot tell" and is treated as fine rather than as a violation.
    """
    if "projectVersion.id" not in df.columns:
        return []
    seen: list[str] = []
    for value in df["projectVersion.id"]:
        text = str(value or "").strip()
        if text and text.lower() not in ("nan", "none", "unknown") and text not in seen:
            seen.append(text)
    return seen


def _empty_summary(
    *,
    include_files: bool,
    include_policy: bool = False,
    include_findings: bool = False,
    include_status: bool = False,
    include_ids: bool = False,
    include_source: bool = False,
    provenance: dict[str, str] | None = None,
    min_note: str = "",
) -> dict[str, Any]:
    return {
        "total_components": 0,
        "components_with_findings": 0,
        "total_findings": 0,
        "severity_totals": dict.fromkeys(SEVERITY_TIERS, 0),
        "total_violations": 0,
        "total_warnings": 0,
        # See the populated path: None = not knowable, not zero.
        "file_components_excluded": None,
        "include_file_components": include_files,
        "include_policy_status": include_policy,
        "include_finding_counts": include_findings,
        "include_component_status": include_status,
        "include_component_ids": include_ids,
        "include_source_column": include_source,
        "project_name": "",
        "version_name": "",
        # NTIA author + timestamp. Set on the EMPTY path too: an artifact that
        # says "no components" still has to say who produced that claim and
        # when, or it cannot be relied on as evidence of anything.
        "provenance": provenance or {},
        "note": min_note,
    }


def _scope_label(
    additional_data: dict[str, Any] | None,
    resolved_key: str,
    config: Any,
    config_key: str,
) -> str:
    """Human-readable scope value, engine-resolved name first.

    The config fallback is a last resort: it holds IDs, not names. It is kept
    because an ID names the scope better than a blank does.
    """
    if additional_data:
        text = str(additional_data.get(resolved_key) or "").strip()
        if text and text.lower() not in ("nan", "none", "unknown"):
            return text
    return str(getattr(config, config_key, "") or "").strip()


def human_readable_sbom_transform(
    data: Any,
    config: Any = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the readable component inventory for one project version."""
    include_files = bool(getattr(config, "include_file_components", False))
    include_policy = bool(getattr(config, "policy_status", False))
    include_findings = bool(getattr(config, "finding_counts", False))
    include_status = bool(getattr(config, "component_status", False))
    include_ids = bool(getattr(config, "component_ids", False))
    include_source = bool(getattr(config, "source_column", False))
    columns = _columns_for(
        include_policy, include_findings, include_status, include_ids, include_source
    )
    notes: list[str] = []

    df = data if isinstance(data, pd.DataFrame) else pd.DataFrame(data or [])
    if df.empty:
        # The exclusion disclosure belongs here MORE than anywhere else: a
        # version whose only components are file entries comes back empty after
        # the server-side type!=file filter, and "no components" would read as
        # "nothing is installed" rather than "everything here was filtered out".
        empty_notes = ["No components were returned for this project version."]
        if not include_files:
            empty_notes.append(
                "File-type components are excluded from this inventory, and the "
                "fetch filters them out server-side — if this version contains "
                "only file entries, that alone explains the empty result. Pass "
                "--include-file-components to list them."
            )
        empty_notes.append(KNOWN_UNKNOWNS_NOTE)
        empty_summary = _empty_summary(
            include_files=include_files,
            include_policy=include_policy,
            include_findings=include_findings,
            include_status=include_status,
            include_ids=include_ids,
            include_source=include_source,
        )
        # Carry the requested scope through. An empty inventory is exactly where
        # the reader most needs to know WHICH project version came back empty —
        # blanking it leaves an artifact that explains the filtering but not
        # what it filtered.
        #
        # Prefer the names the ENGINE resolved. By transform time
        # config.project_filter holds the resolved numeric ID and
        # config.version_filter holds a bare project-version ID — or nothing at
        # all on a current-version run, which is the common case. Using them
        # directly is how IDs leak into a reader-facing scope line, and how the
        # default run ends up labelled with no version whatsoever.
        empty_summary["project_name"] = _scope_label(
            additional_data, "project_name", config, "project_filter"
        )
        empty_summary["version_name"] = _scope_label(
            additional_data, "scope_version_name", config, "version_filter"
        )
        empty_summary["provenance"] = _provenance(
            config, empty_summary["project_name"], empty_summary["version_name"]
        )
        empty_main = pd.DataFrame(columns=columns)
        return {
            "main": empty_main,
            "sbom_summary": empty_summary,
            "json_package": _build_json_package(empty_main, empty_summary, empty_notes),
            "notes": empty_notes,
            "domain": str(getattr(config, "domain", "") or ""),
        }

    df = flatten_component_data(df.copy())
    if include_source:
        df = _map_source_labels(df)

    # --- Single-version guard ------------------------------------------------
    # This report's whole contract is "one project version". --all-versions (or
    # an inherited current_version_only=False) makes the engine fetch components
    # across EVERY version of the project, and the summary would then label that
    # mixed set with whichever version happened to sort first — a plausible-
    # looking SBOM for a build that never existed. Fail loudly instead, matching
    # CVE Component Evidence, the other single-version component report.
    version_ids = _distinct_version_ids(df)
    if len(version_ids) > 1:
        raise ValueError(
            "Human Readable SBOM is scoped to a single project version, but the "
            f"fetched components span {len(version_ids)} versions "
            f"({', '.join(version_ids[:5])}"
            f"{', …' if len(version_ids) > 5 else ''}). "
            "Drop --all-versions, or pass --version <project_version_id> to pin "
            "the version to inventory."
        )

    # --- File-type exclusion -------------------------------------------------
    # Normally a no-op: when the flag is off the engine already filtered files
    # out server-side with `type!=file`, so none reach this frame. It stays for
    # the paths that bypass that filter (a cached frame, a data override).
    #
    # The DISCLOSURE, however, must not be conditional on seeing file rows —
    # that is exactly the case where the reader cannot tell a filtered table
    # from a complete one. So the exclusion is always stated; the count is only
    # added when this layer actually did the filtering and therefore knows it.
    type_series = df["type"] if "type" in df.columns else pd.Series([""] * len(df))
    is_file = type_series.astype(str).str.strip().str.lower() == FILE_TYPE
    file_count = int(is_file.sum())
    if not include_files:
        if file_count:
            df = df[~is_file]
            notes.append(
                f"{file_count:,} file-type component(s) excluded from this "
                "inventory. These are SAST placeholders without license, "
                "supplier or release data. Pass --include-file-components to "
                "list them."
            )
        else:
            notes.append(
                "File-type components are excluded from this inventory. They "
                "are SAST placeholders without license, supplier or release "
                "data, and the fetch filters them out server-side, so they are "
                "not counted here. Pass --include-file-components to list them."
            )
    elif file_count:
        notes.append(
            f"{file_count:,} file-type component(s) included via "
            "--include-file-components. They typically carry no license, "
            "supplier or release data."
        )

    rows: list[dict[str, Any]] = []
    decoded_versions = 0
    for _, rec in df.iterrows():
        severity = rec.get("severityCounts")
        raw_version = _first_nonempty(rec, "version")
        version = _decode_version(raw_version)
        if version != raw_version:
            decoded_versions += 1
        row: dict[str, Any] = {
            "component_name": _first_nonempty(rec, "name") or "(unnamed)",
            "version": version,
            "component_type": _pretty_type(rec.get("type")),
            "supplier": _first_nonempty(rec, "supplier"),
            "licenses": _license_text(rec),
            "release_date": _date_only(rec.get("releaseDate")),
            "source": _first_nonempty(rec, "source_label"),
            "status": _first_nonempty(rec, "status"),
            "findings": _as_int(rec.get("findings")),
            "component_id": _first_nonempty(rec, "id"),
        }
        row["purl"], row["cpe"] = _identifiers(rec)
        for tier in SEVERITY_TIERS:
            row[tier.lower()] = _severity_count(severity, tier)
        if include_policy:
            row["violations"] = _as_int(rec.get("violations"))
            row["warnings"] = _as_int(rec.get("warnings"))
        rows.append(row)

    # Ordering follows what the reader can actually see. With finding counts on,
    # worst-first puts the components needing attention at the top; with them
    # off the report is a pure inventory, and sorting by an invisible column
    # would look arbitrary — so it goes alphabetical. Name (then version) breaks
    # ties either way, so the order is stable across runs rather than inheriting
    # whatever order the API returned.
    if include_findings:
        rows.sort(
            key=lambda r: (
                -r["critical"],
                -r["high"],
                -r["medium"],
                -r["low"],
                # Total findings breaks ties among components with nothing in
                # the four severity tiers. Without it a component carrying 50
                # none/info findings sorts among the untouched ones purely by
                # name, so the visible Findings column runs backwards partway
                # down a table that says it is ordered worst-first.
                -int(r.get("findings", 0)),
                str(r["component_name"]).lower(),
                str(r["version"]),
            )
        )
    else:
        rows.sort(key=lambda r: (str(r["component_name"]).lower(), str(r["version"])))

    # `columns` selects — rows always carry the finding keys (they are needed for
    # the totals below), the frame just drops them when the group is off.
    main = (
        pd.DataFrame(rows, columns=columns) if rows else pd.DataFrame(columns=columns)
    )

    # Computed from `rows`, not `main`: the columns may not be in the frame.
    severity_totals = {
        tier: sum(int(r.get(tier.lower(), 0)) for r in rows) for tier in SEVERITY_TIERS
    }
    total_findings = sum(int(r.get("findings", 0)) for r in rows)
    broken_out = sum(severity_totals.values())
    if include_findings and total_findings > broken_out:
        notes.append(
            f"{total_findings - broken_out:,} finding(s) carry a severity outside "
            "Critical/High/Medium/Low (none or info). They are counted in the "
            "Findings column but have no severity column, so the four severity "
            "columns do not sum to the Findings total."
        )

    # Stated for the same reason the exclusion and severity-sum notes are: a
    # displayed value that differs from the stored one is something this report
    # did to the data, and the reader is entitled to know. Counted in COMPONENTS,
    # since one version can carry several escapes and rows are what is scanned.
    if decoded_versions:
        notes.append(
            f"{decoded_versions:,} component version(s) were stored "
            "percent-encoded (purl escapes `+` as `%2B`) and are shown decoded. "
            "The platform's stored value is unchanged; pass --component-ids "
            "and look the row up by that id to see it."
        )

    # Quantify the NTIA "other unique identifiers" element rather than asserting
    # it. Silence at 100% keeps the common case clean; a tenant whose extractor
    # populates neither field then reads as a measured gap in the artifact
    # itself instead of looking like a bug in this report.
    with_purl = sum(1 for r in rows if r.get("purl"))
    with_cpe = sum(1 for r in rows if r.get("cpe"))
    if rows and (with_purl < len(rows) or with_cpe < len(rows)):
        notes.append(
            f"PURL present for {with_purl:,} of {len(rows):,} components; CPE "
            f"for {with_cpe:,}. Components without an identifier are listed by "
            "name and version only."
        )
    ambiguous = (additional_data or {}).get("identifier_ambiguous_components") or 0
    if ambiguous:
        notes.append(
            f"{ambiguous:,} component row(s) share a name and version with "
            "another entry in this version's SBOM and disagree on their "
            "identifiers. Their PURL/CPE are left blank rather than guessed — "
            "the gap is ambiguity, not absence."
        )
    if additional_data and additional_data.get("identifier_backfill_failed"):
        notes.append(
            "The CycloneDX lookup used to fill PURL and CPE on a "
            "version-scoped run failed, so those columns may be blank for "
            "reasons unrelated to the data. Re-run to retry."
        )

    notes.append(KNOWN_UNKNOWNS_NOTE)

    summary = {
        "total_components": int(len(main)),
        "components_with_findings": sum(
            1 for r in rows if int(r.get("findings", 0)) > 0
        ),
        "total_findings": total_findings,
        "severity_totals": severity_totals,
        "total_violations": (
            sum(int(r.get("violations", 0)) for r in rows) if include_policy else 0
        ),
        "total_warnings": (
            sum(int(r.get("warnings", 0)) for r in rows) if include_policy else 0
        ),
        # None = "not knowable here", NOT zero. When the flag is off the engine
        # already filtered files out server-side, so this layer sees none and
        # cannot count them — reporting 0 would tell a JSON consumer the version
        # had no file components, which is a different (and possibly false)
        # claim. Only a client-side pass yields a real number.
        "file_components_excluded": (
            0 if include_files else (file_count if file_count else None)
        ),
        "include_file_components": include_files,
        "include_policy_status": include_policy,
        "include_finding_counts": include_findings,
        "include_component_status": include_status,
        "include_component_ids": include_ids,
        "include_source_column": include_source,
        # Row values first — they are the version actually inventoried. The
        # engine-resolved names back them up: the version-scoped endpoint
        # (/versions/<id>/components) omits `project` on every row, so a run
        # pinned with --version would otherwise render a scope line with no
        # project in it.
        "project_name": (
            _project_label(df, "project.name")
            or _scope_label(additional_data, "project_name", config, "project_filter")
        ),
        "version_name": (
            _project_label(df, "projectVersion.version")
            or _scope_label(
                additional_data, "scope_version_name", config, "version_filter"
            )
        ),
        "note": "",
    }
    summary["provenance"] = _provenance(
        config, str(summary["project_name"]), str(summary["version_name"])
    )

    # Run-time disclosure of which optional groups are OFF, always (not just
    # --verbose). These all DEFAULT off, so a saved Command Center card or
    # workflow created before that flip stored no override and now renders a
    # narrower artifact than its author saw. Release notes only reach whoever
    # reads them; this reaches the run log of the run that actually changed.
    _off = [
        flag
        for flag, on in (
            ("--policy-status", include_policy),
            ("--finding-counts", include_findings),
            ("--component-status", include_status),
            ("--component-ids", include_ids),
            ("--source-column", include_source),
        )
        if not on
    ]
    if _off:
        logger.info(
            "Human Readable SBOM: shareable defaults — %s omitted. "
            "Pass %s to include them.",
            ", ".join(f.lstrip("-") for f in _off),
            " ".join(_off),
        )

    if getattr(config, "verbose", False):
        logger.info(
            "Human Readable SBOM: %d components, %d with findings, %d file rows %s",
            summary["total_components"],
            summary["components_with_findings"],
            file_count,
            "included" if include_files else "excluded",
        )

    return {
        "main": main,
        "sbom_summary": summary,
        "json_package": _build_json_package(main, summary, notes),
        "notes": notes,
        "domain": str(getattr(config, "domain", "") or ""),
    }


def _project_label(df: pd.DataFrame, column: str) -> str:
    """First non-blank value in ``column`` — every row shares one version."""
    if column not in df.columns or df.empty:
        return ""
    for value in df[column]:
        text = str(value or "").strip()
        if text and text.lower() not in ("nan", "none", "unknown"):
            return text
    return ""


def _build_json_package(
    main: pd.DataFrame, summary: dict[str, Any], notes: list[str]
) -> dict[str, Any]:
    """Machine-readable artifact.

    Routed through the renderer's dedicated ``json_package`` path so the JSON
    output carries the summary and notes, not just the table — the generic path
    would serialize the frame alone and drop the exclusion disclosure, which is
    the one thing a consumer needs to know to interpret the row count.
    """
    records = main.to_dict(orient="records") if not main.empty else []
    # --no-finding-counts means "pure inventory sheet". The row columns are
    # already stripped; leaving the aggregates in the summary would make JSON
    # the one format that still hands back the data the flag exists to remove.
    published = dict(summary)
    # Default FALSE, matching OPTION_DEFAULTS: under the shareable-default
    # contract an absent flag means the group is OFF, so defaulting to True here
    # would leak finding/policy aggregates into JSON for any caller that omits
    # them from `summary`.
    if not summary.get("include_finding_counts", False):
        for key in ("total_findings", "components_with_findings", "severity_totals"):
            published.pop(key, None)
    if not summary.get("include_policy_status", False):
        for key in ("total_violations", "total_warnings"):
            published.pop(key, None)
    # Top level, not buried in `summary`: a consumer checking NTIA conformance
    # is asking "who produced this and when", which is a property of the
    # document, not of the inventory it happens to contain.
    provenance = published.pop("provenance", {})
    return {
        "report": "Human Readable SBOM",
        "provenance": _jsonable(provenance),
        "summary": _jsonable(published),
        "components": _jsonable(records),
        "notes": notes,
    }


def _jsonable(obj: Any) -> Any:
    """Coerce numpy/pandas scalars to native types for strict JSON."""
    import math

    import numpy as np

    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if obj is None or isinstance(obj, (str, bool, int, float)):
        if isinstance(obj, float) and not math.isfinite(obj):
            return None
        return obj
    if isinstance(obj, np.generic):
        value = obj.item()
        if isinstance(value, float) and not math.isfinite(value):
            return None
        return value
    return str(obj)
