"""
Pandas transform for the Human Readable SBOM report.

One project version's component inventory, laid out to be read rather than
parsed. Mirrors the platform's Components table: name, version, policy counts,
findings broken out by severity, type, supplier, licenses, release date, source,
review status — plus the component id as a trailing reference column.

Three things this module deliberately does NOT do:

1. **It does not truncate.** An SBOM that silently drops rows is not an SBOM.
   There is no top-N, no ranking, no cap.
2. **It does not chart.** The table is the deliverable. Charts on a 795-row
   inventory are decoration that pushes the actual content below the fold.
3. **It does not reimplement license or source resolution.** Those live in
   ``component_list`` and are imported, so an SBOM row and a Component List row
   resolve the same license from the same precedence chain. Copying them is how
   the two reports would start disagreeing about a component's license.

``severityCounts`` is the source for the per-severity columns. The API omits
zero counts, so a missing key means 0 — NOT missing data. It also carries NONE
and INFO, which are counted in ``findings`` but not broken out, so the four
severity columns are not guaranteed to sum to ``findings``; that gap is real and
is disclosed in the report rather than papered over by inventing an Other bucket
the platform UI does not show.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import unquote

import pandas as pd

# Imported, not reimplemented — see the module docstring. These are the same
# helpers Component List uses, so both reports resolve a component's license and
# source identically.
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

#: Columns present in every configuration, in render order. ``component_id`` is
#: last on purpose: it is a reference value you look up when you need it, not
#: something you read across.
BASE_COLUMNS: list[str] = [
    "component_name",
    "version",
    "component_type",
    "supplier",
    "licenses",
    "release_date",
    "source",
    "status",
    "component_id",
]

#: Inserted after ``version`` when policy columns are on, matching the position
#: of the platform's Policy Status column.
POLICY_COLUMNS: list[str] = ["violations", "warnings"]

#: The finding-count group, inserted before ``component_type``. Toggled as ONE
#: unit: the platform renders the total and the severity badges as a single
#: "Findings" column, and a total with no breakdown (or a breakdown with no
#: total) is a half-answer. Off, the report is a pure inventory sheet.
FINDING_COLUMNS: list[str] = ["findings", "critical", "high", "medium", "low"]


def _columns_for(include_policy: bool, include_findings: bool = True) -> list[str]:
    """Render-order column list for the active options.

    Both optional groups sit between ``version`` and ``component_type``, in the
    order the platform's own table uses: policy first, then findings.
    """
    cut = BASE_COLUMNS.index("component_type")
    middle: list[str] = []
    if include_policy:
        middle += POLICY_COLUMNS
    if include_findings:
        middle += FINDING_COLUMNS
    return BASE_COLUMNS[:cut] + middle + BASE_COLUMNS[cut:]


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


def _severity_count(counts: Any, tier: str) -> int:
    """Read one tier out of ``severityCounts``, treating absent as 0.

    The API omits zero counts, and a cached row round-trips this as a JSON
    string, so both shapes are accepted. Anything unparseable reads as 0 — for
    a count column that is the honest floor, and the total ``findings`` column
    still carries the real number.
    """
    if isinstance(counts, str):
        import json

        try:
            counts = json.loads(counts)
        except (ValueError, TypeError):
            return 0
    if not isinstance(counts, dict):
        return 0
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
    include_policy: bool,
    include_findings: bool = True,
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
        "project_name": "",
        "version_name": "",
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
    include_policy = bool(getattr(config, "policy_status", True))
    include_findings = bool(getattr(config, "finding_counts", True))
    columns = _columns_for(include_policy, include_findings)
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
        empty_summary = _empty_summary(
            include_files=include_files,
            include_policy=include_policy,
            include_findings=include_findings,
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
        empty_main = pd.DataFrame(columns=columns)
        return {
            "main": empty_main,
            "sbom_summary": empty_summary,
            "json_package": _build_json_package(empty_main, empty_summary, empty_notes),
            "notes": empty_notes,
            "domain": str(getattr(config, "domain", "") or ""),
        }

    df = flatten_component_data(df.copy())
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
            "The platform's stored value is unchanged; look a row up by its "
            "component id to see it."
        )

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
    if not summary.get("include_finding_counts", True):
        for key in ("total_findings", "components_with_findings", "severity_totals"):
            published.pop(key, None)
    if not summary.get("include_policy_status", True):
        for key in ("total_violations", "total_warnings"):
            published.pop(key, None)
    return {
        "report": "Human Readable SBOM",
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
