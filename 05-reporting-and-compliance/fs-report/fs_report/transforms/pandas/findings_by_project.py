"""
Pandas transform functions for Findings by Project report.
"""

import logging
import re
from collections.abc import Callable
from functools import partial
from typing import Any, NamedTuple

import pandas as pd

# derive_tiers is imported from the CRA module on purpose: a tier name must mean
# the same thing in `--exploit-maturity` regardless of which recipe reads it.
from fs_report.cra.tiers import derive_tiers, normalize_tiers, validate_tier_names
from fs_report.cvss import looks_like_vector
from fs_report.models import Config
from fs_report.purl_utils import parse_purl

logger = logging.getLogger(__name__)

# CVSS AV: metric letter -> display label. The letters mean the same thing in
# v2, v3 and v4; v2 has no P (Physical) and folds physical access into L.
_ATTACK_VECTOR_LABELS = {
    "N": "Network",
    "A": "Adjacent",
    "L": "Local",
    "P": "Physical",
}


def _attack_vector_label(vector: Any) -> str:
    """Read the AV: metric out of a CVSS vector string of any version.

    ``CVSS:3.1/AV:N/AC:L/...`` -> ``"Network"``. Returns "" when the vector is
    missing or carries no recognizable AV metric.

    Version-agnostic on purpose: ``AV:`` carries the same four letters in
    CVSS v2, v3 and v4, so the same parse serves all three and the caller
    decides which vector to feed it (see ``_cvss_columns``).

    Whitespace is stripped and the match is case-insensitive: NVD writes the
    metrics uppercase and slash-separated, but a lowercase, padded or
    space-separated vector from another enrichment source should still resolve
    rather than silently blank the cell. The metric must still start a field
    (so ``AV:`` inside a longer token is not read) and its value must be the
    whole field (so ``AV:None`` is not read as Network).
    """
    if not vector:
        return ""
    match = re.search(
        r"(?:^|[/\s,;])AV:([NALP])(?![0-9A-Za-z])",
        str(vector).strip(),
        re.IGNORECASE,
    )
    return _ATTACK_VECTOR_LABELS[match.group(1).upper()] if match else ""


# CVSS vector fields in the NVD enrichment, newest scoring version first.
# This is the field order ``_cvss_vectors`` ranks within — it breaks ties, and
# is not the whole rule; a readable version outranks the field order. NVD
# never rescored most pre-2016 CVEs under v3 (CVE-2014-7186 carries a v2
# vector only), so a v3-only read printed nothing and labelled nothing on
# findings the platform shows an AV: for.
_CVSS_VECTOR_SOURCES = (
    "cvss_v4_vector",
    "cvss_v3_vector",
    "cvss_v2_vector",
)

# The v2 field, named once. `_cvss_version` treats it as the one field whose
# text/field conflict is resolvable (v2 vectors carry no prefix by
# definition), and repeating the literal there meant renaming the enrichment
# key would silently blank every v2 row's version cell instead of failing.
_CVSS_V2_SOURCE = _CVSS_VECTOR_SOURCES[-1]


def _cvss_version(source_key: str, vector: Any) -> str:
    """Scoring version of a CVSS vector, from its prefix and its source key.

    ``CVSS:3.1/AV:N/...`` -> ``"3.1"``, ``CVSS:4.0/...`` -> ``"4.0"``: the
    prefix is exact, so it wins whenever it parses. It has to *lead* the
    string and be followed by the metrics it prefixes — a ``CVSS:`` appearing
    mid-string is a note, not a version, and reading one out of it would
    assert a scoring the value does not carry.

    The separator after the version is the same set ``_attack_vector_label``
    accepts (``/``, whitespace, comma, semicolon), so the two parsers agree
    on what a vector looks like: a space-separated
    ``CVSS:3.1 AV:N AC:L`` yields both a version and a label, rather than one
    cell describing the row and its neighbour going blank.

    The number is passed through as published rather than checked against a
    known list, so a CVSS major this code has never seen (``CVSS:5.0/…`` ->
    ``"5.0"``) reports itself instead of blanking. HTML gives an unrecognized
    major the neutral pill; the tabular outputs carry the number as-is.

    CVSS v2 vectors carry no prefix (the prefix was introduced with v3), so a
    prefix-less value reads ``"2"`` only when it came from the v2 field **and**
    still looks like a vector (``looks_like_vector``). The cross-check runs
    both ways: a prefix-less value in the v3/v4 field, a *prefixed* value in
    the v2 field, and junk like ``"n/a"`` anywhere all return "". Printing a
    version there would assert a scoring the data contradicts.

    Returns "" when there is no vector at all. A blank cell means NVD
    published no vector for the CVE, which is not the same claim as "scored
    under v2".
    """
    if not vector:
        return ""
    text = str(vector).strip()
    if re.match(r"CVSS:", text, re.IGNORECASE):
        match = re.match(r"CVSS:(\d+(?:\.\d+)?)(?=[/\s,;])", text, re.IGNORECASE)
        if not match:
            # Claims a prefix whose version will not parse
            # (``CVSS:unknown/…``, or ``CVSS:3.1`` with no metrics after it).
            # That is a v3-or-later shape with an unreadable version, not a
            # v2 vector, so report nothing rather than guess.
            return ""
        if source_key == _CVSS_V2_SOURCE:
            # A prefixed value in the v2 field contradicts its own source:
            # the prefix says v3-or-later, the field says v2. Report neither.
            return ""
        return match.group(1)
    if re.search(r"CVSS:", text, re.IGNORECASE):
        # A ``CVSS:`` that does not lead the string is not a version prefix —
        # it is a note or a concatenation ("see CVSS:3.1 advisory"). Reading
        # a version out of the middle of the text would assert a scoring the
        # value does not carry.
        return ""
    if source_key == _CVSS_V2_SOURCE and looks_like_vector(text):
        return "2"
    return ""


class _CvssCandidate(NamedTuple):
    """One vector a CVE could be reported under, with its scoring version.

    Named fields rather than a bare pair: the two are both strings, so a
    swapped unpack would type-check clean and print a version number in the
    vector cell.
    """

    vector: str
    version: str


def _cvss_vectors(details: Any) -> list[_CvssCandidate]:
    """Vector candidates for a CVE, best first.

    Only strings that look like a CVSS vector survive: a non-string value, a
    whitespace-only one, and a placeholder carrying no CVSS metric field
    (``n/a``, ``unknown``, a bare ``CVSS:3.1``) are all dropped. Filtering
    here rather than at the caller keeps the three columns in step —
    ``_cvss_columns`` reads the vector, the version and the label off this one
    list, so a dropped value is invisible to all three.

    Candidates rank on whether a version can be read off them
    (``_cvss_version``), then on that version newest-first, and only then on
    the field they arrived in. A readable version therefore beats field
    order: a v2-shaped string mis-filed into ``cvss_v4_vector`` loses to the
    correctly filed v3 vector NVD sent in the same payload, rather than
    printing with an empty version cell beside it. So does a versioned one
    that is simply older — a ``CVSS:3.0/…`` in the v4 field loses to a
    correctly filed ``CVSS:3.1/…``, because ranking on the slot would print
    the older scoring, and derive the attack-vector label from it, while the
    newer vector sat unused on the same row. Field order breaks ties between
    equal versions only. A value with no readable version is demoted, never
    dropped, because it is still the only thing to print when it is all NVD
    sent and a vector beats a blank cell.

    A *well-formed* vector is still taken at its word about its own version
    whatever field it arrived in — ``CVSS:3.0/…`` in ``cvss_v4_vector``
    reports ``3.0``, not ``4.0`` — because the vector text is the more
    specific statement and the field assignment is the part this code cannot
    see. That is what the value *says*; which candidate is *printed* is the
    separate question the ranking above answers. The one field/text conflict
    that is resolved lives in ``_cvss_version``: the v2 field, whose values
    carry no prefix by definition.

    Ranking on the text means an enrichment source that emitted a prefix-less
    v4 vector would see it demoted below a well-formed v3 one. That is the
    intended outcome, not a gap: the ``CVSS:4.0/`` prefix is required by the
    CVSS v4 spec, so a prefix-less value in that field is malformed, and it
    still prints when it is all that source sent. Ranking on the field alone
    is the behaviour this ordering replaced.
    """
    if not isinstance(details, dict):
        return []
    versioned: list[_CvssCandidate] = []
    unversioned: list[_CvssCandidate] = []
    for key in _CVSS_VECTOR_SOURCES:
        vector = details.get(key)
        if not isinstance(vector, str):
            continue
        text = vector.strip()
        if not text or not looks_like_vector(text):
            continue
        version = _cvss_version(key, text)
        (versioned if version else unversioned).append(_CvssCandidate(text, version))
    # Newest scoring first, by the version read off the vector itself rather
    # than by the field it arrived in. The two agree until a vector is
    # misfiled, and then field order picks the older one: a `CVSS:3.0/...`
    # string in cvss_v4_vector would outrank the correctly filed
    # `CVSS:3.1/...` and print 3.0 beside an Attack Vector parsed from it —
    # an older scoring, and a different answer, while the newer vector sat
    # unused on the same row. Misfiling is already assumed reachable here:
    # the versioned/unversioned split exists to catch a v2-shaped string in
    # the v4 field. Sorting is stable and `reverse` preserves ties, so field
    # order still breaks a tie between equal versions.
    versioned.sort(key=lambda c: _version_rank(c.version), reverse=True)
    return versioned + unversioned


def _version_rank(version: str) -> tuple[int, int]:
    """Sortable (major, minor) for a version string from ``_cvss_version``.

    ``"2"`` is ``(2, 0)`` so it compares against ``"3.0"`` without a bare
    ``(2,)`` sorting below it on length. Unparseable input sorts last rather
    than raising — ``_cvss_version`` only ever returns digits, so this is a
    guard, not a path.
    """
    major, _, minor = version.partition(".")
    try:
        return (int(major), int(minor) if minor else 0)
    except ValueError:  # pragma: no cover - _cvss_version cannot produce this
        return (0, 0)


class _CvssCells(NamedTuple):
    """The three CVSS cells one CVE contributes to a row.

    Named for the same reason as ``_CvssCandidate``: all three are strings,
    and the columns are written to the output frame in this order, so a
    reordering would type-check clean and put the label in the version
    column. ``_CVSS_CELL_COLUMNS`` below pins the field names to the headers.
    """

    vector: str
    version: str
    label: str


_CVSS_CELL_COLUMNS = {
    "vector": "CVSS Vector",
    "version": "CVSS Version",
    "label": "Attack Vector",
}

# `CVSS v3 Vector` is the header the renamed column shipped as through
# 2.0.x, kept alive for one
# release and removed at 3.0.0. Renaming it outright would have broken every
# consumer keyed on the old name with no error — just a column that stopped
# existing.
#
# It carries the v3 vector, NOT the value of the renamed column. Mirroring
# `CVSS Vector` here would hand a consumer that parses this cell as
# `CVSS:3.x/…` a v2 or v4 string instead, which is a quiet wrong answer where
# the missing column was at least a loud one — the worse of the two failures,
# and not what a compatibility shim is for. Reading the v3 field directly also
# keeps it faithful for a CVE scored under both v3 and v4: the old column
# showed the v3 vector, and so does this, even though v4 now wins the real
# column. The one old behaviour deliberately not reproduced is printing a
# placeholder (`n/a`, a bare `CVSS:3.1`) as if it were a vector.
#
# Consumers that want the fix move to `CVSS Vector` plus `CVSS Version`; that
# is what the deprecation window is for.
#
# CSV, XLSX and JSON only. HTML is read by people, where a duplicate column is
# noise rather than compatibility, and the Markdown findings table never
# carried a vector column in a shipped release, so it has no consumer to keep
# working.
_CVSS_V3_ALIAS_COLUMN = "CVSS v3 Vector"
_CVSS_V3_SOURCE = "cvss_v3_vector"


def _cvss_v3_only(details: Any) -> str:
    """The v3 vector alone, for the deprecated `CVSS v3 Vector` column.

    Gated on the value declaring a 3.x version, not merely on the field it
    arrived in. The whole promise of this column is that a consumer parsing it
    as ``CVSS:3.x/…`` is never handed something else, and this module treats
    misfiling as reachable everywhere else — a ``CVSS:4.0/…`` sitting in the
    v3 field would otherwise walk straight through the one column whose job is
    to be predictable.

    So a misfiled v4, a prefix-less string (a v2 vector, or a malformed v3 one
    the spec requires a prefix on) and a placeholder all read blank here. That
    is narrower than the raw field read this replaces; the values it drops are
    ones a consumer parsing for v3 could not have used anyway, and every one
    of them is still available in ``CVSS Vector``.
    """
    if not isinstance(details, dict):
        return ""
    vector = details.get(_CVSS_V3_SOURCE)
    if not isinstance(vector, str):
        return ""
    text = vector.strip()
    if not looks_like_vector(text):
        return ""
    return text if _cvss_version(_CVSS_V3_SOURCE, text).startswith("3") else ""


def _cvss_columns(details: Any) -> _CvssCells:
    """The ``(CVSS Vector, CVSS Version, Attack Vector)`` triple for one CVE.

    The vector is the top candidate from ``_cvss_vectors`` — normally the
    newest version NVD published, v4 else v3 else v2 — printed as published
    apart from trimmed surrounding whitespace. The version is the one
    ``_cvss_vectors`` already read off that same string, so the two cells
    cannot disagree; it is empty only when no vector was printed or when the
    printed one carries no readable version.

    The label is that vector's ``AV:`` metric. When the newest vector carries
    no readable AV metric, the next candidate on the ranked list supplies the
    label rather than the cell going blank: losing a real attack vector to a
    malformed string is the worse outcome, and the vector is printed next to
    the label either way. Usually that candidate is an older version's
    vector, but it can be a demoted one from a newer field, so this is not a
    fall *back* in version order — it is the next usable ``AV:`` on the list.
    Either way the label then comes from a different scoring than the version
    and vector cells describe, which is why it only fires on a vector the
    ``AV:`` parse could not read at all.

    A v2 vector is coarser than a v3/v4 one: v2 has no Physical value and
    scores physical access as Local, so a physical-only v2 CVE labels
    "Local". That is the price of filling the cell at all for CVEs NVD never
    rescored, and it beats showing nothing.

    One function returns all three so a caller cannot populate one column
    without the others.
    """
    vectors = _cvss_vectors(details)
    label = next(
        (label for vector, _ in vectors if (label := _attack_vector_label(vector))),
        "",
    )
    vector, version = vectors[0] if vectors else ("", "")
    return _CvssCells(vector=vector, version=version, label=label)


_CSV_COLUMNS = [
    "CVE ID",
    "Severity",
    "CVSS",
    "KEV",
    "Project Name",
    "Project Version",
    "Folder",
    "Component Group",
    "Component",
    "Component Version",
    "Status",
    "Reachability",
    "Detected",
    "Exploit Maturity",
    "# exploit signal categories",
    "# in-the-wild exploitation signals",
    "CWE",
    "Description",
    "CVSS Version",
    "Attack Vector",
    "CVSS Vector",
    _CVSS_V3_ALIAS_COLUMN,
    "NVD URL",
    "FS Link",
]


def findings_by_project_pandas_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Config,
    additional_data: dict[str, Any] | None = None,
) -> pd.DataFrame:
    """
    Transform findings data for the Findings by Project report with optional project filtering.

    Args:
        data: Raw findings data from API (list of dicts or DataFrame)
        config: Configuration including optional project_filter
        additional_data: Optional dict with cve_details and domain for enrichment

    Returns:
        Processed DataFrame with findings organized by project
    """

    # Exploit-maturity tiers to keep, using the same tier vocabulary and the
    # same `--exploit-maturity` flag as CRA Compliance. Empty/None = no filter.
    #
    # Matching is EXACT SET MEMBERSHIP, deliberately: tiers do not imply one
    # another. `/findings.exploitMaturity` is a single scalar carrying the
    # finding's HIGHEST tier, so a `poc` threshold does not return a weaponized
    # finding even though a weaponized exploit implies a PoC exists — the
    # platform GUI's PoC filter treats the tiers as ordered and does include
    # them, so GUI parity needs `poc,weaponized`. Exact match is what makes this
    # flag mean the same thing here as in CRA; the ordering caveat and its
    # measured effect belong in the operator docs (CLI help, the recipes skill,
    # REPORT_GUIDE), not inferred here.
    maturity_tiers = normalize_tiers(
        getattr(config, "exploit_maturity_threshold", None)
    )
    # Fail loud on an unrecognized tier, exactly as cra_compliance_transform
    # does. The CLI already validates at parse time, but a programmatic caller
    # building a Config directly bypasses that — and an unknown tier never
    # matches a finding, so without this the report would silently narrow to
    # empty while disclosing the typo as if it were a real filter. Validated
    # BEFORE the empty-payload early returns below: a misconfiguration is a
    # misconfiguration regardless of what the fetch happened to return.
    validate_tier_names(maturity_tiers)

    if isinstance(data, pd.DataFrame):
        if data.empty:
            return pd.DataFrame()
        df = data.copy()
    elif not data:
        return pd.DataFrame()
    else:
        # Convert to DataFrame
        df = pd.DataFrame(data)

    # Flatten nested data structures first. The tier column is derived here,
    # while inKev / inVcKev / exploitInfo are still on the frame — the engine's
    # per-batch prune drops them before this transform runs, so on that path
    # `exploit_tiers` is already present and the derivation is skipped.
    df = flatten_findings_data(df, derive_exploit_tiers=bool(maturity_tiers))

    if maturity_tiers:
        # Vectorized set membership: pad both sides with the separator so a
        # substring can't cross a tier boundary — a bare "kev" search would
        # otherwise also match "cisa-kev".
        wanted = "|".join(re.escape(f",{tier},") for tier in maturity_tiers)
        padded = "," + df["exploit_tiers"].fillna("").astype(str) + ","
        df = df[padded.str.contains(wanted, regex=True, na=False)]
        if df.empty:
            # Keep the output schema on a filtered-to-zero result so CSV/XLSX
            # carry a header row: a filter that matched nothing is a report
            # ("zero rows passed"), and a zero-byte file reads as a failed run.
            # The no-data-at-all early returns above stay bare deliberately —
            # that is the "nothing fetched" case, not a narrowing.
            return pd.DataFrame(columns=_CSV_COLUMNS)

    # Apply component filter if specified
    component_filter = getattr(config, "component_filter", None)
    if component_filter:
        from fs_report.transforms.pandas._component_filter import (
            apply_component_filter,
        )

        match_mode = getattr(config, "component_match", "contains")
        df = apply_component_filter(
            df,
            component_filter,
            match_mode=match_mode,
            name_col="component.name",
            version_col="component.version",
        )
        if df.empty:
            # Same rule as the maturity filter above: filtered-to-zero keeps
            # the output schema so tabular formats get a header row.
            return pd.DataFrame(columns=_CSV_COLUMNS)

    # Select and rename required columns
    required_columns = {
        "cvss_score": "CVSS",
        # Renamed 2026-05-26 (customer-driven column-naming proposal). Old
        # column name "# of known exploits" was misleading — it's len(exploitInfo),
        # i.e. the count of *signal categories* (poc/weaponized/commercial/kev/
        # vcKev/reported/threatActors/ransomware/botnets) the platform observed,
        # not a count of per-source exploit references. The truthful name
        # caps the cardinality customers see and stops the silent disagreement
        # with the platform UI's "Exploits" tab (`counts.exploits`).
        "exploit_count": "# exploit signal categories",
        # Renamed 2026-05-26. Old column name "# of known weaponization" implied
        # it counted weaponized-tier exploits, but the underlying logic scans
        # exploitInfo tokens for `botnet`/`ransomware`/`threat`/`actor` —
        # i.e. in-the-wild exploitation evidence, not maturity tier. The new
        # name aligns the header with what the column actually counts.
        "weaponization_count": "# in-the-wild exploitation signals",
        # Direct field from API; single-value tier string ("poc"/"weaponized"
        # or empty). Mirrors the platform GUI's `columns.exploitMaturity` so
        # operators can filter on maturity tier from script output. Snake-case
        # `exploit_maturity` (the cache-layer name in FINDINGS_FIELDS) is
        # normalized to `exploitMaturity` in flatten_findings_data so this
        # single mapping covers both ingestion paths.
        "exploitMaturity": "Exploit Maturity",
        "component.group": "Component Group",
        "component.name": "Component",
        "component.version": "Component Version",
        "cwe_id": "CWE",
        "folder_name": "Folder",
        "project.name": "Project Name",
        "project.version": "Project Version",
        "cve_id": "CVE ID",
        "severity": "Severity",
        "detected": "Detected",
        "status": "Status",
        "reachability_label": "Reachability",
        "kev_label": "KEV",
    }

    # Create output DataFrame with required columns
    output_df = pd.DataFrame()
    for api_col, output_col in required_columns.items():
        if api_col in df.columns:
            output_df[output_col] = df[api_col]
        else:
            # Handle missing columns gracefully
            output_df[output_col] = None

    # Carry over internal IDs for link construction (not displayed in table).
    # source_project_id is set by the engine's --product-only roll-up: it holds
    # the project the finding ACTUALLY lives in after project.id was repointed
    # at the owning product, and the FS Link below must use it — the platform
    # URL needs the real project + version pair, and a product id paired with a
    # dependency's version id is a dead link.
    for internal_col in (
        "finding_numeric_id",
        "project.id",
        "projectVersion.id",
        "source_project_id",
    ):
        if internal_col in df.columns:
            output_df[internal_col] = df[internal_col].values

    # Carry over dependency path columns (added by dependency expansion)
    for dep_col in ("dependency_path", "component_dependency_path"):
        if dep_col in df.columns:
            output_df[dep_col] = df[dep_col].values

    # Free the large intermediate DataFrame now that we've extracted needed columns
    del df

    # --- Enrich with CVE details from additional_data ---
    cve_details: dict[str, dict[str, str]] = {}
    domain = ""
    if additional_data:
        cve_details = additional_data.get("cve_details", {})
        domain = additional_data.get("domain", "")

    # Description and CVSS Vector from the cve_details lookup. The vector is
    # the newest version NVD published for the CVE — v4, else v3, else v2 — as
    # published. A single version-specific column (it was CVSS v3 Vector until
    # this release) printed nothing for every pre-2016 CVE NVD never rescored,
    # CVE-2014-7186 among them.
    output_df["Description"] = output_df["CVE ID"].map(
        lambda cve: (
            cve_details.get(cve, {}).get("description", "") if cve_details else ""
        )
    )

    # All three CVSS cells come off one ranked list per CVE: the vector cell
    # is the best candidate (newest version NVD published, except that a
    # string with no readable version is demoted below one that has it), CVSS
    # Version is the version read off that same string, and the Attack Vector
    # label is its AV: — or the next candidate's AV: when the winner carries
    # no readable one, so a malformed string cannot blank a real attack
    # vector.
    # Derived here rather than from the API's attackVector field, and in one
    # pass so the cells cannot drift apart. A v2 vector yields the coarser
    # v2 label (no Physical; physical access scores as Local).
    _cvss_cells = [
        (
            _cvss_columns(cve_details.get(cve, {}))
            if cve_details
            else _CvssCells("", "", "")
        )
        for cve in output_df["CVE ID"]
    ]
    _cvss_cols = [_CVSS_CELL_COLUMNS[f] for f in _CvssCells._fields]
    output_df[_cvss_cols] = pd.DataFrame(
        _cvss_cells, columns=_cvss_cols, index=output_df.index
    )
    # Read from the v3 field, not copied from the column above — the two are
    # deliberately different values. See _CVSS_V3_ALIAS_COLUMN.
    output_df[_CVSS_V3_ALIAS_COLUMN] = output_df["CVE ID"].apply(
        lambda cve: _cvss_v3_only(cve_details.get(cve, {})) if cve_details else ""
    )

    # NVD URL — constructed from CVE ID (GHSA IDs link to GitHub Advisories,
    # PYSEC IDs link to OSV)
    output_df["NVD URL"] = output_df["CVE ID"].apply(
        lambda cve: (
            f"https://github.com/advisories/{cve}"
            if isinstance(cve, str) and cve.startswith("GHSA-")
            else (
                f"https://osv.dev/vulnerability/{cve}"
                if isinstance(cve, str) and cve.startswith("PYSEC-")
                else (
                    f"https://nvd.nist.gov/vuln/detail/{cve}"
                    if isinstance(cve, str) and cve and cve != "N/A"
                    else ""
                )
            )
        )
    )

    # FS Link — constructed from domain + project.id + projectVersion.id + finding_numeric_id
    if (
        domain
        and "project.id" in output_df.columns
        and "projectVersion.id" in output_df.columns
        and "finding_numeric_id" in output_df.columns
    ):

        def _fs_link(row: Any) -> str:
            # Prefer the pre-roll-up project id: under --product-only the
            # project.id column points at the owning PRODUCT, but the finding
            # lives in the dependency project's version on the platform.
            link_pid = row.get("source_project_id") or row.get("project.id")
            if (
                link_pid
                and row.get("projectVersion.id")
                and row.get("finding_numeric_id")
            ):
                return (
                    f"https://{domain}/projects/{link_pid}"
                    f"/versions/{row.get('projectVersion.id', '')}"
                    f"/findings?findingId={row.get('finding_numeric_id', '')}"
                )
            return ""

        output_df["FS Link"] = output_df.apply(_fs_link, axis=1)
    else:
        output_df["FS Link"] = ""

    # Drop internal ID columns (not needed in output)
    output_df = output_df.drop(
        columns=[
            "finding_numeric_id",
            "project.id",
            "projectVersion.id",
            "source_project_id",
        ],
        errors="ignore",
    )

    # Apply canonical column ordering (+ dependency columns when present)
    csv_cols = [c for c in _CSV_COLUMNS if c in output_df.columns]
    for dep_col in ("dependency_path", "component_dependency_path"):
        if dep_col in output_df.columns:
            csv_cols.append(dep_col)
    output_df = output_df[csv_cols]

    # Sort: projects as contiguous blocks ordered by finding count
    # (descending), CVSS descending within each block. The old
    # ["CVSS", "Project Name"] sort interleaved projects, which made the
    # template's project-divider rows fire repeatedly and left the
    # project order looking arbitrary (2026-06-06 visual QA).
    project_totals = output_df.groupby("Project Name")["Project Name"].transform("size")
    output_df = (
        output_df.assign(_project_total=project_totals)
        .sort_values(
            ["_project_total", "Project Name", "CVSS"],
            ascending=[False, True, False],
        )
        .drop(columns=["_project_total"])
    )

    # Handle missing data gracefully
    output_df = output_df.fillna(
        {
            "CVE ID": "N/A",
            "CVSS": 0,
            "# exploit signal categories": 0,
            "# in-the-wild exploitation signals": 0,
            "Exploit Maturity": "",
            "Component Group": "",
            "Component": "Unknown",
            "Component Version": "Unknown",
            "CWE": "Unknown",
            "Project Name": "Unknown",
            "Project Version": "Unknown",
            "Severity": "",
            "Detected": "",
            "Status": "",
            "Reachability": "UNKNOWN",
            "KEV": "",
            "Description": "",
            "CVSS Version": "",
            "Attack Vector": "",
            "CVSS Vector": "",
            _CVSS_V3_ALIAS_COLUMN: "",
            "NVD URL": "",
            "FS Link": "",
        }
    )

    return output_df


def _exploit_tier_series(df: pd.DataFrame) -> pd.Series:
    """Derive the comma-joined CRA exploit-tier set for each row.

    Reuses ``fs_report.cra.tiers.derive_tiers`` so the tier names behind
    ``--exploit-maturity`` can never drift between this report and CRA
    Compliance. The signal columns are normalized first because ``derive_tiers``
    reads a raw API record: a NaN ``inKev`` is truthy in Python and would
    otherwise promote every row to ``cisa-kev``.

    ``exploitInfo`` is a list of plain token strings (verified against a live
    deployment 2026-08-24: 113 of 113 sampled exploit-carrying findings had
    string elements, e.g. ``["commercial", "weaponized", "poc"]``), which is what
    ``derive_tiers`` tests membership against. A non-list value is treated as no
    tokens rather than coerced — the sibling ``exploitInfo`` counters in this
    file accept dict elements, but they only count, whereas guessing a token out
    of an unexpected shape here would silently change which rows a filter keeps.
    Because those counters DO accept dict elements, a payload that ever shipped
    them would show in-the-wild signal counts on rows the tier filter drops — so
    non-string elements are warned about loudly below instead of ignored.
    """

    def _flag(col: str) -> pd.Series:
        if col not in df.columns:
            return pd.Series(False, index=df.index)
        return df[col].fillna(False).astype(bool)

    if "exploitMaturity" in df.columns:
        maturity = df["exploitMaturity"].fillna("").astype(str).str.strip().str.lower()
    else:
        maturity = pd.Series("", index=df.index)
    info = (
        df["exploitInfo"]
        if "exploitInfo" in df.columns
        else pd.Series([[]] * len(df), index=df.index)
    )

    kev_flags = _flag("inKev")
    vc_flags = _flag("inVcKev")
    # isinstance FIRST: bool() on a numpy array raises "truth value of an
    # array is ambiguous", and some ingestion paths can hand back array cells.
    has_tokens = info.map(lambda tokens: isinstance(tokens, list) and bool(tokens))

    # Non-string elements derive no tiers (see docstring) but DO feed the
    # exploit-signal counters — surface that divergence instead of hiding it.
    nonstring_rows = int(
        info.map(
            lambda tokens: isinstance(tokens, list)
            and any(not isinstance(t, str) for t in tokens)
        ).sum()
    )
    if nonstring_rows:
        logger.warning(
            "%d finding(s) carry non-string exploitInfo elements; they count "
            "toward the exploit-signal columns but derive no exploit-maturity "
            "tiers, so --exploit-maturity cannot match them. Live payloads "
            "carry string tokens — this shape is unexpected.",
            nonstring_rows,
        )

    # A row with no exploit signal at all can only derive the empty tier set, so
    # call derive_tiers on the rows that carry one. On real data that is a small
    # minority (113 of 1,000 sampled findings), which is what keeps this pass
    # affordable on a portfolio-scale frame — while every row that could produce
    # a tier still goes through the shared CRA classifier rather than a
    # reimplementation of it here.
    signalled = kev_flags | vc_flags | maturity.ne("") | has_tokens
    out = pd.Series("", index=df.index, dtype=object)
    if not signalled.any():
        return out

    derived = [
        ",".join(
            sorted(
                derive_tiers(
                    {
                        "inKev": kev,
                        "inVcKev": vc_kev,
                        "exploitMaturity": mat,
                        "exploitInfo": tokens if isinstance(tokens, list) else [],
                    }
                )
            )
        )
        for kev, vc_kev, mat, tokens in zip(
            kev_flags[signalled],
            vc_flags[signalled],
            maturity[signalled],
            info[signalled],
            strict=True,
        )
    ]
    out.update(pd.Series(derived, index=df.index[signalled], dtype=object))
    return out


def flatten_for_config(config: Any) -> Callable[[pd.DataFrame], pd.DataFrame]:
    """Return the per-batch flatten callable the engine should use for this run.

    ``--exploit-maturity`` needs the tier column derived while inKev / inVcKev /
    exploitInfo are still on the frame — the engine's per-batch prune drops them
    right after flattening. Binding that here keeps the engine's seven call sites
    plain one-argument calls, and an unfiltered run pays nothing for the per-row
    derivation pass.
    """
    if normalize_tiers(getattr(config, "exploit_maturity_threshold", None)):
        return partial(flatten_findings_data, derive_exploit_tiers=True)
    return flatten_findings_data


def flatten_findings_data(
    df: pd.DataFrame, derive_exploit_tiers: bool = False
) -> pd.DataFrame:
    """
    Flatten nested data structures in findings DataFrame and extract all required fields.

    Args:
        df: Raw findings DataFrame
        derive_exploit_tiers: add the ``exploit_tiers`` column used by the
            ``--exploit-maturity`` filter. Off by default because it costs a
            per-row pass; the engine binds it on only when the flag is set.

    Returns:
        Flattened DataFrame with all required fields extracted
    """
    import ast

    # Normalize snake_case cache-layer field names back to the camelCase API
    # names this transform expects. fs_report.sqlite_cache._row_to_record
    # usually does this reverse mapping when reading cached rows, but some
    # pre-flattened ingestion paths leak the snake_case form. Map only the
    # fields this transform consumes directly.
    #
    # All four exploit-signal fields are mapped, not just exploitMaturity: the
    # tier derivation below reads inKev / inVcKev / exploitInfo too, and a
    # snake_case leak there would silently derive NO kev/token tiers — dropping
    # rows from a `--exploit-maturity kev` run rather than failing loudly.
    for _snake, _camel in (
        ("exploit_maturity", "exploitMaturity"),
        ("exploit_info", "exploitInfo"),
        ("in_kev", "inKev"),
        ("in_vc_kev", "inVcKev"),
    ):
        if _snake in df.columns and _camel not in df.columns:
            df[_camel] = df[_snake]

    if derive_exploit_tiers and "exploit_tiers" not in df.columns:
        df["exploit_tiers"] = _exploit_tier_series(df)

    # Handle component data
    if "component" in df.columns:

        def extract_component_name(component: Any) -> str:
            if isinstance(component, dict):
                return str(component.get("name", "Unknown"))
            if isinstance(component, str):
                try:
                    comp = ast.literal_eval(component)
                    if isinstance(comp, dict):
                        return str(comp.get("name", "Unknown"))
                except Exception:
                    pass
                return component.strip() if component.strip() else "Unknown"
            return "Unknown"

        def extract_component_version(component: Any) -> str:
            if isinstance(component, dict):
                return str(component.get("version", "Unknown"))
            if isinstance(component, str):
                try:
                    comp = ast.literal_eval(component)
                    if isinstance(comp, dict):
                        return str(comp.get("version", "Unknown"))
                except Exception:
                    pass
            return "Unknown"

        def extract_component_group(component: Any) -> str:
            if isinstance(component, dict):
                purl = component.get("purl", "")
                if purl:
                    info = parse_purl(purl)
                    if info and info.namespace:
                        return info.namespace
            return ""

        df["component.name"] = df["component"].apply(extract_component_name)
        df["component.version"] = df["component"].apply(extract_component_version)
        # Non-destructive: only write the purl-derived group where the column
        # is empty (or not yet populated).  Engine-level SBOM enrichment
        # pre-populates component.group before the transform runs — clobbering
        # it here would defeat that enrichment.
        derived = df["component"].apply(extract_component_group)
        if "component.group" in df.columns:
            empty_mask = df["component.group"].fillna("").eq("")
            df.loc[empty_mask, "component.group"] = derived[empty_mask]
        else:
            df["component.group"] = derived

    # Handle project data
    if "project" in df.columns:

        def extract_project_name(project: Any) -> str:
            if isinstance(project, dict):
                return str(project.get("name", "Unknown"))
            if isinstance(project, str):
                try:
                    proj = ast.literal_eval(project)
                    if isinstance(proj, dict):
                        return str(proj.get("name", "Unknown"))
                except Exception:
                    pass
                return project.strip() if project.strip() else "Unknown"
            return "Unknown"

        def extract_project_id(project: Any) -> Any:
            if isinstance(project, dict):
                return project.get("id", "Unknown")
            if isinstance(project, str):
                try:
                    proj = ast.literal_eval(project)
                    if isinstance(proj, dict):
                        return proj.get("id", "Unknown")
                except Exception:
                    pass
            return "Unknown"

        df["project.name"] = df["project"].apply(extract_project_name)
        df["project.id"] = df["project"].apply(extract_project_id)

    # Handle projectVersion data
    if "projectVersion" in df.columns:

        def extract_project_version(project_version: Any) -> str:
            if isinstance(project_version, dict):
                return str(project_version.get("version", "Unknown"))
            if isinstance(project_version, str):
                try:
                    pv = ast.literal_eval(project_version)
                    if isinstance(pv, dict):
                        return str(pv.get("version", "Unknown"))
                except Exception:
                    pass
            return "Unknown"

        def extract_project_version_id(project_version: Any) -> Any:
            if isinstance(project_version, dict):
                return project_version.get("id", "")
            if isinstance(project_version, str):
                try:
                    pv = ast.literal_eval(project_version)
                    if isinstance(pv, dict):
                        return pv.get("id", "")
                except Exception:
                    pass
            return ""

        df["project.version"] = df["projectVersion"].apply(extract_project_version)
        df["projectVersion.id"] = df["projectVersion"].apply(extract_project_version_id)

    # Handle CVE ID from findingId
    if "findingId" in df.columns:
        df["cve_id"] = df["findingId"]

    # Extract finding numeric id (for FS link construction)
    if "id" in df.columns:
        df["finding_numeric_id"] = df["id"]

    # Extract severity (already in API response)
    if "severity" not in df.columns:
        df["severity"] = ""

    # Handle CVSS score from risk field
    if "risk" in df.columns:

        def extract_cvss_score(risk: Any) -> float:
            try:
                score = float(risk)
                # API returns risk as 0-100; always convert to 0-10 CVSS scale
                return round(score / 10.0, 1)
            except Exception:
                return 0.0

        df["cvss_score"] = df["risk"].apply(extract_cvss_score)

    # Handle CWE data from cwes field
    if "cwes" in df.columns:

        def extract_cwe_id(cwes: Any) -> str:
            if isinstance(cwes, list) and cwes:
                # Clean up CWE format (remove "CWE-" prefix if doubled)
                cwe = str(cwes[0]).replace("CWE-CWE-", "CWE-")
                return cwe
            if isinstance(cwes, str):
                try:
                    cwe_list = ast.literal_eval(cwes)
                    if isinstance(cwe_list, list) and cwe_list:
                        cwe = str(cwe_list[0]).replace("CWE-CWE-", "CWE-")
                        return cwe
                except Exception:
                    pass
                # Try regex to find CWE pattern
                match = re.search(r"CWE-\d+", cwes)
                if match:
                    return match.group(0)
            return "Unknown"

        df["cwe_id"] = df["cwes"].apply(extract_cwe_id)

    # Handle exploit info
    if "exploitInfo" in df.columns:

        def count_exploits(exploit_data: Any) -> int:
            if isinstance(exploit_data, list):
                return len(exploit_data)
            else:
                return 0

        def calculate_weaponization_count(exploit_info: Any) -> int:
            if not exploit_info or not isinstance(exploit_info, list):
                return 0
            count = 0
            for item in exploit_info:
                if isinstance(item, dict):
                    # Count botnets, ransomware, and threat actors
                    if any(
                        keyword in str(item).lower()
                        for keyword in ["botnet", "ransomware", "threat", "actor"]
                    ):
                        count += 1
                elif isinstance(item, str):
                    # Count if string contains weaponization keywords
                    if any(
                        keyword in item.lower()
                        for keyword in ["botnet", "ransomware", "threat", "actor"]
                    ):
                        count += 1
            return count

        df["exploit_count"] = df["exploitInfo"].apply(count_exploits).astype("int64")
        df["weaponization_count"] = (
            df["exploitInfo"].apply(calculate_weaponization_count).astype("int64")
        )
    else:
        # Preserve already-computed columns (report engine pre-flattens
        # and drops exploitInfo before the transform re-enters here).
        if "exploit_count" not in df.columns:
            df["exploit_count"] = 0
        if "weaponization_count" not in df.columns:
            df["weaponization_count"] = 0

    # Normalize the count columns to int64. The pre-flattened path can
    # leave them as float64 (NaN-imputable). Downstream CSV / JSON
    # consumers expect integers, not `8.0`-style values.
    for _count_col in ("exploit_count", "weaponization_count"):
        if _count_col in df.columns:
            df[_count_col] = (
                pd.to_numeric(df[_count_col], errors="coerce").fillna(0).astype("int64")
            )

    # Handle reachability score
    if "reachabilityScore" in df.columns:
        raw = pd.to_numeric(df["reachabilityScore"], errors="coerce")
        df["reachability_label"] = raw.apply(
            lambda s: (
                "UNKNOWN"
                if pd.isna(s)
                else (
                    "REACHABLE"
                    if s > 0
                    else ("UNREACHABLE" if s < 0 else "INCONCLUSIVE")
                )
            )
        )
    else:
        if "reachability_label" not in df.columns:
            df["reachability_label"] = "UNKNOWN"

    # Handle KEV (Known Exploited Vulnerabilities) indicator
    if "inKev" in df.columns:
        df["kev_label"] = (
            df["inKev"].fillna(False).astype(bool).map({True: "Yes", False: ""})
        )
    else:
        if "kev_label" not in df.columns:
            df["kev_label"] = ""

    # Ensure all required columns exist with defaults
    if "cvss_score" not in df.columns:
        df["cvss_score"] = 0.0
    if "cve_id" not in df.columns:
        df["cve_id"] = "N/A"
    if "cwe_id" not in df.columns:
        df["cwe_id"] = "Unknown"
    if "component.group" not in df.columns:
        df["component.group"] = ""
    if "component.name" not in df.columns:
        df["component.name"] = "Unknown"
    if "component.version" not in df.columns:
        df["component.version"] = "Unknown"
    if "project.name" not in df.columns:
        df["project.name"] = "Unknown"
    if "project.version" not in df.columns:
        df["project.version"] = "Unknown"

    return df
