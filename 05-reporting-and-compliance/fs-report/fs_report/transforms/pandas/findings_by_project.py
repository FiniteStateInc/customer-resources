"""
Pandas transform functions for Findings by Project report.
"""

import logging
import re
from collections.abc import Callable
from functools import partial
from typing import Any

import pandas as pd

# derive_tiers is imported from the CRA module on purpose: a tier name must mean
# the same thing in `--exploit-maturity` regardless of which recipe reads it.
from fs_report.cra.tiers import derive_tiers, normalize_tiers, validate_tier_names
from fs_report.models import Config
from fs_report.purl_utils import parse_purl

logger = logging.getLogger(__name__)

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
    "CVSS v3 Vector",
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

    # Description, CVSS v3 Vector from cve_details lookup. CVSS v2 Vector was
    # dropped (2026-06-14) — NVD stopped assigning CVSS v2 (~2016+), so it is
    # ~always empty for modern data.
    output_df["Description"] = output_df["CVE ID"].map(
        lambda cve: (
            cve_details.get(cve, {}).get("description", "") if cve_details else ""
        )
    )
    output_df["CVSS v3 Vector"] = output_df["CVE ID"].map(
        lambda cve: (
            cve_details.get(cve, {}).get("cvss_v3_vector", "") if cve_details else ""
        )
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
            "CVSS v3 Vector": "",
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
