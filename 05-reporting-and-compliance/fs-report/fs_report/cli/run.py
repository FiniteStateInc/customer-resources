"""The 'run' command: generate reports."""

import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Union, cast

if TYPE_CHECKING:
    from fs_report.vex_applier import VexApplyResult

import click
import typer
from rich.console import Console

from fs_report.cli.common import (
    attach_file_logging,
    get_default_dates,
    load_config_file,
    merge_config,
    redact_token,
    setup_logging,
)
from fs_report.models import Config
from fs_report.period_parser import PeriodParser
from fs_report.renderers.pdf_renderer import cleanup_pdf_engines
from fs_report.report_engine import ReportEngine
from fs_report.scope_ref import ScopeRefError as _ScopeRefError
from fs_report.scope_ref import parse as _parse_scope_ref
from fs_report.sqlite_cache import parse_ttl

console = Console()
logger = logging.getLogger(__name__)

run_app = typer.Typer(
    name="run",
    help="Generate reports from recipes.",
    add_completion=False,
)


# ── helpers ──────────────────────────────────────────────────────────

# Canonical valid sets for --scan-types and --scan-statuses.  Lifted to
# module-level so they can be imported by the web validation layer without
# duplicating the sets (DRY).
VALID_SCAN_TYPES: frozenset[str] = frozenset(
    {"SCA", "SAST", "CONFIG", "SOURCE_SCA", "SBOM_IMPORT", "VULNERABILITY_ANALYSIS"}
)
VALID_SCAN_STATUSES: frozenset[str] = frozenset(
    {
        "INITIAL",
        "PENDING_UPLOAD",
        "UPLOAD_FAILED",
        "COMPLETED",
        "ERROR",
        "STARTED",
        "NOT_APPLICABLE",
    }
)


def _split_csv(value: Union[str, None]) -> Union[list[str], None]:
    """Split a comma-separated string into a list of stripped, non-empty strings."""
    if value is None:
        return None
    return [s.strip() for s in value.split(",") if s.strip()]


def _validate_scoring_file(path: str) -> None:
    """Fail fast if --scoring-file is missing, unreadable, or malformed.

    Thin CLI wrapper over the shared pure validator (`fs_report.scoring_support.
    validate_scoring_yaml`, also used by the serve web upload endpoint): hard
    errors → exit 1; warnings → yellow console note (preserving prior behavior).
    """
    from fs_report.scoring_support import validate_scoring_yaml

    errors, warnings = validate_scoring_yaml(path)
    for w in warnings:
        console.print(f"[yellow]Warning: {w}[/yellow]")
    if errors:
        for e in errors:
            console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


def _invalidate_findings_cache_for_versions(domain: str, results: list[dict]) -> None:
    """Invalidate cached findings for versions affected by VEX apply.

    Delegates to the shared implementation in ``fs_report.vex_apply_support``
    (also used by the serve web post-report apply path, SP2).
    """
    from fs_report.vex_apply_support import invalidate_findings_cache_for_versions

    invalidate_findings_cache_for_versions(domain, results)


# ── create_config ────────────────────────────────────────────────────


def create_config(
    recipes: Union[Path, None] = None,
    output: Union[Path, None] = None,
    start: Union[str, None] = None,
    end: Union[str, None] = None,
    period: Union[str, None] = None,
    token: Union[str, None] = None,
    domain: Union[str, None] = None,
    verbose: bool = False,
    recipe: Union[str, None] = None,
    data_file: Union[str, None] = None,
    project_filter: Union[str, None] = None,
    version_filter: Union[str, None] = None,
    folder_filter: Union[str, None] = None,
    finding_types: str = "cve",
    no_bundled_recipes: bool = False,
    current_version_only: bool = True,
    cache_ttl: int = 0,
    cache_dir: Union[str, None] = None,
    cache_refresh: bool = False,
    detected_after: Union[str, None] = None,
    ai: bool = False,
    ai_provider: Union[str, None] = None,
    ai_model_high: Union[str, None] = None,
    ai_model_low: Union[str, None] = None,
    ai_depth: str = "summary",
    ai_prompts: bool = False,
    ai_export: Union[str, None] = None,
    ai_import: Union[str, None] = None,
    ai_analysis: bool = False,
    nvd_api_key: Union[str, None] = None,
    baseline_date: Union[str, None] = None,
    baseline_version: Union[str, None] = None,
    current_version: Union[str, None] = None,
    open_only: bool = False,
    request_delay: float = 0.5,
    batch_size: int = 5,
    cve_filter: Union[str, None] = None,
    component_filter: Union[str, None] = None,
    component_match: str = "contains",
    component_version: Union[str, None] = None,
    license_filter: Union[str, None] = None,
    threat_context: Union[str, None] = None,
    skip_nvd: bool = False,
    scoring_file: Union[str, None] = None,
    tp_gate: Union[str, None] = None,
    top: int = 0,
    triage: int = 0,
    vex_override: bool = False,
    overwrite: bool = False,
    logo: Union[str, None] = None,
    apply_vex_triage: Union[str, None] = None,
    autotriage: str | None = None,
    autotriage_status: list[str] | None = None,
    scan_types: Union[str, None] = None,
    scan_statuses: Union[str, None] = None,
    low_memory: bool = False,
    context_file: Union[str, None] = None,
    product_type: Union[str, None] = None,
    network_exposure: Union[str, None] = None,
    regulatory: Union[str, None] = None,
    deployment_notes: Union[str, None] = None,
    compare_domain: Union[str, None] = None,
    compare_token: Union[str, None] = None,
    compare_project: Union[str, None] = None,
    compare_version: Union[str, None] = None,
    standalone: bool = False,
    detailed: bool = False,
    theme: Union[str, None] = None,
    since: str = "24h",
    exploit_maturity_threshold: Union[list[str], None] = None,
    include_status: Union[list[str], None] = None,
    exclude_status: Union[list[str], None] = None,
    reachable_only: bool = False,
    with_triage_age: bool = False,
    kev_due_date_source: str = "cisa",
    unfilterable_tier_strategy: str = "wide-fetch",
    snapshot_diff: str = "on",
    left_scope: Union[str, None] = None,
    right_scope: Union[str, None] = None,
) -> Config:
    """Build a Config object from CLI args, config file, and env vars."""
    _component_match: Literal["contains", "exact"] = cast(
        Literal["contains", "exact"], component_match
    )

    cfg = load_config_file()

    # Resolve --theme using the standard CLI > env > config-file > default
    # precedence, then validate. Failing here means the user sees the error
    # at parse time instead of deep in the renderer.
    theme = merge_config(theme, "FS_REPORT_THEME", "theme", "auto", config_data=cfg)
    theme_normalized = str(theme).strip().lower()
    if theme_normalized not in {"light", "dark", "auto"}:
        console.print(
            f"[red]Error: --theme must be one of 'light', 'dark', 'auto'; "
            f"got '{theme}'[/red]"
        )
        raise typer.Exit(1)
    _theme: Literal["light", "dark", "auto"] = cast(
        Literal["light", "dark", "auto"], theme_normalized
    )

    # Merge config-file values for common options
    domain = merge_config(domain, "FINITE_STATE_DOMAIN", "domain", config_data=cfg)
    token = merge_config(token, "FINITE_STATE_AUTH_TOKEN", "token", config_data=cfg)
    finding_types = merge_config(
        finding_types if finding_types != "cve" else None,
        None,
        "finding_types",
        "cve",
        config_data=cfg,
    )
    request_delay = merge_config(
        request_delay if request_delay != 0.5 else None,
        None,
        "request_delay",
        0.5,
        config_data=cfg,
    )
    batch_size = merge_config(
        batch_size if batch_size != 5 else None,
        None,
        "batch_size",
        5,
        config_data=cfg,
    )

    # Handle period parameter. period_explicit is True when any of --period,
    # --start, or --end was user-supplied; False when all three are defaults.
    period_explicit = bool(period) or (start is not None) or (end is not None)
    if period:
        try:
            start, end = PeriodParser.parse_period(period)
        except ValueError as e:
            console.print(f"[red]Error parsing period '{period}': {e}[/red]")
            console.print(PeriodParser.get_help_text())
            raise typer.Exit(1)
    elif start is None or end is None:
        default_start, default_end = get_default_dates()
        start = start or default_start
        end = end or default_end

    # Validate date order
    if start and end and start > end:
        console.print(
            f"[red]Error: --start ({start}) is after --end ({end}). "
            f"Start date must be before end date.[/red]"
        )
        raise typer.Exit(1)

    # If using data file, make token and domain optional
    if data_file:
        auth_token: str = token or os.getenv("FINITE_STATE_AUTH_TOKEN") or "dummy_token"
        domain_value: str = (
            domain or os.getenv("FINITE_STATE_DOMAIN") or "test.finitestate.io"
        )
    else:
        auth_token = str(token or os.getenv("FINITE_STATE_AUTH_TOKEN") or "")
        if not auth_token:
            console.print(
                "[red]Error: API token required. Set FINITE_STATE_AUTH_TOKEN "
                "environment variable or use --token.[/red]"
            )
            raise typer.Exit(2)
        domain_value = str(domain or os.getenv("FINITE_STATE_DOMAIN") or "")
        if not domain_value:
            console.print(
                "[red]Error: Domain required. Set FINITE_STATE_DOMAIN "
                "environment variable or use --domain.[/red]"
            )
            raise typer.Exit(2)

    # Validate finding_types. binary_sca / source_sca are accepted for
    # backward compatibility but stripped with a deprecation warning —
    # they are scan types, not finding-type filters, and were silently
    # broken in every prior fs-report release that advertised them.
    valid_finding_types = {
        "cve",
        "sast",
        "thirdparty",
        "credentials",
        "config_issues",
        "crypto_material",
        "all",
    }
    deprecated_finding_types = {"binary_sca", "source_sca"}
    if finding_types:
        types_list = [t.strip().lower() for t in finding_types.split(",")]
        deprecated = [t for t in types_list if t in deprecated_finding_types]
        if deprecated:
            console.print(
                f"[yellow]Warning: --finding-types value(s) {', '.join(sorted(set(deprecated)))} "
                "are deprecated and ignored — these are scan types, not "
                "finding-type filters; the API has no equivalent filter.[/yellow]"
            )
            types_list = [t for t in types_list if t not in deprecated_finding_types]
            finding_types = ",".join(types_list) if types_list else "cve"
        invalid_types = set(types_list) - valid_finding_types
        if invalid_types:
            console.print(
                f"[red]Error: Invalid finding type(s): {', '.join(invalid_types)}[/red]"
            )
            console.print(
                f"[yellow]Valid types: {', '.join(sorted(valid_finding_types))}[/yellow]"
            )
            raise typer.Exit(1)

    # Validate scan_types
    if scan_types:
        st_list = [t.strip().upper() for t in scan_types.split(",")]
        invalid_st = set(st_list) - VALID_SCAN_TYPES
        if invalid_st:
            console.print(
                f"[red]Error: Invalid scan type(s): {', '.join(invalid_st)}[/red]"
            )
            console.print(
                f"[yellow]Valid types: {', '.join(sorted(VALID_SCAN_TYPES))}[/yellow]"
            )
            raise typer.Exit(1)
        scan_types = ",".join(st_list)  # normalize

    # Validate scan_statuses
    if scan_statuses:
        ss_list = [s.strip().upper() for s in scan_statuses.split(",")]
        invalid_ss = set(ss_list) - VALID_SCAN_STATUSES
        if invalid_ss:
            console.print(
                f"[red]Error: Invalid scan status(es): {', '.join(invalid_ss)}[/red]"
            )
            console.print(
                f"[yellow]Valid statuses: {', '.join(sorted(VALID_SCAN_STATUSES))}[/yellow]"
            )
            raise typer.Exit(1)
        scan_statuses = ",".join(ss_list)  # normalize

    # Merge AI model overrides from config file
    ai_model_high = merge_config(
        ai_model_high, None, "ai_model_high", None, config_data=cfg
    )
    ai_model_low = merge_config(
        ai_model_low, None, "ai_model_low", None, config_data=cfg
    )

    # Merge deployment context from config file / env var
    context_file = merge_config(
        context_file, "FS_REPORT_CONTEXT_FILE", "context_file", None, config_data=cfg
    )
    product_type = merge_config(
        product_type, None, "product_type", None, config_data=cfg
    )
    network_exposure = merge_config(
        network_exposure, None, "network_exposure", None, config_data=cfg
    )
    regulatory = merge_config(regulatory, None, "regulatory", None, config_data=cfg)
    deployment_notes = merge_config(
        deployment_notes, None, "deployment_notes", None, config_data=cfg
    )

    # Validate AI options
    if ai:
        from fs_report.llm_client import AI_ENV_VARS, MODEL_MAP

        # Copilot supports interactive device flow — no env var required
        if ai_provider != "copilot":
            has_any_key = any(os.getenv(v) for v in AI_ENV_VARS)
            if not has_any_key:
                console.print(
                    "[red]Error: --ai requires one of these environment variables: "
                    + ", ".join(AI_ENV_VARS)
                    + "[/red]"
                )
                raise typer.Exit(2)
        if ai_provider and ai_provider not in MODEL_MAP:
            console.print(
                f"[red]Error: --ai-provider must be one of "
                f"{', '.join(MODEL_MAP)}, got '{ai_provider}'[/red]"
            )
            raise typer.Exit(1)
        if ai_depth not in ("summary", "full"):
            console.print(
                f"[red]Error: --ai-depth must be 'summary' or 'full', "
                f"got '{ai_depth}'[/red]"
            )
            raise typer.Exit(1)

    # Validate baseline_date format
    if baseline_date:
        try:
            from datetime import datetime

            datetime.fromisoformat(baseline_date)
        except ValueError:
            console.print(
                f"[red]Error: --baseline-date must be YYYY-MM-DD format, "
                f"got '{baseline_date}'[/red]"
            )
            raise typer.Exit(1)

    # Validate detected_after format
    if detected_after:
        try:
            from datetime import datetime

            datetime.fromisoformat(detected_after)
        except ValueError:
            console.print(
                f"[red]Error: --detected-after must be YYYY-MM-DD format, "
                f"got '{detected_after}'[/red]"
            )
            raise typer.Exit(1)

    # Merge cross-server comparison flags from env vars
    compare_domain = merge_config(
        compare_domain, "FINITE_STATE_COMPARE_DOMAIN", None, None, config_data=cfg
    )
    compare_token = merge_config(
        compare_token, "FINITE_STATE_COMPARE_AUTH_TOKEN", None, None, config_data=cfg
    )

    # Validate cross-server flags
    has_compare = any([compare_domain, compare_token, compare_project, compare_version])
    if has_compare:
        if not compare_domain or not compare_token:
            console.print(
                "[red]Error: --compare-domain and --compare-token are both required "
                "for cross-server comparison.[/red]"
            )
            raise typer.Exit(1)
        if not compare_project and not compare_version:
            console.print(
                "[red]Error: At least one of --compare-project or --compare-version "
                "is required for cross-server comparison.[/red]"
            )
            raise typer.Exit(1)

    return Config(
        auth_token=auth_token,
        domain=domain_value,
        recipes_dir=str(recipes) if recipes else None,
        use_bundled_recipes=not no_bundled_recipes,
        output_dir=str(Path(output or "./output").expanduser()),
        start_date=start,
        end_date=end,
        period_explicit=period_explicit,
        verbose=verbose,
        recipe_filter=recipe,
        project_filter=project_filter,
        version_filter=version_filter,
        folder_filter=folder_filter,
        finding_types=finding_types,
        current_version_only=current_version_only,
        cache_ttl=cache_ttl,
        cache_dir=cache_dir,
        cache_refresh=cache_refresh,
        detected_after=detected_after,
        ai=ai,
        ai_provider=ai_provider,
        ai_model_high=ai_model_high,
        ai_model_low=ai_model_low,
        ai_depth=ai_depth,
        ai_prompts=ai_prompts,
        ai_export=ai_export,
        ai_import=ai_import,
        ai_analysis=ai_analysis,
        context_file=context_file,
        product_type=product_type,
        network_exposure=network_exposure,
        regulatory=regulatory,
        deployment_notes=deployment_notes,
        nvd_api_key=nvd_api_key,
        baseline_date=baseline_date,
        baseline_version=baseline_version,
        current_version=current_version,
        open_only=open_only,
        request_delay=request_delay,
        batch_size=batch_size,
        cve_filter=cve_filter,
        component_filter=component_filter,
        component_match=_component_match,
        component_version=component_version,
        license_filter=license_filter,
        threat_context=threat_context,
        skip_nvd=skip_nvd,
        scoring_file=scoring_file,
        tp_gate=tp_gate,
        top=top,
        triage=triage,
        vex_override=vex_override,
        overwrite=overwrite,
        logo=logo,
        apply_vex_triage=apply_vex_triage,
        autotriage=autotriage,
        autotriage_status=autotriage_status,
        scan_types=scan_types,
        scan_statuses=scan_statuses,
        low_memory=low_memory,
        compare_domain=compare_domain,
        compare_auth_token=compare_token,
        compare_project=compare_project,
        compare_version=compare_version,
        standalone=standalone,
        detailed_mode=detailed,
        theme=_theme,
        since=since,
        exploit_maturity_threshold=exploit_maturity_threshold,
        include_status=include_status,
        exclude_status=exclude_status,
        reachable_only=reachable_only,
        with_triage_age=with_triage_age,
        kev_due_date_source=kev_due_date_source,
        unfilterable_tier_strategy=unfilterable_tier_strategy,
        snapshot_diff=snapshot_diff,
        left_scope=left_scope,
        right_scope=right_scope,
    )


# ── run_reports ──────────────────────────────────────────────────────


def run_reports(
    recipes: Union[Path, None],
    recipe: Union[list[str], None],
    output: Union[Path, None],
    start: Union[str, None],
    end: Union[str, None],
    period: Union[str, None],
    token: Union[str, None],
    domain: Union[str, None],
    verbose: bool,
    data_file: Union[str, None],
    project_filter: Union[str, None],
    version_filter: Union[str, None],
    folder_filter: Union[str, None] = None,
    finding_types: str = "cve",
    current_version_only: bool = True,
    no_bundled_recipes: bool = False,
    cache_ttl: int = 0,
    cache_dir: Union[str, None] = None,
    refresh: bool = False,
    detected_after: Union[str, None] = None,
    ai: bool = False,
    ai_provider: Union[str, None] = None,
    ai_model_high: Union[str, None] = None,
    ai_model_low: Union[str, None] = None,
    ai_depth: str = "summary",
    ai_prompts: bool = False,
    ai_export: Union[str, None] = None,
    ai_import: Union[str, None] = None,
    ai_analysis: bool = False,
    nvd_api_key: Union[str, None] = None,
    baseline_date: Union[str, None] = None,
    baseline_version: Union[str, None] = None,
    current_version: Union[str, None] = None,
    open_only: bool = False,
    request_delay: float = 0.5,
    batch_size: int = 5,
    cve_filter: Union[str, None] = None,
    component_filter: Union[str, None] = None,
    component_match: str = "contains",
    component_version: Union[str, None] = None,
    license_filter: Union[str, None] = None,
    threat_context: Union[str, None] = None,
    skip_nvd: bool = False,
    scoring_file: Union[str, None] = None,
    tp_gate: Union[str, None] = None,
    top: int = 0,
    triage: int = 0,
    vex_override: bool = False,
    overwrite: bool = False,
    logo: Union[str, None] = None,
    apply_vex_triage: Union[str, None] = None,
    autotriage: str | None = None,
    autotriage_status: list[str] | None = None,
    dry_run: bool = False,
    vex_concurrency: int = 5,
    context_file: Union[str, None] = None,
    product_type: Union[str, None] = None,
    network_exposure: Union[str, None] = None,
    scan_types: Union[str, None] = None,
    scan_statuses: Union[str, None] = None,
    low_memory: bool = False,
    compare_domain: Union[str, None] = None,
    compare_token: Union[str, None] = None,
    compare_project: Union[str, None] = None,
    compare_version: Union[str, None] = None,
    standalone: bool = False,
    detailed: bool = False,
    theme: Union[str, None] = None,
    since: str = "24h",
    exploit_maturity_threshold: Union[list[str], None] = None,
    include_status: Union[list[str], None] = None,
    exclude_status: Union[list[str], None] = None,
    reachable_only: bool = False,
    with_triage_age: bool = False,
    kev_due_date_source: str = "cisa",
    unfilterable_tier_strategy: str = "wide-fetch",
    snapshot_diff: str = "on",
    left_scope: Union[str, None] = None,
    right_scope: Union[str, None] = None,
) -> Any:
    """Execute the report generation pipeline."""
    run_id = setup_logging(verbose)
    logger = logging.getLogger(__name__)
    file_handler = None
    try:
        data_override = None
        if data_file:
            with open(data_file, encoding="utf-8") as f:
                data_override = json.load(f)

        config = create_config(
            recipes=recipes,
            output=output,
            start=start,
            end=end,
            period=period,
            token=token,
            domain=domain,
            verbose=verbose,
            recipe=None,
            data_file=data_file,
            project_filter=project_filter,
            version_filter=version_filter,
            folder_filter=folder_filter,
            finding_types=finding_types,
            no_bundled_recipes=no_bundled_recipes,
            current_version_only=current_version_only,
            cache_ttl=cache_ttl,
            cache_dir=cache_dir,
            cache_refresh=refresh,
            detected_after=detected_after,
            ai=ai,
            ai_provider=ai_provider,
            ai_model_high=ai_model_high,
            ai_model_low=ai_model_low,
            ai_depth=ai_depth,
            ai_prompts=ai_prompts,
            ai_export=ai_export,
            ai_import=ai_import,
            ai_analysis=ai_analysis,
            context_file=context_file,
            product_type=product_type,
            network_exposure=network_exposure,
            nvd_api_key=nvd_api_key,
            baseline_date=baseline_date,
            baseline_version=baseline_version,
            current_version=current_version,
            open_only=open_only,
            request_delay=request_delay,
            batch_size=batch_size,
            cve_filter=cve_filter,
            component_filter=component_filter,
            component_match=component_match,
            component_version=component_version,
            license_filter=license_filter,
            threat_context=threat_context,
            skip_nvd=skip_nvd,
            scoring_file=scoring_file,
            tp_gate=tp_gate,
            top=top,
            triage=triage,
            vex_override=vex_override,
            overwrite=overwrite,
            logo=logo,
            apply_vex_triage=apply_vex_triage,
            autotriage=autotriage,
            autotriage_status=autotriage_status,
            scan_types=scan_types,
            scan_statuses=scan_statuses,
            low_memory=low_memory,
            compare_domain=compare_domain,
            compare_token=compare_token,
            compare_project=compare_project,
            compare_version=compare_version,
            standalone=standalone,
            detailed=detailed,
            theme=theme,
            since=since,
            exploit_maturity_threshold=exploit_maturity_threshold,
            include_status=include_status,
            exclude_status=exclude_status,
            reachable_only=reachable_only,
            with_triage_age=with_triage_age,
            kev_due_date_source=kev_due_date_source,
            unfilterable_tier_strategy=unfilterable_tier_strategy,
            snapshot_diff=snapshot_diff,
            left_scope=left_scope,
            right_scope=right_scope,
        )

        file_handler = attach_file_logging(run_id, config.auth_token)

        logger.info("Configuration:")
        logger.info(f"  Domain: {config.domain}")
        logger.info(f"  Token: {redact_token(config.auth_token)}")
        logger.info(
            f"  Recipes: bundled={'yes' if config.use_bundled_recipes else 'no'}"
            f"{', overlay=' + config.recipes_dir if config.recipes_dir else ''}"
        )
        if config.recipe_filter:
            logger.info(f"  Recipe filter: {config.recipe_filter}")
        logger.info(f"  Output directory: {config.output_dir}")
        logger.info(f"  Date range: {config.start_date} to {config.end_date}")
        logger.info(f"  Finding types: {config.finding_types}")
        if config.project_filter:
            logger.info(f"  Project: {config.project_filter}")
        if config.version_filter:
            logger.info(f"  Version: {config.version_filter}")
        if config.folder_filter:
            logger.info(f"  Folder scope: {config.folder_filter}")
        if config.standalone:
            logger.info("  Standalone mode: Yes (no dependency traversal)")
        if config.compare_domain:
            logger.info("  Cross-server comparison:")
            logger.info(f"    Compare domain: {config.compare_domain}")
            if config.compare_project:
                logger.info(f"    Compare project: {config.compare_project}")
            if config.compare_version:
                logger.info(f"    Compare version: {config.compare_version}")
        if config.baseline_version or config.current_version:
            logger.info(
                f"  Version comparison: baseline={config.baseline_version}, "
                f"current={config.current_version}"
            )
        if config.current_version_only:
            logger.info("  Current version only: Yes (filtering to latest versions)")
        if config.detected_after:
            logger.info(f"  Detected after: {config.detected_after}")
        if config.open_only:
            logger.info("  Open findings only: Yes")
        if config.cache_ttl > 0:
            logger.info(f"  SQLite cache: Enabled (TTL: {config.cache_ttl}s)")
        if config.cve_filter:
            logger.info(f"  CVE filter: {config.cve_filter}")
        if config.component_filter:
            logger.info(
                f"  Component filter: {config.component_filter} "
                f"(match: {config.component_match})"
            )
        if config.component_version:
            logger.info(f"  Component version range: {config.component_version}")
        if config.skip_nvd:
            logger.info("  NVD enrichment: Skipped (--no-nvd)")
        if config.scan_types:
            logger.info(f"  Scan types: {config.scan_types}")
        if config.scan_statuses:
            logger.info(f"  Scan statuses: {config.scan_statuses}")
        if config.low_memory:
            logger.info("  Low-memory mode: Enabled")
        if config.scoring_file:
            logger.info(f"  Scoring file: {config.scoring_file}")
        if config.tp_gate:
            logger.info(f"  TP gate filter: {config.tp_gate}")
        if config.ai:
            provider_info = (
                f", provider: {config.ai_provider}" if config.ai_provider else ""
            )
            model_info = ""
            if config.ai_model_high:
                model_info += f", model-high: {config.ai_model_high}"
            if config.ai_model_low:
                model_info += f", model-low: {config.ai_model_low}"
            logger.info(
                f"  AI remediation: Enabled (depth: {config.ai_depth}{provider_info}{model_info})"
            )
            if config.ai_prompts:
                logger.info("  AI prompts: Enabled (saving prompts to output)")
            if config.ai_analysis:
                logger.info("  AI analysis: Enabled")
            if config.product_type:
                logger.info(f"  Product type: {config.product_type}")
            if config.network_exposure:
                logger.info(f"  Network exposure: {config.network_exposure}")
            if config.context_file:
                logger.info(f"  Context file: {config.context_file}")
        if config.apply_vex_triage:
            logger.info(f"  Apply VEX triage: {config.apply_vex_triage}")
        if config.autotriage:
            logger.info(f"  Autotriage: {config.autotriage}")
        if config.autotriage_status:
            logger.info(f"  Autotriage status filter: {config.autotriage_status}")
        _nvd_svc = os.environ.get("FS_NVD_SERVICE_URL", "").strip().lower()
        if _nvd_svc == "off":
            logger.info(
                "  NVD: direct API"
                + (
                    " (key configured)"
                    if config.nvd_api_key
                    else " (no key — rate limited)"
                )
            )
        else:
            logger.info(
                "  NVD: hosted mirror"
                + (" + API key fallback" if config.nvd_api_key else "")
            )
        if config.logo:
            logger.info(f"  Logo: {config.logo}")

        # Validate mutually exclusive VEX flags
        if config.apply_vex_triage and config.autotriage:
            console.print(
                "[red]Error: --apply-vex-triage and --autotriage are "
                "mutually exclusive.[/red]"
            )
            raise typer.Exit(1)

        # ── Standalone VEX mode: apply and exit (no report generation) ──
        if config.apply_vex_triage:
            from fs_report.vex_applier import VexApplier

            console.print(
                f"[cyan]Applying VEX triage from "
                f"{config.apply_vex_triage}...[/cyan]"
            )
            filter_projects = [config.project_filter] if config.project_filter else None
            applier = VexApplier(
                auth_token=config.auth_token,
                domain=config.domain,
                concurrency=vex_concurrency,
                dry_run=dry_run,
                vex_override=config.vex_override,
                filter_projects=filter_projects,
                filter_statuses=config.autotriage_status,
            )
            result = applier.apply_file(config.apply_vex_triage)
            _print_vex_summary(result)
            if not dry_run:
                _invalidate_findings_cache_for_versions(config.domain, result.results)
            return

        # Build deployment context (shared helper — also used by the serve web
        # run path so context_file + the four scalar fields reach AI prompts).
        from fs_report.deployment_context import build_deployment_context

        try:
            deployment_ctx = build_deployment_context(config)
        except FileNotFoundError as e:
            console.print(f"[red]Error loading context file: {e}[/red]")
            raise typer.Exit(1) from e
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1) from e

        output_path = Path(config.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        engine = ReportEngine(
            config,
            data_override=data_override,
            deployment_context=deployment_ctx,
        )

        # Patch API client if using data_override
        if data_override is not None:

            class MockAPIClient:
                def __init__(self, data: dict[str, Any] | list) -> None:
                    self.data = data

                def fetch_data(self, query_config: Any) -> list[dict[str, Any]]:
                    # List overrides have no endpoint keys to match —
                    # the data is already handled by report_engine via data_override
                    if isinstance(self.data, list):
                        return []
                    endpoint = query_config.endpoint
                    for key in self.data:
                        if key in endpoint or key in getattr(query_config, "name", ""):
                            data = self.data[key]
                            if isinstance(data, list):
                                return data
                            else:
                                return [data] if data else []
                    if len(self.data) == 1:
                        data = list(self.data.values())[0]
                        if isinstance(data, list):
                            return data
                        else:
                            return [data] if data else []
                    return []

            engine.api_client = MockAPIClient(data_override)  # type: ignore[assignment]

        # Filter recipes if recipe argument is provided
        if recipe:
            if isinstance(recipe, str):  # type: ignore[unreachable]
                recipe_list = [recipe]  # type: ignore[unreachable]
            else:
                recipe_list = recipe
            # Pass argv tokens through verbatim; recipe_loader normalizes
            # both filter inputs and recipe.name through slug() for matching
            # (compound-reports design spec § 7).
            engine.recipe_loader.recipe_filter = list(recipe_list)

        run_result = engine.run()
        success = run_result.success

        if success:
            # Record run in history DB
            if engine.generated_files:
                try:
                    from fs_report.report_history import append_run

                    output_dir_abs = Path(config.output_dir).expanduser().resolve()
                    history_files = []
                    for gen_file in engine.generated_files:
                        fp = Path(gen_file).resolve()
                        try:
                            rel = fp.relative_to(output_dir_abs)
                        except ValueError:
                            continue
                        parts = rel.parts
                        recipe_name = parts[0] if len(parts) > 1 else rel.stem
                        history_files.append(
                            {
                                "recipe": recipe_name,
                                "path": str(rel),
                                "format": fp.suffix.lstrip("."),
                            }
                        )
                    recipe_list_for_history = (
                        [r.lower() for r in (recipe if recipe else [])]
                        or engine.recipe_loader.recipe_filter
                        or []
                    )
                    if not history_files:
                        raise ValueError("No files to record")
                    append_run(
                        output_dir=str(output_dir_abs),
                        domain=config.domain,
                        recipes=recipe_list_for_history,
                        scope={
                            k: v
                            for k, v in {
                                "project_filter": config.project_filter,
                                "project_name": engine.resolved_project_name,
                                "folder_filter": config.folder_filter,
                                "period": period,
                            }.items()
                            if v
                        },
                        files=history_files,
                    )
                except Exception:
                    logger.warning("Failed to record run in history", exc_info=True)

            console.print("[green]Report generation completed successfully![/green]")

            # ── Auto-triage: apply VEX after reports are fully written ──
            if autotriage:
                vex_path = next(
                    (
                        f
                        for f in engine.generated_files
                        if f.endswith("vex_recommendations.json")
                    ),
                    None,
                )
                if vex_path:
                    console.print(
                        f"\n[cyan]Applying VEX triage recommendations "
                        f"from {vex_path}...[/cyan]"
                    )
                    from fs_report.vex_applier import VexApplier

                    applier = VexApplier(
                        auth_token=config.auth_token,
                        domain=config.domain,
                        concurrency=vex_concurrency,
                        dry_run=dry_run,
                        vex_override=config.vex_override,
                        filter_statuses=config.autotriage_status,
                    )
                    try:
                        vex_result = applier.apply_file(vex_path)
                        _print_vex_summary(vex_result)
                        if not dry_run:
                            _invalidate_findings_cache_for_versions(
                                config.domain, vex_result.results
                            )
                    except Exception:
                        logger.exception(
                            "VEX auto-triage failed (reports already written)"
                        )
                        console.print(
                            "[yellow]Warning: VEX auto-triage failed. "
                            "Reports were generated successfully.[/yellow]"
                        )
                else:
                    logger.warning(
                        "--autotriage requested but no "
                        "vex_recommendations.json was generated"
                    )
        else:
            # Surface an actionable validation message (axis scope-flag check,
            # axis-compound missing-scope precheck, standalone-comparison
            # rejection) instead of the generic banner. (M1-3, M1-4.)
            engine_msg = getattr(run_result, "error_message", None)
            if engine_msg:
                console.print(f"[red]Error: {engine_msg}[/red]")
            else:
                console.print("[red]Report generation failed![/red]")
            raise typer.Exit(1)

        return run_result

    except typer.Exit:
        raise
    except FileNotFoundError as e:
        console.print(f"[red]File not found: {e}[/red]")
        raise typer.Exit(1) from e
    except FileExistsError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    except ValueError as e:
        console.print(f"[red]Validation error: {e}[/red]")
        raise typer.Exit(1) from e
    except Exception as e:
        logger.exception("Unexpected error occurred")
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1) from e
    finally:
        if file_handler is not None:
            logging.getLogger().removeHandler(file_handler)
            file_handler.close()
        cleanup_pdf_engines()


def _print_vex_summary(result: "VexApplyResult") -> None:
    """Print a rich summary of a VEX application result."""
    from fs_report.vex_applier import VexApplyResult  # noqa: F811

    assert isinstance(result, VexApplyResult)
    tag = "[DRY RUN] " if result.dry_run else ""
    rate = result.total / result.elapsed_seconds if result.elapsed_seconds > 0 else 0
    console.print(f"\n[bold]{tag}VEX Application Results[/bold]")
    console.print(f"  Total processed:   {result.total}")
    console.print(f"  Succeeded:         {result.succeeded}")
    console.print(f"  Failed:            {result.failed}")
    if result.skipped_invalid:
        console.print(f"  Skipped (invalid): {result.skipped_invalid}")
    if result.skipped_existing:
        console.print(f"  Skipped (existing):{result.skipped_existing}")
    console.print(
        f"  Time:              {result.elapsed_seconds:.1f}s ({rate:.0f} req/s)"
    )
    if result.results_path:
        console.print(f"  Results log:       {result.results_path}")


# ── Typer command ────────────────────────────────────────────────────

_CONNECTION = "Connection"
_SCOPE = "Scope"
_TIME_RANGE = "Time Range"
_OUTPUT = "Output"
_PERFORMANCE = "Performance"
_AI = "AI"
_RECIPE_SPECIFIC = "Recipe-Specific"


@run_app.callback(invoke_without_command=True)
def run_command(
    ctx: typer.Context,
    recipes: Union[Path, None] = typer.Option(
        None,
        "--recipes",
        "-r",
        help="Path to recipes directory",
        dir_okay=True,
        file_okay=False,
        rich_help_panel=_OUTPUT,
    ),
    recipe: list[str] = typer.Option(
        None,
        "--recipe",
        help="Name of specific recipe(s) to run (can be specified multiple times)",
        rich_help_panel=_OUTPUT,
    ),
    output: Union[Path, None] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output directory for reports",
        dir_okay=True,
        file_okay=False,
        rich_help_panel=_OUTPUT,
    ),
    start: Union[str, None] = typer.Option(
        None,
        "--start",
        "-s",
        help="Start date (ISO8601 format, e.g., 2025-01-01)",
        rich_help_panel=_TIME_RANGE,
    ),
    end: Union[str, None] = typer.Option(
        None,
        "--end",
        "-e",
        help="End date (ISO8601 format, e.g., 2025-01-31)",
        rich_help_panel=_TIME_RANGE,
    ),
    period: Union[str, None] = typer.Option(
        None,
        "--period",
        "-p",
        help="Time period (e.g., '7d', '1m', 'Q1', '2024', 'monday', 'january-2024'). "
        "Version Comparison single-project runs honor this as a version-window "
        "filter (includes predecessor as implicit baseline). Other assessment "
        "recipes (CVA, Triage, Findings by Project) ignore it.",
        rich_help_panel=_TIME_RANGE,
    ),
    since: str = typer.Option(
        "24h",
        "--since",
        help=(
            "CRA Compliance --since delta window: Nh (e.g. 24h), Nd (e.g. 7d), "
            "ISO 8601 datetime, or 'last-run'. Default: 24h."
        ),
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    exploit_maturity: Union[str, None] = typer.Option(
        None,
        "--exploit-maturity",
        help=(
            "CRA threshold tiers, comma-separated. Values: "
            "kev,weaponized,poc,ransomware,threat_actor. "
            "Default (from recipe YAML): kev,ransomware,threat_actor,weaponized."
        ),
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    include_status: Union[str, None] = typer.Option(
        None,
        "--include-status",
        help=(
            "Statuses to include in Fetch A, comma-separated. "
            "Default (recipe YAML): OPEN,NO_STATUS,UNKNOWN,IN_TRIAGE."
        ),
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    exclude_status: Union[str, None] = typer.Option(
        None,
        "--exclude-status",
        help=(
            "Statuses to exclude from Fetch A, comma-separated. "
            "Default (recipe YAML): FALSE_POSITIVE,NOT_AFFECTED,RESOLVED,RESOLVED_WITH_PEDIGREE."
        ),
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    reachable_only: bool = typer.Option(
        False,
        "--reachable-only",
        help="CRA Compliance: filter output to reachability_label==REACHABLE.",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    with_triage_age: bool = typer.Option(
        False,
        "--with-triage-age",
        help=(
            "Enable per-finding /activity fan-out to compute "
            "triage_age_days for the ⏰ section. Off by default to "
            "avoid the per-finding API cost."
        ),
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    kev_due_date_source: str = typer.Option(
        "cisa",
        "--kev-due-date-source",
        help=(
            "Source for the CRA Article 14 notification clock. "
            "'cisa' (default) joins on the public CISA KEV catalog. "
            "'none' disables CISA enrichment and suppresses the 🔥 SLA-Breach "
            "section. 'api' is reserved for a future platform endpoint and "
            "currently raises."
        ),
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    unfilterable_tier_strategy: str = typer.Option(
        "wide-fetch",
        "--unfilterable-tier-strategy",
        help=(
            "How to handle tiers (ransomware, threat_actor) that "
            "the /findings API cannot filter directly. "
            "Choices: wide-fetch (default), drop-tier, require-rsql."
        ),
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    snapshot_diff: str = typer.Option(
        "on",
        "--snapshot-diff",
        help=(
            "CRA Compliance snapshot-diff mode. "
            "Choices: on (default), read-only, off."
        ),
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    token: Union[str, None] = typer.Option(
        None,
        "--token",
        "-t",
        help="Finite State API token",
        hide_input=True,
        rich_help_panel=_CONNECTION,
    ),
    domain: Union[str, None] = typer.Option(
        None,
        "--domain",
        "-d",
        help="Finite State domain (e.g., customer.finitestate.io)",
        rich_help_panel=_CONNECTION,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging",
    ),
    data_file: Union[str, None] = typer.Option(
        None,
        "--data-file",
        "-df",
        help="Path to local JSON file to use as data source",
    ),
    project_filter: Union[str, None] = typer.Option(
        None,
        "--project",
        "-pr",
        help="Filter by project (name or ID).",
        rich_help_panel=_SCOPE,
    ),
    folder_filter: Union[str, None] = typer.Option(
        None,
        "--folder",
        "-fl",
        help="Scope reports to a folder (name or ID, includes subfolders).",
        rich_help_panel=_SCOPE,
    ),
    version_filter: Union[str, None] = typer.Option(
        None,
        "--version",
        "-V",
        help="Filter by project version (version ID or name).",
        rich_help_panel=_SCOPE,
    ),
    left_scope: Union[str, None] = typer.Option(
        None,
        "--left",
        help=(
            "Left/baseline scope reference for a saved meta-compare. "
            "Required (with --right) when running a saved meta-compare bundle: "
            "fs-report run --recipe <saved-compare> --left <scope> --right <scope>. "
            "E.g. 'project:BN85@v3.2.1'."
        ),
        rich_help_panel=_SCOPE,
    ),
    right_scope: Union[str, None] = typer.Option(
        None,
        "--right",
        help=(
            "Right/current scope reference for a saved meta-compare. "
            "See --left. E.g. 'project:BE65@v2.4.0'."
        ),
        rich_help_panel=_SCOPE,
    ),
    finding_types: str = typer.Option(
        "cve",
        "--finding-types",
        "-ft",
        help="Finding types to include. Types: cve, sast, thirdparty. Categories: "
        "credentials, config_issues, crypto_material. Use 'all' for everything. "
        "Comma-separated for multiple (e.g. cve,sast). Note: thirdparty cannot be "
        "combined with other types in one query — pass it alone or use 'all'.",
        rich_help_panel=_SCOPE,
    ),
    scan_types: Union[str, None] = typer.Option(
        None,
        "--scan-type",
        "-st",
        help="Scan types to include (e.g. SCA, SAST, SOURCE_SCA, CONFIG, SBOM_IMPORT). "
        "Comma-separated for multiple.",
        rich_help_panel=_SCOPE,
    ),
    scan_statuses: Union[str, None] = typer.Option(
        None,
        "--scan-status",
        "-ss",
        help="Scan statuses to include (e.g. COMPLETED, ERROR, INITIAL, STARTED). "
        "Comma-separated for multiple.",
        rich_help_panel=_SCOPE,
    ),
    current_version_only: bool = typer.Option(
        True,
        "--current-version-only/--all-versions",
        "-cvo/-av",
        help="Only include latest version per project (default). "
        "Note: Executive Dashboard summary mode is inherently current-version-only; "
        "this flag is inert in that mode and only affects --detailed runs.",
        rich_help_panel=_SCOPE,
    ),
    cache_ttl: Union[str, None] = typer.Option(
        None,
        "--cache-ttl",
        help="Enable persistent SQLite cache with TTL "
        "(e.g., '4' for 4 hours, '30m', '1d').",
        rich_help_panel=_PERFORMANCE,
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Force fresh data fetch, ignore any cached data.",
        rich_help_panel=_PERFORMANCE,
    ),
    refresh: bool = typer.Option(
        False,
        "--refresh",
        help="Force fresh API fetch this run but still update the cache "
        "for future runs.",
        rich_help_panel=_PERFORMANCE,
    ),
    detected_after: Union[str, None] = typer.Option(
        None,
        "--detected-after",
        help="Only include findings detected on or after this date (YYYY-MM-DD).",
        rich_help_panel=_TIME_RANGE,
    ),
    ai: bool = typer.Option(
        False,
        "--ai",
        help="Enable AI remediation guidance "
        "(requires ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY, or GITHUB_TOKEN)",
        rich_help_panel=_AI,
    ),
    ai_provider: Union[str, None] = typer.Option(
        None,
        "--ai-provider",
        help="LLM provider: 'anthropic', 'openai', 'copilot', or 'gemini'. "
        "Auto-detected from env vars if not set.",
        rich_help_panel=_AI,
    ),
    ai_model_high: Union[str, None] = typer.Option(
        None,
        "--ai-model-high",
        help="LLM model for summaries (high-capability). "
        "Overrides the built-in default for the active provider.",
        rich_help_panel=_AI,
    ),
    ai_model_low: Union[str, None] = typer.Option(
        None,
        "--ai-model-low",
        help="LLM model for per-component guidance (fast/cheap). "
        "Overrides the built-in default for the active provider.",
        rich_help_panel=_AI,
    ),
    ai_depth: str = typer.Option(
        "summary",
        "--ai-depth",
        help="AI depth: 'summary' (portfolio/project) or 'full' "
        "(+ Critical/High component guidance)",
        rich_help_panel=_AI,
    ),
    ai_prompts: bool = typer.Option(
        False,
        "--ai-prompts",
        help="Export AI prompts to file and HTML for use with any LLM. "
        "No API key required.",
        rich_help_panel=_AI,
    ),
    ai_analysis: bool = typer.Option(
        False,
        "--ai-analysis",
        help="Generate deep AI analysis per action using the summary model. "
        "Produces detailed markdown remediation analysis embedded in the report. "
        "Expensive — uses the high-capability model. Implies --ai-prompts.",
        rich_help_panel=_AI,
    ),
    ai_export: Union[str, None] = typer.Option(
        None,
        "--ai-export",
        help="Export AI prompts to a JSON file for offline/airgapped LLM processing. "
        "No API key required.",
        rich_help_panel=_AI,
    ),
    ai_import: Union[str, None] = typer.Option(
        None,
        "--ai-import",
        help="Import AI responses from a JSON file (from --ai-export output "
        "processed through an LLM). No API key required.",
        rich_help_panel=_AI,
    ),
    context_file: Union[str, None] = typer.Option(
        None,
        "--context-file",
        envvar="FS_REPORT_CONTEXT_FILE",
        help="Path to deployment context YAML file for AI prompt customization.",
        rich_help_panel=_AI,
    ),
    product_type: Union[str, None] = typer.Option(
        None,
        "--product-type",
        help="Product type for AI prompts (firmware, web_app, container, library, etc.).",
        rich_help_panel=_AI,
    ),
    network_exposure: Union[str, None] = typer.Option(
        None,
        "--network-exposure",
        help="Network exposure level (air_gapped, internal_only, internet_facing, mixed).",
        rich_help_panel=_AI,
    ),
    nvd_api_key: Union[str, None] = typer.Option(
        None,
        "--nvd-api-key",
        envvar="NVD_API_KEY",
        help="NVD API key (optional). A hosted mirror is used by default. Only needed as fallback if the mirror is unavailable.",
        rich_help_panel=_AI,
    ),
    baseline_date: Union[str, None] = typer.Option(
        None,
        "--baseline-date",
        help="Baseline date (YYYY-MM-DD) for Security Progress report.",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    baseline_version: Union[str, None] = typer.Option(
        None,
        "--baseline-version",
        "--baseline",  # alias for backwards compatibility
        help="Baseline version ID for Version Comparison report.",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    current_version: Union[str, None] = typer.Option(
        None,
        "--current-version",
        "--current",  # alias for backwards compatibility
        help="Current version ID for Version Comparison report.",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    open_only: bool = typer.Option(
        False,
        "--open-only",
        help="Only count open findings in Security Progress.",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    request_delay: float = typer.Option(
        0.5,
        "--request-delay",
        help="Delay in seconds between API requests.",
        rich_help_panel=_PERFORMANCE,
    ),
    batch_size: int = typer.Option(
        5,
        "--batch-size",
        help="Number of project versions per API batch (default 5, max 25).",
        min=1,
        max=25,
        rich_help_panel=_PERFORMANCE,
    ),
    cve_filter: Union[str, None] = typer.Option(
        None,
        "--cve",
        help="CVE(s) for CVE Impact or scoped Remediation Package. "
        "Comma-separated (e.g. CVE-2024-1234,CVE-2024-5678).",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    component_filter: Union[str, None] = typer.Option(
        None,
        "--component",
        help="Filter by component name(s). "
        "name@version for exact match, name alone uses --component-match mode. "
        "Comma-separated (e.g. busybox@1.36.1-r2,dropbear). "
        "Works on Findings by Project, Triage Prioritization, "
        "Component Vulnerability Analysis, and Remediation Package.",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    component_match: str = typer.Option(
        "contains",
        "--component-match",
        click_type=click.Choice(["contains", "exact"]),
        help="Match mode for --component: 'contains' (default, case-insensitive "
        "substring) or 'exact' (exact name match). "
        "name@version specs always use exact.",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    component_version: Union[str, None] = typer.Option(
        None,
        "--component-version",
        help="Version range filter for Component Impact report. "
        "Supports exact version ('1.36.1'), comparison operators ('<2.0', '>=1.0'), "
        "or comma-separated ranges ('>=1.0,<2.0'). Used with --component.",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    license_filter: Union[str, None] = typer.Option(
        None,
        "--license",
        help="Filter License Report to specific license name(s). "
        "Comma-separated, case-insensitive substring match (e.g. 'GPL,AGPL'). "
        "Useful for finding which projects/components carry a violation license.",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    threat_context: Union[str, None] = typer.Option(
        None,
        "--context",
        help="Threat context for Component Remediation Package. Describes what is "
        "known about the zero-day or vulnerability scenario. Injected into AI prompts "
        "for more targeted guidance.",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    skip_nvd: bool = typer.Option(
        False,
        "--no-nvd",
        help="Skip NVD enrichment entirely for faster runs.",
        rich_help_panel=_PERFORMANCE,
    ),
    scoring_file: Union[str, None] = typer.Option(
        None,
        "--scoring-file",
        help="Path to YAML with custom scoring weights (Triage Prioritization) "
        "or staleness thresholds (Scan Quality).",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    tp_gate: Union[str, None] = typer.Option(
        None,
        "--tp-gate",
        help="Filter findings to a specific Triage Prioritization gate tier: "
        "GATE_1 (critical), GATE_2 (high), or NONE (additive only).",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    top: int = typer.Option(
        0,
        "--top",
        help="Limit Triage Prioritization output to the top N findings by score. "
        "0 = show all (default).",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    triage: int = typer.Option(
        0,
        "--triage",
        help="Limit VEX triage recommendations to the top N findings by score. "
        "The full findings list is still displayed. 0 = all eligible (default).",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    vex_override: bool = typer.Option(
        False,
        "--vex-override",
        help="Overwrite existing VEX statuses when generating triage recommendations.",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    apply_vex_triage: Union[str, None] = typer.Option(
        None,
        "--apply-vex-triage",
        help="Path to vex_recommendations.json to apply to the platform. "
        "Runs VEX application only (no report generation).",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    autotriage: bool = typer.Option(
        False,
        "--autotriage",
        help="Auto-apply VEX recommendations after report completes.",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    autotriage_status: Union[str, None] = typer.Option(
        None,
        "--autotriage-status",
        help="Filter autotriage/apply-vex-triage to specific VEX statuses. "
        "Comma-separated (e.g. 'NOT_AFFECTED' for unreachables only, "
        "'IN_TRIAGE,NOT_AFFECTED' for both).",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview VEX updates without making API calls "
        "(use with --apply-vex-triage or --autotriage).",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    vex_concurrency: int = typer.Option(
        5,
        "--vex-concurrency",
        help="Parallel API requests for VEX application (1-5).",
        min=1,
        max=5,
        rich_help_panel=_PERFORMANCE,
    ),
    low_memory: bool = typer.Option(
        False,
        "--low-memory",
        help="Reduce peak memory for large findings reports. "
        "Drops heavy columns after scoring; skips HTML/XLSX.",
        rich_help_panel=_PERFORMANCE,
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Overwrite existing report files.",
        rich_help_panel=_OUTPUT,
    ),
    theme: Union[str, None] = typer.Option(
        None,
        "--theme",
        help="HTML theme: 'auto' (default — let the browser pick from "
        "localStorage / ?theme= URL param / prefers-color-scheme, falling "
        "back to light), 'light', or 'dark'. Explicit 'light' or 'dark' "
        "is authoritative on initial render and overrides viewer "
        "preference. Affects reports that include the shared design "
        "system; coverage is rolling out template-by-template. PDF "
        "exports always render in light theme. Also honors "
        "FS_REPORT_THEME env / config-file 'theme'.",
        rich_help_panel=_OUTPUT,
    ),
    standalone: bool = typer.Option(
        False,
        "--standalone",
        help="Skip project dependency resolution. Report only direct findings "
        "for the target project, excluding findings from dependent projects.",
        rich_help_panel=_SCOPE,
    ),
    logo: Union[str, None] = typer.Option(
        None,
        "--logo",
        help="Logo image for HTML reports. Filename (resolved in ~/.fs-report/logos/) "
        "or absolute path. Supports PNG, SVG, JPG, WebP.",
        rich_help_panel=_OUTPUT,
    ),
    no_bundled_recipes: bool = typer.Option(
        False,
        "--no-bundled-recipes",
        help="Disable bundled recipes shipped with the package.",
        rich_help_panel=_OUTPUT,
    ),
    serve: bool = typer.Option(
        False,
        "--serve",
        help="After generating reports, start a local server and open the report "
        "in your browser. Interactive features (Jira/triage) work immediately.",
        rich_help_panel=_OUTPUT,
    ),
    serve_port: int = typer.Option(
        8321,
        "--serve-port",
        help="Port for the local report server (used with --serve).",
        rich_help_panel=_OUTPUT,
    ),
    headless: bool = typer.Option(
        False,
        "--headless",
        help="Explicit non-interactive mode for CI/CD. Never starts a server.",
        rich_help_panel=_OUTPUT,
    ),
    # Hidden cross-server version comparison flags
    compare_domain: Union[str, None] = typer.Option(
        None, "--compare-domain", help="", hidden=True
    ),
    compare_token: Union[str, None] = typer.Option(
        None, "--compare-token", help="", hidden=True
    ),
    compare_project: Union[str, None] = typer.Option(
        None, "--compare-project", help="", hidden=True
    ),
    compare_version: Union[str, None] = typer.Option(
        None, "--compare-version", help="", hidden=True
    ),
    detailed: bool = typer.Option(
        False,
        "--detailed",
        help="Executive Dashboard: use legacy findings-fetch pipeline "
        "(slower; enables Critical/High severity-over-time and per-finding "
        "detection histograms). Default is summary mode.",
    ),
) -> None:
    """Generate reports from recipes.

    Runs all auto_run recipes by default, or specific ones with --recipe.
    """
    if ctx.invoked_subcommand is not None:
        return

    # ── CRA Compliance cross-flag validation ─────────────────────────
    _valid_unfilterable = {"wide-fetch", "drop-tier", "require-rsql"}
    if unfilterable_tier_strategy not in _valid_unfilterable:
        typer.echo(
            f"--unfilterable-tier-strategy must be one of "
            f"{sorted(_valid_unfilterable)}; got {unfilterable_tier_strategy!r}",
            err=True,
        )
        raise typer.Exit(code=2)
    _valid_snapshot_diff = {"on", "read-only", "off"}
    if snapshot_diff not in _valid_snapshot_diff:
        typer.echo(
            f"--snapshot-diff must be one of {sorted(_valid_snapshot_diff)}; "
            f"got {snapshot_diff!r}",
            err=True,
        )
        raise typer.Exit(code=2)

    # Parse-validate --left / --right scope refs when provided so a
    # malformed ref fails fast with a clean message (B3.7). The engine
    # (B3.6) owns the full matrix validation (missing sides, non-axis
    # recipes) — the CLI only fails fast on a parse error here.
    if left_scope is not None:
        try:
            _parse_scope_ref(left_scope)
        except _ScopeRefError as exc:
            console.print(f"[red]Error: invalid --left scope reference: {exc}[/red]")
            raise typer.Exit(code=2) from exc
    if right_scope is not None:
        try:
            _parse_scope_ref(right_scope)
        except _ScopeRefError as exc:
            console.print(f"[red]Error: invalid --right scope reference: {exc}[/red]")
            raise typer.Exit(code=2) from exc

    # M3-1: `run` does NOT enforce both-or-neither for --left/--right. A saved
    # meta-compare may PIN one side via axis.left / axis.right; the user must be
    # able to override just the other side with a lone runtime flag. The engine
    # (_process_axis_compound) resolves runtime-flag-or-pinned-axis per side and
    # raises an actionable "requires --left and --right" message when a side has
    # neither — so the both-required check belongs there, not here. (The
    # `compare` CLI keeps its own both-required check: it has no pinning.)

    # Cross-flag validation: --since=last-run requires snapshot state,
    # which --snapshot-diff=off disables. Reject the combination at
    # parse time (spec §0 ~line 895).
    if since.lower() == "last-run" and snapshot_diff == "off":
        typer.echo(
            "--since=last-run requires --snapshot-diff != off "
            "(last-run reads the snapshot state file).",
            err=True,
        )
        raise typer.Exit(code=2)

    # Parse cache TTL
    cache_ttl_seconds = 0
    if no_cache:
        cache_ttl_seconds = 0
    elif cache_ttl:
        try:
            cache_ttl_seconds = parse_ttl(cache_ttl)
            if cache_ttl_seconds > 0:
                console.print(
                    f"[cyan]SQLite cache enabled with TTL: "
                    f"{cache_ttl} ({cache_ttl_seconds} seconds)[/cyan]"
                )
        except ValueError as e:
            console.print(f"[red]Error: Invalid cache TTL format: {e}[/red]")
            raise typer.Exit(1)

    if refresh and cache_ttl_seconds <= 0:
        logger.warning(
            "--refresh has no effect without --cache-ttl " "(no cache to refresh)"
        )
    elif refresh:
        console.print("[cyan]Cache refresh: fetching fresh data this run[/cyan]")

    # Validate --scoring-file early so typos/missing files fail fast instead of
    # silently falling through to default scoring weights inside the transforms.
    if scoring_file:
        _validate_scoring_file(scoring_file)

    # --ai-export alone produced no file because the export block runs inside the
    # --ai-prompts path. Imply --ai-prompts so the airgap workflow works as
    # documented.
    if ai_export and not ai_prompts:
        console.print(
            "[cyan]--ai-export requires prompt generation — enabling --ai-prompts"
            "[/cyan]"
        )
        ai_prompts = True

    run_result = run_reports(
        recipes=recipes,
        recipe=recipe,
        output=output,
        start=start,
        end=end,
        period=period,
        token=token,
        domain=domain,
        verbose=verbose,
        data_file=data_file,
        project_filter=project_filter,
        version_filter=version_filter,
        folder_filter=folder_filter,
        finding_types=finding_types,
        current_version_only=current_version_only,
        no_bundled_recipes=no_bundled_recipes,
        cache_ttl=cache_ttl_seconds,
        cache_dir=str(Path.home() / ".fs-report") if cache_ttl_seconds > 0 else None,
        refresh=refresh,
        detected_after=detected_after,
        ai=ai,
        ai_provider=ai_provider,
        ai_model_high=ai_model_high,
        ai_model_low=ai_model_low,
        ai_depth=ai_depth,
        ai_prompts=ai_prompts,
        ai_export=ai_export,
        ai_import=ai_import,
        ai_analysis=ai_analysis,
        context_file=context_file,
        product_type=product_type,
        network_exposure=network_exposure,
        nvd_api_key=nvd_api_key,
        baseline_date=baseline_date,
        baseline_version=baseline_version,
        current_version=current_version,
        open_only=open_only,
        request_delay=request_delay,
        batch_size=batch_size,
        cve_filter=cve_filter,
        component_filter=component_filter,
        component_match=component_match,
        license_filter=license_filter,
        threat_context=threat_context,
        skip_nvd=skip_nvd,
        scoring_file=scoring_file,
        tp_gate=tp_gate,
        top=top,
        triage=triage,
        vex_override=vex_override,
        overwrite=overwrite,
        logo=logo,
        apply_vex_triage=apply_vex_triage,
        autotriage="high" if autotriage else None,
        autotriage_status=(
            [s.strip().upper() for s in autotriage_status.split(",")]
            if autotriage_status
            else None
        ),
        dry_run=dry_run,
        vex_concurrency=vex_concurrency,
        scan_types=scan_types,
        scan_statuses=scan_statuses,
        low_memory=low_memory,
        compare_domain=compare_domain,
        compare_token=compare_token,
        compare_project=compare_project,
        compare_version=compare_version,
        standalone=standalone,
        detailed=detailed,
        theme=theme,
        since=since,
        exploit_maturity_threshold=_split_csv(exploit_maturity),
        include_status=_split_csv(include_status),
        exclude_status=_split_csv(exclude_status),
        reachable_only=reachable_only,
        with_triage_age=with_triage_age,
        kev_due_date_source=kev_due_date_source,
        unfilterable_tier_strategy=unfilterable_tier_strategy,
        snapshot_diff=snapshot_diff,
        left_scope=left_scope,
        right_scope=right_scope,
    )

    # In headless mode, print a structured JSON summary to stdout
    if headless and run_result is not None:
        summary = {
            "success": run_result.success,
            "recipes": [
                {
                    "recipe": r.recipe,
                    "output_dir": r.output_dir,
                    "files": r.files,
                    "stats": r.stats,
                }
                for r in run_result.recipes
            ],
        }
        print(json.dumps(summary))

    # Launch local HTTP server if requested
    if serve and not headless:
        from fs_report.web import run_web

        run_web(port=serve_port, open_browser=True)
