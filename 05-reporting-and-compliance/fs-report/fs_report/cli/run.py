"""The 'run' command: generate reports."""

import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Union

if TYPE_CHECKING:
    from fs_report.vex_applier import VexApplyResult

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
from fs_report.report_engine import ReportEngine
from fs_report.sqlite_cache import parse_ttl

console = Console()

run_app = typer.Typer(
    name="run",
    help="Generate reports from recipes.",
    add_completion=False,
)


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
    detected_after: Union[str, None] = None,
    ai: bool = False,
    ai_provider: Union[str, None] = None,
    ai_model_high: Union[str, None] = None,
    ai_model_low: Union[str, None] = None,
    ai_depth: str = "summary",
    ai_prompts: bool = False,
    nvd_api_key: Union[str, None] = None,
    baseline_date: Union[str, None] = None,
    baseline_version: Union[str, None] = None,
    current_version: Union[str, None] = None,
    open_only: bool = False,
    request_delay: float = 0.5,
    batch_size: int = 5,
    cve_filter: Union[str, None] = None,
    scoring_file: Union[str, None] = None,
    vex_override: bool = False,
    overwrite: bool = False,
    logo: Union[str, None] = None,
    apply_vex_triage: Union[str, None] = None,
    autotriage: bool = False,
) -> Config:
    """Build a Config object from CLI args, config file, and env vars."""
    cfg = load_config_file()

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

    # Handle period parameter
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

    # Validate finding_types
    valid_finding_types = {
        "cve",
        "sast",
        "thirdparty",
        "binary_sca",
        "source_sca",
        "credentials",
        "config_issues",
        "crypto_material",
        "all",
    }
    if finding_types:
        types_list = [t.strip().lower() for t in finding_types.split(",")]
        invalid_types = set(types_list) - valid_finding_types
        if invalid_types:
            console.print(
                f"[red]Error: Invalid finding type(s): {', '.join(invalid_types)}[/red]"
            )
            console.print(
                f"[yellow]Valid types: {', '.join(sorted(valid_finding_types))}[/yellow]"
            )
            raise typer.Exit(1)

    # Merge AI model overrides from config file
    ai_model_high = merge_config(
        ai_model_high, None, "ai_model_high", None, config_data=cfg
    )
    ai_model_low = merge_config(
        ai_model_low, None, "ai_model_low", None, config_data=cfg
    )

    # Validate AI options
    if ai:
        _ai_env_vars = ["ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "GITHUB_TOKEN"]
        has_any_key = any(os.getenv(v) for v in _ai_env_vars)
        if not has_any_key:
            console.print(
                "[red]Error: --ai requires one of these environment variables: "
                + ", ".join(_ai_env_vars)
                + "[/red]"
            )
            raise typer.Exit(2)
        if ai_provider and ai_provider not in ("anthropic", "openai", "copilot"):
            console.print(
                f"[red]Error: --ai-provider must be 'anthropic', 'openai', or "
                f"'copilot', got '{ai_provider}'[/red]"
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

    return Config(
        auth_token=auth_token,
        domain=domain_value,
        recipes_dir=str(recipes) if recipes else None,
        use_bundled_recipes=not no_bundled_recipes,
        output_dir=str(Path(output or "./output").expanduser()),
        start_date=start,
        end_date=end,
        verbose=verbose,
        recipe_filter=recipe,
        project_filter=project_filter,
        version_filter=version_filter,
        folder_filter=folder_filter,
        finding_types=finding_types,
        current_version_only=current_version_only,
        cache_ttl=cache_ttl,
        cache_dir=cache_dir,
        detected_after=detected_after,
        ai=ai,
        ai_provider=ai_provider,
        ai_model_high=ai_model_high,
        ai_model_low=ai_model_low,
        ai_depth=ai_depth,
        ai_prompts=ai_prompts,
        nvd_api_key=nvd_api_key,
        baseline_date=baseline_date,
        baseline_version=baseline_version,
        current_version=current_version,
        open_only=open_only,
        request_delay=request_delay,
        batch_size=batch_size,
        cve_filter=cve_filter,
        scoring_file=scoring_file,
        vex_override=vex_override,
        overwrite=overwrite,
        logo=logo,
        apply_vex_triage=apply_vex_triage,
        autotriage=autotriage,
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
    detected_after: Union[str, None] = None,
    ai: bool = False,
    ai_provider: Union[str, None] = None,
    ai_model_high: Union[str, None] = None,
    ai_model_low: Union[str, None] = None,
    ai_depth: str = "summary",
    ai_prompts: bool = False,
    nvd_api_key: Union[str, None] = None,
    baseline_date: Union[str, None] = None,
    baseline_version: Union[str, None] = None,
    current_version: Union[str, None] = None,
    open_only: bool = False,
    request_delay: float = 0.5,
    batch_size: int = 5,
    cve_filter: Union[str, None] = None,
    scoring_file: Union[str, None] = None,
    vex_override: bool = False,
    overwrite: bool = False,
    logo: Union[str, None] = None,
    apply_vex_triage: Union[str, None] = None,
    autotriage: bool = False,
    dry_run: bool = False,
    vex_concurrency: int = 5,
) -> None:
    """Execute the report generation pipeline."""
    run_id = setup_logging(verbose)
    logger = logging.getLogger(__name__)
    file_handler = None
    try:
        data_override = None
        if data_file:
            with open(data_file) as f:
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
            detected_after=detected_after,
            ai=ai,
            ai_provider=ai_provider,
            ai_depth=ai_depth,
            ai_prompts=ai_prompts,
            nvd_api_key=nvd_api_key,
            baseline_date=baseline_date,
            baseline_version=baseline_version,
            current_version=current_version,
            open_only=open_only,
            request_delay=request_delay,
            batch_size=batch_size,
            cve_filter=cve_filter,
            scoring_file=scoring_file,
            vex_override=vex_override,
            overwrite=overwrite,
            logo=logo,
            apply_vex_triage=apply_vex_triage,
            autotriage=autotriage,
        )

        file_handler = attach_file_logging(run_id, config.auth_token)

        logger.info("Configuration:")
        logger.info(f"  Domain: {config.domain}")
        logger.info(f"  Token: {redact_token(config.auth_token)}")
        logger.info(
            f"  Recipes: bundled={'yes' if config.use_bundled_recipes else 'no'}"
            f"{', overlay=' + config.recipes_dir if config.recipes_dir else ''}"
        )
        logger.info(f"  Output directory: {config.output_dir}")
        logger.info(f"  Date range: {config.start_date} to {config.end_date}")
        logger.info(f"  Finding types: {config.finding_types}")
        if config.current_version_only:
            logger.info("  Current version only: Yes (filtering to latest versions)")
        if config.cache_ttl > 0:
            logger.info(f"  [BETA] SQLite cache: Enabled (TTL: {config.cache_ttl}s)")
        if config.folder_filter:
            logger.info(f"  Folder scope: {config.folder_filter}")
        if config.cve_filter:
            logger.info(f"  CVE filter: {config.cve_filter}")
        if config.ai:
            provider_info = (
                f", provider: {config.ai_provider}" if config.ai_provider else ""
            )
            logger.info(
                f"  AI remediation: Enabled (depth: {config.ai_depth}{provider_info})"
            )

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
            applier = VexApplier(
                auth_token=config.auth_token,
                domain=config.domain,
                concurrency=vex_concurrency,
                dry_run=dry_run,
                vex_override=config.vex_override,
            )
            result = applier.apply_file(config.apply_vex_triage)
            _print_vex_summary(result)
            return

        output_path = Path(config.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        engine = ReportEngine(config, data_override=data_override)

        # Patch API client if using data_override
        if data_override is not None:

            class MockAPIClient:
                def __init__(self, data: dict[str, Any]) -> None:
                    self.data = data

                def fetch_data(self, query_config: Any) -> list[dict[str, Any]]:
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
            engine.recipe_loader.recipe_filter = [r.lower() for r in recipe_list]

        success = engine.run()
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
                                "folder_filter": config.folder_filter,
                                "period": period,
                            }.items()
                            if v
                        },
                        files=history_files,
                    )
                except Exception:
                    logger.debug("Failed to record run in history", exc_info=True)

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
                    )
                    try:
                        vex_result = applier.apply_file(vex_path)
                        _print_vex_summary(vex_result)
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
            console.print("[red]Report generation failed![/red]")
            raise typer.Exit(1)

    except typer.Exit:
        raise
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
        help="Time period (e.g., '7d', '1m', 'Q1', '2024', 'monday', 'january-2024')",
        rich_help_panel=_TIME_RANGE,
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
    finding_types: str = typer.Option(
        "cve",
        "--finding-types",
        "-ft",
        help="Finding types to include. Types: cve, sast, thirdparty, binary_sca, "
        "source_sca. Categories: credentials, config_issues, crypto_material. "
        "Use 'all' for everything. Comma-separated for multiple (e.g. cve,sast).",
        rich_help_panel=_SCOPE,
    ),
    current_version_only: bool = typer.Option(
        True,
        "--current-version-only/--all-versions",
        "-cvo/-av",
        help="Latest version only (default, fast) or all versions "
        "(slow, includes historical data)",
        rich_help_panel=_SCOPE,
    ),
    cache_ttl: Union[str, None] = typer.Option(
        None,
        "--cache-ttl",
        help="[BETA] Enable persistent SQLite cache with TTL "
        "(e.g., '4' for 4 hours, '30m', '1d').",
        rich_help_panel=_PERFORMANCE,
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Force fresh data fetch, ignore any cached data.",
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
        "(requires ANTHROPIC_AUTH_TOKEN, OPENAI_API_KEY, or GITHUB_TOKEN)",
        rich_help_panel=_AI,
    ),
    ai_provider: Union[str, None] = typer.Option(
        None,
        "--ai-provider",
        help="LLM provider: 'anthropic', 'openai', or 'copilot'. "
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
    nvd_api_key: Union[str, None] = typer.Option(
        None,
        "--nvd-api-key",
        envvar="NVD_API_KEY",
        help="NVD API key for faster fix-version lookups (10x rate limit).",
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
        help="Baseline version ID for Version Comparison report.",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    current_version: Union[str, None] = typer.Option(
        None,
        "--current-version",
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
        help="CVE(s) for the CVE Impact report. "
        "Comma-separated (e.g. CVE-2024-1234,CVE-2024-5678).",
        rich_help_panel=_RECIPE_SPECIFIC,
    ),
    scoring_file: Union[str, None] = typer.Option(
        None,
        "--scoring-file",
        help="Path to YAML with custom scoring weights for Triage Prioritization.",
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
        help="Auto-apply VEX recommendations after Triage Prioritization "
        "report completes.",
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
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Overwrite existing report files.",
        rich_help_panel=_OUTPUT,
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
) -> None:
    """Generate reports from recipes.

    Runs all auto_run recipes by default, or specific ones with --recipe.
    """
    if ctx.invoked_subcommand is not None:
        return

    # Parse cache TTL
    cache_ttl_seconds = 0
    if no_cache:
        cache_ttl_seconds = 0
    elif cache_ttl:
        try:
            cache_ttl_seconds = parse_ttl(cache_ttl)
            if cache_ttl_seconds > 0:
                console.print(
                    f"[cyan][BETA] SQLite cache enabled with TTL: "
                    f"{cache_ttl} ({cache_ttl_seconds} seconds)[/cyan]"
                )
        except ValueError as e:
            console.print(f"[red]Error: Invalid cache TTL format: {e}[/red]")
            raise typer.Exit(1)

    run_reports(
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
        detected_after=detected_after,
        ai=ai,
        ai_provider=ai_provider,
        ai_model_high=ai_model_high,
        ai_model_low=ai_model_low,
        ai_depth=ai_depth,
        ai_prompts=ai_prompts,
        nvd_api_key=nvd_api_key,
        baseline_date=baseline_date,
        baseline_version=baseline_version,
        current_version=current_version,
        open_only=open_only,
        request_delay=request_delay,
        batch_size=batch_size,
        cve_filter=cve_filter,
        scoring_file=scoring_file,
        vex_override=vex_override,
        overwrite=overwrite,
        logo=logo,
        apply_vex_triage=apply_vex_triage,
        autotriage=autotriage,
        dry_run=dry_run,
        vex_concurrency=vex_concurrency,
    )

    # Launch local HTTP server if requested
    if serve and not headless:
        from fs_report.web import run_web

        run_web(port=serve_port, open_browser=True)
