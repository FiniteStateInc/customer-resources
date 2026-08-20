"""The 'cache' command group: clear, status."""

import re
from pathlib import Path
from typing import Union

import typer
from rich.console import Console

from fs_report.sqlite_cache import (
    NON_API_CACHE_FILES,
    SQLiteCache,
    normalize_domain,
    remove_cache_db,
)
from fs_report.tenant_scope import TENANT_SUFFIX_HEX

console = Console()

cache_app = typer.Typer(
    name="cache",
    help="Manage cached API data and AI guidance.",
    add_completion=False,
)


def _resolve_identity(
    domain: Union[str, None] = None, token: Union[str, None] = None
) -> tuple[str | None, str | None]:
    """Resolve (domain, auth_token) the way every other command does.

    ``--domain`` / ``--token`` > environment > config file. Reading the config
    file matters: it used to be skipped here, so with the env var unset these
    commands built a cache path from ``domain=None`` and cleared/reported a
    DIFFERENT file than the one an actual run had written — a "cache cleared"
    that cleared nothing the run would ever read.

    ``--token`` exists for the same reason ``--domain`` does. The cache file is
    scoped by account, not just host (``fs_report/tenant_scope.py``), so a
    workflow that passes ``--token`` to ``fs-report run`` but keeps no token in
    the environment would otherwise clear a different file than the run writes —
    the identical trap, one layer down.

    The domain is normalized here so the resolved value matches the one
    ``SQLiteCache`` will turn into a filename; callers can compare and glob
    against it directly.
    """
    from fs_report.cli.common import load_config_file, merge_config

    cfg = load_config_file()
    resolved_domain = merge_config(
        domain, "FINITE_STATE_DOMAIN", "domain", config_data=cfg
    )
    resolved_token = merge_config(
        token, "FINITE_STATE_AUTH_TOKEN", "token", config_data=cfg
    )
    normalized = normalize_domain(str(resolved_domain) if resolved_domain else None)
    return (
        normalized or None,
        str(resolved_token) if resolved_token else None,
    )


def _resolve_cache_dir() -> Path:
    """The directory a CLI run actually writes its cache to.

    Deliberately a constant, and deliberately NOT read from the config file.
    ``fs-report run`` hardcodes ``~/.fs-report`` (``cli/run.py``, and the legacy
    entry point likewise), there is no ``--cache-dir`` flag, and nothing
    populates ``Config.cache_dir`` from ``config.yaml``. Honouring a config
    ``cache_dir`` here would therefore point ``clear``/``status`` at a directory
    no run ever writes — creating the very "cleared but still stale" trap this
    module exists to close, just on the directory axis. (The web UI has its own
    ``state["cache_dir"]``, which its own Settings panel already reads; it is
    not reachable from these commands.)

    Kept as a function rather than inlined so that if a real ``--cache-dir``
    knob ever lands, every cache command follows it from one edit.
    """
    return Path.home() / ".fs-report"


def _api_cache(
    domain: Union[str, None] = None, token: Union[str, None] = None
) -> SQLiteCache:
    """Build the SQLiteCache handle for the resolved domain + account."""
    cache_domain, cache_token = _resolve_identity(domain, token)
    return SQLiteCache(
        cache_dir=str(_resolve_cache_dir()),
        domain=cache_domain,
        auth_token=cache_token,
    )


def _get_cache_paths(
    cache: SQLiteCache, cache_domain: str | None, cache_dir: Path
) -> dict:
    """Return a dict of cache name → (path, description) for all caches."""
    return {
        "api": (Path(cache.db_path), "API data", cache_domain),
        "ai": (cache_dir / "cache.db", "AI guidance", None),
        "nvd": (cache_dir / "nvd_cache.db", "NVD CVE data", None),
    }


#: A tenant suffix is exactly ``-`` plus ``TENANT_SUFFIX_HEX`` lowercase hex
#: characters. Matching that shape — rather than "the text after the last
#: hyphen" — is what keeps hyphenated hosts working: splitting
#: ``big-corp.example.io.db`` on its last hyphen yields the base ``big``, which
#: then globs ``big-*.db`` and sweeps every unrelated ``big-…`` domain the
#: operator has cached.
_TENANT_SUFFIX_RE = re.compile(rf"-[0-9a-f]{{{TENANT_SUFFIX_HEX}}}$")


def _sibling_cache_files(
    cache_dir: Path, cache_domain: str | None, current: Path
) -> list[Path]:
    """Every OTHER API-cache file for *cache_domain*, newest naming or legacy.

    Two kinds live here: the pre-tenant-scoping ``<domain>.db`` written before
    the cache carried an account digest, and ``<domain>-<other-account>.db`` for
    the operator's other tenants on the same host.

    ``clear`` removes these and ``status`` lists them, because a clear that only
    empties the file the *current* environment resolves to recreates the trap
    this whole change exists to close: an operator who ran a report with a token
    in the environment and then cleared in a shell without one would empty a
    different file and see the same stale data. Caches refetch, so over-clearing
    within one domain is cheap; under-clearing is what misleads. It also removes
    stale copies of other tenants' records, which is the point.

    Scoping is driven by the RESOLVED DOMAIN, never by parsing the current
    filename. With no domain there are no domain siblings — the domain-less
    ``api-cache.db`` must not be treated as host ``api`` and sweep up every
    ``api-*.db`` in the directory.
    """
    if not cache_domain or not cache_dir.is_dir():
        return []
    found = {
        path
        for pattern in (f"{cache_domain}.db", f"{cache_domain}-*.db")
        for path in cache_dir.glob(pattern)
        if path.name not in NON_API_CACHE_FILES
    }
    return sorted(
        p
        for p in found
        if p.name != current.name
        # Either the legacy un-suffixed file, or a real tenant suffix. Anything
        # else sharing the prefix belongs to a different host.
        and (p.stem == cache_domain or _TENANT_SUFFIX_RE.search(p.stem))
    )


def _warn_unresolved(cache_domain: str | None, cache_token: str | None) -> None:
    """Say plainly when the target file is not the one a real run would use.

    Both halves of the identity matter. A missing TOKEN is the quieter failure:
    the path still looks plausible (``<domain>.db``), so without this the
    operator sees a domain echoed back and assumes the right file was hit, while
    every tenant-scoped cache for that host survives untouched.
    """
    if not cache_domain:
        console.print(
            "[yellow]No domain resolved (no --domain, FINITE_STATE_DOMAIN, "
            "or config-file domain), so the un-scoped cache was targeted — "
            "NOT any domain-specific one. Pass --domain to target a "
            "tenant's cache.[/yellow]"
        )
    elif not cache_token:
        console.print(
            "[yellow]No API token resolved (no --token, FINITE_STATE_AUTH_TOKEN, "
            "or config-file token), so the legacy un-scoped file for this domain "
            "was addressed directly. A run that supplies a token uses an "
            "account-scoped file instead — pass --token to address that "
            "account's cache. ('clear --api' still sweeps this domain's "
            "account-scoped files; '--findings' does not.)[/yellow]"
        )


def clear_api_cache(cache: SQLiteCache, cache_domain: str | None) -> list[Path]:
    """Empty *cache* and delete every other cache file for its domain.

    Shared by ``cache clear --api`` and the deprecated ``--clear-cache`` entry
    point so the two cannot drift — divergent copies of "which files are the
    cache" is the class of bug this module keeps having. Returns the sibling
    files removed.

    Siblings go through ``remove_cache_db``, not ``Path.unlink``: a bare unlink
    leaves ``-wal``/``-shm`` sidecars holding committed pages of the cache that
    was just "deleted", which for another tenant's file is the leak this whole
    change exists to close.

    Only files actually gone are returned. A sibling whose unlink failed is
    reported to the operator as a failure instead, because "Removed cache file:
    X" printed over a file still on disk is the same lie the bare ``clear``
    used to tell.

    NOTE ON SCOPE: this is deliberately DOMAIN-scoped, unlike the web
    Settings "Clear API cache" button, which clears every API cache file on the
    machine. The two differ because each matches what its own surface shows —
    the web panel totals every domain, so a scoped clear there would leave
    entries visibly behind.
    """
    cache.clear()
    removed: list[Path] = []
    for sibling in _sibling_cache_files(
        Path(cache.db_path).parent, cache_domain, Path(cache.db_path)
    ):
        if remove_cache_db(sibling):
            removed.append(sibling)
        else:
            console.print(
                f"[red]Could not remove {sibling.name} — it may still serve "
                f"stale data. Check permissions and remove it manually.[/red]"
            )
    return removed


def _print_status_table(
    domain: Union[str, None] = None, token: Union[str, None] = None
) -> None:
    """Print the cache status table."""
    from rich.table import Table

    cache_domain, cache_token = _resolve_identity(domain, token)
    cache_dir = _resolve_cache_dir()
    cache = SQLiteCache(
        cache_dir=str(cache_dir), domain=cache_domain, auth_token=cache_token
    )
    paths = _get_cache_paths(cache, cache_domain, cache_dir)

    table = Table(title="Cache Status")
    table.add_column("Cache", style="cyan")
    table.add_column("Location", style="dim")
    table.add_column("Size", style="green")
    table.add_column("Exists", style="yellow")

    for _key, (path, label, _extra) in paths.items():
        exists = path.exists()
        size = f"{path.stat().st_size / 1024:.1f} KB" if exists else "—"
        table.add_row(label, str(path), size, "Yes" if exists else "No")

    console.print(table)
    if cache_domain:
        console.print(f"[dim]Domain: {cache_domain}[/dim]")
    _warn_unresolved(cache_domain, cache_token)

    api_path = paths["api"][0]
    siblings = _sibling_cache_files(api_path.parent, cache_domain, api_path)
    if siblings:
        console.print()
        console.print("[yellow]Other cache files for this domain:[/yellow]")
        for path in siblings:
            size = f"{path.stat().st_size / 1024 / 1024:.1f} MB"
            console.print(f"[yellow]  {path.name} ({size})[/yellow]")
        console.print(
            "[dim]Written by another account on this host, or by a run predating "
            "account-scoped caching. Not read by the current environment. "
            "'fs-report cache clear --api' removes them.[/dim]"
        )


@cache_app.command()
def clear(
    api: bool = typer.Option(
        False,
        "--api",
        help="Clear API data cache.",
    ),
    ai: bool = typer.Option(
        False,
        "--ai",
        help="Clear AI remediation guidance cache.",
    ),
    nvd: bool = typer.Option(
        False,
        "--nvd",
        help="Clear NVD CVE description cache.",
    ),
    findings: bool = typer.Option(
        False,
        "--findings",
        help="Clear findings data from API cache.",
    ),
    versions: Union[str, None] = typer.Option(
        None,
        "--versions",
        help="Comma-separated version IDs to invalidate (use with --findings).",
    ),
    all_caches: bool = typer.Option(
        False,
        "--all",
        help="Clear all caches.",
    ),
    domain: Union[str, None] = typer.Option(
        None,
        "--domain",
        "-d",
        help="Finite State domain (for domain-scoped API cache).",
    ),
    token: Union[str, None] = typer.Option(
        None,
        "--token",
        help=(
            "API token identifying the account whose cache to target. "
            "Defaults to FINITE_STATE_AUTH_TOKEN or the config file, matching "
            "'fs-report run'."
        ),
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip the confirmation prompt for a bare 'cache clear'.",
    ),
) -> None:
    """Delete cached data.

    With no flags, clears the API data cache for the resolved domain — the
    command is named "clear", so it clears. Use --ai / --nvd (or --all) to
    include the AI-guidance and NVD caches, or --findings to drop only findings.
    """
    if all_caches:
        api = ai = nvd = True

    # No flags → clear the API data cache. This previously printed a status
    # table plus a usage hint and returned 0 WITHOUT deleting anything, which
    # read as success: the operator saw a table, believed the cache was gone,
    # and the next run served the same stale (and possibly cross-tenant) data.
    # A command whose name is a verb must either do the thing or fail loudly.
    #
    # It is still a contract flip from "show" to "delete, and sweep this
    # domain's other files too", so confirm when a human is watching. --yes and
    # any explicit flag skip the prompt, which keeps existing scripts working:
    # a script that passed --api never sees it, and one relying on the old
    # bare-clear no-op gets a prompt rather than a silent wipe. Non-interactive
    # callers (no TTY) proceed, since there is nobody to answer.
    if not api and not ai and not nvd and not findings:
        api = True
        import sys

        if not yes:
            warning = (
                "'cache clear' with no flags deletes the API data cache for the "
                "resolved domain, including this domain's other account cache "
                "files."
            )
            if sys.stdin.isatty():
                console.print(f"[yellow]{warning}[/yellow]")
                if not typer.confirm("Proceed?", default=False):
                    console.print("[dim]Nothing cleared.[/dim]")
                    raise typer.Exit(0)
            else:
                # No TTY and no --yes: refuse rather than wipe. This command
                # used to be a no-op with no flags, so a CI job or cron
                # inherited from that era would otherwise start silently
                # deleting caches on upgrade. Failing loudly is the whole point
                # of the change — a silent wipe is just the old lie inverted.
                console.print(f"[red]{warning}[/red]")
                console.print(
                    "[red]Refusing to do that unattended. Pass --yes to confirm, "
                    "or --api to be explicit about what to clear.[/red]"
                )
                raise typer.Exit(2)
        console.print(
            "[dim]No flags given — clearing the API data cache. "
            "Use --all to include the AI and NVD caches.[/dim]"
        )

    cache_domain, cache_token = _resolve_identity(domain, token)
    cache_dir = _resolve_cache_dir()

    if findings and not api:
        # --findings never sweeps, so it is the one path where addressing the
        # wrong file is silent. A domain/token pair that no run ever used
        # resolves to a filename that does not exist; SQLiteCache would create
        # it empty and report a confident success over an untouched real cache.
        # Check BEFORE constructing the handle, and STOP if it is missing.
        # Continuing would create the file empty and then print a green
        # "Findings cache cleared" over it — a success message for work that
        # did not happen, while the operator's real cache sits untouched under
        # a different domain/token. That is the trap this PR exists to close,
        # so refuse rather than warn-and-carry-on.
        expected = SQLiteCache.db_path_for(cache_dir, cache_domain, cache_token)
        if not expected.exists():
            console.print(
                f"[red]No cache at {expected.name} — no run has written one for "
                "this domain/token pair, so there is nothing to invalidate. "
                "Check that --domain and --token match the run you are trying "
                "to invalidate.[/red]"
            )
            raise typer.Exit(2)
        cache = SQLiteCache(
            cache_dir=str(cache_dir), domain=cache_domain, auth_token=cache_token
        )
        if versions:
            vid_set = {v.strip() for v in versions.split(",") if v.strip()}
            removed = cache.invalidate_versions(vid_set)
            console.print(
                f"[green]Invalidated {removed} cache entries "
                f"for {len(vid_set)} version(s).[/green]"
            )
        else:
            cache.clear(endpoint="/findings")
            console.print("[green]Findings cache cleared.[/green]")
        if cache_domain:
            console.print(f"[dim]Domain: {cache_domain}[/dim]")
        _warn_unresolved(cache_domain, cache_token)
        # --findings is surgical (a version list, or one endpoint), so it does NOT
        # sweep sibling files the way --api does. Say so when siblings exist,
        # rather than letting the operator assume every cache for this domain
        # was touched.
        api_path = Path(cache.db_path)
        siblings = _sibling_cache_files(api_path.parent, cache_domain, api_path)
        if siblings:
            console.print(
                f"[yellow]{len(siblings)} other cache file(s) for this domain were "
                "NOT touched (other accounts, or pre-account-scoping runs). "
                "Use 'cache clear --api' to remove them.[/yellow]"
            )

    if api:
        cache = SQLiteCache(
            cache_dir=str(cache_dir), domain=cache_domain, auth_token=cache_token
        )
        removed_files = clear_api_cache(cache, cache_domain)
        console.print("[green]API data cache cleared successfully.[/green]")
        console.print(f"[dim]Cache location: {cache.db_path}[/dim]")
        if cache_domain:
            console.print(f"[dim]Domain: {cache_domain}[/dim]")
        _warn_unresolved(cache_domain, cache_token)
        for sibling in removed_files:
            console.print(f"[green]Removed cache file: {sibling.name}[/green]")

    if ai:
        ai_cache_db = cache_dir / "cache.db"
        if ai_cache_db.exists():
            ai_cache_db.unlink()
            console.print("[green]AI remediation cache cleared successfully.[/green]")
        else:
            console.print("[yellow]No AI cache found (nothing to clear).[/yellow]")
        console.print(f"[dim]Cache location: {ai_cache_db}[/dim]")

    if nvd:
        nvd_cache_db = cache_dir / "nvd_cache.db"
        if nvd_cache_db.exists():
            nvd_cache_db.unlink()
            console.print("[green]NVD CVE cache cleared successfully.[/green]")
        else:
            console.print("[yellow]No NVD cache found (nothing to clear).[/yellow]")
        console.print(f"[dim]Cache location: {nvd_cache_db}[/dim]")


@cache_app.command()
def status(
    domain: Union[str, None] = typer.Option(
        None,
        "--domain",
        "-d",
        help="Finite State domain (for domain-scoped API cache).",
    ),
    token: Union[str, None] = typer.Option(
        None,
        "--token",
        help=(
            "API token identifying the account whose cache to report. "
            "Defaults to FINITE_STATE_AUTH_TOKEN or the config file."
        ),
    ),
) -> None:
    """Show cache location, size, and age."""
    _print_status_table(domain, token)
