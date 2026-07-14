"""`fs-report doctor` — first-run configuration and connectivity preflight.

Diagnoses the failure classes new installs actually hit (support threads:
missing/wrong credentials, scheme-prefixed domains, DNS, corporate proxy /
TLS interception, unauthorized tokens after tenant migrations) and prints
where the per-run log files live. Read-only apart from creating the log
directory to prove it is writable.

Exit codes: 0 = all checks passed (warnings allowed), 1 = at least one
check failed.
"""

from __future__ import annotations

import os
import socket
import sys

import typer
from rich.console import Console

doctor_app = typer.Typer(
    name="doctor",
    help=(
        "Diagnose configuration and connectivity (first-run preflight). "
        "Checks the ONLINE path — offline --data-file runs don't need it."
    ),
    invoke_without_command=True,
)
console = Console()

_OK = "[green]✓[/green]"
_WARN = "[yellow]⚠[/yellow]"
_FAIL = "[red]✗[/red]"

_API_PROBE_TIMEOUT = 15.0


@doctor_app.callback()
def doctor(
    token: str | None = typer.Option(
        None, "--token", help="API token (overrides env/config file)."
    ),
    domain: str | None = typer.Option(
        None, "--domain", help="Finite State domain (overrides env/config file)."
    ),
) -> None:
    """Run read-only environment and connectivity checks."""
    from fs_report.cli.common import load_config_file, merge_config, redact_token
    from fs_report.logging_utils import LOG_DIR
    from fs_report.models import normalize_domain

    failures = 0

    # ── 1. Versions ──────────────────────────────────────────────────
    from fs_report import __version__

    console.print(
        f"{_OK} fs-report {__version__} on Python {sys.version.split()[0]} "
        f"({sys.executable})"
    )

    # ── 2. Credentials + where they came from ───────────────────────
    # Resolve EXACTLY like `fs-report run` (merge_config: CLI flag > env var >
    # config file — where an explicitly-empty env var still wins), so doctor
    # can never pass an environment that run would reject.
    cfg = load_config_file()
    token_value = str(
        merge_config(
            token, "FINITE_STATE_AUTH_TOKEN", "token", default="", config_data=cfg
        )
        or ""
    )
    domain_raw = str(
        merge_config(
            domain, "FINITE_STATE_DOMAIN", "domain", default="", config_data=cfg
        )
        or ""
    )

    def _source(cli_val: str | None, env_var: str, cfg_key: str) -> str:
        if cli_val is not None:
            return f"--{cfg_key if cfg_key != 'token' else 'token'} flag"
        if os.getenv(env_var) is not None:
            return f"{env_var} env var"
        if cfg.get(cfg_key) is not None:
            return "config file"
        return "unset"

    token_src = _source(token, "FINITE_STATE_AUTH_TOKEN", "token")
    domain_src = _source(domain, "FINITE_STATE_DOMAIN", "domain")

    if token_value:
        console.print(f"{_OK} API token: {redact_token(token_value)} ({token_src})")
    else:
        failures += 1
        detail = (
            f"empty (resolved from {token_src})" if token_src != "unset" else "not set"
        )
        console.print(
            f"{_FAIL} API token: {detail} — export FINITE_STATE_AUTH_TOKEN, "
            f"use --token, or run `fs-report config`"
        )

    domain_value = normalize_domain(domain_raw) if domain_raw else ""
    if domain_value:
        note = (
            ""
            if domain_value == domain_raw.strip().lower()
            else f" (normalized from {domain_raw!r})"
        )
        console.print(f"{_OK} Domain: {domain_value} ({domain_src}){note}")
    else:
        failures += 1
        detail = (
            f"empty (resolved from {domain_src})"
            if domain_src != "unset"
            else "not set"
        )
        console.print(
            f"{_FAIL} Domain: {detail} — export FINITE_STATE_DOMAIN, "
            f"use --domain, or run `fs-report config`"
        )

    # ── 3. DNS ───────────────────────────────────────────────────────
    probe_skip_reason = (
        "" if (domain_value and token_value) else ("credentials incomplete")
    )
    if domain_value:
        try:
            socket.getaddrinfo(domain_value, 443)
            console.print(f"{_OK} DNS: {domain_value} resolves")
        except OSError as e:
            failures += 1
            console.print(
                f"{_FAIL} DNS: cannot resolve {domain_value} ({e}) — check the "
                f"domain spelling, VPN, or corporate DNS"
            )
            domain_value = ""  # no point probing the API
            probe_skip_reason = "DNS resolution failed above"

    # ── 4. API reachability + token validity ────────────────────────
    if domain_value and token_value:
        import httpx

        url = f"https://{domain_value}/api/public/v0/projects"
        try:
            resp = httpx.get(
                url,
                params={"limit": 1},
                headers={
                    # Match APIClient's request headers so the probe behaves
                    # like a real run behind picky gateways/proxies.
                    "X-Authorization": token_value,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=_API_PROBE_TIMEOUT,
            )
            if resp.status_code == 200:
                try:
                    resp.json()
                except ValueError:
                    failures += 1
                    console.print(
                        f"{_FAIL} API: HTTP 200 but the body is not JSON — "
                        f"likely a captive portal or proxy interstitial "
                        f"answering instead of the platform"
                    )
                else:
                    console.print(f"{_OK} API: reachable and token accepted ({url})")
            elif resp.status_code in (401, 403):
                failures += 1
                console.print(
                    f"{_FAIL} API: HTTP {resp.status_code} — token rejected. "
                    f"It may be expired, for a different tenant, or invalidated "
                    f"by a platform migration; re-issue it at Settings → API "
                    f"Tokens on https://{domain_value}"
                )
            elif resp.status_code == 429:
                # Transient — credentials reached the platform. Warn, don't
                # fail (exit semantics: 0 = healthy, warnings allowed).
                console.print(
                    f"{_WARN} API: HTTP 429 — the platform is rate-limiting "
                    f"this account right now; credentials look deliverable, "
                    f"wait a few minutes and re-run"
                )
            elif resp.status_code >= 500:
                failures += 1
                console.print(
                    f"{_FAIL} API: HTTP {resp.status_code} — platform-side "
                    f"error (transient outage or maintenance); credentials "
                    f"reached the server, retry shortly"
                )
            else:
                failures += 1
                console.print(
                    f"{_FAIL} API: unexpected HTTP {resp.status_code} from {url}"
                )
        except httpx.ConnectError as e:
            failures += 1
            msg = str(e)
            hint = (
                "TLS interception by a corporate proxy — your IT may need to "
                "add the proxy CA to this machine's trust store"
                if "certificate" in msg.lower() or "ssl" in msg.lower()
                else "check firewall/proxy settings and outbound HTTPS access"
            )
            console.print(f"{_FAIL} API: connection failed ({msg}) — {hint}")
        except httpx.RequestError as e:
            failures += 1
            console.print(f"{_FAIL} API: request failed ({e})")
    else:
        console.print(f"{_WARN} API: probe skipped ({probe_skip_reason})")

    # ── 5. Run-log directory ─────────────────────────────────────────
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        try:
            LOG_DIR.chmod(0o700)  # parity with create_file_handler…
        except OSError:
            pass  # …which also swallows chmod failures and logs anyway
        probe = LOG_DIR / ".doctor-write-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        console.print(
            f"{_OK} Run logs: {LOG_DIR} (writable) — every "
            f"`fs-report run` writes <date>_<run_id>.log here"
        )
    except OSError as e:
        failures += 1
        console.print(f"{_FAIL} Run logs: {LOG_DIR} not writable ({e})")

    # ── Summary ──────────────────────────────────────────────────────
    if failures:
        console.print(f"[red]{failures} check(s) failed.[/red]")
        raise typer.Exit(1)
    console.print("[green]All checks passed.[/green]")
