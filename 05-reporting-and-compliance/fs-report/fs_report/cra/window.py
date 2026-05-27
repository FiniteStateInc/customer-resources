"""CRA Compliance --since window parser.

Separate from the project-wide PeriodParser because:

  1. PeriodParser.parse_period() lowercases its input, which corrupts
     valid ISO 8601 datetimes ("2026-05-20T00:00:00Z" → "...t...z").
  2. PeriodParser returns date-only strings; the /cves/updates API and
     the CRA snapshot state file both want ISO datetime strings with
     the Z suffix.

Output format: a (start, end) tuple of ISO 8601 datetime strings
with 'Z' suffix (UTC), e.g. ("2026-05-23T18:00:00Z", "2026-05-24T18:00:00Z").
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime, timedelta

logger = logging.getLogger(__name__)

_FALLBACK_HOURS = 24


def _fmt_z(dt: datetime) -> str:
    """Format an aware datetime as 'YYYY-MM-DDTHH:MM:SSZ' (UTC)."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utcnow() -> datetime:
    """UTC now, aware. Wrapped so tests can monkeypatch."""
    return datetime.now(UTC)


def _hours_window(hours: int) -> tuple[str, str]:
    end = _utcnow()
    start = end - timedelta(hours=hours)
    return _fmt_z(start), _fmt_z(end)


def _days_window(days: int) -> tuple[str, str]:
    end = _utcnow()
    start = end - timedelta(days=days)
    return _fmt_z(start), _fmt_z(end)


def _last_run_window(scope_hash: str | None) -> tuple[str, str]:
    """Return (start, end) using the persisted last_run_at if available,
    else fall back to 24h with a warning."""
    if scope_hash is None:
        logger.warning(
            "--since=last-run requires a scope hash; falling back to %dh.",
            _FALLBACK_HOURS,
        )
        return _hours_window(_FALLBACK_HOURS)
    # Late import to avoid circular dependency.
    from fs_report.cra import snapshot

    state = snapshot.load_state(scope_hash)
    if state.last_run_at is None:
        logger.warning(
            "--since=last-run: no prior state for scope %s; falling back to %dh.",
            scope_hash,
            _FALLBACK_HOURS,
        )
        return _hours_window(_FALLBACK_HOURS)
    end_dt = _utcnow()
    return state.last_run_at, _fmt_z(end_dt)


def parse_since_window(
    since: str,
    *,
    scope_hash: str | None = None,
) -> tuple[str, str]:
    """Parse a CRA --since value to (start_iso, end_iso) in UTC Z form.

    Accepted shapes:
      - Hours: '24h', '1h', '72h', ...
      - Days:  '7d', '30d', ...
      - ISO 8601 datetime with or without 'Z': '2026-05-20T00:00:00Z',
        '2026-05-20T07:00:00+07:00'. Case is preserved during parse —
        no .lower().
      - 'last-run': read last_run_at from the snapshot state file.
        Falls back to 24h when state is missing.
    """
    raw = since.strip()

    # last-run is case-insensitive, lowercase the comparison only.
    if raw.lower() == "last-run":
        return _last_run_window(scope_hash)

    # Hours pattern (Nh) — match against lowercase, but only after
    # the ISO check would have failed.
    if re.fullmatch(r"\d+h", raw.lower()):
        return _hours_window(int(raw[:-1]))

    # Days pattern (Nd)
    if re.fullmatch(r"\d+d", raw.lower()):
        return _days_window(int(raw[:-1]))

    # ISO 8601 datetime. fromisoformat() handles 'Z' starting in
    # Python 3.11; for safety we also handle the '+00:00' replacement.
    iso_candidate = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
    try:
        start_dt = datetime.fromisoformat(iso_candidate)
    except ValueError:
        raise ValueError(f"Invalid --since value: {since!r}") from None

    if start_dt.tzinfo is None:
        # Treat naive ISO as UTC
        start_dt = start_dt.replace(tzinfo=UTC)
    end_dt = _utcnow()
    if end_dt < start_dt:
        # Defensive: if the user picked a future start, treat end as start+24h
        end_dt = start_dt + timedelta(hours=_FALLBACK_HOURS)
    return _fmt_z(start_dt), _fmt_z(end_dt)
