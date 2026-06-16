"""Shared, date-bounded, memoized scan fetch for the queue + Command Center.

Generalizes the loop previously inlined in queue.py (spec §8.1):
two fetch shapes via `since` / `early_stop_terminal`, a `max_pages` cap,
a token-keyed TTL memo with a per-key in-flight lock, and a shared 429 breaker.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

import httpx

logger = logging.getLogger(__name__)

TERMINAL_STATUSES = frozenset({"COMPLETED", "ERROR", "NOT_APPLICABLE"})
_PAGE_SIZE = 100
_BACKOFF_SECONDS = 120
_CACHE_TTL = 120.0  # ≥ queue's 2-min auto-refresh

ScanStatus = Literal["ok", "rate_limited", "unreachable", "unconfigured"]


@dataclass
class ScanFetchResult:
    scans: list[dict[str, Any]] = field(default_factory=list)
    status: ScanStatus = "ok"
    pages_fetched: int = 0
    capped: bool = False


# module-level shared state
_last_429_time: float = 0.0
_cache: dict[str, tuple[float, ScanFetchResult]] = {}
_locks: dict[str, asyncio.Lock] = {}


def _clear_cache_for_tests() -> None:
    """Reset in-memory cache and locks. Test helper only."""
    _cache.clear()
    _locks.clear()


def _reset_backoff_for_tests() -> None:
    """Reset the 429 backoff timer. Test helper only."""
    global _last_429_time  # noqa: PLW0603
    _last_429_time = 0.0


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except (ValueError, AttributeError):
        return None


def _parse_scan_list(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("items") or data.get("scans") or []
    return []


def _cache_key(domain: str, token: str, since: datetime | None, early: bool) -> str:
    tok = hashlib.sha256(token.encode()).hexdigest()[:16]
    bucket = "none" if since is None else since.strftime("%Y-%U")
    return f"{domain}|{tok}|{bucket}|{int(early)}"


async def fetch_scans(
    state: Any,
    *,
    since: datetime | None = None,
    early_stop_terminal: bool = False,
    max_pages: int = 12,
    page_size: int = _PAGE_SIZE,
    force: bool = False,
) -> ScanFetchResult:
    """Fetch scans `created:desc`. See spec §8.1.

    - ``early_stop_terminal=True`` + ``since=None`` → legacy queue shape.
    - ``since=<window start>`` + ``early_stop_terminal=False`` → aggregate shape.
    - ``force=True`` bypasses the TTL memo (a manual Refresh wants live data)
      but still honors the 429 breaker and refreshes the cache for later
      readers. Auto-refresh leaves ``force`` False so it stays within the
      idle request budget.
    """
    state.reload()
    token: str = state.token
    domain: str = state.domain
    if not token or not domain:
        return ScanFetchResult(status="unconfigured")

    key = _cache_key(domain, token, since, early_stop_terminal)
    now_mono = time.monotonic()

    pre_cached = _cache.get(key)
    if not force and pre_cached and now_mono - pre_cached[0] < _CACHE_TTL:
        return pre_cached[1]

    lock = _locks.setdefault(key, asyncio.Lock())
    async with lock:
        # Re-read the cache after acquiring the lock.
        cached = _cache.get(key)
        if cached and time.monotonic() - cached[0] < _CACHE_TTL:
            # Non-force: serve the TTL-fresh memo. Force: only reuse a result
            # that was REPLACED while THIS call waited on the lock — i.e. a
            # concurrent forced refresh already fetched it. Detected by tuple
            # identity (each fetch writes a NEW tuple), which is robust to the
            # coarse monotonic() resolution on some platforms (Windows ~16 ms);
            # the stale memo this call meant to bypass has the same identity as
            # the pre-lock read.
            if not force or cached is not pre_cached:
                return cached[1]

        global _last_429_time  # noqa: PLW0603
        if time.monotonic() - _last_429_time < _BACKOFF_SECONDS:
            # Breaker open: we can't fetch. A forced refresh serves the cache
            # only while it's still TTL-fresh — that's exactly what the
            # un-forced path would have shown, so a healthy panel is never
            # wiped; but an out-of-TTL snapshot is NOT presented as a live
            # refresh (that would silently hide the rate-limit). Stale or
            # missing cache → honest rate_limited.
            if force and cached and time.monotonic() - cached[0] < _CACHE_TTL:
                return cached[1]
            return ScanFetchResult(status="rate_limited")

        base_url = f"https://{domain}/api/public/v0/scans"
        headers = {"X-Authorization": token}
        result = ScanFetchResult()
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                for i in range(max_pages):
                    resp = await client.get(
                        base_url,
                        headers=headers,
                        params={
                            "sort": "created:desc",
                            "limit": str(page_size),
                            "offset": str(i * page_size),
                        },
                    )
                    if resp.status_code == 429:
                        _last_429_time = time.monotonic()
                        result.status = "rate_limited"
                        logger.warning(
                            "Scans fetch: 429 rate-limit, backing off %ds",
                            _BACKOFF_SECONDS,
                        )
                        break
                    if resp.status_code != 200:
                        result.status = "unreachable"
                        logger.warning(
                            "Scans fetch: unexpected status %d", resp.status_code
                        )
                        break

                    page = _parse_scan_list(resp.json())
                    result.scans.extend(page)
                    result.pages_fetched += 1

                    # No more pages available.
                    if len(page) < page_size:
                        break

                    # Early-stop: all scans on page are terminal.
                    if (
                        early_stop_terminal
                        and page
                        and all(s.get("status") in TERMINAL_STATUSES for s in page)
                    ):
                        logger.debug(
                            "Scans fetch: page %d all terminal, stopping early", i
                        )
                        break

                    # Date-window: oldest scan on page is before `since`.
                    if since is not None:
                        oldest = min(
                            (
                                dt
                                for s in page
                                if (dt := _parse_iso(s.get("created"))) is not None
                            ),
                            default=None,
                        )
                        if oldest is not None and oldest < since:
                            break

                    # Reached the cap; mark as capped.
                    if i == max_pages - 1:
                        result.capped = True

        except Exception as exc:
            logger.warning("Scans fetch error: %s", exc)
            result.status = "unreachable"

        # Only cache successful results.
        if result.status == "ok":
            _cache[key] = (time.monotonic(), result)
            # Prune stale cache entries and any locks whose key is no longer cached,
            # preventing unbounded dict growth across many unique cache keys.
            now_prune = time.monotonic()
            stale = [k for k, (t, _) in _cache.items() if now_prune - t >= _CACHE_TTL]
            for k in stale:
                _cache.pop(k, None)
            orphan_locks = [k for k in list(_locks) if k not in _cache]
            for k in orphan_locks:
                _locks.pop(k, None)

        return result
