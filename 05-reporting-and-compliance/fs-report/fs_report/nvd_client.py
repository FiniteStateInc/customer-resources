# Copyright (c) 2024 Finite State, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
NVD (National Vulnerability Database) API 2.0 client.

Fetches CVE records from NVD and extracts:
- Known fix versions from CPE match criteria (``versionEndExcluding``)
- Advisory / patch reference URLs
- Affected version ranges

Results are cached in-memory (per session) and optionally in SQLite
to minimise redundant API calls.  NVD rate limits are respected:
- **Without API key**: 5 requests / 30 s (≈ 1 req / 6 s)
- **With API key**: 50 requests / 30 s (≈ 1 req / 0.6 s)

Set the ``NVD_API_KEY`` environment variable for higher throughput.

**NVD Terms of Use Compliance**:

    This product uses the NVD API but is not endorsed or certified by the NVD.

- Version ranges and fix versions shown in reports are *derived from* NVD data
  and may be reformatted for readability.  The authoritative source is the NVD
  itself at https://nvd.nist.gov/.
- NVD API keys are per-requestor.  Do not share your key with other individuals
  or organisations.  See https://nvd.nist.gov/developers/request-an-api-key.
- The NVD API is provided "as is" and on an "as-available" basis without
  warranties of any kind.  See full terms at
  https://nvd.nist.gov/developers/terms-of-use.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests

from fs_report.cvss import looks_like_vector

logger = logging.getLogger(__name__)

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# --- NVD Terms of Use: required attribution notice ---
NVD_ATTRIBUTION = (
    "This product uses the NVD API but is not endorsed or certified by the NVD."
)

# Rate-limit settings
_RATE_LIMIT_WITH_KEY = 0.8  # seconds between requests (conservative for 50 req / 30 s)
_RATE_LIMIT_WITHOUT_KEY = 6.0  # seconds between requests (5 req / 30 s)
_REQUEST_TIMEOUT = 30  # seconds
_MAX_RETRIES = 3  # retry attempts on 429 rate-limit responses
_RETRY_BACKOFF_BASE = 10.0  # base seconds for exponential backoff (10, 20, 40)


@dataclass
class AffectedRange:
    """A single affected version range extracted from NVD CPE match data."""

    vendor: str = ""
    product: str = ""
    version_start: str = ""
    version_start_type: str = ""  # "including" or "excluding"
    version_end: str = ""
    version_end_type: str = ""  # "including" or "excluding"

    @property
    def fix_version(self) -> str:
        """Return the minimum fixed version, if determinable.

        ``versionEndExcluding`` is the first *non-affected* version,
        i.e. the fix version.  ``versionEndIncluding`` is the last
        *affected* version — the fix is the *next* version (unknown).
        """
        if self.version_end and self.version_end_type == "excluding":
            return self.version_end
        return ""


def _vector_str(value: Any) -> str:
    """A CVSS vector field as a trimmed string, or "" for anything else.

    Applied wherever a vector arrives from outside the direct NVD API parse —
    the hosted mirror and the SQLite cache both hand back rows whose fields
    are whatever the writer stored. The mirror sends already-parsed records,
    so _vector_from_metric never runs on that path and cannot trim or rank
    them; this is the one normalization that still applies there. A padded
    value is trimmed, and a whitespace-only or non-string one becomes "" so
    it cannot shadow a usable older vector downstream.
    """
    return value.strip() if isinstance(value, str) else ""


@dataclass
class NVDCveRecord:
    """Structured data extracted from a single NVD CVE record."""

    cve_id: str = ""
    description: str = ""
    affected_ranges: list[AffectedRange] = field(default_factory=list)
    references: list[dict[str, Any]] = field(default_factory=list)
    patch_urls: list[str] = field(default_factory=list)
    advisory_urls: list[str] = field(default_factory=list)
    workaround_urls: list[str] = field(default_factory=list)
    cvss_v2_vector: str = ""
    cvss_v3_vector: str = ""
    cvss_v4_vector: str = ""
    vuln_status: str = (
        ""  # NVD vulnStatus: Analyzed, Modified, Rejected, Disputed, etc.
    )

    @property
    def fix_versions(self) -> list[str]:
        """All distinct fix versions across affected ranges."""
        versions = []
        for r in self.affected_ranges:
            fv = r.fix_version
            if fv and fv not in versions:
                versions.append(fv)
        return versions

    def fix_version_for(self, installed_version: str) -> str:
        """Return the fix version for the range containing *installed_version*.

        Iterates affected ranges and checks if the installed version falls
        within [version_start, version_end). Returns the matching range's
        fix_version, or falls back to best_fix_for_version() across all
        fix versions.
        """
        from fs_report.purl_utils import _version_tuple, best_fix_for_version

        inst = _version_tuple(installed_version)
        if inst is None:
            return self.fix_versions[0] if self.fix_versions else ""

        for r in self.affected_ranges:
            fv = r.fix_version
            if not fv:
                continue
            # Check if installed is in this range
            start = _version_tuple(r.version_start) if r.version_start else None
            end = _version_tuple(r.version_end) if r.version_end else None

            in_range = True
            if start is not None:
                if r.version_start_type == "including":
                    in_range = inst >= start
                else:
                    in_range = inst > start
            if in_range and end is not None:
                if r.version_end_type == "excluding":
                    in_range = inst < end
                else:
                    in_range = inst <= end

            if in_range:
                return fv

        # No range matched — use best_fix_for_version as fallback
        return best_fix_for_version(installed_version, self.fix_versions)

    @property
    def fix_versions_summary(self) -> str:
        """Human-readable summary of known fix versions.

        Uses clear language to distinguish:
        - ``versionEndExcluding`` → exact minimum fix version (safe to recommend)
        - ``versionEndIncluding`` → last AFFECTED version (NOT safe — fix is
          a later version)
        """
        lines: list[str] = []
        for r in self.affected_ranges:
            fv = r.fix_version
            product = r.product or "unknown"
            if fv:
                # versionEndExcluding — this IS the fix version
                affected = ""
                if r.version_start:
                    op = ">=" if r.version_start_type == "including" else ">"
                    affected = f" (affects {op} {r.version_start})"
                lines.append(f"- {product}: FIXED in >= {fv}{affected}")
            elif r.version_end and r.version_end_type == "including":
                # versionEndIncluding — this version is STILL VULNERABLE
                start_info = ""
                if r.version_start:
                    op = ">=" if r.version_start_type == "including" else ">"
                    start_info = f" (from {op} {r.version_start})"
                lines.append(
                    f"- {product}: version {r.version_end} is STILL VULNERABLE"
                    f"{start_info}. "
                    f"Fix version is NOT in NVD — must be > {r.version_end}. "
                    f"Recommend version AFTER {r.version_end} or verify latest "
                    f"stable release."
                )
        return "\n".join(lines) if lines else ""

    def _serialize(self) -> dict[str, Any]:
        """Serialize this NVDCveRecord to a JSON-safe dict."""
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "affected_ranges": [
                {
                    "vendor": r.vendor,
                    "product": r.product,
                    "version_start": r.version_start,
                    "version_start_type": r.version_start_type,
                    "version_end": r.version_end,
                    "version_end_type": r.version_end_type,
                }
                for r in self.affected_ranges
            ],
            "references": self.references,
            "patch_urls": self.patch_urls,
            "advisory_urls": self.advisory_urls,
            "workaround_urls": self.workaround_urls,
            "cvss_v2_vector": self.cvss_v2_vector,
            "cvss_v3_vector": self.cvss_v3_vector,
            "cvss_v4_vector": self.cvss_v4_vector,
            "vuln_status": self.vuln_status,
        }

    @classmethod
    def _deserialize(cls, data: dict[str, Any]) -> NVDCveRecord:
        """Deserialize a dict back into an NVDCveRecord."""
        ranges = [AffectedRange(**r) for r in data.get("affected_ranges", [])]
        return cls(
            cve_id=data.get("cve_id", ""),
            description=data.get("description", ""),
            affected_ranges=ranges,
            references=data.get("references", []),
            patch_urls=data.get("patch_urls", []),
            advisory_urls=data.get("advisory_urls", []),
            workaround_urls=data.get("workaround_urls", []),
            cvss_v2_vector=_vector_str(data.get("cvss_v2_vector")),
            cvss_v3_vector=_vector_str(data.get("cvss_v3_vector")),
            cvss_v4_vector=_vector_str(data.get("cvss_v4_vector")),
            vuln_status=data.get("vuln_status", ""),
        )


_NVD_METRIC_SOURCE = "nvd@nist.gov"


def _vector_from_metric(*entry_lists: Any) -> str:
    """Vector string out of one or more NVD ``metrics.cvssMetricVxx`` lists.

    A CVE can carry several scorings of the same version — NVD's own plus one
    or more from the CNA or another source — and each entry declares a
    ``type`` of ``"Primary"`` or ``"Secondary"`` and a ``source``. Entries are
    ranked so the vector matches what NVD's own CVE detail page shows:

    1. ``source: nvd@nist.gov`` (NVD's own scoring, whatever its type). A CNA
       can also publish a Primary entry, so ``type`` alone does not identify
       authorship.
    2. Any other ``type: "Primary"`` entry.
    3. Anything else, in list order.

    Several lists can be passed when one version spans more than one metrics
    key (v3 is ``cvssMetricV31`` plus ``cvssMetricV30``): all of them are
    ranked together, so NVD's own v3.0 scoring beats a CNA-supplied v3.1 one,
    and the earlier list only wins a tie. Returns "" when no list holds a
    usable vector.

    A padded vector is returned trimmed, and a whitespace-only one counts as
    no vector at all: a blank ``vectorString`` on the top-ranked entry must
    not suppress a real vector sitting on a lower-ranked one.
    """
    entries = [
        entry
        for entry_list in entry_lists
        if isinstance(entry_list, list)
        for entry in entry_list
        if isinstance(entry, dict)
    ]

    def rank(entry: dict[str, Any]) -> int:
        if str(entry.get("source", "")).lower() == _NVD_METRIC_SOURCE:
            return 0
        return 1 if str(entry.get("type", "")).upper() == "PRIMARY" else 2

    for entry in sorted(entries, key=rank):
        data = entry.get("cvssData", {})
        if not isinstance(data, dict):
            continue
        vector = data.get("vectorString", "")
        if not isinstance(vector, str):
            continue
        text = vector.strip()
        # Shape-check BEFORE accepting the entry, not after. Rank alone would
        # hand back a top-ranked placeholder and discard the real vector below
        # it in the same pool; the transform drops the placeholder later but
        # can no longer recover what was thrown away here, so the row falls
        # back to an older scoring or blanks with a usable vector in hand.
        if text and looks_like_vector(text):
            return text
    return ""


def _parse_cve_record(cve_data: dict[str, Any]) -> NVDCveRecord:
    """Parse a raw NVD CVE JSON object into an NVDCveRecord.

    Module-level helper so it can be used independently of NVDClient.
    """
    cve_id = cve_data.get("id", "")
    vuln_status = cve_data.get("vulnStatus", "")

    # Extract English description
    description = ""
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    # Extract affected version ranges from configurations
    affected_ranges: list[AffectedRange] = []
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                criteria = match.get("criteria", "")
                # Parse CPE 2.3 string: cpe:2.3:a:vendor:product:version:...
                parts = criteria.split(":")
                vendor = parts[3] if len(parts) > 3 else ""
                product = parts[4] if len(parts) > 4 else ""

                ar = AffectedRange(
                    vendor=vendor,
                    product=product,
                )
                if "versionStartIncluding" in match:
                    ar.version_start = match["versionStartIncluding"]
                    ar.version_start_type = "including"
                elif "versionStartExcluding" in match:
                    ar.version_start = match["versionStartExcluding"]
                    ar.version_start_type = "excluding"

                if "versionEndExcluding" in match:
                    ar.version_end = match["versionEndExcluding"]
                    ar.version_end_type = "excluding"
                elif "versionEndIncluding" in match:
                    ar.version_end = match["versionEndIncluding"]
                    ar.version_end_type = "including"

                # Only include ranges that have meaningful version bounds
                if ar.version_start or ar.version_end:
                    affected_ranges.append(ar)

    # Extract references, categorise by tag
    references: list[dict[str, Any]] = []
    patch_urls: list[str] = []
    advisory_urls: list[str] = []
    workaround_urls: list[str] = []
    for ref in cve_data.get("references", []):
        url = ref.get("url", "")
        tags = ref.get("tags", [])
        references.append({"url": url, "tags": tags})
        if "Patch" in tags:
            patch_urls.append(url)
        if "Vendor Advisory" in tags or "Third Party Advisory" in tags:
            advisory_urls.append(url)
        if "Mitigation" in tags or "Workaround" in tags:
            workaround_urls.append(url)

    # Extract CVSS vectors from metrics
    cvss_v2_vector = ""
    cvss_v3_vector = ""
    cvss_v4_vector = ""
    metrics = cve_data.get("metrics", {})
    if isinstance(metrics, dict):
        cvss_v2_vector = _vector_from_metric(metrics.get("cvssMetricV2"))
        # v3.1 and v3.0 are ranked as one pool, v3.1 first: NVD scored
        # 2016–2019 CVEs under v3.0 and CNAs later added v3.1 entries, so
        # taking any v3.1 before looking at v3.0 would print the CNA vector
        # instead of NVD's own.
        cvss_v3_vector = _vector_from_metric(
            metrics.get("cvssMetricV31"), metrics.get("cvssMetricV30")
        )
        cvss_v4_vector = _vector_from_metric(metrics.get("cvssMetricV40"))

    return NVDCveRecord(
        cve_id=cve_id,
        description=description,
        affected_ranges=affected_ranges,
        references=references,
        patch_urls=patch_urls,
        advisory_urls=advisory_urls,
        workaround_urls=workaround_urls,
        cvss_v2_vector=cvss_v2_vector,
        cvss_v3_vector=cvss_v3_vector,
        cvss_v4_vector=cvss_v4_vector,
        vuln_status=vuln_status,
    )


class NVDClient:
    """Lightweight NVD CVE API 2.0 client with rate limiting and caching."""

    def __init__(
        self,
        api_key: str | None = None,
        cache_dir: str | None = None,
        cache_ttl: int = 86400,  # 24 hours default
        cancel_event: threading.Event | None = None,
        domain: str | None = None,
    ) -> None:
        self._api_key = api_key or os.environ.get("NVD_API_KEY", "")
        self._domain = domain or os.environ.get("FINITE_STATE_DOMAIN", "")
        self._rate_limit = (
            _RATE_LIMIT_WITH_KEY if self._api_key else _RATE_LIMIT_WITHOUT_KEY
        )
        self._last_request_time: float = 0.0
        self._cache_ttl = cache_ttl
        self._request_count = 0
        self._cancel_event = cancel_event

        # Hosted NVD mirror service (default backend).
        # Set FS_NVD_SERVICE_URL to override, or "off" to disable.
        _DEFAULT_SERVICE_URL = "https://finite-state-mirror.vercel.app"
        _env_url = os.environ.get("FS_NVD_SERVICE_URL", "").strip()
        if _env_url.lower() == "off":
            self._service_url = ""
        else:
            self._service_url = (_env_url or _DEFAULT_SERVICE_URL).rstrip("/")
        self._service_token = os.environ.get("FS_TOKEN", "") or os.environ.get(
            "FINITE_STATE_AUTH_TOKEN", ""
        )

        # In-memory cache (session-scoped)
        self._db_lock = threading.Lock()
        self._mem_cache: dict[str, NVDCveRecord] = {}
        self.last_batch_missing: list[str] = []

        # SQLite cache — always enabled (defaults to ~/.fs-report/)
        resolved_dir = Path(cache_dir) if cache_dir else Path.home() / ".fs-report"
        resolved_dir.mkdir(parents=True, exist_ok=True)
        self._db_path: Path | None = resolved_dir / "nvd_cache.db"
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self) -> None:
        """Create the SQLite cache table if it doesn't exist."""
        if not self._db_path:
            return
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("""CREATE TABLE IF NOT EXISTS nvd_cve_cache (
                cve_id TEXT PRIMARY KEY,
                data_json TEXT NOT NULL,
                fetched_at TEXT NOT NULL
            )""")
        self._conn.commit()

    def close(self) -> None:
        """Close the persistent SQLite connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _fetch_batch_from_service(
        self, cve_ids: list[str]
    ) -> dict[str, NVDCveRecord] | None:
        """Fetch CVE records from the hosted NVD mirror service.

        Returns dict of results, or None if the service is unavailable
        (caller should fall back to direct NVD API).

        The mirror sends already-serialized NVDCveRecord rows, not raw NVD
        JSON, so _parse_cve_record never runs on this path: each field arrives
        only if the mirror emits it, and which of several same-version
        scorings won is whatever the mirror's own parser decided, not what
        _vector_from_metric would pick. A mirror still on the v2/v3 schema
        therefore yields cvss_v4_vector="" for every CVE — the Findings by
        Project CVSS Vector column falls back to v3 (or v2) until the mirror
        ships the field. Nothing here can synthesize it; the field flows
        through the moment the mirror sends it, which tests/test_nvd_client.py
        pins. The parsing rules in _vector_from_metric apply to the direct NVD
        API path, taken when the mirror is off, unreachable or errors. A
        deployment that needs fs-report's own ranking today can set
        FS_NVD_SERVICE_URL=off to take that path.

        What does still apply here is _vector_str, which _deserialize runs on
        every vector field: a padded string arrives trimmed and a
        whitespace-only one arrives empty, so a blank mirror value cannot
        shadow a usable older vector in the report.
        """
        if not self._service_url or not self._service_token:
            return None

        # Filter to valid CVE IDs only — non-CVE finding IDs (e.g. FS-602-0005)
        # will cause a 400 from the service's CVE ID validation.
        valid_ids = [cid for cid in cve_ids if cid.startswith("CVE-")]
        if not valid_ids:
            return {}

        try:
            headers = {
                "Authorization": f"Bearer {self._service_token}",
                "Accept": "application/x-ndjson",
            }
            if self._domain:
                headers["X-FS-Domain"] = self._domain
            resp = requests.post(
                f"{self._service_url}/api/v1/cves",
                json={"ids": valid_ids},
                headers=headers,
                timeout=60,
            )
            if not resp.ok:
                logger.warning(
                    f"NVD service returned {resp.status_code}, "
                    f"falling back to NVD API"
                )
                return None

            results: dict[str, NVDCveRecord] = {}
            for line in resp.text.strip().split("\n"):
                if not line:
                    continue
                data = json.loads(line)
                if "_meta" in data:
                    continue
                record = NVDCveRecord._deserialize(data)
                results[record.cve_id] = record
            return results
        except Exception as e:
            logger.warning(f"NVD service unavailable ({e}), falling back to NVD API")
            return None

    def _cancellable_sleep(self, seconds: float) -> None:
        """Sleep in short intervals, checking for cancellation."""
        if self._cancel_event is None:
            time.sleep(max(0, seconds))
            return
        # Sleep in 0.5s chunks so we can respond to cancel quickly
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if self._cancel_event.is_set():
                from fs_report.report_engine import ReportCancelled

                raise ReportCancelled("Report cancelled by user")
            time.sleep(max(0, min(0.5, end - time.monotonic())))

    def _rate_limit_wait(self) -> None:
        """Sleep if necessary to respect NVD rate limits."""
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < self._rate_limit:
            wait = self._rate_limit - elapsed
            logger.debug(f"NVD rate limit: waiting {wait:.1f}s")
            self._cancellable_sleep(wait)

    def _get_from_sqlite(self, cve_id: str) -> NVDCveRecord | None:
        """Retrieve a cached record from SQLite, respecting TTL."""
        if not self._conn:
            return None
        with self._db_lock:
            try:
                row = self._conn.execute(
                    "SELECT data_json, fetched_at FROM nvd_cve_cache WHERE cve_id = ?",
                    (cve_id,),
                ).fetchone()
                if row:
                    fetched_at = datetime.fromisoformat(row["fetched_at"])
                    if fetched_at.tzinfo is None:
                        fetched_at = fetched_at.replace(tzinfo=UTC)
                    age = (datetime.now(UTC) - fetched_at).total_seconds()
                    if age < self._cache_ttl:
                        # Rows written before a field existed deserialize with
                        # that field empty (_deserialize defaults every key),
                        # and are served as-is rather than forced stale: this
                        # cache is shared by every NVD-backed report, so
                        # invalidating on schema age would cold-start all of
                        # them at once and would drop a whole CVE's data if
                        # the refetch then failed. A newly parsed field fills
                        # in as entries expire normally. An operator who
                        # needs it sooner runs `fs-report cache clear --nvd`
                        # (or the web UI's Settings > Cache > Clear on the NVD
                        # row), which drops the whole store deliberately
                        # rather than silently expiring rows by schema age.
                        return self._deserialize(json.loads(row["data_json"]))
                    logger.debug(f"NVD cache expired for {cve_id} ({age:.0f}s old)")
            except Exception as e:
                logger.debug(f"NVD SQLite cache read error for {cve_id}: {e}")
        return None

    def _save_to_sqlite(self, cve_id: str, record: NVDCveRecord) -> None:
        """Persist a record to SQLite cache."""
        if not self._conn:
            return
        with self._db_lock:
            try:
                data = self._serialize(record)
                self._conn.execute(
                    """INSERT OR REPLACE INTO nvd_cve_cache
                       (cve_id, data_json, fetched_at)
                       VALUES (?, ?, ?)""",
                    (cve_id, json.dumps(data), datetime.now(UTC).isoformat()),
                )
                self._conn.commit()
            except Exception as e:
                logger.debug(f"NVD SQLite cache write error for {cve_id}: {e}")

    @staticmethod
    def _serialize(record: NVDCveRecord) -> dict[str, Any]:
        """Serialize an NVDCveRecord to a JSON-safe dict."""
        return record._serialize()

    @staticmethod
    def _deserialize(data: dict[str, Any]) -> NVDCveRecord:
        """Deserialize a dict back into an NVDCveRecord."""
        return NVDCveRecord._deserialize(data)

    def _fetch_from_api(self, cve_id: str) -> NVDCveRecord | None:
        """Fetch a single CVE record from the NVD API with retry on 429."""
        headers: dict[str, str] = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

        for attempt in range(_MAX_RETRIES + 1):
            self._rate_limit_wait()
            try:
                self._last_request_time = time.monotonic()
                self._request_count += 1
                response = requests.get(
                    NVD_CVE_API,
                    params={"cveId": cve_id},
                    headers=headers,
                    timeout=_REQUEST_TIMEOUT,
                )
                response.raise_for_status()
                data = response.json()
                break  # success
            except requests.exceptions.HTTPError as e:
                if e.response is not None and e.response.status_code == 404:
                    logger.debug(f"CVE {cve_id} not found in NVD")
                    return None
                if (
                    e.response is not None
                    and e.response.status_code == 429
                    and attempt < _MAX_RETRIES
                ):
                    wait = _RETRY_BACKOFF_BASE * (2**attempt)
                    logger.warning(
                        f"NVD 429 rate-limited for {cve_id}, "
                        f"retrying in {wait:.0f}s (attempt {attempt + 1}/{_MAX_RETRIES})"
                    )
                    self._cancellable_sleep(wait)
                    continue
                logger.warning(f"NVD API error for {cve_id}: {e}")
                return None
            except Exception as e:
                logger.warning(f"NVD API request failed for {cve_id}: {e}")
                return None
        else:
            # All retries exhausted
            logger.warning(f"NVD API retries exhausted for {cve_id}")
            return None

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            logger.debug(f"No vulnerability data returned for {cve_id}")
            return None

        cve_data = vulnerabilities[0].get("cve", {})
        return self._parse_cve_record(cve_data)

    def _parse_cve_record(self, cve_data: dict[str, Any]) -> NVDCveRecord:
        """Parse a raw NVD CVE JSON object into an NVDCveRecord."""
        return _parse_cve_record(cve_data)

    def get_cve(self, cve_id: str) -> NVDCveRecord | None:
        """
        Get structured CVE data, checking caches first.

        Lookup order: in-memory → SQLite → NVD API.

        Returns:
            NVDCveRecord or None if the CVE cannot be resolved.
        """
        # 1. In-memory cache
        if cve_id in self._mem_cache:
            return self._mem_cache[cve_id]

        # 2. SQLite cache
        cached = self._get_from_sqlite(cve_id)
        if cached:
            self._mem_cache[cve_id] = cached
            return cached

        # 3. Live API
        record = self._fetch_from_api(cve_id)
        if record:
            self._mem_cache[cve_id] = record
            self._save_to_sqlite(cve_id, record)
        return record

    def get_batch(
        self,
        cve_ids: list[str],
        progress: bool = True,
    ) -> dict[str, NVDCveRecord]:
        """
        Fetch multiple CVE records with progress reporting.

        Args:
            cve_ids: List of CVE identifiers (e.g. ["CVE-2024-1234"]).
            progress: Show tqdm progress bar.

        Returns:
            Dict mapping CVE ID → NVDCveRecord (missing CVEs omitted).
        """
        results: dict[str, NVDCveRecord] = {}
        to_fetch: list[str] = []

        # Resolve from caches first
        for cve_id in cve_ids:
            if cve_id in self._mem_cache:
                results[cve_id] = self._mem_cache[cve_id]
            else:
                cached = self._get_from_sqlite(cve_id)
                if cached:
                    self._mem_cache[cve_id] = cached
                    results[cve_id] = cached
                else:
                    to_fetch.append(cve_id)

        if not to_fetch:
            return results

        # Try hosted service first (all uncached IDs in one batch)
        if self._service_url:
            service_results = self._fetch_batch_from_service(to_fetch)
            if service_results is not None:
                for cve_id, record in service_results.items():
                    self._mem_cache[cve_id] = record
                    self._save_to_sqlite(cve_id, record)
                    results[cve_id] = record
                # Track missing
                self.last_batch_missing = [
                    cve_id for cve_id in cve_ids if cve_id not in results
                ]
                if self.last_batch_missing:
                    preview = self.last_batch_missing[:10]
                    logger.warning(
                        f"NVD: {len(self.last_batch_missing)}/{len(cve_ids)} CVEs could "
                        f"not be resolved: {', '.join(preview)}"
                        + (" ..." if len(self.last_batch_missing) > 10 else "")
                    )
                return results

        logger.info(f"NVD: {len(results)} cached, {len(to_fetch)} to fetch from API")

        iterator: Any = to_fetch
        if progress:
            try:
                from tqdm import tqdm

                iterator = tqdm(
                    to_fetch,
                    desc="Fetching NVD fix data",
                    unit=" CVEs",
                )
            except ImportError:
                pass

        for cve_id in iterator:
            if self._cancel_event is not None and self._cancel_event.is_set():
                from fs_report.report_engine import ReportCancelled

                raise ReportCancelled("Report cancelled by user")
            api_record = self._fetch_from_api(cve_id)
            if api_record:
                self._mem_cache[cve_id] = api_record
                self._save_to_sqlite(cve_id, api_record)
                results[cve_id] = api_record

        # Track CVEs that could not be resolved
        self.last_batch_missing = [
            cve_id for cve_id in cve_ids if cve_id not in results
        ]
        if self.last_batch_missing:
            preview = self.last_batch_missing[:10]
            logger.warning(
                f"NVD: {len(self.last_batch_missing)}/{len(cve_ids)} CVEs could "
                f"not be resolved: {', '.join(preview)}"
                + (" ..." if len(self.last_batch_missing) > 10 else "")
            )

        return results

    def format_for_prompt(self, cve_id: str) -> str:
        """
        Build a compact prompt snippet with NVD fix data for a single CVE.

        Version ranges are derived from NVD CPE match criteria and reformatted
        for readability.  Per NVD Terms of Use, modified content is labelled
        as "derived from" rather than attributed directly to NVD.

        Returns an empty string if no useful data is available.
        """
        record = self.get_cve(cve_id)
        if not record:
            return ""

        lines: list[str] = []

        # Description helps LLMs detect false-positive CPE matches
        if record.description:
            desc = record.description[:200]
            if len(record.description) > 200:
                desc += "..."
            lines.append(f"NVD Description: {desc}")

        # Vendor/product pairs show what the CVE actually targets
        if record.affected_ranges:
            targets = []
            for ar in record.affected_ranges:
                if ar.vendor or ar.product:
                    targets.append(
                        f"{ar.vendor}/{ar.product}" if ar.vendor else ar.product
                    )
            if targets:
                lines.append(f"NVD Target: {', '.join(dict.fromkeys(targets))}")

        if lines:
            lines.append("")  # blank separator before fix versions

        fix_summary = record.fix_versions_summary
        if fix_summary:
            lines.append("## Known Fix Versions (derived from NVD)")
            lines.append(fix_summary)

        if record.patch_urls:
            lines.append("\n## Patch References (via NVD)")
            for url in record.patch_urls[:5]:
                lines.append(f"- {url}")

        if record.advisory_urls and not record.patch_urls:
            lines.append("\n## Advisory References (via NVD)")
            for url in record.advisory_urls[:3]:
                lines.append(f"- {url}")

        if record.workaround_urls:
            lines.append("\n## Workaround & Mitigation References (via NVD)")
            for url in record.workaround_urls[:5]:
                lines.append(f"- {url}")

        return "\n".join(lines)

    def format_batch_for_prompt(self, cve_ids: list[str]) -> str:
        """
        Build a combined prompt snippet with NVD fix data for multiple CVEs.

        Returns an empty string if no useful data is available.
        """
        sections: list[str] = []
        for cve_id in cve_ids:
            snippet = self.format_for_prompt(cve_id)
            if snippet:
                sections.append(f"### {cve_id}\n{snippet}")

        if not sections:
            return ""

        return (
            "## NVD Fix Intelligence\n"
            "_Version data derived from NVD API. "
            "This product uses the NVD API but is not endorsed or certified "
            "by the NVD._\n\n" + "\n\n".join(sections)
        )

    def get_stats(self) -> dict[str, int]:
        """Return request statistics."""
        return {
            "nvd_api_requests": self._request_count,
            "nvd_cache_size": len(self._mem_cache),
        }
