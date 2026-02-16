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
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# --- NVD Terms of Use: required attribution notice ---
NVD_ATTRIBUTION = (
    "This product uses the NVD API but is not endorsed or certified by the NVD."
)

# Rate-limit settings
_RATE_LIMIT_WITH_KEY = 0.6  # seconds between requests (50 req / 30 s)
_RATE_LIMIT_WITHOUT_KEY = 6.0  # seconds between requests (5 req / 30 s)
_REQUEST_TIMEOUT = 30  # seconds


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


@dataclass
class NVDCveRecord:
    """Structured data extracted from a single NVD CVE record."""

    cve_id: str = ""
    description: str = ""
    affected_ranges: list[AffectedRange] = field(default_factory=list)
    references: list[dict[str, Any]] = field(default_factory=list)
    patch_urls: list[str] = field(default_factory=list)
    advisory_urls: list[str] = field(default_factory=list)
    cvss_v2_vector: str = ""
    cvss_v3_vector: str = ""

    @property
    def fix_versions(self) -> list[str]:
        """All distinct fix versions across affected ranges."""
        versions = []
        for r in self.affected_ranges:
            fv = r.fix_version
            if fv and fv not in versions:
                versions.append(fv)
        return versions

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


class NVDClient:
    """Lightweight NVD CVE API 2.0 client with rate limiting and caching."""

    def __init__(
        self,
        api_key: str | None = None,
        cache_dir: str | None = None,
        cache_ttl: int = 86400,  # 24 hours default
    ) -> None:
        self._api_key = api_key or os.environ.get("NVD_API_KEY", "")
        self._rate_limit = (
            _RATE_LIMIT_WITH_KEY if self._api_key else _RATE_LIMIT_WITHOUT_KEY
        )
        self._last_request_time: float = 0.0
        self._cache_ttl = cache_ttl
        self._request_count = 0

        # In-memory cache (session-scoped)
        self._mem_cache: dict[str, NVDCveRecord] = {}

        # SQLite cache — always enabled (defaults to ~/.fs-report/)
        resolved_dir = Path(cache_dir) if cache_dir else Path.home() / ".fs-report"
        resolved_dir.mkdir(parents=True, exist_ok=True)
        self._db_path: Path | None = resolved_dir / "nvd_cache.db"
        self._init_db()

    def _init_db(self) -> None:
        """Create the SQLite cache table if it doesn't exist."""
        if not self._db_path:
            return
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(self._db_path)) as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS nvd_cve_cache (
                    cve_id TEXT PRIMARY KEY,
                    data_json TEXT NOT NULL,
                    fetched_at TEXT NOT NULL
                )"""
            )

    def _rate_limit_wait(self) -> None:
        """Sleep if necessary to respect NVD rate limits."""
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < self._rate_limit:
            wait = self._rate_limit - elapsed
            logger.debug(f"NVD rate limit: waiting {wait:.1f}s")
            time.sleep(wait)

    def _get_from_sqlite(self, cve_id: str) -> NVDCveRecord | None:
        """Retrieve a cached record from SQLite, respecting TTL."""
        if not self._db_path:
            return None
        try:
            with sqlite3.connect(str(self._db_path)) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT data_json, fetched_at FROM nvd_cve_cache WHERE cve_id = ?",
                    (cve_id,),
                ).fetchone()
                if row:
                    fetched_at = datetime.fromisoformat(row["fetched_at"])
                    age = (datetime.utcnow() - fetched_at).total_seconds()
                    if age < self._cache_ttl:
                        return self._deserialize(json.loads(row["data_json"]))
                    logger.debug(f"NVD cache expired for {cve_id} ({age:.0f}s old)")
        except Exception as e:
            logger.debug(f"NVD SQLite cache read error for {cve_id}: {e}")
        return None

    def _save_to_sqlite(self, cve_id: str, record: NVDCveRecord) -> None:
        """Persist a record to SQLite cache."""
        if not self._db_path:
            return
        try:
            data = self._serialize(record)
            with sqlite3.connect(str(self._db_path)) as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO nvd_cve_cache
                       (cve_id, data_json, fetched_at)
                       VALUES (?, ?, ?)""",
                    (cve_id, json.dumps(data), datetime.utcnow().isoformat()),
                )
        except Exception as e:
            logger.debug(f"NVD SQLite cache write error for {cve_id}: {e}")

    @staticmethod
    def _serialize(record: NVDCveRecord) -> dict[str, Any]:
        """Serialize an NVDCveRecord to a JSON-safe dict."""
        return {
            "cve_id": record.cve_id,
            "description": record.description,
            "affected_ranges": [
                {
                    "vendor": r.vendor,
                    "product": r.product,
                    "version_start": r.version_start,
                    "version_start_type": r.version_start_type,
                    "version_end": r.version_end,
                    "version_end_type": r.version_end_type,
                }
                for r in record.affected_ranges
            ],
            "references": record.references,
            "patch_urls": record.patch_urls,
            "advisory_urls": record.advisory_urls,
            "cvss_v2_vector": record.cvss_v2_vector,
            "cvss_v3_vector": record.cvss_v3_vector,
        }

    @staticmethod
    def _deserialize(data: dict[str, Any]) -> NVDCveRecord:
        """Deserialize a dict back into an NVDCveRecord."""
        ranges = [AffectedRange(**r) for r in data.get("affected_ranges", [])]
        return NVDCveRecord(
            cve_id=data.get("cve_id", ""),
            description=data.get("description", ""),
            affected_ranges=ranges,
            references=data.get("references", []),
            patch_urls=data.get("patch_urls", []),
            advisory_urls=data.get("advisory_urls", []),
            cvss_v2_vector=data.get("cvss_v2_vector", ""),
            cvss_v3_vector=data.get("cvss_v3_vector", ""),
        )

    def _fetch_from_api(self, cve_id: str) -> NVDCveRecord | None:
        """Fetch a single CVE record from the NVD API."""
        self._rate_limit_wait()

        headers: dict[str, str] = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

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
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                logger.debug(f"CVE {cve_id} not found in NVD")
            else:
                logger.warning(f"NVD API error for {cve_id}: {e}")
            return None
        except Exception as e:
            logger.warning(f"NVD API request failed for {cve_id}: {e}")
            return None

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            logger.debug(f"No vulnerability data returned for {cve_id}")
            return None

        cve_data = vulnerabilities[0].get("cve", {})
        return self._parse_cve_record(cve_data)

    def _parse_cve_record(self, cve_data: dict[str, Any]) -> NVDCveRecord:
        """Parse a raw NVD CVE JSON object into an NVDCveRecord."""
        cve_id = cve_data.get("id", "")

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
        for ref in cve_data.get("references", []):
            url = ref.get("url", "")
            tags = ref.get("tags", [])
            references.append({"url": url, "tags": tags})
            if "Patch" in tags:
                patch_urls.append(url)
            if "Vendor Advisory" in tags or "Third Party Advisory" in tags:
                advisory_urls.append(url)

        # Extract CVSS vectors from metrics
        cvss_v2_vector = ""
        cvss_v3_vector = ""
        metrics = cve_data.get("metrics", {})
        if isinstance(metrics, dict):
            v2_list = metrics.get("cvssMetricV2", [])
            if isinstance(v2_list, list) and v2_list:
                v2_data = v2_list[0].get("cvssData", {})
                if isinstance(v2_data, dict):
                    cvss_v2_vector = v2_data.get("vectorString", "")
            v3_list = metrics.get("cvssMetricV31", [])
            if not v3_list or not isinstance(v3_list, list):
                v3_list = metrics.get("cvssMetricV30", [])
            if isinstance(v3_list, list) and v3_list:
                v3_data = v3_list[0].get("cvssData", {})
                if isinstance(v3_data, dict):
                    cvss_v3_vector = v3_data.get("vectorString", "")

        return NVDCveRecord(
            cve_id=cve_id,
            description=description,
            affected_ranges=affected_ranges,
            references=references,
            patch_urls=patch_urls,
            advisory_urls=advisory_urls,
            cvss_v2_vector=cvss_v2_vector,
            cvss_v3_vector=cvss_v3_vector,
        )

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
            record = self._fetch_from_api(cve_id)
            if record:
                self._mem_cache[cve_id] = record
                self._save_to_sqlite(cve_id, record)
                results[cve_id] = record

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

        return "\n".join(lines)

    def format_batch_for_prompt(
        self,
        cve_ids: list[str],
    ) -> str:
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
