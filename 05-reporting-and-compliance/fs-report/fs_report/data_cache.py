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

"""Data caching layer for efficient API data reuse across recipes."""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from fs_report.models import QueryConfig


@dataclass
class CacheKey:
    """Cache key for storing API responses."""

    endpoint: str
    params_hash: str
    full_params: dict[str, Any] = field(default_factory=dict)


@dataclass
class CacheEntry:
    """Cache entry containing API response data."""

    data: list[dict[str, Any]]
    timestamp: float
    params: dict[str, Any]


class DataCache:
    """Cache for API responses to enable data reuse across recipes."""

    def __init__(self) -> None:
        """Initialize the data cache."""
        self.cache: dict[str, CacheEntry] = {}
        self.logger = logging.getLogger(__name__)

    def _generate_cache_key(self, query: QueryConfig) -> CacheKey:
        """Generate a cache key for the given query."""
        # Create a hash of the parameters
        params_dict = {
            "filter": query.params.filter,
            "sort": query.params.sort,
            "limit": query.params.limit,
            "offset": query.params.offset,
            "archived": query.params.archived,
        }

        # Remove None values for consistent hashing
        params_dict = {k: v for k, v in params_dict.items() if v is not None}

        # Create hash of parameters
        params_json = json.dumps(params_dict, sort_keys=True)
        params_hash = hashlib.md5(params_json.encode()).hexdigest()

        return CacheKey(
            endpoint=query.endpoint, params_hash=params_hash, full_params=params_dict
        )

    def _can_reuse_data(
        self, cached_params: dict[str, Any], requested_params: dict[str, Any]
    ) -> bool:
        """Check if cached data can be reused for the requested parameters."""
        # If exact match, we can reuse
        if cached_params == requested_params:
            return True

        # Check if we can subset the cached data
        cached_filter = cached_params.get("filter", "")
        requested_filter = requested_params.get("filter", "")

        # If requested filter is more restrictive than cached filter, we can subset
        if self._is_subset_filter(cached_filter, requested_filter):
            return True

        return False

    def _is_subset_filter(self, cached_filter: str, requested_filter: str) -> bool:
        """Check if requested filter is a subset of cached filter."""
        if not cached_filter and requested_filter:
            return False

        if cached_filter == requested_filter:
            return True

        # Simple heuristic: if cached filter is empty or more general,
        # and requested filter adds restrictions, it's likely a subset
        if not cached_filter and requested_filter:
            return True

        # Check for common patterns
        # If cached has date range and requested has same date range + additional filters
        if "detected>=" in cached_filter and "detected>=" in requested_filter:
            # Extract date ranges and compare
            cached_dates = self._extract_date_range(cached_filter)
            requested_dates = self._extract_date_range(requested_filter)

            if cached_dates and requested_dates:
                if cached_dates == requested_dates:
                    # Same date range, check if requested has additional filters
                    return len(requested_filter) > len(cached_filter)

        return False

    def _extract_date_range(self, filter_expr: str) -> tuple[str, str] | None:
        """Extract date range from filter expression."""
        import re

        # Look for detected>= and detected<= patterns
        start_match = re.search(r"detected>=([^;]+)", filter_expr)
        end_match = re.search(r"detected<=([^;]+)", filter_expr)

        if start_match and end_match:
            return (start_match.group(1), end_match.group(1))

        return None

    def _subset_data(
        self, data: list[dict[str, Any]], filter_expr: str
    ) -> list[dict[str, Any]]:
        """Subset data based on filter expression."""
        if not filter_expr:
            return data

        # Simple filtering for common patterns
        # This is a basic implementation - could be enhanced with proper RSQL parsing

        filtered_data = []

        for item in data:
            if self._matches_filter(item, filter_expr):
                filtered_data.append(item)

        return filtered_data

    def _matches_filter(self, item: dict[str, Any], filter_expr: str) -> bool:
        """Check if item matches the filter expression."""
        # Simple implementation for common filters
        # This could be enhanced with proper RSQL parsing

        # Handle type filters
        if "type==" in filter_expr:
            type_match = filter_expr.split("type==")[1].split(";")[0].strip()
            if item.get("type") != type_match:
                return False

        # Handle status filters
        if "status=in=" in filter_expr:
            status_match = filter_expr.split("status=in=")[1].split(";")[0].strip()
            if status_match.startswith("(") and status_match.endswith(")"):
                statuses = status_match[1:-1].split(",")
                if item.get("status") not in statuses:
                    return False

        # Handle severity filters
        if "severity==" in filter_expr:
            severity_match = filter_expr.split("severity==")[1].split(";")[0].strip()
            if item.get("severity") != severity_match:
                return False

        return True

    def get(self, query: QueryConfig) -> list[dict[str, Any]] | None:
        """Get data from cache if available and reusable."""
        cache_key = self._generate_cache_key(query)
        cache_id = f"{cache_key.endpoint}:{cache_key.params_hash}"
        
        # Debug logging to see cache key generation
        self.logger.debug(f"Cache lookup for {cache_id} with params: {cache_key.full_params}")

        if cache_id in self.cache:
            cached_entry = self.cache[cache_id]
            requested_params = cache_key.full_params

            if self._can_reuse_data(cached_entry.params, requested_params):
                self.logger.debug(f"Cache hit for {cache_id}")

                # If exact match, return cached data
                if cached_entry.params == requested_params:
                    return cached_entry.data

                # If subset, filter the cached data
                if requested_params.get("filter"):
                    filtered_data = self._subset_data(
                        cached_entry.data, requested_params["filter"]
                    )
                    self.logger.debug(
                        f"Subset {len(cached_entry.data)} records to {len(filtered_data)} records"
                    )
                    return filtered_data

        return None

    def put(self, query: QueryConfig, data: list[dict[str, Any]]) -> None:
        """Store data in cache."""
        cache_key = self._generate_cache_key(query)
        cache_id = f"{cache_key.endpoint}:{cache_key.params_hash}"
        
        # Debug logging to see what's being cached
        self.logger.debug(f"Caching data for {cache_id} with params: {cache_key.full_params}")

        import time

        self.cache[cache_id] = CacheEntry(
            data=data, timestamp=time.time(), params=cache_key.full_params
        )

        self.logger.debug(f"Cached {len(data)} records for {cache_id}")

    def clear(self) -> None:
        """Clear all cached data."""
        self.cache.clear()
        self.logger.debug("Cache cleared")

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        total_entries = len(self.cache)
        total_records = sum(len(entry.data) for entry in self.cache.values())

        return {
            "total_entries": total_entries,
            "total_records": total_records,
            "cache_keys": list(self.cache.keys()),
        }
