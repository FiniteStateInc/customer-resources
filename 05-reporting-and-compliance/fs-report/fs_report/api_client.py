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

"""API client for communicating with the Finite State REST API."""

import logging
import os
import json
import time
import random
from typing import Any, List

import httpx
from httpx import HTTPStatusError
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

import tempfile
import shutil
import json.decoder
from json.decoder import JSONDecodeError

from fs_report.data_cache import DataCache
from fs_report.models import Config, QueryConfig, QueryParams
from tqdm import tqdm


class APIClient:
    """Client for interacting with the Finite State REST API."""

    def __init__(self, config: Config, cache: DataCache | None = None) -> None:
        """Initialize the API client."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.cache = cache or DataCache()

        # Suppress httpx HTTP request logging unless verbose
        if not config.verbose:
            logging.getLogger("httpx").setLevel(logging.WARNING)

        # Setup HTTP client
        self.base_url = f"https://{config.domain}/api"
        self.headers = {
            "X-Authorization": config.auth_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        # Initialize HTTP client with timeout and retry logic
        self.client = httpx.Client(
            timeout=httpx.Timeout(30.0),
            headers=self.headers,
        )

    def fetch_data(self, query: QueryConfig) -> list[dict[str, Any]]:
        """Fetch a single page of data from the API based on query configuration."""
        self.logger.debug(f"Fetching data from endpoint: {query.endpoint}")

        # Check cache first
        cached_data = self.cache.get(query)
        if cached_data is not None:
            self.logger.debug(f"Using cached data for {query.endpoint} ({len(self.cache.get(query))} records)")
            return cached_data

        # Build URL
        url = f"{self.base_url}{query.endpoint}"

        # Prepare query parameters
        params: dict[str, str] = {}
        if query.params.filter:
            endpoint_str = getattr(query, 'endpoint', '') or ''
            self.logger.debug(f"Substituting variables for endpoint: {endpoint_str}, filter: {query.params.filter}")
            params["filter"] = self._substitute_variables(query.params.filter, endpoint_str)
        if query.params.sort:
            params["sort"] = query.params.sort
        if query.params.limit:
            params["limit"] = str(query.params.limit)
        if query.params.offset:
            params["offset"] = str(query.params.offset)
        if query.params.archived is not None:
            params["archived"] = str(query.params.archived).lower()

        # Log the actual API request parameters
        self.logger.debug(f"Actual API request params: {params}")

        try:
            self.logger.debug(f"Making API request to {url} with params {params}")
            response = self.client.get(url, params=params, timeout=60)
            self.logger.debug(f"API response received for {url}")
            response.raise_for_status()
            data = response.json()

            # Handle different API response formats
            # Some endpoints return a list directly, others return {"items": [...]} or {"scans": [...]}
            if isinstance(data, list):
                self.logger.debug(f"Retrieved {len(data)} records (single page, list format)")
                # Cache the data for this page
                self.cache.put(query, data)
                return data
            elif isinstance(data, dict):
                # Check for common pagination response formats
                items = data.get("items") or data.get("scans") or data.get("data")
                if items and isinstance(items, list):
                    self.logger.debug(f"Retrieved {len(items)} records (single page, object format with items/scans/data key)")
                    # Cache the data for this page
                    self.cache.put(query, items)
                    return items
                else:
                    # Single record as dict
                    self.logger.debug("Retrieved single record (dict format)")
                    result = [data] if data else []
                    self.cache.put(query, result)
                    return result
            else:
                self.logger.debug("Retrieved single record")
                result = [data] if data else []
                self.cache.put(query, result)
                return result
        except Exception as e:
            self.logger.error(f"Error fetching data from {url}: {e}")
            raise

    def fetch_all_with_resume(self, query: Any, progress_file: str = None, max_retries: int = 8) -> List[dict]:
        """
        Fetch all paginated results with robust retry, progress logging, and resume support.
        Stores progress/results in a JSON file (progress_file). Resumes from last offset if interrupted.
        """
        # Check cache first
        cached_data = self.cache.get(query)
        if cached_data is not None:
            self.logger.info(f"Using cached data for {query.endpoint} ({len(cached_data)} records)")
            return cached_data
        
        # Only proceed with API calls if not using cache
        offset = 0
        all_results = []
        limit = getattr(query.params, 'limit', 10000) or 10000
        consecutive_empty_pages = 0
        max_consecutive_empty = 3  # Stop after 3 consecutive empty pages
        self.logger.debug(f"fetch_all_with_resume called for endpoint: {getattr(query, 'endpoint', None)}, progress_file: {progress_file}")
        if not progress_file:
            # Default: output/findings_progress.json or output/{endpoint}_progress.json
            endpoint = query.endpoint.strip('/').replace('/', '_')
            progress_file = os.path.join(self.config.output_dir, f"{endpoint}_progress.json")
        # Resume support
        if os.path.exists(progress_file):
            try:
                with open(progress_file, "r") as f:
                    progress = json.load(f)
                    offset = progress.get("offset", 0)
                    all_results = progress.get("results", [])
                self.logger.info(f"Resuming from offset {offset}, {len(all_results)} records already fetched.")
            except JSONDecodeError as e:
                self.logger.warning(f"Progress file {progress_file} is corrupted: {e}. Deleting and starting over.")
                os.remove(progress_file)
                offset = 0
                all_results = []
        retry_count = 0
        using_cache = False
        try:
            # TQDM progress bar setup
            bar_desc = f"           Fetching {getattr(query, 'endpoint', '')}"
            pbar = tqdm(total=None, desc=bar_desc, ncols=100, bar_format="{desc} |{bar}| {n_fmt} records")
            
            while True:
                page_query = query.copy(deep=True)
                page_query.params.offset = offset
                self.logger.debug(f"Fetching: {query.endpoint} offset={offset} limit={limit}")
                try:
                    # Log query parameters
                    self.logger.debug(f"Query params: {getattr(page_query, 'params', None)}")
                    self.logger.debug(f"Actual API request params: {getattr(page_query, 'params', None)}")
                    self.logger.debug(f"Making API request to {self.config.domain}{query.endpoint} with params {getattr(page_query, 'params', None)}")
                    # Check if this page will come from cache
                    cached_check = self.cache.get(page_query)
                    if cached_check is not None and not using_cache:
                        # Update progress bar to indicate cache usage
                        using_cache = True
                        pbar.set_description_str(f"           Using cache for {getattr(query, 'endpoint', '')}")
                    
                    page = self.fetch_data(page_query)
                    self.logger.debug(f"API response received for {self.config.domain}{query.endpoint}")
                    self.logger.debug(f"Fetched page with {len(page) if page else 0} records at offset {offset}")
                    # Log first 5 record IDs (if present)
                    if page and isinstance(page, list) and len(page) > 0:
                        ids = [rec.get('id', '<no id>') for rec in page[:5]]
                        self.logger.debug(f"First 5 record IDs at offset {offset}: {ids}")
                except Exception as e:
                    # Handle rate limit (429) or network error
                    wait = (2 ** min(retry_count, 6)) + random.uniform(0, 1)
                    self.logger.warning(f"Error fetching page at offset {offset}: {e}. Retrying in {wait:.1f}s...")
                    time.sleep(wait)
                    retry_count += 1
                    if retry_count > max_retries:
                        self.logger.error(f"Max retries exceeded at offset {offset}. Aborting.")
                        break
                    continue
                retry_count = 0  # Reset on success
                if not page:
                    consecutive_empty_pages += 1
                    self.logger.debug(f"Empty page at offset {offset} (consecutive empty: {consecutive_empty_pages})")
                    if consecutive_empty_pages >= max_consecutive_empty:
                        self.logger.debug(f"Stopping pagination after {consecutive_empty_pages} consecutive empty pages.")
                        break
                    offset += limit
                    continue
                
                consecutive_empty_pages = 0  # Reset on successful page
                
                # Check for duplicate records (indicates we've reached the end)
                if all_results and len(page) > 0:
                    page_ids = {rec.get('id') for rec in page if rec.get('id')}
                    existing_ids = {rec.get('id') for rec in all_results if rec.get('id')}
                    duplicates = page_ids & existing_ids
                    if duplicates:
                        self.logger.debug(f"Found {len(duplicates)} duplicate record IDs at offset {offset}. Stopping pagination.")
                        break
                    
                    # Safety check: if all records in this page are duplicates, stop
                    if len(page_ids) > 0 and len(duplicates) == len(page_ids):
                        self.logger.debug(f"All {len(page_ids)} records in page at offset {offset} are duplicates. Stopping pagination.")
                        break
                
                all_results.extend(page)
                offset += limit
                # Progress logging (atomic write)
                tempdir = os.path.dirname(progress_file) or "."
                with tempfile.NamedTemporaryFile("w", delete=False, dir=tempdir) as tf:
                    json.dump({"offset": offset, "results": all_results}, tf)
                    tempname = tf.name
                shutil.move(tempname, progress_file)
                pbar.update(len(page))
                self.logger.debug(f"Fetched {len(all_results)} records so far (page had {len(page)} records). Progress saved to {progress_file}.")
                
                # Continue pagination until we get an empty page or duplicates
                # Don't stop just because a page has fewer than limit records - the API may return
                # fewer records on the last page, but we should continue to check for more
                # The loop will continue and check the next page, which will be empty if we've reached the end
        finally:
            pbar.close()
        self.logger.debug(f"Total records fetched: {len(all_results)}")
        # Clean up progress file after successful fetch
        if os.path.exists(progress_file):
            try:
                os.remove(progress_file)
                self.logger.debug(f"Progress file {progress_file} removed after successful fetch.")
            except Exception as e:
                self.logger.warning(f"Could not remove progress file {progress_file}: {e}")
        return all_results

    def _substitute_variables(self, filter_expr: str, endpoint: str = "") -> str:
        """Substitute date variables in filter expressions."""
        from datetime import datetime

        # Convert date strings to UTC datetime format
        start_dt = datetime.fromisoformat(self.config.start_date).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        end_dt = datetime.fromisoformat(self.config.end_date).replace(
            hour=23, minute=59, second=59, microsecond=999999
        )

        # Format as UTC datetime strings
        # Findings endpoint expects format without Z suffix (e.g., "2025-02-25T14:23:00")
        # Other endpoints may require Z suffix
        # Check for findings endpoint (case-insensitive, handles /public/v0/findings or /findings)
        is_findings_endpoint = "/findings" in endpoint.lower() if endpoint else False
        if is_findings_endpoint:
            start_str = start_dt.strftime("%Y-%m-%dT%H:%M:%S")
            end_str = end_dt.strftime("%Y-%m-%dT%H:%M:%S")
            self.logger.debug(f"Formatting dates for findings endpoint (no Z): {start_str} to {end_str}")
        else:
            # For other endpoints, use Z suffix
            start_str = start_dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
            end_str = end_dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
            self.logger.debug(f"Formatting dates for other endpoint (with Z): {start_str} to {end_str}, endpoint={endpoint}")

        # Replace ${start} and ${end} with actual datetime strings
        result = filter_expr.replace("${start}", start_str)
        result = result.replace("${end}", end_str)
        
        # Log the substitution for debugging
        if "${start}" in filter_expr or "${end}" in filter_expr:
            self.logger.debug(f"Date filter substitution: {filter_expr} -> {result}")

        return result

    def test_connection(self) -> bool:
        """Test the API connection and authentication."""
        try:
            # Try to fetch a small amount of data from a simple endpoint
            test_query = QueryConfig(
                endpoint="/public/v0/projects",
                params=QueryParams(limit=1),
            )
            self.fetch_data(test_query)
            return True
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        return self.cache.get_stats()

    def clear_cache(self) -> None:
        """Clear the data cache."""
        self.cache.clear()

    def __enter__(self) -> "APIClient":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.client.close()
