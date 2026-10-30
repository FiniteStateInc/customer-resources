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

"""Dependency resolution for project version trees."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx

from fs_report.api_client import _cancellable_sleep, _is_retryable, _retry_wait

if TYPE_CHECKING:
    from fs_report.api_client import APIClient

logger = logging.getLogger(__name__)

_DEP_PAGE_SIZE = 100
_MAX_DEP_PAGES = 1000  # 100k direct dependencies; beyond this assume a looping server
_STRICT_RETRIES = 8  # as list pagination (fetch_all_with_resume)


@dataclass
class DependencyNode:
    """A node in a project version dependency tree."""

    project_id: int | str
    project_name: str
    version_id: int | str
    path: list[str]  # e.g. ["Root", "Child", "Grandchild"]
    children: list[DependencyNode] = field(default_factory=list)
    version_name: str = ""

    @property
    def dependency_path_str(self) -> str:
        """Human-readable path: 'Root -> Child -> Grandchild'."""
        return " -> ".join(self.path)

    @property
    def has_dependencies(self) -> bool:
        return len(self.children) > 0

    def all_version_ids(self) -> list:
        """Return all unique version IDs in tree (depth-first)."""
        seen: set = set()
        result: list = []
        self._collect_version_ids(seen, result)
        return result

    def _collect_version_ids(self, seen: set, result: list) -> None:
        if self.version_id not in seen:
            seen.add(self.version_id)
            result.append(self.version_id)
        for child in self.children:
            child._collect_version_ids(seen, result)

    def all_nodes(self) -> list[DependencyNode]:
        """Return every node in the tree (root first, depth-first)."""
        out: list[DependencyNode] = [self]
        for child in self.children:
            out.extend(child.all_nodes())
        return out

    def version_id_to_path_map(self) -> dict:
        """Map version ID -> dependency path string. First path wins for diamonds."""
        result: dict = {}
        self._collect_path_map(result)
        return result

    def _collect_path_map(self, result: dict) -> None:
        if self.version_id not in result:
            result[self.version_id] = self.dependency_path_str
        for child in self.children:
            child._collect_path_map(result)


class DependencyResolver:
    """Resolves full dependency trees for project versions via the Finite State API."""

    def __init__(
        self,
        api_client: APIClient,
        strict: bool = False,
        check_cancel: Callable[[], None] | None = None,
    ) -> None:
        """strict=True retries transient failures, then raises instead of
        silently treating a version as a leaf (for exports that must be complete).
        ``check_cancel`` is called before each page and during waits, and
        raises to stop."""
        self._api_client = api_client
        self._strict = strict
        self._cancel = check_cancel
        # Set once check_cancel raised, so a Stop during a retry wait is
        # re-raised as is rather than reported as a failed fetch.
        self._stopped = False
        # Spacing between pages, as list pagination uses.
        self._delay = float(getattr(api_client, "request_delay", 0) or 0)
        self._cache: dict[int | str, DependencyNode] = {}
        # Lenient mode: versions whose dependency list was kept partial (a later
        # page failed, the server repeated a page, or the page cap was hit).
        self.truncated_versions: set[int | str] = set()

    def resolve(
        self, project_id: int | str, project_name: str, version_id: int | str
    ) -> DependencyNode:
        """Resolve full dependency tree. Cached by version_id."""
        if version_id in self._cache:
            return self._cache[version_id]
        root = self._resolve_recursive(
            project_id, project_name, version_id, [project_name]
        )
        self._cache[version_id] = root
        return root

    def _resolve_recursive(
        self,
        project_id: int | str,
        project_name: str,
        version_id: int | str,
        path: list[str],
        _visited: set | None = None,
        version_name: str = "",
    ) -> DependencyNode:
        if _visited is None:
            _visited = set()
        if version_id in _visited:
            logger.debug(
                "Already visited version %s (%s); skipping re-traversal "
                "(diamond dependency)",
                version_id,
                project_name,
            )
            return DependencyNode(
                project_id=project_id,
                project_name=project_name,
                version_id=version_id,
                path=path,
                children=[],
                version_name=version_name,
            )
        _visited.add(version_id)

        children = []
        deps = self._fetch_dependencies(version_id)
        for dep in deps:
            dep_project = dep.get("dependencyProject", {})
            dep_version = dep.get("dependencyProjectVersion", {})
            child_proj_id = dep_project.get("id")
            child_proj_name = dep_project.get("name", "")
            child_ver_id = dep_version.get("id")
            if not child_proj_id or not child_ver_id:
                continue
            child_path = path + [child_proj_name]
            child_node = self._resolve_recursive(
                child_proj_id,
                child_proj_name,
                child_ver_id,
                child_path,
                _visited,
                dep_version.get("version") or dep_version.get("name") or "",
            )
            children.append(child_node)
        return DependencyNode(
            project_id=project_id,
            project_name=project_name,
            version_id=version_id,
            path=path,
            children=children,
            version_name=version_name,
        )

    def _check_cancel(self) -> None:
        if self._cancel is None:
            return
        try:
            self._cancel()
        except BaseException:
            self._stopped = True
            raise

    def _wait(self, seconds: float) -> None:
        _cancellable_sleep(seconds, self._check_cancel if self._cancel else None)

    def _get_page(self, url: str, params: dict[str, int]) -> tuple[Any, int | None]:
        """The page's JSON and the server's x-total-count, if it sent one."""
        attempt = 0
        while True:
            try:
                resp = self._api_client.client.get(url, params=params)
                resp.raise_for_status()
                total = str(resp.headers.get("x-total-count") or "")
                return resp.json(), int(total) if total.isdigit() else None
            except (httpx.HTTPStatusError, httpx.RequestError) as e:
                status = getattr(getattr(e, "response", None), "status_code", None)
                retryable = status is None or _is_retryable(status)
                if not self._strict or not retryable or attempt >= _STRICT_RETRIES:
                    raise
                retry_after = (
                    e.response.headers.get("Retry-After")
                    if isinstance(e, httpx.HTTPStatusError)
                    else None
                )
                wait = _retry_wait(retry_after, attempt)
                attempt += 1
                logger.warning(
                    "Dependency fetch failed (%s), retry %d/%d in %.0fs",
                    status or e,
                    attempt,
                    _STRICT_RETRIES,
                    wait,
                )
                self._wait(wait)

    def _incomplete(self, version_id: int | str, why: str) -> None:
        if self._strict:
            raise RuntimeError(f"Dependencies for version {version_id}: {why}")
        self.truncated_versions.add(version_id)
        logger.warning("Dependencies for version %s: %s", version_id, why)

    def _fetch_dependencies(self, version_id: int | str) -> list[dict]:
        url = f"{self._api_client.base_url}/public/v0/project-versions/{version_id}/dependencies"
        result: list[dict] = []
        prev_first: Any = None
        total: int | None = None
        for page_no in range(_MAX_DEP_PAGES):
            self._check_cancel()  # outside the try: a Stop is not a fetch failure
            if page_no and self._delay:
                self._wait(self._delay)
            try:
                data, page_total = self._get_page(
                    url, {"limit": _DEP_PAGE_SIZE, "offset": len(result)}
                )
            except Exception as e:
                if self._stopped:
                    raise
                if self._strict:
                    raise RuntimeError(
                        f"Failed to fetch dependencies for version {version_id}: {e}"
                    ) from e
                logger.warning(
                    "Failed to fetch dependencies for version %s",
                    version_id,
                    exc_info=True,
                )
                if result:
                    self.truncated_versions.add(version_id)
                return result  # keep earlier pages (pre-pagination behaviour)
            # The last count the server sent: a final page without the header
            # still gets checked.
            if page_total is not None:
                total = page_total
            if isinstance(data, dict):
                data = data.get("content", [])
            if not isinstance(data, list) or not data:
                return self._checked(version_id, result, total)
            # Records may carry no top-level id: key on the dependency too. A
            # record with neither has no key, so it is never called a repeat.
            first = (
                (
                    data[0].get("id"),
                    (data[0].get("dependencyProjectVersion") or {}).get("id"),
                )
                if isinstance(data[0], dict)
                else None
            )
            if first == (None, None):
                first = None
            if first is not None and first == prev_first:
                self._incomplete(version_id, "server repeated a page (offset ignored)")
                return result
            prev_first = first
            result.extend(data)
            if len(data) < _DEP_PAGE_SIZE:
                return self._checked(version_id, result, total)
        self._incomplete(version_id, f"stopped after {_MAX_DEP_PAGES} pages")
        return result

    def _checked(
        self, version_id: int | str, result: list[dict], total: int | None
    ) -> list[dict]:
        # A short page ends paging; the server's count says whether it was last.
        if total is not None and len(result) < total:
            self._incomplete(version_id, f"got {len(result)} of {total} dependencies")
        return result
