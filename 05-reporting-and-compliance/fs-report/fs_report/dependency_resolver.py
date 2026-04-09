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
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fs_report.api_client import APIClient

logger = logging.getLogger(__name__)


@dataclass
class DependencyNode:
    """A node in a project version dependency tree."""

    project_id: int | str
    project_name: str
    version_id: int | str
    path: list[str]  # e.g. ["Root", "Child", "Grandchild"]
    children: list[DependencyNode] = field(default_factory=list)

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

    def __init__(self, api_client: APIClient) -> None:
        self._api_client = api_client
        self._cache: dict[int | str, DependencyNode] = {}

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
                child_proj_id, child_proj_name, child_ver_id, child_path, _visited
            )
            children.append(child_node)
        return DependencyNode(
            project_id=project_id,
            project_name=project_name,
            version_id=version_id,
            path=path,
            children=children,
        )

    def _fetch_dependencies(self, version_id: int | str) -> list[dict]:
        url = f"{self._api_client.base_url}/public/v0/project-versions/{version_id}/dependencies"
        try:
            resp = self._api_client.client.get(url, params={"limit": 100})
            resp.raise_for_status()
            data = resp.json()
            result: list[dict]
            if isinstance(data, list):
                result = data
            elif isinstance(data, dict) and "content" in data:
                result = list(data["content"])
            else:
                return []
            if len(result) >= 100:
                logger.warning(
                    "Version %s returned %d dependencies (limit=100); "
                    "some may be missing due to pagination",
                    version_id,
                    len(result),
                )
            return result
        except Exception:
            logger.warning(
                "Failed to fetch dependencies for version %s", version_id, exc_info=True
            )
            return []
