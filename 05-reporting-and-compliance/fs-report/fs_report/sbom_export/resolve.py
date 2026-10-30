"""Unique project / version resolution for SBOM export."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from fs_report.models import QueryConfig, QueryParams

_ID_SHAPE = re.compile(r"^(-?\d+|[0-9a-fA-F-]{32,36})$")  # as ApiClient.resolve_project


class AmbiguousProjectError(ValueError):
    """A project name matched several projects."""

    def __init__(self, message: str, candidates: list[dict[str, Any]]):
        super().__init__(message)
        self.candidates = candidates


def _fetch_all(api_client: Any, query: QueryConfig) -> list[dict[str, Any]]:
    """Every page (fetch_data returns only the first)."""
    rows: list[dict[str, Any]] = api_client.fetch_all_with_resume(
        query, show_progress=False, strict=True
    )
    return rows


def _folder(p: dict[str, Any]) -> dict[str, Any]:
    return p.get("folder") or {}


def _path_parts(folder: str) -> list[str]:
    """``A/B/C`` or the engine's ``A / B / C`` as lowercased segments."""
    return [p.strip() for p in folder.lower().split("/") if p.strip()]


def _folder_tree_ids(api_client: Any, folder: str) -> set[str]:
    """Lowercased ids of the folders ``folder`` names, ids or paths, and all
    their descendants: --folder includes sub-folders, as ReportEngine's
    _collect_folder_tree does. A path matches the last segments of a folder's
    full path from the top (``Division-A/Devices`` never matches
    ``Division-B/Devices``)."""
    folders = _fetch_all(
        api_client,
        QueryConfig(endpoint="/public/v0/folders", params=QueryParams(limit=10000)),
    )
    by_id = {str(f.get("id", "")).lower(): f for f in folders}
    children: dict[str, list[str]] = {}
    for f in folders:
        if f.get("parentFolderId"):
            children.setdefault(str(f["parentFolderId"]).lower(), []).append(
                str(f.get("id", "")).lower()
            )

    def full_path(f: dict[str, Any]) -> list[str]:
        parts: list[str] = []
        seen: set[str] = set()
        node: dict[str, Any] | None = f
        while node and (nid := str(node.get("id", "")).lower()) not in seen:
            seen.add(nid)
            parts.append(str(node.get("name", "")).strip().lower())
            node = by_id.get(str(node.get("parentFolderId") or "").lower())
        return parts[::-1]

    wanted = _path_parts(folder)
    todo = [
        str(f.get("id", "")).lower()
        for f in folders
        if wanted
        and (
            full_path(f)[-len(wanted) :] == wanted
            if len(wanted) > 1
            else wanted[0]
            in {str(f.get("id", "")).lower(), str(f.get("name", "")).lower()}
        )
    ]
    seen: set[str] = set()
    while todo:
        fid = todo.pop()
        if fid not in seen:
            seen.add(fid)
            todo += children.get(fid, [])
    return seen


def _folder_check(api_client: Any, folder: str) -> Callable[[dict[str, Any]], bool]:
    """Predicate: project lies in ``folder`` (name, id or path) or a descendant."""
    scope = _folder_tree_ids(api_client, folder)
    # A bare name or ID also matches the project's own folder record; a path
    # only matches through the folder tree.
    parts = _path_parts(folder)
    own = set(parts) if len(parts) == 1 else set()

    def inside(p: dict[str, Any]) -> bool:
        fid = str(_folder(p).get("id", "")).lower()
        return fid in scope or bool(
            {fid, str(_folder(p).get("name", "")).lower()} & own
        )

    return inside


def _project_by_id(
    api_client: Any, projects: list[dict[str, Any]], value: str
) -> dict[str, Any]:
    for p in projects:
        if str(p.get("id")).lower() == value.lower():
            return p
    try:
        found: list[dict[str, Any]] = api_client.fetch_data(
            QueryConfig(endpoint=f"/public/v0/projects/{value}", params=QueryParams()),
            use_cache=False,
        )
    except Exception as e:
        if getattr(e, "status_code", None) == 404:
            raise LookupError(f"Project {value} not found") from e
        raise
    if not found:
        raise LookupError(f"Project {value} not found")
    return found[0]


def resolve_unique_project(
    api_client: Any, name_or_id: str, folder: str | None
) -> dict[str, Any]:
    """Return the single project matching name_or_id (optionally within folder)."""
    projects = _fetch_all(
        api_client,
        QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(limit=10000, archived=False, excluded=False),
        ),
    )
    value = str(name_or_id).strip()
    if _ID_SHAPE.match(value):
        project = _project_by_id(api_client, projects, value)
        if folder and not _folder_check(api_client, folder)(project):
            raise LookupError(
                f"Project '{project.get('name')}' ({value}) is not in folder "
                f"'{folder}' or its sub-folders"
            )
        return project

    key = value.lower()
    matches = [p for p in projects if str(p.get("name", "")).lower() == key]
    if folder:
        inside = _folder_check(api_client, folder)
        matches = [p for p in matches if inside(p)]
    if not matches:
        close = [
            p["name"] for p in projects if p.get("name") and key in p["name"].lower()
        ]
        hint = f" Did you mean one of these? {close[:5]}" if close else ""
        where = f" in folder '{folder}'" if folder else ""
        raise LookupError(f"No project named '{name_or_id}'{where}.{hint}")
    if len(matches) > 1:
        lines = [
            f"  - {p['name']} (id {p['id']}, folder: "
            f"{_folder(p).get('name') or '(no folder)'})"
            for p in matches
        ]
        hint = (
            "Folder is still ambiguous; use the project ID."
            if folder
            else "Pass --folder to narrow it, or use the project ID."
        )
        raise AmbiguousProjectError(
            f"Project name '{name_or_id}' matches {len(matches)} projects:\n"
            + "\n".join(lines)
            + "\n"
            + hint,
            matches,
        )
    return matches[0]


def resolve_version_id(
    api_client: Any, project: dict[str, Any], version: str | None
) -> tuple[str, str]:
    """Return (version_id, version_name); default is the latest version."""
    if version is None:
        latest = (project.get("defaultBranch") or {}).get("latestVersion") or {}
        if not latest.get("id") or not (latest.get("name") or latest.get("version")):
            # The listing can omit defaultBranch (or its label); the detail
            # endpoint has it (ReportEngine._fetch_version_id_map_per_project
            # does the same). Uncached: the persistent cache is trimmed.
            detail = api_client.fetch_data(
                QueryConfig(
                    endpoint=f"/public/v0/projects/{project['id']}",
                    params=QueryParams(),
                ),
                use_cache=False,
            )
            branch = (detail[0] if detail else {}).get("defaultBranch") or {}
            full = branch.get("latestVersion") or {}
            latest = full if full.get("id") else latest
        if not latest.get("id"):
            raise LookupError(f"Project '{project.get('name')}' has no current version")
        label = str(latest.get("name") or latest.get("version") or "")
        if not label:
            for v in _fetch_all(
                api_client,
                QueryConfig(
                    endpoint=f"/public/v0/projects/{project['id']}/versions",
                    params=QueryParams(limit=10000),
                ),
            ):
                if str(v.get("id")) == str(latest["id"]):
                    label = str(v.get("version") or v.get("name") or "")
            # Never an empty label: fall back to the id.
            label = label or str(latest["id"])
        return str(latest["id"]), label
    versions = _fetch_all(
        api_client,
        QueryConfig(
            endpoint=f"/public/v0/projects/{project['id']}/versions",
            params=QueryParams(limit=10000),
        ),
    )
    want = version.strip().lower()

    def _name(v: dict[str, Any]) -> str:
        return str(v.get("version") or v.get("name") or "")

    for v in versions:  # an exact id wins over a name that looks like it
        if str(v.get("id")).lower() == want:
            return str(v["id"]), _name(v)
    named = [v for v in versions if _name(v).lower() == want]
    if len(named) > 1:
        ids = ", ".join(str(v["id"]) for v in named)
        raise LookupError(
            f"Version name '{version}' is ambiguous in project "
            f"'{project.get('name')}' (ids: {ids}); pass the version id."
        )
    if named:
        return str(named[0]["id"]), _name(named[0])
    raise LookupError(
        f"Version '{version}' not found in project '{project.get('name')}'"
    )
