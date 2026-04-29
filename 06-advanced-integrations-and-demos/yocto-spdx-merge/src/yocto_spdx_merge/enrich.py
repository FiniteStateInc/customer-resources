"""Enrich SPDX packages with CPE and purl externalRefs."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

import yaml


_DATA_DIR = Path(__file__).parent / "data"

_KNOWN_SUFFIXES = [
    "-dev",
    "-dbg",
    "-doc",
    "-staticdev",
    "-src",
    "-ptest",
]


def load_cpe_map(path: str | Path | None = None) -> dict[str, dict]:
    """Load the Yocto recipe name to CPE mapping from YAML."""
    if path is None:
        path = _DATA_DIR / "cpe_map.yaml"
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _candidate_base_names(name: str) -> list[str]:
    """Generate candidate base package names by progressively stripping suffixes.

    Returns candidates in order of preference (most specific first):
    1. Known Yocto package suffixes (-dev, -dbg, etc.)
    2. Iterative dash-stripping from the right (covers sub-packages like
       busybox-syslog -> busybox, iptables-module-ebt-802-3 -> iptables-module
       -> iptables, util-linux-mount -> util-linux, etc.)
    """
    candidates: list[str] = []

    # Try stripping known terminal suffixes first
    for suffix in _KNOWN_SUFFIXES:
        if name.endswith(suffix):
            candidates.append(name[: -len(suffix)])
            break

    # Iteratively strip the last dash-delimited segment
    current = name
    while "-" in current:
        current = current.rsplit("-", 1)[0]
        candidates.append(current)

    return candidates


def _make_purl(name: str, version: str) -> str:
    """Build a purl for a Yocto package."""
    encoded_name = quote(name, safe="")
    if version:
        encoded_version = quote(version, safe="")
        return f"pkg:yocto/{encoded_name}@{encoded_version}"
    return f"pkg:yocto/{encoded_name}"


def _sanitize_cpe_version(version: str) -> str:
    """Strip Yocto-specific suffixes that are invalid in CPE 2.3 version fields.

    CPE 2.3 version components may not contain '+'. Yocto appends '+git',
    '+git<hash>', etc. to upstream version strings. Strip at the first '+'.
    """
    return version.split("+")[0] if "+" in version else version


def _make_cpe(vendor: str, product: str, version: str) -> str:
    """Build a CPE 2.3 string."""
    safe_version = _sanitize_cpe_version(version)
    return f"cpe:2.3:a:{vendor}:{product}:{safe_version}:*:*:*:*:*:*:*"


def build_external_refs(
    name: str,
    version: str,
    cpe_map: dict[str, dict],
) -> list[dict]:
    """Build externalRefs for a package (purl always, CPE if mapped)."""
    refs = []

    # Always add purl
    refs.append({
        "referenceCategory": "PACKAGE-MANAGER",
        "referenceType": "purl",
        "referenceLocator": _make_purl(name, version),
    })

    # Try CPE mapping: exact match first, then candidate base names
    mapping = cpe_map.get(name)
    if mapping is None:
        for candidate in _candidate_base_names(name):
            mapping = cpe_map.get(candidate)
            if mapping is not None:
                break

    if mapping:
        refs.append({
            "referenceCategory": "SECURITY",
            "referenceType": "cpe23Type",
            "referenceLocator": _make_cpe(mapping["vendor"], mapping["product"], version),
        })

    return refs


def enrich_package(pkg: dict, cpe_map: dict[str, dict]) -> dict:
    """Add externalRefs to a package dict. Returns a new dict (no mutation)."""
    enriched = dict(pkg)

    existing_refs = list(pkg.get("externalRefs", []))
    existing_locators = {r["referenceLocator"] for r in existing_refs}

    new_refs = build_external_refs(
        pkg["name"],
        pkg.get("versionInfo", ""),
        cpe_map,
    )

    # Only add refs that don't already exist
    for ref in new_refs:
        if ref["referenceLocator"] not in existing_locators:
            existing_refs.append(ref)

    enriched["externalRefs"] = existing_refs
    return enriched
