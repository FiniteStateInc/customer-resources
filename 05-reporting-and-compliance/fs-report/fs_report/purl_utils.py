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
PURL (Package URL) utilities for remediation package generation.

Parses Package URLs per the PURL specification, maps ecosystems to package
managers, generates upgrade commands, and classifies version bumps by semver.

See: https://github.com/package-url/purl-spec
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import unquote


class UpgradeType(StrEnum):
    """Classification of a version upgrade by semver magnitude."""

    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PurlInfo:
    """Parsed components of a Package URL."""

    type: str  # e.g. "npm", "pypi", "maven"
    namespace: str  # e.g. "com.fasterxml.jackson.core" (maven group)
    name: str  # e.g. "jackson-databind"
    version: str  # e.g. "2.10.0"
    qualifiers: dict[str, str]  # e.g. {"type": "jar"}
    subpath: str  # rarely used

    @property
    def ecosystem(self) -> str:
        """Map PURL type to canonical ecosystem name."""
        return PURL_TYPE_TO_ECOSYSTEM.get(self.type, self.type)

    @property
    def full_name(self) -> str:
        """Full package name including namespace where applicable."""
        if self.namespace:
            sep = NAMESPACE_SEPARATORS.get(self.type, "/")
            return f"{self.namespace}{sep}{self.name}"
        return self.name


# PURL type → canonical ecosystem name
PURL_TYPE_TO_ECOSYSTEM = {
    "npm": "npm",
    "pypi": "pypi",
    "maven": "maven",
    "cargo": "cargo",
    "gem": "rubygems",
    "golang": "go",
    "nuget": "nuget",
    "deb": "debian",
    "rpm": "rpm",
    "docker": "docker",
    "composer": "composer",
    "cocoapods": "cocoapods",
    "hex": "hex",
    "conan": "conan",
    "swift": "swift",
    "pub": "pub",
    "generic": "generic",
    "github": "github",
    "apk": "alpine",
    "cran": "cran",
    "hackage": "hackage",
    "huggingface": "huggingface",
    "mlflow": "mlflow",
    "oci": "oci",
    "qpkg": "qpkg",
    "swid": "swid",
    "bitbucket": "bitbucket",
}

# Namespace separator per ecosystem (for full_name construction)
NAMESPACE_SEPARATORS: dict[str, str] = {
    "maven": ":",
    "golang": "/",
    "composer": "/",
    "npm": "/",  # scoped packages: @scope/name
    "github": "/",
    "bitbucket": "/",
    "docker": "/",
}

# Ecosystem → (command_template, manifest_files)
# Template placeholders: {name}, {full_name}, {version}
_ECOSYSTEM_CONFIG: dict[str, tuple[str | None, list[str]]] = {
    "npm": (
        "npm install {name}@{version}",
        ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
    ),
    "pypi": (
        "pip install {name}>={version}",
        ["requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg"],
    ),
    "maven": (
        None,  # No single CLI command — must edit pom.xml/build.gradle
        ["pom.xml", "build.gradle", "build.gradle.kts"],
    ),
    "cargo": (
        "cargo update -p {name} --precise {version}",
        ["Cargo.toml", "Cargo.lock"],
    ),
    "rubygems": (
        "gem install {name} -v {version}",
        ["Gemfile", "Gemfile.lock", "*.gemspec"],
    ),
    "go": (
        "go get {full_name}@v{version}",
        ["go.mod", "go.sum"],
    ),
    "nuget": (
        "dotnet add package {name} --version {version}",
        ["*.csproj", "*.fsproj", "packages.config", "Directory.Packages.props"],
    ),
    "debian": (
        "apt install {name}={version}",
        ["Dockerfile", "*.deb"],
    ),
    "rpm": (
        "dnf update {name}-{version}",
        ["Dockerfile", "*.spec"],
    ),
    "docker": (
        None,  # Must edit Dockerfile FROM line
        ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
    ),
    "composer": (
        "composer require {full_name}:{version}",
        ["composer.json", "composer.lock"],
    ),
    "cocoapods": (
        "pod update {name}",
        ["Podfile", "Podfile.lock"],
    ),
    "hex": (
        None,  # Must edit mix.exs
        ["mix.exs", "mix.lock"],
    ),
    "conan": (
        None,  # Must edit conanfile
        ["conanfile.txt", "conanfile.py"],
    ),
    "swift": (
        None,  # Must edit Package.swift
        ["Package.swift", "Package.resolved"],
    ),
    "pub": (
        "dart pub upgrade {name}",
        ["pubspec.yaml", "pubspec.lock"],
    ),
    "alpine": (
        "apk add {name}={version}",
        ["Dockerfile"],
    ),
    "generic": (
        None,  # No standard package manager
        [],
    ),
}

# Regex for the PURL spec: pkg:type/namespace/name@version?qualifiers#subpath
_PURL_RE = re.compile(r"^pkg:" r"(?P<type>[a-zA-Z][a-zA-Z0-9.+\-]*)" r"/(?P<rest>.+)$")

# Simple semver regex — handles 1.2.3, 1.2.3-beta, etc.
_SEMVER_RE = re.compile(r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)")


def parse_purl(purl: str) -> PurlInfo | None:
    """Parse a Package URL string into its components.

    Returns ``None`` if the string is not a valid PURL.

    Example::

        >>> parse_purl("pkg:npm/%40scope/lodash@4.17.4?type=module")
        PurlInfo(type='npm', namespace='@scope', name='lodash', ...)
    """
    if not purl or not purl.startswith("pkg:"):
        return None

    m = _PURL_RE.match(purl)
    if not m:
        return None

    purl_type = m.group("type").lower()
    rest = m.group("rest")

    # Split off subpath (#...)
    subpath = ""
    if "#" in rest:
        rest, subpath = rest.rsplit("#", 1)
        subpath = unquote(subpath)

    # Split off qualifiers (?...)
    qualifiers: dict[str, str] = {}
    if "?" in rest:
        rest, qs = rest.rsplit("?", 1)
        for pair in qs.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                qualifiers[unquote(k)] = unquote(v)

    # Split off version (@...)
    version = ""
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
        version = unquote(version)

    # Split namespace/name
    parts = rest.split("/")
    name = unquote(parts[-1])
    namespace = "/".join(unquote(p) for p in parts[:-1]) if len(parts) > 1 else ""

    return PurlInfo(
        type=purl_type,
        namespace=namespace,
        name=name,
        version=version,
        qualifiers=qualifiers,
        subpath=subpath,
    )


def ecosystem_from_purl(purl: str) -> str:
    """Extract the ecosystem name from a PURL string.

    Returns the PURL type itself if no canonical mapping exists.
    Returns ``"unknown"`` if the PURL is unparseable.
    """
    info = parse_purl(purl)
    if info is None:
        return "unknown"
    return info.ecosystem


def upgrade_command(purl: str, fixed_version: str) -> str | None:
    """Generate the package-manager upgrade command for a PURL.

    Returns ``None`` if no standard CLI command exists for the ecosystem
    (e.g. Maven, Docker, generic).

    Args:
        purl: The Package URL of the *currently installed* component.
        fixed_version: The target version to upgrade to.
    """
    info = parse_purl(purl)
    if info is None:
        return None

    config = _ECOSYSTEM_CONFIG.get(info.ecosystem)
    if config is None:
        return None

    template, _ = config
    if template is None:
        return None

    return template.format(
        name=info.name,
        full_name=info.full_name,
        version=fixed_version,
    )


def manifest_patterns(purl: str) -> list[str]:
    """Return manifest file glob patterns for the PURL's ecosystem.

    The IDE plugin uses these patterns to locate the file where the
    dependency is declared.
    """
    info = parse_purl(purl)
    if info is None:
        return []

    config = _ECOSYSTEM_CONFIG.get(info.ecosystem)
    if config is None:
        return []

    _, patterns = config
    return list(patterns)


def search_pattern(purl: str) -> str | None:
    """Generate a regex pattern to find the dependency declaration in manifests.

    Returns ``None`` if the ecosystem is not supported or the PURL is invalid.
    """
    info = parse_purl(purl)
    if info is None:
        return None

    name_escaped = re.escape(info.name)
    version_escaped = re.escape(info.version) if info.version else r"[^\s\"',]+"

    if info.ecosystem == "npm":
        # Matches "lodash": "^4.17.4" or "lodash": "~4.17.4" etc.
        return rf'"{name_escaped}":\s*"[~^]?{version_escaped}"'
    elif info.ecosystem == "pypi":
        # Matches lodash==4.17.4 or lodash>=4.17.4 etc.
        return rf"{name_escaped}\s*[=><~!]+\s*{version_escaped}"
    elif info.ecosystem == "maven":
        # Matches <version>2.10.0</version> in context of artifact
        return rf"<version>\s*{version_escaped}\s*</version>"
    elif info.ecosystem == "cargo":
        # Matches name = "4.17.4" in Cargo.toml
        return rf'{name_escaped}\s*=\s*"[~^]?{version_escaped}"'
    elif info.ecosystem == "go":
        full = re.escape(info.full_name)
        return rf"{full}\s+v{version_escaped}"
    elif info.ecosystem == "nuget":
        return rf'Include="{name_escaped}".*Version="{version_escaped}"'
    elif info.ecosystem == "composer":
        return rf'"{re.escape(info.full_name)}":\s*"[~^]?{version_escaped}"'
    elif info.ecosystem == "rubygems":
        return rf"""gem\s+['"]{name_escaped}['"],\s*['"]~>\s*{version_escaped}['"]"""

    return None


def classify_upgrade(current_version: str, target_version: str) -> UpgradeType:
    """Classify a version bump as patch, minor, or major.

    Uses semver comparison. Returns ``UNKNOWN`` if either version
    cannot be parsed as semver.
    """
    cur = _SEMVER_RE.match(current_version)
    tgt = _SEMVER_RE.match(target_version)

    if not cur or not tgt:
        return UpgradeType.UNKNOWN

    cur_major, cur_minor = int(cur.group("major")), int(cur.group("minor"))
    tgt_major, tgt_minor = int(tgt.group("major")), int(tgt.group("minor"))

    if tgt_major != cur_major:
        return UpgradeType.MAJOR
    if tgt_minor != cur_minor:
        return UpgradeType.MINOR
    return UpgradeType.PATCH


def breaking_change_risk(upgrade_type: UpgradeType) -> str:
    """Estimate breaking change risk from the upgrade classification."""
    return {
        UpgradeType.PATCH: "low",
        UpgradeType.MINOR: "medium",
        UpgradeType.MAJOR: "high",
        UpgradeType.UNKNOWN: "unknown",
    }[upgrade_type]


def _version_tuple(v: str) -> tuple[int, ...] | None:
    """Parse a version string into a tuple of ints for comparison."""
    parts = []
    for seg in v.split("."):
        numeric = ""
        for ch in seg:
            if ch.isdigit():
                numeric += ch
            else:
                break
        if numeric:
            parts.append(int(numeric))
        else:
            return None  # unparseable segment
    return tuple(parts) if parts else None


def best_fix_for_version(installed: str, candidates: list[str]) -> str:
    """Select the best fix version for an installed version from candidates.

    Prefers a fix on the same major.minor branch (smallest valid upgrade).
    Falls back to the smallest candidate that's > installed.
    Returns "" if no candidate is a valid upgrade.
    """
    inst = _version_tuple(installed)
    if inst is None or not candidates:
        return ""

    inst_major_minor = inst[:2]  # (major, minor)

    parsed: list[tuple[tuple[int, ...], str]] = []
    for c in candidates:
        t = _version_tuple(c)
        if t is not None and t > inst:  # only valid upgrades
            parsed.append((t, c))

    if not parsed:
        return ""

    # Prefer same major.minor branch
    same_branch = [(t, v) for t, v in parsed if t[:2] == inst_major_minor]
    if same_branch:
        same_branch.sort()
        return same_branch[0][1]  # smallest upgrade on same branch

    # Fall back to smallest valid upgrade
    parsed.sort()
    return parsed[0][1]


def upgrade_instruction(purl: str, fixed_version: str) -> str:
    """Generate a human-readable upgrade instruction.

    Always returns a useful string, even for ecosystems without a CLI command.
    """
    info = parse_purl(purl)
    if info is None:
        return f"Upgrade to version {fixed_version}"

    cmd = upgrade_command(purl, fixed_version)
    if cmd:
        return cmd

    # Ecosystems that require manifest edits
    config = _ECOSYSTEM_CONFIG.get(info.ecosystem)
    manifests = config[1] if config else []

    if info.ecosystem == "maven":
        group = info.namespace or "GROUP_ID"
        return (
            f"Update {', '.join(manifests)}: set "
            f"<version>{fixed_version}</version> for "
            f"{group}:{info.name}"
        )
    elif info.ecosystem == "docker":
        return f"Update Dockerfile: FROM {info.full_name}:{fixed_version}"
    elif info.ecosystem == "hex":
        return f'Update mix.exs: set {{:"{info.name}", "~> {fixed_version}"}}'
    elif info.ecosystem == "conan":
        return f"Update conanfile: set {info.name}/{fixed_version}"
    elif info.ecosystem == "swift":
        return f'Update Package.swift: .package(url: "...", from: "{fixed_version}")'
    elif info.ecosystem == "generic":
        return f"Update {info.name} to version {fixed_version} from vendor"

    if manifests:
        return f"Update {manifests[0]}: set {info.name} to version {fixed_version}"
    return f"Upgrade {info.name} to version {fixed_version}"
