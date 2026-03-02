"""Deployment context for AI prompt customization.

Provides a ``DeploymentContext`` model that flows from CLI → Config → transforms
→ prompts, enabling product-type-aware persona selection, workaround templates,
and optional deployment metadata injection into LLM prompts.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = logging.getLogger(__name__)

# ── Allowed values ──────────────────────────────────────────────────

PRODUCT_TYPES = frozenset(
    {
        "firmware",
        "web_app",
        "mobile_app",
        "library",
        "device_driver",
        "container",
        "desktop_app",
        "generic",
    }
)

NETWORK_EXPOSURES = frozenset(
    {
        "air_gapped",
        "internal_only",
        "internet_facing",
        "mixed",
        "unknown",
    }
)

# ── Persona and workaround maps ────────────────────────────────────

_PERSONA_MAP: dict[str, str] = {
    "firmware": "firmware security analyst specializing in embedded device remediation",
    "web_app": "application security analyst specializing in web application remediation",
    "mobile_app": "mobile security analyst specializing in mobile application remediation",
    "library": "software security analyst specializing in library and dependency remediation",
    "device_driver": "systems security analyst specializing in driver and kernel-level remediation",
    "container": "cloud security analyst specializing in container and microservice remediation",
    "desktop_app": "application security analyst specializing in desktop application remediation",
    "generic": "security analyst specializing in vulnerability remediation",
}

_WORKAROUND_MAP: dict[str, str] = {
    "firmware": (
        "disabling affected services, network segmentation, "
        "restricting exposed interfaces, or configuration hardening"
    ),
    "web_app": (
        "WAF rules, CSP headers, input validation, "
        "feature flags, or request filtering"
    ),
    "mobile_app": (
        "certificate pinning, runtime application self-protection, "
        "feature toggles, or API gateway rules"
    ),
    "library": (
        "dependency pinning, shading/vendoring an unaffected fork, "
        "disabling vulnerable features, or API-level input guards"
    ),
    "device_driver": (
        "disabling affected driver features, restricting device access, "
        "kernel parameter hardening, or module blacklisting"
    ),
    "container": (
        "network policies, read-only filesystems, seccomp profiles, "
        "capability dropping, or sidecar proxy filtering"
    ),
    "desktop_app": (
        "application sandboxing, disabling vulnerable plugins, "
        "firewall rules, or configuration lockdown"
    ),
    "generic": (
        "disabling affected features, network segmentation, "
        "access controls, or configuration hardening"
    ),
}

_NOTES_MAX_LENGTH = 500


# ── Model ───────────────────────────────────────────────────────────


class DeploymentContext(BaseModel):
    """Deployment context that tailors AI prompts to the target product."""

    model_config = ConfigDict(validate_assignment=True, extra="forbid")

    product_type: str = Field(
        "generic",
        description="Product type for AI persona selection.",
    )
    network_exposure: str = Field(
        "unknown",
        description="Network exposure level of the target product.",
    )
    regulatory: str = Field(
        "",
        description="Regulatory frameworks (e.g. 'IEC-62443, FDA').",
    )
    deployment_notes: str = Field(
        "",
        description="Free-text deployment notes (capped at 500 chars).",
    )
    # Auto-populated from SBOM when available
    root_component_name: str = Field("", description="Root component name from SBOM.")
    root_component_type: str = Field("", description="Root component type from SBOM.")

    @field_validator("product_type")
    @classmethod
    def _validate_product_type(cls, v: str) -> str:
        v = v.strip().lower()
        if not v:
            return "generic"
        if v not in PRODUCT_TYPES:
            raise ValueError(
                f"Invalid product_type '{v}'. "
                f"Allowed: {', '.join(sorted(PRODUCT_TYPES))}"
            )
        return v

    @field_validator("network_exposure")
    @classmethod
    def _validate_network_exposure(cls, v: str) -> str:
        v = v.strip().lower()
        if not v:
            return "unknown"
        if v not in NETWORK_EXPOSURES:
            raise ValueError(
                f"Invalid network_exposure '{v}'. "
                f"Allowed: {', '.join(sorted(NETWORK_EXPOSURES))}"
            )
        return v

    @field_validator("deployment_notes")
    @classmethod
    def _cap_notes(cls, v: str) -> str:
        if len(v) > _NOTES_MAX_LENGTH:
            return v[:_NOTES_MAX_LENGTH]
        return v

    # ── Helpers ──────────────────────────────────────────────────────

    def context_hash(self) -> str:
        """Stable SHA256 hash of user-supplied fields (for cache keys)."""
        data = json.dumps(
            {
                "product_type": self.product_type,
                "network_exposure": self.network_exposure,
                "regulatory": self.regulatory,
                "deployment_notes": self.deployment_notes,
            },
            sort_keys=True,
        )
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def is_default(self) -> bool:
        """True when no user context was provided."""
        return (
            self.product_type == "generic"
            and self.network_exposure == "unknown"
            and not self.regulatory
            and not self.deployment_notes
        )


# ── Free functions ──────────────────────────────────────────────────


def get_persona(ctx: DeploymentContext | None = None) -> str:
    """Return the persona string for the given context."""
    if ctx is None:
        return _PERSONA_MAP["generic"]
    return _PERSONA_MAP.get(ctx.product_type, _PERSONA_MAP["generic"])


def get_workaround_template(ctx: DeploymentContext | None = None) -> str:
    """Return the workaround examples string for the given context."""
    if ctx is None:
        return _WORKAROUND_MAP["generic"]
    return _WORKAROUND_MAP.get(ctx.product_type, _WORKAROUND_MAP["generic"])


def build_context_section(ctx: DeploymentContext | None = None) -> str:
    """Build a deployment context section for LLM prompts.

    Returns ``""`` when context is default (no user-supplied values).
    """
    if ctx is None or ctx.is_default():
        return ""

    lines = ["## Deployment Context"]
    lines.append(f"- Product type: {ctx.product_type}")
    lines.append(f"- Network exposure: {ctx.network_exposure}")
    if ctx.regulatory:
        lines.append(f"- Regulatory: {ctx.regulatory}")
    if ctx.deployment_notes:
        lines.append(f"- Notes: {ctx.deployment_notes}")
    if ctx.root_component_name:
        lines.append(f"- Root component: {ctx.root_component_name}")
    if ctx.root_component_type:
        lines.append(f"- Root component type: {ctx.root_component_type}")
    lines.append("")
    return "\n".join(lines)


def load_context_file(path: str | Path) -> DeploymentContext:
    """Load a deployment context from a YAML file.

    Args:
        path: Path to the YAML file.

    Returns:
        Parsed DeploymentContext.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file contains invalid fields.
    """
    import yaml

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Deployment context file not found: {path}")

    with open(path) as f:
        data: dict[str, Any] = yaml.safe_load(f) or {}

    try:
        return DeploymentContext(**data)
    except Exception as e:
        raise ValueError(f"Invalid deployment context file {path}: {e}") from e
