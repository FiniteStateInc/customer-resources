"""CRA Compliance snapshot-diff state.

Persists per-scope sets of inKev/inVcKev row IDs and per-row
exploitInfo signal tokens so the next run can detect KEV / ransomware /
threat-actor crossings (the audit confirmed /cves/updates does NOT
carry these deltas — see API wishlist #15-#17).

Storage: ~/.fs-report/state/cra-compliance/<scope-hash>.json (schema v2).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_STATE_ROOT = Path.home() / ".fs-report" / "state" / "cra-compliance"


@dataclass
class State:
    schema_version: int = 2
    inkev_rows: set[str] = field(default_factory=set)
    exploitinfo_signals: dict[str, list[str]] = field(default_factory=dict)
    last_run_at: str | None = None


def scope_hash(*parts: str) -> str:
    """Stable hash for state-file naming. Composed from scope identifiers
    (folder, projects, version pins). Two runs with different scopes get
    independent state."""
    digest = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:16]


def _state_path(scope: str) -> Path:
    return _STATE_ROOT / f"{scope}.json"


def load_state(scope: str) -> State:
    path = _state_path(scope)
    if not path.exists():
        return State()
    data: dict[str, Any] = json.loads(path.read_text())
    return State(
        schema_version=data.get("schema_version", 2),
        inkev_rows=set(data.get("inkev_rows", [])),
        exploitinfo_signals=dict(data.get("exploitinfo_signals", {})),
        last_run_at=data.get("last_run_at"),
    )


def save_state(scope: str, state: State) -> None:
    path = _state_path(scope)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": state.schema_version,
        "inkev_rows": sorted(state.inkev_rows),
        "exploitinfo_signals": state.exploitinfo_signals,
        "last_run_at": state.last_run_at,
    }
    path.write_text(json.dumps(payload, indent=2))


# Map exploitInfo token names → CRA tier names. Spec §0 lines 475-510.
_TOKEN_TO_TIER: dict[str, str] = {
    "ransomware": "ransomware",
    "threatActors": "threat_actor",
}


def snapshot_diff_kev_crossings(
    prior: State,
    *,
    current_kev_rows: set[str],
    row_id_to_cve: dict[str, str],
    threshold: set[str],
) -> set[str]:
    """Return ROW IDs (per-finding) newly flagged inKev/inVcKev vs prior snapshot.

    Row-level (not CVE-level) because two findings for the same CVE on
    different products/versions can have independent KEV signals — flagging
    the whole CVE would create false "newly above" alerts for sibling rows
    that did not themselves cross. Spec §6 morning-queue contract.

    Returns the empty set when 'kev' is not in `threshold` — the operator
    excluded the KEV tier from scope, so a KEV-only crossing must not
    surface in NEW / REPEAT even when the snapshot detects it (spec §0
    line ~501).

    First-run behavior: if prior.last_run_at is None, return empty set
    (don't flood the operator with the entire KEV universe on day one).
    """
    if "kev" not in threshold:
        return set()
    if prior.last_run_at is None:
        return set()
    newly_kev = current_kev_rows - prior.inkev_rows
    return {r for r in newly_kev if r in row_id_to_cve}


def snapshot_diff_token_crossings(
    prior: State,
    *,
    current_signals: dict[str, list[str]],
    row_id_to_cve: dict[str, str],
    threshold: set[str],
) -> set[str]:
    """Return ROW IDs whose exploitInfo newly contains any token whose
    tier is in `threshold`.

    Row-level (not CVE-level): a ransomware/threat_actor token addition on
    one finding row must not flag sibling rows for the same CVE that did
    not themselves get the token. Spec §6 morning-queue contract.

    Per spec §0 lines 502-512: 'newly-added ransomware token -> crossing
    iff ransomware in threshold; newly-added threatActors token ->
    crossing iff threat_actor in threshold'. Tokens are gated by the
    threshold individually.
    """
    if prior.last_run_at is None:
        return set()
    eligible_tokens = {tok for tok, tier in _TOKEN_TO_TIER.items() if tier in threshold}
    if not eligible_tokens:
        return set()
    crossed_rows: set[str] = set()
    for row_id, current_tokens in current_signals.items():
        if row_id not in row_id_to_cve:
            continue
        prior_tokens = set(prior.exploitinfo_signals.get(row_id, []))
        newly_added = set(current_tokens) - prior_tokens
        if newly_added & eligible_tokens:
            crossed_rows.add(row_id)
    return crossed_rows
