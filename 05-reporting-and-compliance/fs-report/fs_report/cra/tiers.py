"""CRA Compliance tier classification + threshold filter.

Maps a raw /findings record to the set of CRA tiers it triggers and
builds the RSQL filter for Fetch A's /findings query. Both functions
implement spec §1 (2026-05-23 audit against a live environment).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

logger = logging.getLogger(__name__)

# Maturity values appearing on /findings.exploitMaturity (lowercase).
_MATURITY_TIERS: set[str] = {"weaponized", "poc"}

# exploitInfo token → CRA tier name. The canonical source of the token→tier
# mapping — derive_tiers (below) and snapshot.py (crossing detection) both read
# it so the two can never drift. Tokens are the platform's canonical
# exploit-category keys (the same vocabulary enumerated in-repo by
# assessment_overview._EXPLOIT_CATEGORY_LABELS, though that display map
# lowercases the keys; cf. the API's EXPLOIT_POLICY_KEY_MAP for the source).
TOKEN_TO_TIER: dict[str, str] = {
    "ransomware": "ransomware",
    "threatActors": "threat_actor",
    "botnets": "botnet",
    "commercial": "commercial",
    "reported": "reported",
}

# Tier sets by API filterability.
FILTERABLE_MATURITY_TIERS: set[str] = {"weaponized", "poc"}
# exploitInfo-token tiers: /findings has no RSQL token containment for these,
# so they are narrowed client-side (see build_threshold_filter strategy).
UNFILTERABLE_TOKEN_TIERS: set[str] = set(TOKEN_TO_TIER.values())

# The full recognized CRA tier vocabulary — the domain of
# ``exploit_maturity_threshold``. Kept in sync with derive_tiers below.
VALID_TIERS: frozenset[str] = frozenset(
    {"kev"} | _MATURITY_TIERS | UNFILTERABLE_TOKEN_TIERS
)


def validate_tier_names(names: Iterable[str]) -> None:
    """Raise ValueError if any name is not a recognized CRA tier.

    Guards ``exploit_maturity_threshold`` against silent queue-shrinking typos
    — e.g. the exploitInfo *token* ``botnets`` vs. the *tier* ``botnet``. An
    unrecognized tier never matches a finding, so it would quietly drop rows
    from what is a notification report; fail loudly instead.
    """
    unknown = sorted(set(names) - VALID_TIERS)
    if unknown:
        raise ValueError(
            f"unknown CRA tier(s) {unknown}; expected a subset of "
            f"{sorted(VALID_TIERS)}. Tier names are singular (e.g. 'botnet', "
            "not the exploitInfo token 'botnets')."
        )


def derive_tiers(record: dict[str, Any]) -> set[str]:
    """Return the set of CRA tiers a finding record triggers.

    Tiers: kev, weaponized, poc, ransomware, threat_actor, botnet,
    commercial, reported.

    Signal rules (audit-confirmed; the exploitInfo tokens are the platform's
    canonical exploit-category keys — see the ``TOKEN_TO_TIER`` comment above
    for their provenance):
      - kev: record['inKev'] is True OR record['inVcKev'] is True
      - weaponized: record['exploitMaturity'] == 'weaponized' (lowercase)
      - poc: record['exploitMaturity'] == 'poc' (lowercase)
      - ransomware: 'ransomware' in record['exploitInfo']
      - threat_actor: 'threatActors' in record['exploitInfo']
      - botnet: 'botnets' in record['exploitInfo']
      - commercial: 'commercial' in record['exploitInfo']
      - reported: 'reported' in record['exploitInfo']

    This is a *recognition* map, not a promotion decision: only the tiers in
    the recipe's ``exploit_maturity_threshold`` retain a finding *above
    threshold* (the Full-Snapshot and Newly-Above sections). The 🔥 SLA-Breach
    section is narrower still — KEV-only, because only KEV findings carry the
    Article-14 24h clock (see sections._classify_row). The default
    threshold promotes kev / weaponized / ransomware / threat_actor / botnet;
    poc / commercial / reported are recognized so operators can opt them in, but
    they are weaker (capability/availability) signals held out of the default —
    see cra_compliance.yaml.
    """
    out: set[str] = set()

    if record.get("inKev") or record.get("inVcKev"):
        out.add("kev")

    maturity = record.get("exploitMaturity")
    if maturity in _MATURITY_TIERS:
        out.add(maturity)

    exploit_info = record.get("exploitInfo") or []
    for token, tier in TOKEN_TO_TIER.items():
        if token in exploit_info:
            out.add(tier)

    return out


_VALID_STRATEGIES: set[str] = {"wide-fetch", "drop-tier", "require-rsql"}


def build_threshold_filter(
    threshold: set[str],
    *,
    strategy: str,
) -> tuple[str, set[str]]:
    """Build the RSQL filter for Fetch A's /findings query.

    Args:
        threshold: tier names to filter to (subset of
            {kev, weaponized, poc, ransomware, threat_actor, botnet,
            commercial, reported}).
        strategy: how to handle unfilterable exploitInfo-token tiers
            (ransomware, threat_actor, botnet, commercial, reported) when
            present in `threshold`.
            - 'wide-fetch': return ('', threshold). Fetch A drops the
              threshold filter and the transform narrows client-side.
            - 'drop-tier': WARN, remove unfilterable tiers from the
              effective threshold, proceed with RSQL on the remainder.
            - 'require-rsql': raise ValueError with a clear message.

    Returns:
        (filter_string, effective_threshold) tuple.

    Raises:
        ValueError: if `strategy` is invalid or 'require-rsql' is set
            with unfilterable tiers in the threshold.
    """
    if strategy not in _VALID_STRATEGIES:
        raise ValueError(
            f"unknown strategy {strategy!r}; expected one of "
            f"{sorted(_VALID_STRATEGIES)}"
        )

    if not threshold:
        return "", set()

    unfilterable = threshold & UNFILTERABLE_TOKEN_TIERS
    effective = set(threshold)

    if unfilterable:
        if strategy == "require-rsql":
            raise ValueError(
                "require-rsql: cannot build server-side filter for tiers "
                f"{sorted(unfilterable)}; /findings has no RSQL token "
                "containment for exploitInfo. Use --unfilterable-tier-strategy "
                "wide-fetch or drop-tier."
            )
        if strategy == "drop-tier":
            logger.warning(
                "drop-tier: omitting unfilterable tiers %s from the Fetch A "
                "filter; newly-crossed rows for these tiers are still surfaced "
                "in the 🆕 Newly-Above section (snapshot-diff crossing detection "
                "uses the full threshold, not the dropped one).",
                sorted(unfilterable),
            )
            effective -= unfilterable
        elif strategy == "wide-fetch":
            return "", effective

    clauses: list[str] = []

    if "kev" in effective:
        clauses.append("(inKev==true,inVcKev==true)")

    maturity_values = sorted(effective & FILTERABLE_MATURITY_TIERS)
    if maturity_values:
        clauses.append(f"exploitMaturity=in=({','.join(maturity_values)})")

    return ",".join(clauses), effective
