"""CRA Compliance tier classification + threshold filter.

Maps a raw /findings record to the set of CRA tiers it triggers and
builds the RSQL filter for Fetch A's /findings query. Both functions
implement spec §1 (2026-05-23 audit against rolandl.finitestate.io).
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Maturity values appearing on /findings.exploitMaturity (lowercase).
_MATURITY_TIERS: set[str] = {"weaponized", "poc"}

# Tier sets by API filterability.
FILTERABLE_MATURITY_TIERS: set[str] = {"weaponized", "poc"}
UNFILTERABLE_TOKEN_TIERS: set[str] = {"ransomware", "threat_actor"}


def derive_tiers(record: dict[str, Any]) -> set[str]:
    """Return the set of CRA tiers a finding record triggers.

    Tiers: kev, weaponized, poc, ransomware, threat_actor.

    Signal rules (audit-confirmed):
      - kev: record['inKev'] is True OR record['inVcKev'] is True
      - weaponized: record['exploitMaturity'] == 'weaponized' (lowercase)
      - poc: record['exploitMaturity'] == 'poc' (lowercase)
      - ransomware: 'ransomware' in record['exploitInfo']
      - threat_actor: 'threatActors' in record['exploitInfo']
    """
    out: set[str] = set()

    if record.get("inKev") or record.get("inVcKev"):
        out.add("kev")

    maturity = record.get("exploitMaturity")
    if maturity in _MATURITY_TIERS:
        out.add(maturity)

    exploit_info = record.get("exploitInfo") or []
    if "ransomware" in exploit_info:
        out.add("ransomware")
    if "threatActors" in exploit_info:
        out.add("threat_actor")

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
            {kev, weaponized, poc, ransomware, threat_actor}).
        strategy: how to handle unfilterable tiers (ransomware,
            threat_actor) when present in `threshold`.
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
                "drop-tier: omitting unfilterable tiers %s from threshold; "
                "the new section will still include them via snapshot-diff.",
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
