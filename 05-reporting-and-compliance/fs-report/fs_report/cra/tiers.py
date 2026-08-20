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

# KEV tiers. `kev` is the union (CISA KEV OR VulnCheck KEV) and stays the
# default; `cisa-kev` / `vc-kev` narrow to one catalog.
KEV_TIERS: frozenset[str] = frozenset({"kev", "cisa-kev", "vc-kev"})


def kev_signals(threshold: Iterable[str]) -> tuple[bool, bool]:
    """Return (cisa_selected, vckev_selected) for a tier threshold.

    Single source of truth for "which KEV catalog(s) does this threshold
    cover" — the RSQL filter, the snapshot-diff crossing narrowing and the
    🔥 SLA-Breach routing all read it so they can never disagree.
    """
    tiers = set(threshold)
    return bool(tiers & {"kev", "cisa-kev"}), bool(tiers & {"kev", "vc-kev"})


# exploitInfo-token tiers. Kept as a named set because derive_tiers and the
# snapshot crossing detector both key off the token→tier map.
UNFILTERABLE_TOKEN_TIERS: set[str] = set(TOKEN_TO_TIER.values())

# The full recognized CRA tier vocabulary — the domain of
# ``exploit_maturity_threshold``. Kept in sync with derive_tiers below.
VALID_TIERS: frozenset[str] = frozenset(
    KEV_TIERS | _MATURITY_TIERS | UNFILTERABLE_TOKEN_TIERS
)

# Each single-catalog KEV tier and the /findings field its clause would name.
# `FILTERABLE_TIERS` is DERIVED from this map by intersecting it with
# `SUPPORTED_FILTER_FIELDS` below, so removing a field from the allowlist also
# stops the tier being pushed — one edit, not two kept in sync by hand.
_CISA_KEV_FIELD = "inKev"
TIER_FILTER_FIELD: dict[str, str] = {
    "cisa-kev": _CISA_KEV_FIELD,
    "vc-kev": "inVcKev",
}

# /findings filter fields this module is allowed to emit. The guard test walks
# every threshold/strategy pair and fails if a built filter names anything
# outside this set.
#
# This is a CONSERVATIVE FLOOR, not a transcription of the API spec. It lists
# only fields observed accepted, and we emit nothing else even where a given
# deployment might accept more. Observed 2026-08-18 against a live deployment;
# a separate deployment was reported to answer 200 for `inVcKev`, so field
# availability may vary by deployment or backend.
#
# Emitting only the floor is correct everywhere: on a deployment that *would*
# accept `inVcKev`, a vc-kev threshold costs one wider fetch and returns
# identical rows via client-side narrowing, whereas a filter the backend
# rejects 400s the entire run. That asymmetry — a bounded fetch cost against a
# dead report — is why the floor is deliberate. Widen it via capability
# detection if the cost ever matters, not by assuming a field exists.
#
# The endpoint rejects an unknown field with a precise 400:
#   {"error": "Error building query: <field> is not a supported filter field"}
# Observed unsupported: `inVcKev`, `exploitMaturity`, `exploitInfo` — and
# VulnCheck KEV has no filterable alias (`vcKev`, `inVulnCheckKev` → same
# 400). VulnCheck-KEV membership is readable on a returned row but is not
# queryable, so every vc-kev threshold narrows client-side.
#
# NB: an earlier version of this comment blamed the 400 on RSQL grammar —
# "no grouping parens", "no cross-field OR", "same-field OR matches nothing".
# All three are false: `(severity==critical,severity==high)`,
# `(severity==CRITICAL,inKev==true)` and the paren-less
# `inKev==true,severity==HIGH` each return 200 with rows, and
# `report_engine.py` has long shipped `(inKev==true,hasKnownExploit==true)`
# for Triage Prioritization. The constraint is which FIELDS exist. Don't
# re-derive grammar limits from a 400 without reading the error body.
SUPPORTED_FILTER_FIELDS: frozenset[str] = frozenset({_CISA_KEV_FIELD})

# Tiers /findings can filter server-side — DERIVED, never hand-maintained: a
# tier is pushable exactly when the field its clause names is in the allowlist
# above. Today that resolves to {"cisa-kev"} (`inKev==true`); `vc-kev` drops
# out because `inVcKev` is not supported. Every other tier — the KEV union,
# the maturity tiers and the exploitInfo-token tiers — has no field at all and
# narrows client-side under the caller's --unfilterable-tier-strategy.
FILTERABLE_TIERS: frozenset[str] = frozenset(
    tier
    for tier, field in TIER_FILTER_FIELD.items()
    if field in SUPPORTED_FILTER_FIELDS
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

    Tiers: kev, cisa-kev, vc-kev, weaponized, poc, ransomware, threat_actor,
    botnet, commercial, reported.

    Signal rules (audit-confirmed; the exploitInfo tokens are the platform's
    canonical exploit-category keys — see the ``TOKEN_TO_TIER`` comment above
    for their provenance):
      - kev: record['inKev'] is True OR record['inVcKev'] is True
      - cisa-kev: record['inKev'] is True
      - vc-kev: record['inVcKev'] is True
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

    if record.get("inKev"):
        out.add("cisa-kev")
    if record.get("inVcKev"):
        out.add("vc-kev")
    if out & KEV_TIERS:
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
            {kev, cisa-kev, vc-kev, weaponized, poc, ransomware,
            threat_actor, botnet, commercial, reported}).
        strategy: how to handle unfilterable tiers — everything except
            `cisa-kev`, i.e. the exploitInfo-token tiers (ransomware,
            threat_actor, botnet, commercial, reported), the maturity tiers
            (weaponized, poc), `vc-kev` alone, and the KEV union (`kev`, or
            `cisa-kev` + `vc-kev` together) — when present in `threshold`.
            - 'wide-fetch': return ('', threshold). Fetch A drops the
              threshold filter and the transform narrows client-side.
            - 'drop-tier': WARN, remove unfilterable tiers from the
              effective threshold, proceed with RSQL on the remainder.
            - 'require-rsql': raise ValueError with a clear message.

    Returns:
        (filter_string, effective_threshold) tuple.

    Raises:
        ValueError: if `strategy` is invalid; if 'require-rsql' is set with
            unfilterable tiers in the threshold; or if 'drop-tier' would drop
            every tier, leaving nothing above threshold.
    """
    if strategy not in _VALID_STRATEGIES:
        raise ValueError(
            f"unknown strategy {strategy!r}; expected one of "
            f"{sorted(_VALID_STRATEGIES)}"
        )

    if not threshold:
        return "", set()

    unfilterable = threshold - FILTERABLE_TIERS
    if all(kev_signals(threshold)):
        # Both catalogs selected (`kev`, or `cisa-kev` + `vc-kev`). The union
        # is not expressible: `inVcKev` is not a filter field at all, so the
        # only pushable half is `inKev==true` — and pushing that alone would
        # silently drop VulnCheck-only rows the caller asked for. Send the
        # whole union client-side instead of half-answering it.
        unfilterable |= threshold & KEV_TIERS
    effective = set(threshold)

    if unfilterable:
        if strategy == "require-rsql":
            raise ValueError(
                "require-rsql: cannot build server-side filter for tiers "
                f"{sorted(unfilterable)}; /findings exposes no filter field "
                "for them — `inVcKev`, `exploitMaturity` and `exploitInfo` "
                "are all rejected with 400 'not a supported filter field', "
                "so `inKev` (CISA KEV) is the only pushable signal. Use "
                "--unfilterable-tier-strategy wide-fetch, which returns "
                "identical rows via one wider fetch. (drop-tier only helps if "
                "the threshold also contains the pushable cisa-kev tier — it "
                "refuses when dropping would leave nothing above threshold.) "
                "Alternatively narrow the threshold to cisa-kev."
            )
        if strategy == "drop-tier":
            if not (threshold - unfilterable):
                # Dropping every tier leaves nothing above threshold. The run
                # would fetch the whole (status-filtered) portfolio and retain
                # zero rows — the widest possible fetch for an empty queue that
                # reads as "nothing to report". On a CRA notification report
                # that misreads as a clean bill of health, so refuse instead.
                raise ValueError(
                    "drop-tier: every tier in the threshold "
                    f"{sorted(threshold)} is unfilterable, so dropping them "
                    "leaves nothing above threshold — the run would fetch the "
                    "whole portfolio and retain zero rows, rendering an empty "
                    "CRA queue that reads as 'nothing to report'. Use "
                    "--unfilterable-tier-strategy wide-fetch (identical rows, "
                    "one wider fetch), or include the pushable cisa-kev tier."
                )
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

    # Exactly one clause, or none. Everything unpushable went into
    # `unfilterable` above, so it either returned early (wide-fetch) or was
    # stripped from `effective` (drop-tier). `inKev` is the only field in
    # SUPPORTED_FILTER_FIELDS, so cisa-kev is the only clause we can emit.
    cisa_on, _vc_on = kev_signals(effective)
    if cisa_on and "cisa-kev" in FILTERABLE_TIERS:
        return f"{TIER_FILTER_FIELD['cisa-kev']}==true", effective
    return "", effective
