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

"""What counts as a CVSS vector string, and what its ``AV:`` metric is called.

The NVD client and the Findings by Project transform both have to answer the
first question, at opposite ends of the same pipeline: the client picks one
entry out of a metrics list, and the transform picks one field out of the
enrichment it produced. Two copies of the rule would let them disagree about
the same string — the client handing back a placeholder the transform then
drops, with the real vector already discarded — so the rule lives here and both
import it.

The attack-vector vocabulary below is here for the same reason, one step
further out: the transform derives the ``Attack Vector`` column from ``AV:``,
and ``--attack-vector`` filters rows against that column, so the CLI has to
spell the four labels exactly as the column does. A second copy in the CLI
would let ``--attack-vector adjacent`` validate cleanly and then match nothing.
"""

import re
from collections.abc import Iterable
from typing import Any

# At least one slash-separated metric field: ``AV:N``, ``S:U``, ``Au:N``.
#
# Deliberately loose about metric names, version and field order, because the
# column prints vectors as published and a vector fs-report does not recognize
# is still a vector. It only has to rule out text that is no version's vector:
# a placeholder (``n/a``, ``unknown``, ``-``), a bare prefix (``CVSS:3.1`` with
# nothing after it), or a free-text note.
CVSS_METRIC_FIELD = re.compile(r"(?:^|[/\s,;])[A-Za-z]{1,2}:[A-Za-z]")


def looks_like_vector(text: str) -> bool:
    """True when the text carries at least one CVSS metric field."""
    return bool(CVSS_METRIC_FIELD.search(text))


# CVSS AV: metric letter -> display label, and the canonical spelling of the
# four attack vectors everywhere in fs-report. The letters mean the same thing
# in v2, v3 and v4; v2 has no P (Physical) and folds physical access into L.
ATTACK_VECTOR_LABELS: dict[str, str] = {
    "N": "Network",
    "A": "Adjacent",
    "L": "Local",
    "P": "Physical",
}

# What an operator may type for each label. The full label is the documented
# spelling; the CVSS letter is accepted because it is what the vector string
# itself carries, and ``adjacent-network`` / ``adjacent_network`` because
# CVSS v3 names AV:A "Adjacent Network" while the column shows "Adjacent" —
# a reader copying the metric's own name should not get an error.
#
# Matched against the lowercased token, so the map's keys are all lowercase.
_ATTACK_VECTOR_ALIASES: dict[str, str] = {
    **{letter.lower(): label for letter, label in ATTACK_VECTOR_LABELS.items()},
    **{f"av:{letter.lower()}": label for letter, label in ATTACK_VECTOR_LABELS.items()},
    **{label.lower(): label for label in ATTACK_VECTOR_LABELS.values()},
    "adjacent-network": "Adjacent",
    "adjacent_network": "Adjacent",
    "adjacent network": "Adjacent",
}


def normalize_attack_vectors(names: Iterable[str] | None) -> list[str]:
    """Canonical ``Attack Vector`` labels for the names given, deduped.

    The single normalizer for ``attack_vector_filter``. Returns the labels as
    the report's ``Attack Vector`` column spells them — ``["network", "AV:N"]``
    both come back as ``["Network"]`` — because the filter compares against
    that column and the report's filter disclosure reads back the same list.
    Normalizing to the column's own spelling is what keeps the two in step: a
    disclosure echoing the operator's ``n`` would name something no cell
    contains. Order is the caller's, so the disclosure reads back the order
    they asked for.

    Idempotent by construction: a canonical label lowercases to one of its own
    aliases, so re-normalizing a stored filter (the CLI validates at parse
    time, the transform again at use time) is a no-op rather than a second
    chance to fail.

    Raises ``ValueError`` on a name outside the vocabulary. An unrecognized
    name can never match a cell, so accepting one would silently narrow the
    report to nothing while disclosing a filter as if it were real — the same
    failure ``validate_tier_names`` guards ``--exploit-maturity`` against.
    Validation lives inside the normalizer rather than beside it because every
    caller of one wants the other, and a caller that skipped the check would
    fail silently rather than loudly.
    """
    out: list[str] = []
    unknown: list[str] = []
    for raw in names or []:
        token = str(raw).strip().lower()
        if not token:
            continue
        label = _ATTACK_VECTOR_ALIASES.get(token)
        if label is None:
            if token not in unknown:
                unknown.append(token)
        elif label not in out:
            out.append(label)
    if unknown:
        raise ValueError(
            f"unknown attack vector(s) {sorted(unknown)}; expected a subset of "
            f"{sorted(ATTACK_VECTOR_LABELS.values())} (the CVSS AV: letters "
            "N/A/L/P are also accepted)."
        )
    return out


def split_attack_vectors(raw: Any) -> list[str]:
    """Canonical labels from a stored ``attack_vector_filter`` of any shape.

    The web surface carries the filter comma-joined over the wire while
    ``Config.attack_vector_filter`` is a ``list[str]`` and a hand-written
    ``config.yaml`` may use either — so the string/list fork lives here, once,
    beside the normalizer it feeds. Every reader of a stored filter (the
    router's save validation, the engine-config build, the two templates'
    checkbox state) goes through this, which is what keeps a value that runs
    from rendering as no filter at all.

    Raises ``ValueError`` on an unrecognized name, exactly as
    ``normalize_attack_vectors`` does.
    """
    items = raw if isinstance(raw, list) else str(raw or "").split(",")
    return normalize_attack_vectors(items)
