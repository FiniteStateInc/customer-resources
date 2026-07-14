"""CRA Article 14 — 24h early-warning notification recipe transform.

Thin entry point; all logic lives in :mod:`fs_report.cra.srp_notification`.
Consumes the whole ``exploitability-dataset/v2`` export un-coerced (the engine's
``transform_input: object`` path) and emits the ``early`` stage ``json_package``
(the 6 authored early-warning fields + the machine-readable ``meta.clock``).
"""

from __future__ import annotations

from typing import Any

from fs_report.cra.srp_notification import run_cra_recipe


def early_warning_notification_transform(
    data: Any,
    config: Any = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return run_cra_recipe(data, "early", config=config, additional_data=additional_data)
