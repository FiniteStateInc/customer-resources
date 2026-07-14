"""CRA Article 14 — 14d final report recipe transform.

Thin entry point; all logic lives in :mod:`fs_report.cra.srp_notification`.
Consumes the whole ``exploitability-dataset/v2`` export un-coerced (the engine's
``transform_input: object`` path) and emits the ``final`` stage ``json_package``
(the 29 authored final-report fields; no ``meta.clock``).
"""

from __future__ import annotations

from typing import Any

from fs_report.cra.srp_notification import run_cra_recipe


def final_report_transform(
    data: Any,
    config: Any = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return run_cra_recipe(data, "final", config=config, additional_data=additional_data)
