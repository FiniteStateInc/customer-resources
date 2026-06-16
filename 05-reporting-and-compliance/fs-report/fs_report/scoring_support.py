"""Shared validation for ``--scoring-file`` YAML.

The CLI (`fs_report.cli.run._validate_scoring_file`) and the serve web upload
endpoint both need to validate a scoring-file. This module holds the **pure**
validator — it returns ``(errors, warnings)`` and never touches the console or
raises ``typer.Exit`` — so the web endpoint can produce clean 400s and the CLI
can keep its console/exit behavior by wrapping it.
"""

from __future__ import annotations

from pathlib import Path

# Keys a scoring-file may contain (Triage Prioritization weights/gates,
# Scan Quality staleness thresholds). Unknown keys are a WARNING, not an error.
SCORING_FILE_EXPECTED_KEYS = frozenset(
    {"scoring_weights", "gates", "staleness_thresholds"}
)


def validate_scoring_yaml(path: str) -> tuple[list[str], list[str]]:
    """Validate a ``--scoring-file`` YAML at ``path``.

    Returns ``(errors, warnings)``:
    - **errors** (hard failures the CLI rejects with exit 1 / the web 400s):
      missing, not a regular file, unreadable, invalid YAML, empty, or not a
      mapping.
    - **warnings** (non-blocking, matching the CLI's yellow warnings): no
      recognized keys, or unknown keys that will be ignored.
    """
    import yaml

    errors: list[str] = []
    warnings: list[str] = []

    p = Path(path)
    if not p.exists():
        return [f"scoring-file not found: {path}"], warnings
    if not p.is_file():
        return [f"scoring-file is not a regular file: {path}"], warnings
    try:
        raw = p.read_text()
    except (OSError, UnicodeDecodeError) as exc:
        return [f"cannot read scoring-file {path}: {exc}"], warnings
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        return [f"scoring-file has invalid YAML ({path}): {exc}"], warnings
    if data is None:
        return [f"scoring-file is empty: {path}"], warnings
    if not isinstance(data, dict):
        return [
            f"scoring-file must be a YAML mapping (got {type(data).__name__}): {path}"
        ], warnings

    unknown = set(data.keys()) - SCORING_FILE_EXPECTED_KEYS
    if not data.keys() & SCORING_FILE_EXPECTED_KEYS:
        warnings.append(
            f"scoring-file {path} has no recognized keys (expected one of: "
            f"{', '.join(sorted(SCORING_FILE_EXPECTED_KEYS))}). "
            "Scoring will fall back to defaults."
        )
    elif unknown:
        warnings.append(
            f"scoring-file {path} has unknown keys that will be ignored: "
            f"{', '.join(sorted(unknown))}"
        )
    return errors, warnings
