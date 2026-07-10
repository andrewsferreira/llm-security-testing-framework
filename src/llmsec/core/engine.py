"""The campaign execution engine: loads test cases, runs them against a target, scores and
reports the results.

Implemented in Phase 4 (runner/execution) and Phase 6 (scoring/reporting).
"""

from __future__ import annotations

from pathlib import Path

from llmsec.config import Config


def run_campaign(cfg: Config, *, suite: str) -> int:
    raise NotImplementedError("The execution engine is implemented in Phase 4.")


def regenerate_reports(input_path: Path, *, formats: list[str], output_dir: Path | None) -> None:
    raise NotImplementedError("Report regeneration is implemented in Phase 6.")
