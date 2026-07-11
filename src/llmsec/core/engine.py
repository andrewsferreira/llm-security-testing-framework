"""The campaign execution engine: runs test cases against a target, scores the results, and
writes reports in every configured format.

Deliberately does no printing/rendering of its own — it returns data (a `Campaign` and the
report paths written) and raises exceptions on failure. All human/JSON output formatting lives
in `rendering.py`, called from the CLI. This split is what makes `--json` a real, separate
output path rather than something scraped out of human-formatted text (see
docs/architecture-review.md, "core/engine.py prints directly to stdout").
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from llmsec import __version__
from llmsec.config import Config
from llmsec.core.runner import run_campaign_async
from llmsec.exceptions import LlmsecError
from llmsec.logging import get_logger
from llmsec.models.campaign import Campaign, CampaignConfig
from llmsec.models.result import TestResult
from llmsec.models.test_case import TestCase
from llmsec.reporters import write_reports
from llmsec.targets import Target, build_target
from llmsec.utils.identifiers import new_campaign_id
from llmsec.utils.serialization import read_json

logger = get_logger("engine")


async def _run_and_cleanup(
    target: Target[Any],
    test_cases: list[TestCase],
    campaign_config: CampaignConfig,
    campaign_id: str,
    *,
    redact: bool,
    on_result: Callable[[TestResult], None] | None,
) -> list[TestResult]:
    try:
        return await run_campaign_async(
            target, test_cases, campaign_config, campaign_id, redact=redact, on_result=on_result
        )
    finally:
        await target.aclose()


def run_campaign(
    cfg: Config,
    *,
    suite: str,
    test_cases: list[TestCase],
    on_result: Callable[[TestResult], None] | None = None,
) -> tuple[Campaign, dict[str, Path]]:
    """Run `test_cases` (already resolved/filtered by the caller — see
    `core.registry.load_all_test_cases`/`select_suite`) against `cfg.target`, score the
    results, and write reports. Returns the `Campaign` and the format->path mapping written."""
    target = build_target(cfg.target, allow_external=cfg.security.allow_external_targets)
    campaign_id = new_campaign_id()
    started_at = datetime.now(UTC)

    results = asyncio.run(
        _run_and_cleanup(
            target,
            test_cases,
            cfg.campaign,
            campaign_id,
            redact=cfg.security.redact_sensitive_values,
            on_result=on_result,
        )
    )

    finished_at = datetime.now(UTC)
    campaign = Campaign(
        id=campaign_id,
        suite=suite,
        target=cfg.target,
        config=cfg.campaign,
        framework_version=__version__,
        started_at=started_at,
        finished_at=finished_at,
        total_tests=len(results),
        results=results,
    )

    output_dir = Path(cfg.reporting.output_directory) / campaign_id
    written = write_reports(campaign, formats=cfg.reporting.formats, output_dir=output_dir)
    logger.info(f"Wrote reports to {output_dir}", extra={"campaign_id": campaign_id})

    return campaign, written


def regenerate_reports(
    input_path: Path, *, formats: list[str], output_dir: Path | None
) -> dict[str, Path]:
    """Re-render report formats from a previously written JSON report. Returns the format->path
    mapping written."""
    if not input_path.is_file():
        raise LlmsecError(f"Input file not found: {input_path}")

    try:
        data = read_json(input_path)
    except ValueError as exc:
        raise LlmsecError(f"Could not parse JSON in {input_path}: {exc}") from exc

    campaign_data = data.get("campaign", data) if isinstance(data, dict) else data
    if not isinstance(campaign_data, dict):
        raise LlmsecError(f"{input_path} does not contain a recognizable campaign report.")

    try:
        campaign = Campaign.model_validate(campaign_data)
    except Exception as exc:  # pydantic ValidationError or similar
        raise LlmsecError(f"{input_path} does not contain a valid campaign report: {exc}") from exc

    target_dir = output_dir if output_dir is not None else input_path.parent
    return write_reports(campaign, formats=formats, output_dir=target_dir)
