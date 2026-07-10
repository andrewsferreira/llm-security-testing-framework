"""The campaign execution engine: loads test cases, runs them against a target, scores the
results, and writes reports in every configured format."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

from llmsec import __version__
from llmsec.config import Config
from llmsec.constants import ExitCode
from llmsec.core.registry import load_all_test_cases, select_suite
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
    target: Target,
    test_cases: list[TestCase],
    campaign_config: CampaignConfig,
    campaign_id: str,
    *,
    redact: bool,
) -> list[TestResult]:
    try:
        return await run_campaign_async(
            target, test_cases, campaign_config, campaign_id, redact=redact
        )
    finally:
        await target.aclose()


def run_campaign(cfg: Config, *, suite: str) -> int:
    all_cases = load_all_test_cases()
    test_cases = select_suite(all_cases, suite)
    if not test_cases:
        logger.error(f"No test cases matched suite {suite!r}.")
        print(f"No test cases matched suite {suite!r}.")
        return int(ExitCode.USAGE_ERROR)

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

    _print_summary(campaign, written)

    return int(ExitCode.FINDINGS) if campaign.failed_count > 0 else int(ExitCode.SUCCESS)


def _print_summary(campaign: Campaign, written: dict[str, Path]) -> None:
    print(f"\nCampaign {campaign.id} ({campaign.suite}): {campaign.total_tests} test(s)")
    print(f"  passed:       {campaign.passed_count}")
    print(f"  failed:       {campaign.failed_count}")
    print(f"  inconclusive: {campaign.inconclusive_count}")
    print(f"  errors:       {campaign.error_count}")
    for fmt, path in written.items():
        print(f"  {fmt:<10}: {path}")


def regenerate_reports(input_path: Path, *, formats: list[str], output_dir: Path | None) -> None:
    """Re-render report formats from a previously written JSON report."""
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
    written = write_reports(campaign, formats=formats, output_dir=target_dir)
    for fmt, path in written.items():
        print(f"{fmt:<10}: {path}")
