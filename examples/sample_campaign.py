"""Runs a full campaign programmatically — the same pipeline `llmsec scan` uses (registry ->
runner -> scoring -> reporters), without going through the CLI at all.

Uses the mock target (no HTTP, in-process) so this runs standalone. Swap in
`llmsec.targets.build_target(cfg.target, allow_external=...)` with a `generic_http` config to
point this at a real target instead.

Run from the repo root: python examples/sample_campaign.py
"""

from __future__ import annotations

import asyncio
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from llmsec import __version__  # noqa: E402
from llmsec.core.registry import load_all_test_cases, select_suite  # noqa: E402
from llmsec.core.runner import run_campaign_async  # noqa: E402
from llmsec.models.campaign import Campaign, CampaignConfig  # noqa: E402
from llmsec.models.target import MockTargetConfig  # noqa: E402
from llmsec.reporters import write_reports  # noqa: E402
from llmsec.targets.mock_target import MockTarget  # noqa: E402
from llmsec.utils.identifiers import new_campaign_id  # noqa: E402


async def main() -> None:
    test_cases = select_suite(load_all_test_cases(REPO_ROOT / "payloads"), "jailbreak")

    target = MockTarget(MockTargetConfig(base_url="http://localhost:8000"), mode="vulnerable")
    campaign_config = CampaignConfig(max_concurrency=4, retry_count=1)
    campaign_id = new_campaign_id()
    started_at = datetime.now(UTC)

    results = await run_campaign_async(
        target, test_cases, campaign_config, campaign_id, redact=True
    )

    campaign = Campaign(
        id=campaign_id,
        suite="jailbreak",
        target=target.config,
        config=campaign_config,
        framework_version=__version__,
        started_at=started_at,
        finished_at=datetime.now(UTC),
        total_tests=len(results),
        results=results,
    )

    output_dir = REPO_ROOT / "reports" / campaign_id
    written = write_reports(campaign, formats=["json", "markdown"], output_dir=output_dir)

    print(f"{campaign.passed_count} passed, {campaign.failed_count} failed")
    for fmt, path in written.items():
        print(f"{fmt}: {path}")


if __name__ == "__main__":
    asyncio.run(main())
