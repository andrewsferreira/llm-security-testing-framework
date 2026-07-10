"""Runs the real engine/runner against the lab's agent (via MockTarget, no HTTP) using the
fixture payloads, proving the whole pipeline — registry -> runner -> evaluator -> TestResult —
behaves correctly and differently in vulnerable vs hardened mode."""

from __future__ import annotations

from pathlib import Path

from llmsec.core.registry import load_all_test_cases
from llmsec.core.runner import run_campaign_async
from llmsec.models.campaign import CampaignConfig
from llmsec.models.result import ResultStatus
from llmsec.models.target import TargetConfig
from llmsec.targets.mock_target import MockTarget

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "sample_payloads"


async def _run(mode: str) -> dict[str, ResultStatus]:
    test_cases = load_all_test_cases(FIXTURES)
    target = MockTarget(TargetConfig(base_url="http://localhost:8000"), mode=mode)
    config = CampaignConfig(max_concurrency=4, retry_count=0)
    results = await run_campaign_async(target, test_cases, config, "camp-lab", redact=True)
    return {r.test_id: r.status for r in results}


async def test_vulnerable_mode_produces_failed_findings() -> None:
    statuses = await _run("vulnerable")
    assert statuses["FIX-SPI-001"] == ResultStatus.FAILED
    assert statuses["FIX-DEX-001"] == ResultStatus.FAILED
    assert statuses["FIX-JBK-001"] == ResultStatus.FAILED
    assert statuses["FIX-IPI-001"] == ResultStatus.FAILED
    assert statuses["FIX-TAB-001"] == ResultStatus.FAILED


async def test_hardened_mode_passes_the_same_suite() -> None:
    statuses = await _run("hardened")
    assert statuses["FIX-SPI-001"] == ResultStatus.PASSED
    assert statuses["FIX-DEX-001"] == ResultStatus.PASSED
    assert statuses["FIX-JBK-001"] == ResultStatus.PASSED
    assert statuses["FIX-IPI-001"] == ResultStatus.PASSED
    assert statuses["FIX-TAB-001"] == ResultStatus.PASSED


async def test_vulnerable_has_more_failures_than_hardened() -> None:
    vulnerable = await _run("vulnerable")
    hardened = await _run("hardened")
    vulnerable_failures = sum(1 for s in vulnerable.values() if s == ResultStatus.FAILED)
    hardened_failures = sum(1 for s in hardened.values() if s == ResultStatus.FAILED)
    assert vulnerable_failures > hardened_failures
    assert hardened_failures == 0
