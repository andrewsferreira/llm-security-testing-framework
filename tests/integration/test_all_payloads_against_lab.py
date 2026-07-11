"""Runs every real payloads/*.yaml test case against the lab (via MockTarget) in both modes.

This is the key correctness guarantee for the whole payload set: every single case must
demonstrate the vulnerability in vulnerable mode and resist it in hardened mode. A test case
whose trigger phrase doesn't actually match the lab's agent — or accidentally collides with a
different category's trigger — shows up here as a failure, not silently later.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from llmsec.core.registry import load_all_test_cases
from llmsec.core.runner import run_campaign_async
from llmsec.models.campaign import CampaignConfig
from llmsec.models.result import ResultStatus
from llmsec.models.target import MockTargetConfig
from llmsec.models.test_case import AttackCategory, TestCase
from llmsec.targets.mock_target import MockTarget

PAYLOADS_DIR = Path(__file__).resolve().parent.parent.parent / "payloads"


def _load_cases() -> list[TestCase]:
    return load_all_test_cases(PAYLOADS_DIR)


async def _run(mode: str) -> dict[str, ResultStatus]:
    test_cases = _load_cases()
    target = MockTarget(MockTargetConfig(base_url="http://localhost:8000"), mode=mode)
    config = CampaignConfig(max_concurrency=8, retry_count=0)
    results = await run_campaign_async(target, test_cases, config, "camp-payloads", redact=True)
    return {r.test_id: r.status for r in results}


def test_payloads_directory_has_every_category_covered() -> None:
    cases = _load_cases()
    assert {c.category for c in cases} == set(AttackCategory)
    assert len(cases) >= 45  # at minimum ~5 per category


async def test_every_payload_fails_in_vulnerable_mode() -> None:
    statuses = await _run("vulnerable")
    not_failed = {tid: s.value for tid, s in statuses.items() if s != ResultStatus.FAILED}
    assert not not_failed, f"Expected FAILED in vulnerable mode, got: {not_failed}"


async def test_every_payload_passes_in_hardened_mode() -> None:
    statuses = await _run("hardened")
    not_passed = {tid: s.value for tid, s in statuses.items() if s != ResultStatus.PASSED}
    assert not not_passed, f"Expected PASSED in hardened mode, got: {not_passed}"


@pytest.mark.parametrize("category", list(AttackCategory))
async def test_each_category_is_fully_covered_in_both_modes(category: AttackCategory) -> None:
    cases = [c for c in _load_cases() if c.category == category]
    assert cases, f"No test cases found for category {category.value}"

    target_vuln = MockTarget(MockTargetConfig(base_url="http://localhost:8000"), mode="vulnerable")
    target_hard = MockTarget(MockTargetConfig(base_url="http://localhost:8000"), mode="hardened")
    config = CampaignConfig(max_concurrency=4, retry_count=0)

    vuln_results = await run_campaign_async(target_vuln, cases, config, "camp-cat", redact=True)
    hard_results = await run_campaign_async(target_hard, cases, config, "camp-cat", redact=True)

    assert all(r.status == ResultStatus.FAILED for r in vuln_results), (
        f"{category.value}: not all vulnerable-mode results were FAILED: "
        f"{[(r.test_id, r.status.value) for r in vuln_results if r.status != ResultStatus.FAILED]}"
    )
    assert all(r.status == ResultStatus.PASSED for r in hard_results), (
        f"{category.value}: not all hardened-mode results were PASSED: "
        f"{[(r.test_id, r.status.value) for r in hard_results if r.status != ResultStatus.PASSED]}"
    )
