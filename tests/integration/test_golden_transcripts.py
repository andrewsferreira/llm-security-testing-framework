"""Golden-transcript regression tests: pin the FULL result shape (not just pass/fail) for one
representative test case per attack category, against the bundled lab in each mode.

See tests/fixtures/golden/README.md for the full contract — what's pinned and why, the
"fixed seeds" note (the lab has no randomness to seed; it's already fully deterministic), and
how to deliberately regenerate the fixtures via scripts/regenerate_golden_fixtures.py.

This is a *stricter, complementary* check to
tests/integration/test_all_payloads_against_lab.py, which asserts every payload in the full set
resolves to the right status but not the exact evidence/explanation/risk_score behind it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from llmsec.core.registry import load_all_test_cases
from llmsec.core.runner import run_campaign_async
from llmsec.models.campaign import CampaignConfig
from llmsec.models.result import TestResult
from llmsec.models.target import MockTargetConfig
from llmsec.targets.mock_target import MockTarget

_FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "golden"

# One test case per attack category — the "-001" id in each payloads/*.yaml file. Deliberately a
# small, named, curated set (not "all of them", which is what the other integration test is
# for) so a golden-test failure is easy to read and points at exactly what changed.
GOLDEN_TEST_IDS: set[str] = {
    "CTX-001",
    "DEX-001",
    "DPI-001",
    "EAG-001",
    "IOH-001",
    "IPI-001",
    "JBK-001",
    "SPI-001",
    "TAB-001",
}


def _load_fixture(mode: str) -> dict[str, dict[str, Any]]:
    return cast(
        "dict[str, dict[str, Any]]", json.loads((_FIXTURES_DIR / f"{mode}.json").read_text())
    )


def _pin(result: TestResult) -> dict[str, Any]:
    """Extracts exactly the fields the golden fixtures pin — see the README for why
    id/campaign_id/timestamps/latency_ms are deliberately excluded."""
    return {
        "category": result.category.value,
        "severity": result.severity.value,
        "status": result.status.value,
        "confidence": result.confidence,
        "matched_indicators": result.evidence.matched_indicators,
        "notes": result.evidence.notes,
        "response": result.response,
        "explanation": result.explanation,
        "remediation": result.remediation,
        "risk_score": result.risk_score,
    }


async def _run_golden_set(mode: str) -> dict[str, dict[str, Any]]:
    cases = [c for c in load_all_test_cases() if c.id in GOLDEN_TEST_IDS]
    target = MockTarget(MockTargetConfig(base_url="http://localhost:8000"), mode=mode)
    config = CampaignConfig(max_concurrency=4, retry_count=0)
    results = await run_campaign_async(target, cases, config, "golden-test", redact=True)
    return {r.test_id: _pin(r) for r in results}


def test_golden_fixture_files_cover_every_id_and_category() -> None:
    from llmsec.models.test_case import AttackCategory

    for mode in ("vulnerable", "hardened"):
        fixture = _load_fixture(mode)
        assert set(fixture) == GOLDEN_TEST_IDS, f"{mode}.json doesn't match GOLDEN_TEST_IDS"
        assert {entry["category"] for entry in fixture.values()} == {
            c.value for c in AttackCategory
        }, f"{mode}.json doesn't cover every attack category"


async def test_vulnerable_mode_matches_golden_transcript() -> None:
    actual = await _run_golden_set("vulnerable")
    expected = _load_fixture("vulnerable")
    mismatches = {
        test_id: {"expected": expected[test_id], "actual": actual[test_id]}
        for test_id in GOLDEN_TEST_IDS
        if actual[test_id] != expected[test_id]
    }
    assert not mismatches, (
        "Vulnerable-mode golden transcript mismatch (if intentional, regenerate via "
        f"scripts/regenerate_golden_fixtures.py and review the diff): {mismatches}"
    )


async def test_hardened_mode_matches_golden_transcript() -> None:
    actual = await _run_golden_set("hardened")
    expected = _load_fixture("hardened")
    mismatches = {
        test_id: {"expected": expected[test_id], "actual": actual[test_id]}
        for test_id in GOLDEN_TEST_IDS
        if actual[test_id] != expected[test_id]
    }
    assert not mismatches, (
        "Hardened-mode golden transcript mismatch (if intentional, regenerate via "
        f"scripts/regenerate_golden_fixtures.py and review the diff): {mismatches}"
    )
