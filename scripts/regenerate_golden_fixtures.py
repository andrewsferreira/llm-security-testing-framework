#!/usr/bin/env python3
"""Regenerates tests/fixtures/golden/{vulnerable,hardened}.json from a real run against the
bundled lab. Only run this deliberately, after confirming a behavior change to one of the 9
golden test cases is intentional — see tests/fixtures/golden/README.md for the contract this
is regenerating. Always review the diff before committing.

Usage: python scripts/regenerate_golden_fixtures.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tests.integration.test_golden_transcripts import GOLDEN_TEST_IDS  # noqa: E402

from llmsec.core.registry import load_all_test_cases  # noqa: E402
from llmsec.core.runner import run_campaign_async  # noqa: E402
from llmsec.models.campaign import CampaignConfig  # noqa: E402
from llmsec.models.result import TestResult  # noqa: E402
from llmsec.models.target import MockTargetConfig  # noqa: E402
from llmsec.targets.mock_target import MockTarget  # noqa: E402

_FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "golden"


def _pin(result: TestResult) -> dict[str, Any]:
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


async def _run(mode: str) -> dict[str, Any]:
    cases = [c for c in load_all_test_cases() if c.id in GOLDEN_TEST_IDS]
    target = MockTarget(MockTargetConfig(base_url="http://localhost:8000"), mode=mode)
    config = CampaignConfig(max_concurrency=4, retry_count=0)
    results = await run_campaign_async(target, cases, config, "golden-regen", redact=True)
    return {r.test_id: _pin(r) for r in results}


def main() -> None:
    for mode in ("vulnerable", "hardened"):
        data = asyncio.run(_run(mode))
        missing = GOLDEN_TEST_IDS - data.keys()
        if missing:
            raise SystemExit(f"Golden test id(s) not found in payloads/: {sorted(missing)}")
        path = _FIXTURES_DIR / f"{mode}.json"
        path.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        print(f"Wrote {path}")


if __name__ == "__main__":
    main()
