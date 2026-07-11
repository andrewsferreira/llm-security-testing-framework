from datetime import UTC, datetime

import pytest

from llmsec.core.comparison import campaign_label, compare_campaigns
from llmsec.models.campaign import Campaign, CampaignConfig
from llmsec.models.result import Evidence, ResultStatus, TestResult
from llmsec.models.target import GenericHttpTargetConfig, ProviderTargetConfig
from llmsec.models.test_case import AttackCategory, Severity

_NOW = datetime.now(UTC)


def _result(
    test_id: str,
    *,
    status: ResultStatus,
    category: AttackCategory = AttackCategory.JAILBREAK,
    severity: Severity = Severity.HIGH,
    risk_score: float | None = None,
) -> TestResult:
    return TestResult(
        id=f"result-{test_id}",
        campaign_id="camp",
        test_id=test_id,
        test_name=f"case {test_id}",
        category=category,
        severity=severity,
        status=status,
        confidence=0.8,
        evidence=Evidence(),
        latency_ms=1.0,
        evaluator="keyword",
        explanation="explained",
        risk_score=risk_score,
        started_at=_NOW,
        finished_at=_NOW,
    )


def _campaign(campaign_id: str, target: object, results: list[TestResult]) -> Campaign:
    return Campaign(
        id=campaign_id,
        suite="all",
        target=target,  # type: ignore[arg-type]
        config=CampaignConfig(),
        framework_version="0.1.0",
        started_at=_NOW,
        finished_at=_NOW,
        total_tests=len(results),
        results=results,
    )


def test_campaign_label_uses_provider_and_model_for_provider_targets() -> None:
    campaign = _campaign(
        "c1",
        ProviderTargetConfig(
            base_url="https://api.openai.com",
            provider="openai",
            model="gpt-4o-mini",
            auth_token_env="KEY",
        ),
        [],
    )
    assert campaign_label(campaign) == "openai:gpt-4o-mini"


def test_campaign_label_uses_base_url_for_generic_http_targets() -> None:
    campaign = _campaign("c1", GenericHttpTargetConfig(base_url="http://localhost:8000"), [])
    assert campaign_label(campaign) == "http://localhost:8000"


def test_compare_campaigns_requires_at_least_two() -> None:
    campaign = _campaign("c1", GenericHttpTargetConfig(base_url="http://localhost:8000"), [])
    with pytest.raises(ValueError, match="at least 2"):
        compare_campaigns([campaign])


def test_compare_campaigns_builds_one_entry_per_campaign() -> None:
    vulnerable = _campaign(
        "vuln",
        GenericHttpTargetConfig(base_url="http://localhost:8000"),
        [
            _result("A", status=ResultStatus.FAILED, risk_score=8.0),
            _result("B", status=ResultStatus.PASSED),
        ],
    )
    hardened = _campaign(
        "hard",
        GenericHttpTargetConfig(base_url="http://localhost:8001"),
        [_result("A", status=ResultStatus.PASSED)],
    )
    comparison = compare_campaigns([vulnerable, hardened])

    assert len(comparison.entries) == 2
    assert comparison.entries[0].campaign_id == "vuln"
    assert comparison.entries[0].failed == 1
    assert comparison.entries[0].average_finding_risk_score == 8.0
    assert comparison.entries[1].failed == 0
    assert comparison.entries[1].average_finding_risk_score == 0.0
    # summarize() zero-fills every AttackCategory in category_distribution_findings (see
    # core/scoring.py), so the union across entries is always the full category set, not just
    # categories with an actual finding — matches the single-campaign reporters' own behavior.
    assert comparison.categories == sorted(c.value for c in AttackCategory)
    assert comparison.entries[0].category_distribution_findings["jailbreak"] == 1


def test_compare_campaigns_category_union_covers_all_entries() -> None:
    a = _campaign(
        "a",
        GenericHttpTargetConfig(base_url="http://localhost:8000"),
        [
            _result(
                "A", status=ResultStatus.FAILED, category=AttackCategory.JAILBREAK, risk_score=5.0
            )
        ],
    )
    b = _campaign(
        "b",
        GenericHttpTargetConfig(base_url="http://localhost:8001"),
        [
            _result(
                "B",
                status=ResultStatus.FAILED,
                category=AttackCategory.DATA_EXFILTRATION,
                risk_score=5.0,
            )
        ],
    )
    comparison = compare_campaigns([a, b])
    assert comparison.categories == sorted(c.value for c in AttackCategory)
    assert comparison.entries[0].category_distribution_findings["jailbreak"] == 1
    assert comparison.entries[0].category_distribution_findings["data_exfiltration"] == 0
    assert comparison.entries[1].category_distribution_findings["data_exfiltration"] == 1
