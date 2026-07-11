from datetime import UTC, datetime

from llmsec.core.scoring import compute_risk_score, summarize
from llmsec.models.campaign import Campaign, CampaignConfig
from llmsec.models.result import Evidence, ResultStatus, TestResult
from llmsec.models.target import GenericHttpTargetConfig
from llmsec.models.test_case import AttackCategory, Severity

_NOW = datetime.now(UTC)


def test_compute_risk_score_critical_single_turn_is_maximal() -> None:
    score = compute_risk_score(
        severity=Severity.CRITICAL, confidence=1.0, requires_multi_turn=False
    )
    assert score == 10.0


def test_compute_risk_score_low_severity_is_small() -> None:
    score = compute_risk_score(severity=Severity.LOW, confidence=1.0, requires_multi_turn=False)
    assert 0 < score < 2


def test_compute_risk_score_multi_turn_is_lower_than_single_turn() -> None:
    single = compute_risk_score(severity=Severity.HIGH, confidence=0.9, requires_multi_turn=False)
    multi = compute_risk_score(severity=Severity.HIGH, confidence=0.9, requires_multi_turn=True)
    assert multi < single


def test_compute_risk_score_scales_with_confidence() -> None:
    high_conf = compute_risk_score(
        severity=Severity.HIGH, confidence=0.9, requires_multi_turn=False
    )
    low_conf = compute_risk_score(severity=Severity.HIGH, confidence=0.3, requires_multi_turn=False)
    assert high_conf > low_conf


def test_compute_risk_score_never_exceeds_ten() -> None:
    score = compute_risk_score(
        severity=Severity.CRITICAL, confidence=1.0, requires_multi_turn=False
    )
    assert score <= 10.0


def _result(
    test_id: str,
    *,
    status: ResultStatus,
    severity: Severity = Severity.HIGH,
    category: AttackCategory = AttackCategory.JAILBREAK,
    risk_score: float | None = None,
    remediation: str | None = None,
) -> TestResult:
    return TestResult(
        id=f"result-{test_id}",
        campaign_id="camp-1",
        test_id=test_id,
        test_name=f"case {test_id}",
        category=category,
        severity=severity,
        status=status,
        confidence=0.8,
        evidence=Evidence(matched_indicators=["X"], notes="n"),
        latency_ms=1.0,
        evaluator="keyword",
        explanation="explained",
        remediation=remediation,
        risk_score=risk_score,
        started_at=_NOW,
        finished_at=_NOW,
    )


def _campaign(results: list[TestResult]) -> Campaign:
    return Campaign(
        id="camp-1",
        suite="all",
        target=GenericHttpTargetConfig(base_url="http://localhost:8000"),
        config=CampaignConfig(),
        framework_version="0.1.0",
        started_at=_NOW,
        finished_at=_NOW,
        total_tests=len(results),
        results=results,
    )


def test_summarize_counts_by_status() -> None:
    campaign = _campaign(
        [
            _result("A", status=ResultStatus.PASSED),
            _result("B", status=ResultStatus.FAILED, risk_score=5.0),
            _result("C", status=ResultStatus.INCONCLUSIVE),
            _result("D", status=ResultStatus.ERROR),
        ]
    )
    summary = summarize(campaign)
    assert summary.total_tests == 4
    assert summary.passed == 1
    assert summary.failed == 1
    assert summary.inconclusive == 1
    assert summary.errors == 1


def test_summarize_findings_sorted_by_risk_score_descending() -> None:
    campaign = _campaign(
        [
            _result("A", status=ResultStatus.FAILED, risk_score=3.0),
            _result("B", status=ResultStatus.FAILED, risk_score=9.0),
            _result("C", status=ResultStatus.FAILED, risk_score=6.0),
        ]
    )
    summary = summarize(campaign)
    assert [f.test_id for f in summary.findings] == ["B", "C", "A"]


def test_summarize_severity_distribution_only_counts_findings() -> None:
    campaign = _campaign(
        [
            _result("A", status=ResultStatus.FAILED, severity=Severity.CRITICAL, risk_score=9.0),
            _result("B", status=ResultStatus.PASSED, severity=Severity.CRITICAL),
        ]
    )
    summary = summarize(campaign)
    assert summary.severity_distribution_findings.critical == 1
    assert summary.severity_distribution_all.critical == 2


def test_summarize_category_distribution_only_counts_findings() -> None:
    campaign = _campaign(
        [
            _result(
                "A", status=ResultStatus.FAILED, category=AttackCategory.TOOL_ABUSE, risk_score=5.0
            ),
            _result("B", status=ResultStatus.PASSED, category=AttackCategory.TOOL_ABUSE),
        ]
    )
    summary = summarize(campaign)
    assert summary.category_distribution_findings["tool_abuse"] == 1
    assert summary.category_distribution_findings["jailbreak"] == 0


def test_summarize_deduplicates_recommendations() -> None:
    campaign = _campaign(
        [
            _result("A", status=ResultStatus.FAILED, risk_score=5.0, remediation="Fix X"),
            _result("B", status=ResultStatus.FAILED, risk_score=4.0, remediation="Fix X"),
            _result("C", status=ResultStatus.FAILED, risk_score=3.0, remediation="Fix Y"),
        ]
    )
    summary = summarize(campaign)
    assert summary.recommendations == ["Fix X", "Fix Y"]


def test_summarize_no_findings_gives_empty_lists() -> None:
    campaign = _campaign([_result("A", status=ResultStatus.PASSED)])
    summary = summarize(campaign)
    assert summary.findings == []
    assert summary.recommendations == []
