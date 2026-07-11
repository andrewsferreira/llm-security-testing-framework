from datetime import UTC, datetime, timedelta

from llmsec.core.dashboard import build_dashboard
from llmsec.models.campaign import Campaign, CampaignConfig
from llmsec.models.result import Evidence, ResultStatus, TestResult
from llmsec.models.target import GenericHttpTargetConfig
from llmsec.models.test_case import AttackCategory, Severity
from llmsec.reporters import dashboard_reporter

_NOW = datetime.now(UTC)


def _result(test_id: str, *, status: ResultStatus, risk_score: float | None = None) -> TestResult:
    return TestResult(
        id=f"result-{test_id}",
        campaign_id="camp",
        test_id=test_id,
        test_name=f"case {test_id}",
        category=AttackCategory.JAILBREAK,
        severity=Severity.HIGH,
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


def _campaign(campaign_id: str, started_at: datetime, results: list[TestResult]) -> Campaign:
    return Campaign(
        id=campaign_id,
        suite="jailbreak",
        target=GenericHttpTargetConfig(base_url=f"http://{campaign_id}.example"),
        config=CampaignConfig(),
        framework_version="0.1.0",
        started_at=started_at,
        finished_at=started_at,
        total_tests=len(results),
        results=results,
    )


def _dashboard():
    a = _campaign("a", _NOW, [_result("A", status=ResultStatus.FAILED, risk_score=8.0)])
    b = _campaign("b", _NOW + timedelta(hours=1), [_result("B", status=ResultStatus.PASSED)])
    return build_dashboard([a, b])


def test_render_is_self_contained_html_with_charts() -> None:
    content = dashboard_reporter.render(_dashboard())
    assert "<script src=" not in content  # no external script
    assert "http://a.example" in content
    assert "http://b.example" in content
    assert content.count("<svg") >= 2  # trend + severity charts at minimum


def test_render_includes_overview_counts() -> None:
    content = dashboard_reporter.render(_dashboard())
    assert ">2<" in content  # total_campaigns card
    assert ">1<" in content  # total_findings card
