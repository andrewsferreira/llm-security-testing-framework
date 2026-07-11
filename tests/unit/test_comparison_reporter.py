import json
from datetime import UTC, datetime

from llmsec.core.comparison import compare_campaigns
from llmsec.models.campaign import Campaign, CampaignConfig
from llmsec.models.result import Evidence, ResultStatus, TestResult
from llmsec.models.target import GenericHttpTargetConfig
from llmsec.models.test_case import AttackCategory, Severity
from llmsec.reporters import comparison_reporter

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


def _comparison():
    vulnerable = Campaign(
        id="vuln",
        suite="jailbreak",
        target=GenericHttpTargetConfig(base_url="http://localhost:8000"),
        config=CampaignConfig(),
        framework_version="0.1.0",
        started_at=_NOW,
        finished_at=_NOW,
        total_tests=1,
        results=[_result("A", status=ResultStatus.FAILED, risk_score=7.5)],
    )
    hardened = Campaign(
        id="hard",
        suite="jailbreak",
        target=GenericHttpTargetConfig(base_url="http://localhost:8001"),
        config=CampaignConfig(),
        framework_version="0.1.0",
        started_at=_NOW,
        finished_at=_NOW,
        total_tests=1,
        results=[_result("A", status=ResultStatus.PASSED)],
    )
    return compare_campaigns([vulnerable, hardened])


def test_render_markdown_includes_both_labels_and_findings_table() -> None:
    content = comparison_reporter.render_markdown(_comparison())
    assert "# llmsec Campaign Comparison" in content
    assert "http://localhost:8000" in content
    assert "http://localhost:8001" in content
    assert "## Findings by Category" in content
    assert "## Severity Distribution" in content


def test_render_json_round_trips_entries() -> None:
    content = comparison_reporter.render_json(_comparison())
    data = json.loads(content)
    assert len(data["entries"]) == 2
    assert data["entries"][0]["label"] == "http://localhost:8000"
    assert data["entries"][0]["failed"] == 1
    assert data["entries"][1]["failed"] == 0


def test_render_html_is_self_contained_and_includes_charts() -> None:
    content = comparison_reporter.render_html(_comparison())
    assert "<script src=" not in content  # no external script
    assert "http://localhost:8000" in content
    assert "http://localhost:8001" in content
    assert content.count("<svg") >= 1  # at least the overview chart
