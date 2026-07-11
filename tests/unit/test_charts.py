from datetime import UTC, datetime, timedelta

from llmsec.core.scoring import SeverityDistribution
from llmsec.models.result import Evidence, ResultStatus, TestResult
from llmsec.models.test_case import AttackCategory, Severity
from llmsec.reporters.charts import (
    findings_timeline_svg,
    horizontal_bar_chart,
    severity_bar_chart_svg,
)

_NOW = datetime.now(UTC)


def _finding(test_id: str, *, severity: Severity, started_at: datetime) -> TestResult:
    return TestResult(
        id=f"result-{test_id}",
        campaign_id="camp-1",
        test_id=test_id,
        test_name="case",
        category=AttackCategory.JAILBREAK,
        severity=severity,
        status=ResultStatus.FAILED,
        confidence=0.8,
        evidence=Evidence(),
        latency_ms=1.0,
        evaluator="keyword",
        explanation="explained",
        started_at=started_at,
        finished_at=started_at,
    )


def test_horizontal_bar_chart_empty_rows_returns_empty_string() -> None:
    assert horizontal_bar_chart([]) == ""


def test_horizontal_bar_chart_renders_one_rect_per_row() -> None:
    svg = horizontal_bar_chart([("Critical", 3, "--critical"), ("Low", 0, "--low")])
    assert svg.startswith("<svg")
    assert svg.count("<rect") == 2
    assert "Critical: 3" in svg
    assert "Low: 0" in svg


def test_severity_bar_chart_svg_includes_all_four_severities() -> None:
    dist = SeverityDistribution(critical=2, high=1, medium=0, low=0)
    svg = severity_bar_chart_svg(dist)
    assert svg.count("<rect") == 4
    assert "Critical: 2" in svg
    assert "High: 1" in svg


def test_findings_timeline_svg_empty_when_no_findings() -> None:
    assert findings_timeline_svg([], started_at=_NOW, duration_seconds=10.0) == ""


def test_findings_timeline_svg_empty_when_zero_duration() -> None:
    finding = _finding("T-1", severity=Severity.HIGH, started_at=_NOW)
    assert findings_timeline_svg([finding], started_at=_NOW, duration_seconds=0.0) == ""


def test_findings_timeline_svg_places_one_circle_per_finding() -> None:
    findings = [
        _finding("T-1", severity=Severity.CRITICAL, started_at=_NOW),
        _finding("T-2", severity=Severity.LOW, started_at=_NOW + timedelta(seconds=5)),
    ]
    svg = findings_timeline_svg(findings, started_at=_NOW, duration_seconds=10.0)
    assert svg.count("<circle") == 2
    assert "T-1" in svg
    assert "T-2" in svg


def test_findings_timeline_svg_escapes_malicious_test_id() -> None:
    finding = _finding('<script>alert("xss")</script>', severity=Severity.HIGH, started_at=_NOW)
    svg = findings_timeline_svg([finding], started_at=_NOW, duration_seconds=5.0)
    assert "<script>alert" not in svg
    assert "&lt;script&gt;" in svg
