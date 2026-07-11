from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from llmsec.core.dashboard import build_dashboard, discover_campaign_report_paths
from llmsec.models.campaign import Campaign, CampaignConfig
from llmsec.models.result import Evidence, ResultStatus, TestResult
from llmsec.models.target import GenericHttpTargetConfig
from llmsec.models.test_case import AttackCategory, Severity
from llmsec.reporters import write_reports

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
        target=GenericHttpTargetConfig(base_url="http://localhost:8000"),
        config=CampaignConfig(),
        framework_version="0.1.0",
        started_at=started_at,
        finished_at=started_at,
        total_tests=len(results),
        results=results,
    )


def test_discover_campaign_report_paths_finds_nested_results_json(tmp_path: Path) -> None:
    (tmp_path / "run-1" / "campaign-a").mkdir(parents=True)
    (tmp_path / "run-2" / "campaign-b").mkdir(parents=True)
    (tmp_path / "run-1" / "campaign-a" / "results.json").write_text("{}")
    (tmp_path / "run-2" / "campaign-b" / "results.json").write_text("{}")
    (tmp_path / "run-2" / "campaign-b" / "report.md").write_text("not this one")

    found = discover_campaign_report_paths(tmp_path)
    assert len(found) == 2
    assert all(p.name == "results.json" for p in found)


def test_discover_campaign_report_paths_returns_empty_for_missing_directory(
    tmp_path: Path,
) -> None:
    assert discover_campaign_report_paths(tmp_path / "does-not-exist") == []


def test_build_dashboard_requires_at_least_one_campaign() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        build_dashboard([])


def test_build_dashboard_sorts_entries_by_started_at() -> None:
    older = _campaign("old", _NOW, [_result("A", status=ResultStatus.PASSED)])
    newer = _campaign(
        "new", _NOW + timedelta(hours=1), [_result("B", status=ResultStatus.FAILED, risk_score=6.0)]
    )
    dashboard = build_dashboard([newer, older])

    assert [e.campaign_id for e in dashboard.entries] == ["old", "new"]
    assert dashboard.total_campaigns == 2
    assert dashboard.total_tests == 2
    assert dashboard.total_findings == 1


def test_build_dashboard_aggregates_severity_and_category_totals() -> None:
    a = _campaign("a", _NOW, [_result("A", status=ResultStatus.FAILED, risk_score=6.0)])
    b = _campaign(
        "b",
        _NOW + timedelta(minutes=5),
        [_result("B", status=ResultStatus.FAILED, risk_score=6.0)],
    )
    dashboard = build_dashboard([a, b])

    assert dashboard.severity_distribution_total.high == 2
    assert dashboard.category_distribution_total["jailbreak"] == 2
    assert dashboard.category_distribution_total["data_exfiltration"] == 0


def test_build_dashboard_works_with_a_single_campaign() -> None:
    a = _campaign("solo", _NOW, [_result("A", status=ResultStatus.PASSED)])
    dashboard = build_dashboard([a])
    assert dashboard.total_campaigns == 1
    assert dashboard.entries[0].campaign_id == "solo"


def test_dashboard_end_to_end_from_real_written_reports(tmp_path: Path) -> None:
    a = _campaign("a", _NOW, [_result("A", status=ResultStatus.FAILED, risk_score=8.0)])
    b = _campaign("b", _NOW + timedelta(hours=1), [_result("B", status=ResultStatus.PASSED)])
    write_reports(a, formats=["json"], output_dir=tmp_path / "a")
    write_reports(b, formats=["json"], output_dir=tmp_path / "b")

    paths = discover_campaign_report_paths(tmp_path)
    assert len(paths) == 2

    from llmsec.core.engine import load_campaign_from_json

    campaigns = [load_campaign_from_json(p) for p in paths]
    dashboard = build_dashboard(campaigns)
    assert dashboard.total_campaigns == 2
    assert dashboard.total_findings == 1
