import json
from datetime import UTC, datetime
from pathlib import Path

from llmsec.core.scoring import summarize
from llmsec.models.campaign import Campaign, CampaignConfig
from llmsec.models.result import Evidence, ResultStatus, TestResult
from llmsec.models.target import GenericHttpTargetConfig
from llmsec.models.test_case import AttackCategory, Severity
from llmsec.reporters import (
    FILE_NAMES,
    html_reporter,
    json_reporter,
    markdown_reporter,
    sarif_reporter,
    write_reports,
)

_NOW = datetime.now(UTC)


def _result(
    test_id: str,
    *,
    status: ResultStatus,
    severity: Severity = Severity.HIGH,
    risk_score: float | None = None,
    response: str | None = "some response",
) -> TestResult:
    return TestResult(
        id=f"result-{test_id}",
        campaign_id="camp-1",
        test_id=test_id,
        test_name=f"Case {test_id}",
        category=AttackCategory.JAILBREAK,
        severity=severity,
        status=status,
        confidence=0.8,
        evidence=Evidence(matched_indicators=["MARKER"], notes="matched"),
        response=response,
        latency_ms=1.0,
        evaluator="keyword",
        explanation="the target complied",
        remediation="do not trust untrusted input",
        risk_score=risk_score,
        started_at=_NOW,
        finished_at=_NOW,
    )


def _campaign(results: list[TestResult]) -> Campaign:
    return Campaign(
        id="campaign-20260101T000000Z-deadbeef",
        suite="all",
        target=GenericHttpTargetConfig(base_url="http://localhost:8000"),
        config=CampaignConfig(),
        framework_version="0.1.0",
        started_at=_NOW,
        finished_at=_NOW,
        total_tests=len(results),
        results=results,
    )


def _campaign_with_finding() -> Campaign:
    return _campaign(
        [
            _result("A", status=ResultStatus.FAILED, severity=Severity.CRITICAL, risk_score=9.5),
            _result("B", status=ResultStatus.PASSED),
        ]
    )


def test_json_reporter_round_trips_summary_and_campaign() -> None:
    campaign = _campaign_with_finding()
    summary = summarize(campaign)
    content = json_reporter.render(campaign, summary)
    data = json.loads(content)
    assert data["summary"]["failed"] == 1
    assert data["campaign"]["id"] == campaign.id


def test_json_reporter_includes_framework_mappings() -> None:
    campaign = _campaign_with_finding()
    summary = summarize(campaign)
    content = json_reporter.render(campaign, summary)
    data = json.loads(content)
    mapping = data["framework_mappings"]["jailbreak"]
    assert mapping["owasp_llm_reference"] == "LLM01: Prompt Injection"
    assert mapping["atlas_technique_id"] == "AML.T0054"
    assert mapping["atlas_tactic"] == "Defense Evasion"


def test_markdown_reporter_includes_key_sections() -> None:
    campaign = _campaign_with_finding()
    summary = summarize(campaign)
    content = markdown_reporter.render(campaign, summary)
    assert "# llmsec Security Report" in content
    assert "## Executive Summary" in content
    assert "## Findings" in content
    assert "## Recommendations" in content
    assert "## Limitations" in content
    assert "A" in content  # the finding's test_id
    assert "do not trust untrusted input" in content


def test_markdown_reporter_category_table_includes_owasp_and_atlas() -> None:
    campaign = _campaign_with_finding()
    summary = summarize(campaign)
    content = markdown_reporter.render(campaign, summary)
    assert "OWASP LLM Top 10" in content
    assert "MITRE ATLAS" in content
    assert "AML.T0054" in content  # jailbreak's ATLAS technique id


def test_markdown_reporter_handles_no_findings() -> None:
    campaign = _campaign([_result("A", status=ResultStatus.PASSED)])
    summary = summarize(campaign)
    content = markdown_reporter.render(campaign, summary)
    assert "No findings" in content


def test_sarif_reporter_produces_valid_shape() -> None:
    campaign = _campaign_with_finding()
    summary = summarize(campaign)
    content = sarif_reporter.render(campaign, summary)
    data = json.loads(content)
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "llmsec"
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "A"
    assert run["results"][0]["level"] == "error"


def test_sarif_reporter_rule_includes_owasp_and_atlas_properties() -> None:
    campaign = _campaign_with_finding()
    summary = summarize(campaign)
    content = sarif_reporter.render(campaign, summary)
    data = json.loads(content)
    rule_props = data["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
    assert rule_props["owaspLlmReference"] == "LLM01: Prompt Injection"
    assert rule_props["atlasTechniqueId"] == "AML.T0054"
    assert rule_props["atlasTactic"] == "Defense Evasion"


def test_sarif_reporter_only_includes_failed_results() -> None:
    campaign = _campaign(
        [
            _result("A", status=ResultStatus.PASSED),
            _result("B", status=ResultStatus.INCONCLUSIVE),
            _result("C", status=ResultStatus.ERROR),
        ]
    )
    summary = summarize(campaign)
    content = sarif_reporter.render(campaign, summary)
    data = json.loads(content)
    assert data["runs"][0]["results"] == []


def test_html_reporter_escapes_dangerous_response_content() -> None:
    campaign = _campaign(
        [
            _result(
                "A",
                status=ResultStatus.FAILED,
                risk_score=8.0,
                response="<script>alert('xss')</script>",
            )
        ]
    )
    summary = summarize(campaign)
    content = html_reporter.render(campaign, summary)
    assert "<script>alert" not in content
    assert "&lt;script&gt;" in content


def test_html_reporter_includes_filter_controls() -> None:
    campaign = _campaign_with_finding()
    summary = summarize(campaign)
    content = html_reporter.render(campaign, summary)
    assert 'id="category-filter"' in content
    assert 'id="severity-filter"' in content
    assert "<script src=" not in content  # no external script


def test_html_reporter_category_table_includes_owasp_and_atlas() -> None:
    campaign = _campaign_with_finding()
    summary = summarize(campaign)
    content = html_reporter.render(campaign, summary)
    assert "OWASP LLM Top 10" in content
    assert "MITRE ATLAS" in content
    assert "AML.T0054" in content  # jailbreak's ATLAS technique id


def test_write_reports_writes_every_requested_format(tmp_path: Path) -> None:
    campaign = _campaign_with_finding()
    written = write_reports(
        campaign, formats=["json", "markdown", "html", "sarif"], output_dir=tmp_path
    )
    assert set(written) == {"json", "markdown", "html", "sarif"}
    for fmt, path in written.items():
        assert path.is_file()
        assert path.name == FILE_NAMES[fmt]


def test_write_reports_respects_output_directory_containment(tmp_path: Path) -> None:
    campaign = _campaign_with_finding()
    written = write_reports(campaign, formats=["json"], output_dir=tmp_path / "nested" / "dir")
    assert written["json"].is_relative_to(tmp_path)
