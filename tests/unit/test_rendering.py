import json
from datetime import UTC, datetime
from pathlib import Path

from llmsec.config import Config
from llmsec.models.campaign import Campaign, CampaignConfig
from llmsec.models.result import Evidence, ResultStatus, TestResult
from llmsec.models.target import GenericHttpTargetConfig
from llmsec.models.test_case import AttackCategory, Severity, TestCase
from llmsec.rendering import JsonRenderer, RichRenderer, get_renderer

_NOW = datetime.now(UTC)


def _test_case(id_: str) -> TestCase:
    return TestCase.model_validate(
        {
            "id": id_,
            "name": f"case {id_}",
            "category": AttackCategory.JAILBREAK,
            "description": "d",
            "severity": Severity.HIGH,
            "prompt": "p",
            "expected_behavior": "e",
            "evaluator_config": {"type": "keyword"},
        }
    )


def _result(status: ResultStatus) -> TestResult:
    return TestResult(
        id="result-1",
        campaign_id="camp-1",
        test_id="T-1",
        test_name="case",
        category=AttackCategory.JAILBREAK,
        severity=Severity.HIGH,
        status=status,
        confidence=0.9,
        evidence=Evidence(),
        latency_ms=1.0,
        evaluator="keyword",
        explanation="explained",
        started_at=_NOW,
        finished_at=_NOW,
    )


def _campaign() -> Campaign:
    return Campaign(
        id="campaign-test",
        suite="jailbreak",
        target=GenericHttpTargetConfig(base_url="http://localhost:8000"),
        config=CampaignConfig(),
        framework_version="0.1.0",
        started_at=_NOW,
        finished_at=_NOW,
        total_tests=2,
        results=[_result(ResultStatus.FAILED), _result(ResultStatus.PASSED)],
    )


def test_get_renderer_dispatches_on_json_flag() -> None:
    assert isinstance(get_renderer(json_output=True), JsonRenderer)
    assert isinstance(get_renderer(json_output=False), RichRenderer)


def test_json_renderer_version(capsys: object) -> None:
    JsonRenderer().version("1.2.3")
    out = capsys.readouterr().out  # type: ignore[attr-defined]
    assert json.loads(out) == {"version": "1.2.3"}


def test_json_renderer_error(capsys: object) -> None:
    JsonRenderer().error("boom")
    out = capsys.readouterr().out  # type: ignore[attr-defined]
    assert json.loads(out) == {"error": "boom"}


def test_json_renderer_config_valid(capsys: object) -> None:
    cfg = Config.model_validate({"target": {"base_url": "http://localhost:8000"}})
    JsonRenderer().config_valid(Path("configs/local.yaml"), cfg)
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["valid"] is True
    assert payload["target"] == "http://localhost:8000"


def test_json_renderer_list_tests(capsys: object) -> None:
    JsonRenderer().list_tests([_test_case("A"), _test_case("B")])
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["count"] == 2
    assert {c["id"] for c in payload["test_cases"]} == {"A", "B"}


def test_json_renderer_scan_progress_yields_noop_callback() -> None:
    with JsonRenderer().scan_progress(3) as on_result:
        on_result(_result(ResultStatus.FAILED))  # must not raise or print anything


def test_json_renderer_scan_summary(capsys: object, tmp_path: Path) -> None:
    written = {"json": tmp_path / "results.json"}
    JsonRenderer().scan_summary(_campaign(), written)
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["campaign_id"] == "campaign-test"
    assert payload["failed"] == 1
    assert payload["passed"] == 1
    assert payload["reports"]["json"] == str(tmp_path / "results.json")


def test_json_renderer_report_written(capsys: object, tmp_path: Path) -> None:
    written = {"markdown": tmp_path / "report.md"}
    JsonRenderer().report_written(written)
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["reports"]["markdown"] == str(tmp_path / "report.md")


def test_rich_renderer_list_tests_includes_ids(capsys: object) -> None:
    renderer = RichRenderer()
    renderer.list_tests([_test_case("FIX-A")])
    out = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "FIX-A" in out


def test_rich_renderer_list_tests_handles_empty(capsys: object) -> None:
    renderer = RichRenderer()
    renderer.list_tests([])
    out = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "No test cases found" in out


def test_rich_renderer_scan_progress_advances_without_error() -> None:
    renderer = RichRenderer()
    with renderer.scan_progress(2) as on_result:
        on_result(_result(ResultStatus.FAILED))
        on_result(_result(ResultStatus.PASSED))


def test_rich_renderer_scan_summary_mentions_counts(capsys: object, tmp_path: Path) -> None:
    renderer = RichRenderer()
    written = {"json": tmp_path / "results.json"}
    renderer.scan_summary(_campaign(), written)
    out = capsys.readouterr().out.lower()  # type: ignore[attr-defined]
    assert "passed" in out
    assert "failed" in out
