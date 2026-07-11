import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from llmsec import __version__
from llmsec.cli import app
from llmsec.models.campaign import Campaign, CampaignConfig
from llmsec.models.target import GenericHttpTargetConfig
from llmsec.reporters import write_reports

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_version_command_json() -> None:
    result = runner.invoke(app, ["version", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.output) == {"version": __version__}


def test_validate_config_success() -> None:
    result = runner.invoke(app, ["validate-config", "--config", "configs/local.yaml"])
    assert result.exit_code == 0
    assert "Configuration is valid" in result.stdout


def test_validate_config_json() -> None:
    result = runner.invoke(app, ["validate-config", "--config", "configs/local.yaml", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["valid"] is True
    assert payload["target"] == "http://localhost:8000"


def test_validate_config_json_on_error(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["validate-config", "--config", str(tmp_path / "nope.yaml"), "--json"]
    )
    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert "error" in payload


def test_validate_config_missing_file() -> None:
    result = runner.invoke(app, ["validate-config", "--config", "configs/nope.yaml"])
    assert result.exit_code == 2


def test_validate_config_rejects_external_target(tmp_path: Path) -> None:
    config = tmp_path / "external.yaml"
    config.write_text("target:\n  base_url: http://example.com\n")
    result = runner.invoke(app, ["validate-config", "--config", str(config)])
    assert result.exit_code == 2
    assert "allow_external_targets" in result.output


def test_list_tests_lists_fixture_cases(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLMSEC_PAYLOADS_DIR", "tests/fixtures/sample_payloads")
    result = runner.invoke(app, ["list-tests"])
    assert result.exit_code == 0
    assert "FIX-SPI-001" in result.output
    assert "test case(s)" in result.output


def test_list_tests_filters_by_category(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLMSEC_PAYLOADS_DIR", "tests/fixtures/sample_payloads")
    result = runner.invoke(app, ["list-tests", "--category", "data_exfiltration"])
    assert result.exit_code == 0
    assert "FIX-DEX-001" in result.output
    assert "FIX-SPI-001" not in result.output


def test_list_tests_reports_none_found_for_empty_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("LLMSEC_PAYLOADS_DIR", str(tmp_path))
    result = runner.invoke(app, ["list-tests"])
    assert result.exit_code == 0
    assert "No test cases found" in result.output


def test_list_tests_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLMSEC_PAYLOADS_DIR", "tests/fixtures/sample_payloads")
    result = runner.invoke(app, ["list-tests", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["count"] >= 1
    assert any(c["id"] == "FIX-SPI-001" for c in payload["test_cases"])


def test_report_command_rejects_missing_input(tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", "--input", str(tmp_path / "nope.json")])
    assert result.exit_code == 2
    assert "not found" in result.output


def test_report_command_rejects_unrecognizable_json(tmp_path: Path) -> None:
    input_path = tmp_path / "results.json"
    input_path.write_text("{}")
    result = runner.invoke(app, ["report", "--input", str(input_path)])
    assert result.exit_code == 2


def test_report_command_rejects_unsupported_format(tmp_path: Path) -> None:
    input_path = tmp_path / "results.json"
    input_path.write_text("{}")
    result = runner.invoke(app, ["report", "--input", str(input_path), "--format", "pdf"])
    assert result.exit_code == 2
    assert "Unsupported report format" in result.output


def test_report_command_regenerates_from_a_real_campaign_json(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    campaign = Campaign(
        id="campaign-test",
        suite="all",
        target=GenericHttpTargetConfig(base_url="http://localhost:8000"),
        config=CampaignConfig(),
        framework_version="0.1.0",
        started_at=now,
        finished_at=now,
        total_tests=0,
        results=[],
    )
    original_dir = tmp_path / "original"
    write_reports(campaign, formats=["json"], output_dir=original_dir)

    regenerated_dir = tmp_path / "regenerated"
    result = runner.invoke(
        app,
        [
            "report",
            "--input",
            str(original_dir / "results.json"),
            "--format",
            "markdown",
            "--output",
            str(regenerated_dir),
        ],
    )
    assert result.exit_code == 0
    assert (regenerated_dir / "report.md").is_file()


def _write_campaign_json(path: Path, *, campaign_id: str, base_url: str) -> Path:
    now = datetime.now(UTC)
    campaign = Campaign(
        id=campaign_id,
        suite="all",
        target=GenericHttpTargetConfig(base_url=base_url),
        config=CampaignConfig(),
        framework_version="0.1.0",
        started_at=now,
        finished_at=now,
        total_tests=0,
        results=[],
    )
    write_reports(campaign, formats=["json"], output_dir=path)
    return path / "results.json"


def test_compare_command_rejects_a_single_input(tmp_path: Path) -> None:
    campaign_json = _write_campaign_json(tmp_path / "a", campaign_id="a", base_url="http://x")
    result = runner.invoke(app, ["compare", "--input", str(campaign_json)])
    assert result.exit_code == 2
    assert "at least twice" in result.output


def test_compare_command_rejects_unsupported_format(tmp_path: Path) -> None:
    a = _write_campaign_json(tmp_path / "a", campaign_id="a", base_url="http://x")
    b = _write_campaign_json(tmp_path / "b", campaign_id="b", base_url="http://y")
    result = runner.invoke(
        app, ["compare", "--input", str(a), "--input", str(b), "--format", "sarif"]
    )
    assert result.exit_code == 2
    assert "Unsupported comparison format" in result.output


def test_compare_command_writes_comparison_reports(tmp_path: Path) -> None:
    a = _write_campaign_json(tmp_path / "a", campaign_id="a", base_url="http://localhost:8000")
    b = _write_campaign_json(tmp_path / "b", campaign_id="b", base_url="http://localhost:8001")
    output_dir = tmp_path / "comparison"

    result = runner.invoke(
        app,
        [
            "compare",
            "--input",
            str(a),
            "--input",
            str(b),
            "--output",
            str(output_dir),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (output_dir / "comparison.md").is_file()
    assert (output_dir / "comparison.html").is_file()


def test_compare_command_json_output(tmp_path: Path) -> None:
    a = _write_campaign_json(tmp_path / "a", campaign_id="a", base_url="http://localhost:8000")
    b = _write_campaign_json(tmp_path / "b", campaign_id="b", base_url="http://localhost:8001")
    output_dir = tmp_path / "comparison"

    result = runner.invoke(
        app,
        [
            "compare",
            "--input",
            str(a),
            "--input",
            str(b),
            "--output",
            str(output_dir),
            "--format",
            "json",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "json" in payload["reports"]


def test_dashboard_command_rejects_a_reports_dir_with_no_results(tmp_path: Path) -> None:
    result = runner.invoke(app, ["dashboard", "--reports-dir", str(tmp_path)])
    assert result.exit_code == 2
    assert "No results.json files found" in result.output


def test_dashboard_command_writes_a_dashboard_page(tmp_path: Path) -> None:
    _write_campaign_json(tmp_path / "a", campaign_id="a", base_url="http://localhost:8000")
    _write_campaign_json(tmp_path / "b", campaign_id="b", base_url="http://localhost:8001")
    output_path = tmp_path / "dashboard.html"

    result = runner.invoke(
        app,
        [
            "dashboard",
            "--reports-dir",
            str(tmp_path),
            "--output",
            str(output_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert output_path.is_file()
    assert "llmsec dashboard" in output_path.read_text()


def test_dashboard_command_json_output(tmp_path: Path) -> None:
    _write_campaign_json(tmp_path / "a", campaign_id="a", base_url="http://localhost:8000")
    output_path = tmp_path / "dashboard.html"

    result = runner.invoke(
        app,
        [
            "dashboard",
            "--reports-dir",
            str(tmp_path),
            "--output",
            str(output_path),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["reports"]["html"] == str(output_path)
