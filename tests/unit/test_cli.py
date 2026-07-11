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
