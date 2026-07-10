from pathlib import Path

import pytest
from typer.testing import CliRunner

from llmsec import __version__
from llmsec.cli import app

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_validate_config_success() -> None:
    result = runner.invoke(app, ["validate-config", "--config", "configs/local.yaml"])
    assert result.exit_code == 0
    assert "Configuration is valid" in result.stdout


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


def test_report_command_is_not_yet_implemented(tmp_path: Path) -> None:
    input_path = tmp_path / "results.json"
    input_path.write_text("{}")
    result = runner.invoke(app, ["report", "--input", str(input_path)])
    assert result.exit_code != 0
