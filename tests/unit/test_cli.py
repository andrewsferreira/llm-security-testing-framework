from pathlib import Path

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


def test_list_tests_not_yet_implemented() -> None:
    result = runner.invoke(app, ["list-tests"])
    assert result.exit_code != 0
