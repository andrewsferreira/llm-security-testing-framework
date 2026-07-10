"""Exercises `llmsec scan` in-process (CliRunner) against the mock target, so the engine's
main code path (registry -> runner -> scoring -> reporters) is covered by the test suite
itself, not only by the subprocess-based tests/e2e suite (which runs as a separate process and
isn't visible to coverage measurement)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from llmsec.cli import app

runner = CliRunner()


def _write_mock_config(path: Path) -> None:
    path.write_text(
        "target:\n"
        "  type: mock\n"
        "  base_url: http://localhost:8000\n"
        "campaign:\n"
        "  max_concurrency: 4\n"
        "  retry_count: 0\n"
        "reporting:\n"
        "  formats: [json, markdown, html, sarif]\n"
    )


def test_scan_against_mock_target_writes_reports_and_exits_with_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LLMSEC_PAYLOADS_DIR", "tests/fixtures/sample_payloads")
    config_path = tmp_path / "mock.yaml"
    _write_mock_config(config_path)
    output_dir = tmp_path / "reports"

    result = runner.invoke(
        app,
        [
            "scan",
            "--suite",
            "all",
            "--config",
            str(config_path),
            "--output",
            str(output_dir),
        ],
    )

    assert result.exit_code == 1, result.output
    assert "failed:" in result.output

    campaign_dirs = list(output_dir.glob("campaign-*"))
    assert len(campaign_dirs) == 1
    for filename in ("results.json", "report.md", "report.html", "results.sarif"):
        assert (campaign_dirs[0] / filename).is_file()

    data = json.loads((campaign_dirs[0] / "results.json").read_text())
    assert data["summary"]["failed"] == data["summary"]["total_tests"]


def test_scan_reports_usage_error_for_unmatched_suite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LLMSEC_PAYLOADS_DIR", "tests/fixtures/sample_payloads")
    config_path = tmp_path / "mock.yaml"
    _write_mock_config(config_path)

    result = runner.invoke(
        app,
        [
            "scan",
            "--suite",
            "excessive_agency",
            "--config",
            str(config_path),
            "--output",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 2
    assert "No test cases matched" in result.output


def test_scan_target_override_takes_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LLMSEC_PAYLOADS_DIR", "tests/fixtures/sample_payloads")
    config_path = tmp_path / "mock.yaml"
    _write_mock_config(config_path)

    result = runner.invoke(
        app,
        [
            "scan",
            "--suite",
            "system_prompt_leakage",
            "--config",
            str(config_path),
            "--output",
            str(tmp_path / "out"),
            "--target",
            "http://localhost:9",
        ],
    )
    # The mock target ignores base_url entirely, so this should still succeed rather than
    # trying to connect anywhere.
    assert result.exit_code == 1, result.output
