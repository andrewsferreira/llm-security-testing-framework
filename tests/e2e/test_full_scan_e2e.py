"""True black-box end-to-end test: spins up the lab as a real subprocess (real socket, real
uvicorn), drives the actual installed `llmsec` console script as a subprocess against it, and
inspects the report files it writes on disk.

This is the one place in the test suite that doesn't take any in-process shortcut (no
CliRunner, no ASGITransport, no MockTarget) — it's the closest thing to "what a user actually
does" and is what proves the vulnerable/hardened demonstration end to end, per
docs/portfolio-demo.md.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
HEALTH_TIMEOUT_SECONDS = 15.0


def _free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_until_healthy(base_url: str, *, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response = httpx.get(f"{base_url}/health", timeout=1.0)
            if response.status_code == 200:
                return
        except httpx.HTTPError as exc:
            last_error = exc
        time.sleep(0.2)
    raise TimeoutError(f"Lab did not become healthy at {base_url} in time: {last_error}")


@contextlib.contextmanager
def _running_lab(mode: str) -> Iterator[str]:
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    env = {**os.environ, "LAB_MODE": mode}
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "lab.app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        _wait_until_healthy(base_url, timeout=HEALTH_TIMEOUT_SECONDS)
        yield base_url
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def _run_scan(*, target: str, output: Path, suite: str = "all") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "llmsec",
            "scan",
            "--target",
            target,
            "--suite",
            suite,
            "--config",
            "configs/local.yaml",
            "--output",
            str(output),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _load_campaign_json(output_dir: Path) -> tuple[dict[str, Any], Path]:
    campaign_dirs = list(output_dir.glob("campaign-*"))
    assert len(campaign_dirs) == 1, f"expected exactly one campaign dir, found {campaign_dirs}"
    data: dict[str, Any] = json.loads((campaign_dirs[0] / "results.json").read_text())
    return data, campaign_dirs[0]


@pytest.mark.e2e
def test_e2e_vulnerable_scan_finds_issues_and_writes_all_reports(tmp_path: Path) -> None:
    with _running_lab("vulnerable") as base_url:
        output_dir = tmp_path / "vulnerable-run"
        result = _run_scan(target=base_url, output=output_dir)

    assert result.returncode == 1, result.stdout + result.stderr

    data, campaign_dir = _load_campaign_json(output_dir)
    assert data["summary"]["failed"] > 0
    assert data["summary"]["total_tests"] >= 45

    for filename in ("results.json", "report.md", "report.html", "results.sarif"):
        assert (campaign_dir / filename).is_file(), f"missing {filename}"


@pytest.mark.e2e
def test_e2e_hardened_scan_passes_everything(tmp_path: Path) -> None:
    with _running_lab("hardened") as base_url:
        output_dir = tmp_path / "hardened-run"
        result = _run_scan(target=base_url, output=output_dir)

    assert result.returncode == 0, result.stdout + result.stderr

    data, _campaign_dir = _load_campaign_json(output_dir)
    assert data["summary"]["failed"] == 0
    assert data["summary"]["passed"] == data["summary"]["total_tests"]


@pytest.mark.e2e
def test_e2e_vulnerable_has_strictly_more_findings_than_hardened(tmp_path: Path) -> None:
    with _running_lab("vulnerable") as vuln_url:
        vuln_output = tmp_path / "vuln"
        vuln_result = _run_scan(target=vuln_url, output=vuln_output)

    with _running_lab("hardened") as hard_url:
        hard_output = tmp_path / "hard"
        hard_result = _run_scan(target=hard_url, output=hard_output)

    vuln_data, _ = _load_campaign_json(vuln_output)
    hard_data, _ = _load_campaign_json(hard_output)

    assert vuln_result.returncode == 1
    assert hard_result.returncode == 0
    assert vuln_data["summary"]["failed"] > hard_data["summary"]["failed"]
    assert vuln_data["summary"]["total_tests"] == hard_data["summary"]["total_tests"]


@pytest.mark.e2e
def test_e2e_single_category_suite_scopes_correctly(tmp_path: Path) -> None:
    with _running_lab("vulnerable") as base_url:
        output_dir = tmp_path / "jailbreak-only"
        result = _run_scan(target=base_url, output=output_dir, suite="jailbreak")

    assert result.returncode == 1
    data, _ = _load_campaign_json(output_dir)
    assert all(r["category"] == "jailbreak" for r in data["campaign"]["results"])
