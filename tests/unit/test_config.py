from pathlib import Path

import pytest

from llmsec.config import load_config
from llmsec.exceptions import ConfigError


def test_loads_bundled_local_config() -> None:
    cfg = load_config("configs/local.yaml")
    assert cfg.target.base_url == "http://localhost:8000"
    assert cfg.security.allow_external_targets is False
    assert "json" in cfg.reporting.formats


def test_loads_bundled_safe_example_config() -> None:
    cfg = load_config("configs/safe-example.yaml")
    assert cfg.target.type.value == "generic_http"


def test_loads_bundled_ci_config() -> None:
    cfg = load_config("configs/ci.yaml")
    assert cfg.campaign.max_concurrency == 3


def test_missing_file_raises_config_error() -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config("configs/does-not-exist.yaml")


def test_invalid_yaml_raises_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("target: [unterminated")
    with pytest.raises(ConfigError):
        load_config(bad)


def test_non_mapping_yaml_raises_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "list.yaml"
    bad.write_text("- one\n- two\n")
    with pytest.raises(ConfigError, match="mapping"):
        load_config(bad)


def test_missing_target_raises_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "no-target.yaml"
    bad.write_text("campaign:\n  max_concurrency: 2\n")
    with pytest.raises(ConfigError, match="target"):
        load_config(bad)


def test_unknown_report_format_raises_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad-format.yaml"
    bad.write_text(
        "target:\n  base_url: http://localhost:8000\nreporting:\n  formats: [json, pdf]\n"
    )
    with pytest.raises(ConfigError, match="Unsupported report format"):
        load_config(bad)


def test_external_target_rejected_by_default(tmp_path: Path) -> None:
    bad = tmp_path / "external.yaml"
    bad.write_text("target:\n  base_url: http://example.com\n")
    with pytest.raises(ConfigError, match="allow_external_targets"):
        load_config(bad)


def test_external_target_allowed_when_flagged(tmp_path: Path) -> None:
    ok = tmp_path / "external-ok.yaml"
    ok.write_text(
        "target:\n  base_url: http://example.com\nsecurity:\n  allow_external_targets: true\n"
    )
    cfg = load_config(ok)
    assert cfg.security.allow_external_targets is True


def test_extra_field_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "extra.yaml"
    bad.write_text("target:\n  base_url: http://localhost:8000\nbogus_section: {}\n")
    with pytest.raises(ConfigError):
        load_config(bad)
