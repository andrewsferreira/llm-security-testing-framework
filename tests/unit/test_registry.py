from pathlib import Path

import pytest

from llmsec.core.registry import default_payloads_dir, load_all_test_cases, select_suite
from llmsec.exceptions import RegistryError
from llmsec.models.test_case import AttackCategory

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAMPLE_DIR = FIXTURES / "sample_payloads"
INVALID_DIR = FIXTURES / "invalid_payloads"
DUPLICATE_DIR = FIXTURES / "duplicate_id_payloads"


def test_loads_all_fixture_test_cases() -> None:
    cases = load_all_test_cases(SAMPLE_DIR)
    ids = {c.id for c in cases}
    assert "FIX-SPI-001" in ids
    assert "FIX-DEX-001" in ids
    assert "FIX-TAB-001" in ids
    assert "FIX-JBK-001" in ids
    assert "FIX-IPI-001" in ids


def test_missing_directory_raises_registry_error() -> None:
    with pytest.raises(RegistryError, match="not found"):
        load_all_test_cases(SAMPLE_DIR / "does-not-exist")


def test_invalid_test_case_raises_registry_error() -> None:
    with pytest.raises(RegistryError, match="Invalid test case"):
        load_all_test_cases(INVALID_DIR)


def test_duplicate_id_raises_registry_error() -> None:
    with pytest.raises(RegistryError, match="Duplicate test case id"):
        load_all_test_cases(DUPLICATE_DIR)


def test_select_suite_all_returns_everything() -> None:
    cases = load_all_test_cases(SAMPLE_DIR)
    assert select_suite(cases, "all") == cases


def test_select_suite_by_category() -> None:
    cases = load_all_test_cases(SAMPLE_DIR)
    selected = select_suite(cases, "system_prompt_leakage")
    assert {c.id for c in selected} == {"FIX-SPI-001"}


def test_select_suite_by_kebab_case_category() -> None:
    cases = load_all_test_cases(SAMPLE_DIR)
    selected = select_suite(cases, "data-exfiltration")
    assert {c.id for c in selected} == {"FIX-DEX-001"}


def test_select_suite_alias_expands_to_multiple_categories() -> None:
    cases = load_all_test_cases(SAMPLE_DIR)
    selected = select_suite(cases, "prompt-injection")
    assert {c.category for c in selected} <= {
        AttackCategory.DIRECT_PROMPT_INJECTION,
        AttackCategory.INDIRECT_PROMPT_INJECTION,
    }
    assert any(c.id == "FIX-IPI-001" for c in selected)


def test_unknown_suite_raises_registry_error() -> None:
    cases = load_all_test_cases(SAMPLE_DIR)
    with pytest.raises(RegistryError, match="Unknown suite"):
        select_suite(cases, "not-a-real-suite")


def test_default_payloads_dir_env_var_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LLMSEC_PAYLOADS_DIR", str(tmp_path))
    assert default_payloads_dir() == tmp_path
