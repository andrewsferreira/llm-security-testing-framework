"""Loads and validates TestCase definitions from a directory of YAML files (payloads/*.yaml).

Each YAML file is a list of test case mappings. Discovery is directory-based, not tied to any
fixed set of category filenames, so Phase 5's payloads/*.yaml files (and any custom ones a user
adds) are picked up the same way as the fixtures this module's own tests use.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from importlib import resources
from pathlib import Path

import yaml
from pydantic import ValidationError

from llmsec.exceptions import RegistryError
from llmsec.models.test_case import AttackCategory, TestCase

PAYLOADS_DIR_ENV_VAR = "LLMSEC_PAYLOADS_DIR"

# Convenience suite names that expand to more than one category (used by `--suite`).
SUITE_ALIASES: dict[str, frozenset[AttackCategory]] = {
    "prompt-injection": frozenset(
        {AttackCategory.DIRECT_PROMPT_INJECTION, AttackCategory.INDIRECT_PROMPT_INJECTION}
    ),
}


def default_payloads_dir() -> Path:
    """Resolve the payloads directory: LLMSEC_PAYLOADS_DIR env var, else the packaged data,
    else a repo-root `payloads/` fallback for editable/local-dev installs."""
    override = os.environ.get(PAYLOADS_DIR_ENV_VAR)
    if override:
        return Path(override)

    packaged = resources.files("llmsec") / "payloads"
    if packaged.is_dir():
        return Path(str(packaged))

    return Path(__file__).resolve().parents[3] / "payloads"


def _load_file(path: Path) -> list[TestCase]:
    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise RegistryError(f"Could not parse YAML in {path}: {exc}") from exc

    if raw is None:
        return []
    if not isinstance(raw, list):
        raise RegistryError(f"{path} must contain a YAML list of test cases.")

    cases: list[TestCase] = []
    for index, entry in enumerate(raw):
        try:
            cases.append(TestCase.model_validate(entry))
        except ValidationError as exc:
            raise RegistryError(f"Invalid test case at {path}[{index}]: {exc}") from exc
    return cases


def load_all_test_cases(directory: Path | str | None = None) -> list[TestCase]:
    """Load every TestCase from every *.yaml file in `directory` (default: resolved payloads
    dir), raising RegistryError with a clear message on the first invalid file encountered."""
    payloads_dir = Path(directory) if directory is not None else default_payloads_dir()
    if not payloads_dir.is_dir():
        raise RegistryError(f"Payloads directory not found: {payloads_dir}")

    cases: list[TestCase] = []
    seen_ids: dict[str, Path] = {}
    for path in sorted(payloads_dir.glob("*.yaml")):
        for case in _load_file(path):
            if case.id in seen_ids:
                raise RegistryError(
                    f"Duplicate test case id {case.id!r} in {path} "
                    f"(already defined in {seen_ids[case.id]})."
                )
            seen_ids[case.id] = path
            cases.append(case)
    return cases


def _resolve_suite_categories(suite: str) -> frozenset[AttackCategory] | None:
    """Return the set of categories `suite` refers to, or None if `suite` is "all"."""
    if suite == "all":
        return None
    normalized = suite.replace("-", "_")
    if suite in SUITE_ALIASES:
        return SUITE_ALIASES[suite]
    try:
        return frozenset({AttackCategory(normalized)})
    except ValueError as exc:
        valid = sorted(c.value.replace("_", "-") for c in AttackCategory) + [
            *SUITE_ALIASES,
            "all",
        ]
        raise RegistryError(f"Unknown suite {suite!r}. Valid suites: {sorted(valid)}.") from exc


def select_suite(test_cases: Iterable[TestCase], suite: str) -> list[TestCase]:
    """Filter `test_cases` down to the ones matching `suite` ("all" or a category/alias)."""
    categories = _resolve_suite_categories(suite)
    if categories is None:
        return list(test_cases)
    return [tc for tc in test_cases if tc.category in categories]
