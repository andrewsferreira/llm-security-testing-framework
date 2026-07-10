"""Loads and validates TestCase definitions from payloads/*.yaml.

Implemented in Phase 5 alongside the attack category modules and payload files.
"""

from __future__ import annotations

from llmsec.models.test_case import TestCase


def load_all_test_cases() -> list[TestCase]:
    raise NotImplementedError(
        "The test-case registry is implemented in Phase 5 (attacks/ + payloads/)."
    )
