"""Reference metadata for each attack category: not executable logic (the test cases
themselves, loaded by core/registry.py, carry all the runtime behavior) — this is the
descriptive catalog used by docs and the executive-summary section of Phase 6's reporters."""

from __future__ import annotations

from dataclasses import dataclass

from llmsec.models.test_case import AttackCategory


@dataclass(frozen=True)
class AttackSuiteInfo:
    category: AttackCategory
    title: str
    description: str
    payload_file: str
    owasp_llm_reference: str
