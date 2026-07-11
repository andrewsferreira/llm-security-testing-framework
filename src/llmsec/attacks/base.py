"""Reference metadata for each attack category: not executable logic (the test cases
themselves, loaded by core/registry.py, carry all the runtime behavior) — this is the
descriptive catalog used by docs and the executive-summary section of Phase 6's reporters.

`atlas_*` fields map each category to MITRE ATLAS (https://atlas.mitre.org), the ATT&CK-style
knowledge base of adversary tactics/techniques against ML systems. Unlike OWASP LLM Top 10
(a risk taxonomy), ATLAS models attacker TTPs, so the fit is closer for the prompt-injection
family than for consumer-side categories like insecure output handling or excessive agency,
where the mapping is a best-effort "closest applicable technique" rather than a precise match.
Verify against the current matrix before citing in a compliance context — ATLAS is revised
over time and these IDs reflect the matrix as of this project's authoring.
"""

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
    atlas_technique_id: str
    atlas_technique_name: str
    atlas_tactic: str
