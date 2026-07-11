"""Reference catalog of the 9 attack categories (title, description, payload file, OWASP LLM
Top 10 mapping, MITRE ATLAS technique/tactic mapping). The actual test cases live in
payloads/*.yaml and are loaded by core/registry.py; this catalog is descriptive metadata used
by docs and reporters."""

from __future__ import annotations

from llmsec.attacks import (
    context_manipulation,
    data_exfiltration,
    direct_prompt_injection,
    excessive_agency,
    indirect_prompt_injection,
    insecure_output_handling,
    jailbreak,
    system_prompt_leakage,
    tool_abuse,
)
from llmsec.attacks.base import AttackSuiteInfo
from llmsec.models.test_case import AttackCategory

ATTACK_CATALOG: dict[AttackCategory, AttackSuiteInfo] = {
    module.SUITE_INFO.category: module.SUITE_INFO
    for module in (
        direct_prompt_injection,
        indirect_prompt_injection,
        jailbreak,
        system_prompt_leakage,
        data_exfiltration,
        tool_abuse,
        context_manipulation,
        insecure_output_handling,
        excessive_agency,
    )
}

__all__ = ["ATTACK_CATALOG", "AttackSuiteInfo"]
