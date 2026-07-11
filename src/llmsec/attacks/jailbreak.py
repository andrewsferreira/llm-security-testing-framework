from llmsec.attacks.base import AttackSuiteInfo
from llmsec.models.test_case import AttackCategory

SUITE_INFO = AttackSuiteInfo(
    category=AttackCategory.JAILBREAK,
    title="Jailbreak",
    description=(
        "Roleplay, hypothetical framing, authority impersonation, nested/split instructions, "
        "translation tricks, and multi-turn escalation attempting to bypass safety guidelines "
        "without relying on any single fixed phrase."
    ),
    payload_file="jailbreak.yaml",
    owasp_llm_reference="LLM01: Prompt Injection",
    atlas_technique_id="AML.T0054",
    atlas_technique_name="LLM Jailbreak",
    atlas_tactic="Defense Evasion",
)
