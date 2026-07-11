from llmsec.attacks.base import AttackSuiteInfo
from llmsec.models.test_case import AttackCategory

SUITE_INFO = AttackSuiteInfo(
    category=AttackCategory.SYSTEM_PROMPT_LEAKAGE,
    title="System Prompt Leakage",
    description=(
        "Attempts to extract the hidden system prompt, internal rules, tool descriptions, or "
        "developer instructions the target was configured with."
    ),
    payload_file="system_prompt_leakage.yaml",
    owasp_llm_reference="LLM07: System Prompt Leakage",
    atlas_technique_id="AML.T0056",
    atlas_technique_name="LLM Meta Prompt Extraction",
    atlas_tactic="Exfiltration",
)
