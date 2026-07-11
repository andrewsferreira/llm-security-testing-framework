from llmsec.attacks.base import AttackSuiteInfo
from llmsec.models.test_case import AttackCategory

SUITE_INFO = AttackSuiteInfo(
    category=AttackCategory.CONTEXT_MANIPULATION,
    title="Context Manipulation",
    description=(
        "Attempts to poison conversational memory, insert false facts, redefine the "
        "assistant's identity or task, or confuse the boundary between system/user/tool "
        "messages so untrusted content is treated as trusted instruction."
    ),
    payload_file="context_manipulation.yaml",
    owasp_llm_reference="LLM01: Prompt Injection",
    atlas_technique_id="AML.T0051",
    atlas_technique_name="LLM Prompt Injection",
    atlas_tactic="Persistence",
)
