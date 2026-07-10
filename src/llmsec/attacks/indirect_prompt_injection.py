from llmsec.attacks.base import AttackSuiteInfo
from llmsec.models.test_case import AttackCategory

SUITE_INFO = AttackSuiteInfo(
    category=AttackCategory.INDIRECT_PROMPT_INJECTION,
    title="Indirect Prompt Injection",
    description=(
        "Malicious instructions embedded in content the target treats as data — a retrieved "
        "document, a web page, a tool result — rather than as the user's own words."
    ),
    payload_file="indirect_prompt_injection.yaml",
    owasp_llm_reference="LLM01: Prompt Injection",
)
