from llmsec.attacks.base import AttackSuiteInfo
from llmsec.models.test_case import AttackCategory

SUITE_INFO = AttackSuiteInfo(
    category=AttackCategory.DIRECT_PROMPT_INJECTION,
    title="Direct Prompt Injection",
    description=(
        "Explicit user instructions attempting to override, ignore, or bypass the target's "
        "system instructions and policy hierarchy."
    ),
    payload_file="direct_prompt_injection.yaml",
    owasp_llm_reference="LLM01: Prompt Injection",
)
