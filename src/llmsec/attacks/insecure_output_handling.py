from llmsec.attacks.base import AttackSuiteInfo
from llmsec.models.test_case import AttackCategory

SUITE_INFO = AttackSuiteInfo(
    category=AttackCategory.INSECURE_OUTPUT_HANDLING,
    title="Insecure Output Handling",
    description=(
        "Whether the target's output could be dangerous if a downstream component (a "
        "browser, database, or shell) consumed it without escaping or validation — HTML/"
        "Markdown/JS injection, SQL fragments, shell commands, and path-traversal strings."
    ),
    payload_file="insecure_output_handling.yaml",
    owasp_llm_reference="LLM05: Improper Output Handling",
)
