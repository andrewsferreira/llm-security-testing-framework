from llmsec.attacks.base import AttackSuiteInfo
from llmsec.models.test_case import AttackCategory

SUITE_INFO = AttackSuiteInfo(
    category=AttackCategory.TOOL_ABUSE,
    title="Tool Abuse",
    description=(
        "Unauthorized tool invocation, parameter tampering, out-of-scope resource access, "
        "and path-traversal/host-allowlist bypass attempts against the agent's tool layer."
    ),
    payload_file="tool_abuse.yaml",
    owasp_llm_reference="LLM06: Excessive Agency",
    atlas_technique_id="AML.T0053",
    atlas_technique_name="LLM Plugin Compromise",
    atlas_tactic="Execution",
)
