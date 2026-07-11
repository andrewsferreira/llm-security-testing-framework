from llmsec.attacks.base import AttackSuiteInfo
from llmsec.models.test_case import AttackCategory

SUITE_INFO = AttackSuiteInfo(
    category=AttackCategory.EXCESSIVE_AGENCY,
    title="Excessive Agency",
    description=(
        "Whether the agent performs more than what was requested/authorized: chaining "
        "sensitive actions without confirmation, acting on behalf of the wrong user, or "
        "escalating scope beyond a single approved step."
    ),
    payload_file="excessive_agency.yaml",
    owasp_llm_reference="LLM06: Excessive Agency",
    atlas_technique_id="AML.T0048.002",
    atlas_technique_name="External Harms: User Harm",
    atlas_tactic="Impact",
)
