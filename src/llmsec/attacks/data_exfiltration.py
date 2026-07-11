from llmsec.attacks.base import AttackSuiteInfo
from llmsec.models.test_case import AttackCategory

SUITE_INFO = AttackSuiteInfo(
    category=AttackCategory.DATA_EXFILTRATION,
    title="Data Exfiltration",
    description=(
        "Attempts to extract fictional in-context secrets — directly, via summarization, "
        "transformation, encoding, translation, tool use, or across multiple turns."
    ),
    payload_file="data_exfiltration.yaml",
    owasp_llm_reference="LLM02: Sensitive Information Disclosure",
    atlas_technique_id="AML.T0057",
    atlas_technique_name="LLM Data Leakage",
    atlas_tactic="Exfiltration",
)
