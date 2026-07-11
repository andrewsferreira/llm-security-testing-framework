from llmsec.attacks import ATTACK_CATALOG
from llmsec.models.test_case import AttackCategory


def test_catalog_has_an_entry_for_every_category() -> None:
    assert set(ATTACK_CATALOG) == set(AttackCategory)


def test_catalog_entries_reference_owasp_llm_top_10() -> None:
    for info in ATTACK_CATALOG.values():
        assert info.owasp_llm_reference.startswith("LLM")


def test_catalog_payload_files_are_named_after_the_category() -> None:
    for category, info in ATTACK_CATALOG.items():
        assert info.payload_file == f"{category.value}.yaml"


def test_catalog_entries_reference_mitre_atlas() -> None:
    for info in ATTACK_CATALOG.values():
        assert info.atlas_technique_id.startswith("AML.T")
        assert info.atlas_technique_name
        assert info.atlas_tactic


def test_catalog_atlas_technique_ids_are_unique_per_category() -> None:
    technique_ids = [info.atlas_technique_id for info in ATTACK_CATALOG.values()]
    assert len(technique_ids) == len(set(technique_ids))
