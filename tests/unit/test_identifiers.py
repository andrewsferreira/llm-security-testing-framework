import re

from llmsec.utils.identifiers import new_campaign_id, new_result_id


def test_campaign_id_format() -> None:
    campaign_id = new_campaign_id()
    assert re.match(r"^campaign-\d{8}T\d{6}Z-[0-9a-f]{8}$", campaign_id)


def test_result_id_format() -> None:
    result_id = new_result_id()
    assert re.match(r"^result-\d{8}T\d{6}Z-[0-9a-f]{8}$", result_id)


def test_ids_are_unique() -> None:
    assert new_campaign_id() != new_campaign_id()
    assert new_result_id() != new_result_id()
