"""JSON report: the full campaign plus its computed summary, in one file.

This is also the canonical input to `llmsec report --input <this file>` for regenerating the
other formats later.
"""

from __future__ import annotations

import json

from llmsec.attacks import ATTACK_CATALOG
from llmsec.core.scoring import CampaignSummary
from llmsec.models.campaign import Campaign
from llmsec.utils.serialization import to_jsonable

_FRAMEWORK_MAPPINGS = {
    category.value: {
        "owasp_llm_reference": info.owasp_llm_reference,
        "atlas_technique_id": info.atlas_technique_id,
        "atlas_technique_name": info.atlas_technique_name,
        "atlas_tactic": info.atlas_tactic,
    }
    for category, info in ATTACK_CATALOG.items()
}


def render(campaign: Campaign, summary: CampaignSummary) -> str:
    payload = {
        "summary": to_jsonable(summary),
        "campaign": to_jsonable(campaign),
        "framework_mappings": _FRAMEWORK_MAPPINGS,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
