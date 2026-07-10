"""JSON report: the full campaign plus its computed summary, in one file.

This is also the canonical input to `llmsec report --input <this file>` for regenerating the
other formats later.
"""

from __future__ import annotations

import json

from llmsec.core.scoring import CampaignSummary
from llmsec.models.campaign import Campaign
from llmsec.utils.serialization import to_jsonable


def render(campaign: Campaign, summary: CampaignSummary) -> str:
    payload = {"summary": to_jsonable(summary), "campaign": to_jsonable(campaign)}
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
