"""ID generation helpers for campaigns and results."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime


def _stamped_id(prefix: str) -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    suffix = uuid.uuid4().hex[:8]
    return f"{prefix}-{timestamp}-{suffix}"


def new_campaign_id() -> str:
    return _stamped_id("campaign")


def new_result_id() -> str:
    return _stamped_id("result")
