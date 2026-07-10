"""Central redaction utilities.

Used before anything (logs, evidence, reports) that might contain request/response bodies is
persisted or displayed, so that fake lab secrets and secret-shaped strings never leak into
artifacts. Never log or write raw target payloads without passing them through here first.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

_REDACTED = "[REDACTED]"

# Generic secret-shaped patterns. These are heuristics, not a guarantee — they exist to catch
# accidental leakage of key/token-like strings even when the caller didn't know to flag them.
_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._-]{8,}\b", re.IGNORECASE),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    re.compile(r"\b[A-Za-z0-9_-]{32,}\b"),
)


def redact_text(text: str, *, extra_markers: Sequence[str] = ()) -> str:
    """Redact secret-shaped substrings and any explicitly known markers in `text`."""
    if not text:
        return text

    redacted = text
    for marker in extra_markers:
        if marker:
            redacted = redacted.replace(marker, _REDACTED)

    for pattern in _PATTERNS:
        redacted = pattern.sub(_REDACTED, redacted)

    return redacted


def redact_value(value: Any, *, extra_markers: Sequence[str] = ()) -> Any:
    """Recursively redact strings nested in dicts/lists/tuples; pass other types through."""
    if isinstance(value, str):
        return redact_text(value, extra_markers=extra_markers)
    if isinstance(value, Mapping):
        return {k: redact_value(v, extra_markers=extra_markers) for k, v in value.items()}
    if isinstance(value, list | tuple):
        redacted_items = [redact_value(v, extra_markers=extra_markers) for v in value]
        return type(value)(redacted_items) if isinstance(value, tuple) else redacted_items
    return value
