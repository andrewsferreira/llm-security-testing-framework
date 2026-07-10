"""Structured JSON logging.

Log records carry campaign_id/test_id/category/target/status/latency/error_type as structured
fields (never raw secrets). Never pass unredacted request/response content into log calls —
use llmsec.utils.redaction first.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

_CONTEXT_FIELDS = (
    "campaign_id",
    "test_id",
    "category",
    "target",
    "status",
    "latency_ms",
    "error_type",
)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in _CONTEXT_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: int = logging.INFO, *, json_output: bool = True) -> None:
    """Configure the "llmsec" logger tree. Safe to call more than once (idempotent)."""
    root = logging.getLogger("llmsec")
    root.setLevel(level)
    root.handlers.clear()

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(JsonFormatter() if json_output else logging.Formatter("%(message)s"))
    root.addHandler(handler)
    root.propagate = False


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"llmsec.{name}")


def bind_context(logger: logging.Logger, **context: Any) -> logging.LoggerAdapter[Any]:
    """Return a LoggerAdapter that merges `context` into every record's `extra`."""
    return logging.LoggerAdapter(logger, extra=context)
