"""An in-process fake responder used by fast unit/integration tests of the engine.

Delegates directly to lab.app.agent.generate_reply (the same rule-based simulator behind the
lab FastAPI app) without any HTTP round-trip, so the test suite doesn't need a running server.
This target type is a development convenience for this repository, not something an external
llmsec install can rely on unless the lab/ package is present alongside it.
"""

from __future__ import annotations

import time
from typing import Any

from llmsec.exceptions import TargetError
from llmsec.models.target import TargetConfig
from llmsec.targets.base import Endpoint, HistoryTurn, Target, TargetResponse


class MockTarget(Target):
    def __init__(self, config: TargetConfig, *, mode: str = "vulnerable") -> None:
        super().__init__(config)
        self.mode = mode

    async def send(
        self, *, endpoint: Endpoint, prompt: str, history: list[HistoryTurn] | None = None
    ) -> TargetResponse:
        try:
            from lab.app.agent import Message, generate_reply
        except ImportError as exc:
            raise TargetError(
                "The mock target requires this repository's lab/ package, which is not "
                "available in this installation."
            ) from exc

        started = time.monotonic()
        lab_history = [Message(role=turn.role, content=turn.content) for turn in (history or [])]
        reply = generate_reply(
            mode=self.mode, endpoint=endpoint, prompt=prompt, history=lab_history
        )
        latency_ms = (time.monotonic() - started) * 1000

        raw: dict[str, Any] = {
            "tool_calls": [
                {
                    "tool_name": call.tool_name,
                    "arguments": call.arguments,
                    "authorized": call.authorized,
                    "reason": call.reason,
                }
                for call in reply.tool_calls
            ]
        }
        return TargetResponse(text=reply.text, raw=raw, latency_ms=latency_ms, status_code=200)
