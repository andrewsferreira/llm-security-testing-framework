"""Abstract interface every target adapter implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from llmsec.models.target import TargetConfig

Endpoint = Literal["chat", "agent", "rag"]


class HistoryTurn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["user", "tool", "document"]
    content: str


class TargetResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str
    raw: dict[str, Any] | str | None = None
    latency_ms: float
    status_code: int | None = None


class Target(ABC):
    """Sends a prompt (optionally with prior turns) to a target and returns its reply."""

    def __init__(self, config: TargetConfig) -> None:
        self.config = config

    @abstractmethod
    async def send(
        self, *, endpoint: Endpoint, prompt: str, history: list[HistoryTurn] | None = None
    ) -> TargetResponse: ...

    async def aclose(self) -> None:
        """Release any held resources (connections, etc.). Default: no-op."""
        return None

    async def __aenter__(self) -> Target:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()
