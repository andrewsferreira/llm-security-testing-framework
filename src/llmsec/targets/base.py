"""Abstract interface every target adapter implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from llmsec.models.target import BaseTargetConfig

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


class Target[TConfig: BaseTargetConfig](ABC):
    """Sends a prompt (optionally with prior turns) to a target and returns its reply.

    Generic over its config type (`TConfig`, bound to `BaseTargetConfig`) so each concrete
    target — `GenericHttpTarget`, `MockTarget`, `ProviderAdapterTarget` — gets its own config
    subtype narrowed on `self.config`, rather than every target seeing the full discriminated
    union and needing runtime `isinstance`/`match` checks to use its own fields.
    """

    def __init__(self, config: TConfig) -> None:
        self.config: TConfig = config

    @abstractmethod
    async def send(
        self, *, endpoint: Endpoint, prompt: str, history: list[HistoryTurn] | None = None
    ) -> TargetResponse: ...

    async def aclose(self) -> None:
        """Release any held resources (connections, etc.). Default: no-op."""
        return None

    async def __aenter__(self) -> Target[TConfig]:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()
