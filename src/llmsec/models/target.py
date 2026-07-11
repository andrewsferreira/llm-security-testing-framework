"""Typed models describing the target under test.

`TargetConfig` is a discriminated union on `type`, not one flat model with every target type's
fields bolted on — each target type only carries the fields it actually uses. A flat model
looked fine with 2-3 target types; it stops scaling the moment more provider integrations are
added (see docs/architecture-review.md, "TargetConfig is a flat field bag").
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class TargetType(StrEnum):
    GENERIC_HTTP = "generic_http"
    MOCK = "mock"
    PROVIDER = "provider"


ProviderName = Literal["openai", "anthropic"]


class BaseTargetConfig(BaseModel):
    """Fields every target type needs, regardless of how it actually reaches the target."""

    model_config = ConfigDict(extra="forbid")

    base_url: str = Field(min_length=1)
    timeout_seconds: float = Field(default=10.0, gt=0)
    headers: dict[str, str] = Field(default_factory=dict)
    auth_token_env: str | None = None

    def endpoint_url(self, endpoint: str) -> str:
        return f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"


class GenericHttpTargetConfig(BaseTargetConfig):
    """The default target type: POSTs a small, configurable JSON envelope to your own HTTP API.

    See targets/generic_http.py and docs/target-integration.md.
    """

    type: Literal[TargetType.GENERIC_HTTP] = TargetType.GENERIC_HTTP
    chat_endpoint: str = "/chat"
    agent_endpoint: str = "/agent"
    rag_endpoint: str = "/rag"
    request_field: str = "message"
    response_field: str = "reply"
    history_field: str = "history"


class MockTargetConfig(BaseTargetConfig):
    """In-process target used by this repository's own fast tests; see targets/mock_target.py.

    Not something an external `pip install llmsec` can rely on unless the lab/ package is
    present alongside it.
    """

    type: Literal[TargetType.MOCK] = TargetType.MOCK


class ProviderTargetConfig(BaseTargetConfig):
    """Speaks a real LLM provider's native chat API directly; see targets/provider_adapter.py.

    Entirely optional — never required to use this framework — and only reachable when
    `type: provider` is explicitly configured with an env var holding that provider's API key.
    """

    type: Literal[TargetType.PROVIDER] = TargetType.PROVIDER
    provider: ProviderName
    model: str
    system_prompt: str | None = None
    # Required (not the optional inherited default): a provider target is useless without a
    # credential source, so this fails at config-validation time rather than at first request.
    auth_token_env: str = Field(min_length=1)


TargetConfig = Annotated[
    GenericHttpTargetConfig | MockTargetConfig | ProviderTargetConfig,
    Field(discriminator="type"),
]
