"""Typed model describing the target under test."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class TargetType(StrEnum):
    GENERIC_HTTP = "generic_http"
    MOCK = "mock"
    PROVIDER = "provider"


class TargetConfig(BaseModel):
    """How to talk to the target under test.

    For `generic_http`, the framework POSTs JSON of the shape
    `{request_field: <prompt>, history_field: [...]}}` and reads the reply out of
    `response_field` (a dot path, e.g. "data.reply") in the JSON response. This generic
    envelope keeps target integration simple; see docs/target-integration.md for adapting it
    to a specific API shape, and targets/provider_adapter.py for talking to a real LLM
    provider's own API instead.
    """

    model_config = ConfigDict(extra="forbid")

    type: TargetType = TargetType.GENERIC_HTTP
    base_url: str = Field(min_length=1)
    chat_endpoint: str = "/chat"
    agent_endpoint: str = "/agent"
    rag_endpoint: str = "/rag"
    timeout_seconds: float = Field(default=10.0, gt=0)

    request_field: str = "message"
    response_field: str = "reply"
    history_field: str = "history"

    headers: dict[str, str] = Field(default_factory=dict)
    auth_token_env: str | None = None

    def endpoint_url(self, endpoint: str) -> str:
        return f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
