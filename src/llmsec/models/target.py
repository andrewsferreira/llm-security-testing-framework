"""Typed models describing the target under test.

`TargetConfig` is a discriminated union on `type`, not one flat model with every target type's
fields bolted on — each target type only carries the fields it actually uses. A flat model
looked fine with 2-3 target types; it stops scaling the moment more provider integrations are
added (see docs/architecture-review.md, "TargetConfig is a flat field bag").
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class TargetType(StrEnum):
    GENERIC_HTTP = "generic_http"
    MOCK = "mock"
    PROVIDER = "provider"


ProviderName = Literal[
    "openai",
    "anthropic",
    "gemini",
    "azure_openai",
    "ollama",
    "mistral",
    "bedrock",
    "openrouter",
]

# Providers that don't require a credential at all (a local, unauthenticated Ollama server is
# the common case). Every other provider's `auth_token_env` must resolve to a non-empty
# environment variable at construction time; for these, a missing/unset value is not an error —
# see targets/provider_adapter.py.
PROVIDERS_WITHOUT_REQUIRED_AUTH: frozenset[ProviderName] = frozenset({"ollama"})


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
    # The one exception is `ollama` (see PROVIDERS_WITHOUT_REQUIRED_AUTH) — the env var still
    # must be *named* here, but it's allowed to be unset at runtime for that provider.
    auth_token_env: str = Field(min_length=1)

    # Azure OpenAI only: the REST API version query parameter and the deployment name (Azure
    # addresses models by deployment, not by model name — `model` above is used as the
    # deployment name for this provider).
    api_version: str = "2024-02-15-preview"

    # AWS Bedrock only: request signing is AWS SigV4, not a static bearer/api-key header, so it
    # needs more than the shared `auth_token_env`. `auth_token_env` doubles as the AWS secret
    # access key's env var name for this provider; `aws_access_key_id_env` names the paired
    # access key ID env var. `aws_session_token_env` is optional, for temporary/STS credentials.
    aws_access_key_id_env: str | None = None
    aws_session_token_env: str | None = None
    aws_region: str = "us-east-1"

    @model_validator(mode="after")
    def _bedrock_requires_access_key_id_env(self) -> ProviderTargetConfig:
        if self.provider == "bedrock" and not self.aws_access_key_id_env:
            raise ValueError(
                "aws_access_key_id_env is required when provider is 'bedrock' (in addition to "
                "auth_token_env, which holds the paired AWS secret access key's env var name)."
            )
        return self


TargetConfig = Annotated[
    GenericHttpTargetConfig | MockTargetConfig | ProviderTargetConfig,
    Field(discriminator="type"),
]
