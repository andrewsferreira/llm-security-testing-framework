"""Shared contract, run uniformly against all 8 supported providers: a provider adapter's raw
credential is used to authenticate the outgoing request and nothing else — it must never show
up in the parsed response the rest of the framework persists (TargetResponse.raw/.text, which
flow straight into TestResult/reports via core/evidence.py) and it must never be logged.

This is a regression guard rather than a bug-detection test today (no provider adapter
currently logs request/response content at all) — its job is to make sure a future change to
provider_adapter.py can't silently start leaking a secret into a log line or into evidence.
"""

from __future__ import annotations

import json
import logging

import httpx
import pytest

from llmsec.models.target import ProviderName, ProviderTargetConfig
from llmsec.targets.provider_adapter import ProviderAdapterTarget

_SECRET_ENV_VAR = "CONTRACT_TEST_SECRET"
_ACCESS_KEY_ID_ENV_VAR = "CONTRACT_TEST_ACCESS_KEY_ID"
_SECRET_VALUE = "SUPER-SECRET-DO-NOT-LEAK-9f8e7d6c"
_ACCESS_KEY_ID_VALUE = "AKIAFAKEACCESSKEYID9F8E"

_BASE_URLS: dict[ProviderName, str] = {
    "openai": "https://api.openai.com",
    "anthropic": "https://api.anthropic.com",
    "gemini": "https://generativelanguage.googleapis.com",
    "azure_openai": "https://my-resource.openai.azure.com",
    "ollama": "http://localhost:11434",
    "mistral": "https://api.mistral.ai",
    "openrouter": "https://openrouter.ai/api/v1",
    "bedrock": "https://bedrock-runtime.us-east-1.amazonaws.com",
}

_SUCCESS_BODY_BY_PROVIDER: dict[ProviderName, dict[str, object]] = {
    "openai": {"choices": [{"message": {"content": "ok"}}]},
    "anthropic": {"content": [{"text": "ok"}]},
    "gemini": {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]},
    "azure_openai": {"choices": [{"message": {"content": "ok"}}]},
    "ollama": {"message": {"content": "ok"}},
    "mistral": {"choices": [{"message": {"content": "ok"}}]},
    "openrouter": {"choices": [{"message": {"content": "ok"}}]},
    "bedrock": {"output": {"message": {"content": [{"text": "ok"}]}}},
}


def _config_for(provider: ProviderName) -> ProviderTargetConfig:
    kwargs: dict[str, object] = {
        "base_url": _BASE_URLS[provider],
        "provider": provider,
        "model": "test-model",
        "auth_token_env": _SECRET_ENV_VAR,
    }
    if provider == "bedrock":
        kwargs["aws_access_key_id_env"] = _ACCESS_KEY_ID_ENV_VAR
        kwargs["aws_region"] = "us-east-1"
    return ProviderTargetConfig(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("provider", sorted(_SUCCESS_BODY_BY_PROVIDER))
async def test_provider_never_logs_or_persists_its_raw_credential(
    provider: ProviderName,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv(_SECRET_ENV_VAR, _SECRET_VALUE)
    monkeypatch.setenv(_ACCESS_KEY_ID_ENV_VAR, _ACCESS_KEY_ID_VALUE)

    sent_header_values: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent_header_values.extend(request.headers.values())
        return httpx.Response(200, json=_SUCCESS_BODY_BY_PROVIDER[provider])

    config = _config_for(provider)
    caplog.set_level(logging.DEBUG)
    target = ProviderAdapterTarget(
        config, allow_external=True, transport=httpx.MockTransport(handler)
    )
    response = await target.send(endpoint="chat", prompt="hello")

    # Sanity check: the credential really was used to authenticate (this test would be vacuous
    # otherwise). Every provider except ollama requires it. Bedrock is the one exception to
    # "sent verbatim": SigV4 signing means the secret itself never goes over the wire, only a
    # derived HMAC signature — so its sanity check looks for that signature instead.
    if provider == "bedrock":
        assert any("Signature=" in value for value in sent_header_values)
    elif provider != "ollama":
        assert any(_SECRET_VALUE in value for value in sent_header_values)

    raw_repr = json.dumps(response.raw) if response.raw is not None else ""
    assert _SECRET_VALUE not in response.text
    assert _SECRET_VALUE not in raw_repr

    for record in caplog.records:
        message = record.getMessage()
        assert _SECRET_VALUE not in message
        assert _ACCESS_KEY_ID_VALUE not in message

    await target.aclose()
