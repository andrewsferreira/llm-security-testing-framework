import json

import httpx
import pytest
from pydantic import ValidationError

from llmsec.exceptions import TargetError
from llmsec.models.target import ProviderTargetConfig
from llmsec.targets.base import HistoryTurn
from llmsec.targets.provider_adapter import ProviderAdapterTarget


def _openai_config() -> ProviderTargetConfig:
    return ProviderTargetConfig(
        base_url="https://api.openai.com",
        provider="openai",
        model="gpt-test",
        auth_token_env="TEST_OPENAI_KEY",
    )


def test_schema_requires_provider_field() -> None:
    # provider/model/auth_token_env are required on ProviderTargetConfig (not optional, as they
    # would be on a flat config shared with other target types) — this fails at config
    # construction/validation time, before a ProviderAdapterTarget is ever built.
    with pytest.raises(ValidationError, match="provider"):
        ProviderTargetConfig(base_url="https://api.openai.com", model="x", auth_token_env="K")  # type: ignore[call-arg]


def test_schema_requires_model_field() -> None:
    with pytest.raises(ValidationError, match="model"):
        ProviderTargetConfig(
            base_url="https://api.openai.com", provider="openai", auth_token_env="K"
        )  # type: ignore[call-arg]


def test_schema_requires_non_empty_auth_token_env() -> None:
    with pytest.raises(ValidationError):
        ProviderTargetConfig(
            base_url="https://api.openai.com", provider="openai", model="x", auth_token_env=""
        )


def test_requires_api_key_env_var_to_be_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TEST_OPENAI_KEY", raising=False)
    with pytest.raises(TargetError, match="TEST_OPENAI_KEY"):
        ProviderAdapterTarget(_openai_config(), allow_external=True)


def test_rejects_external_target_without_allow_external(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_OPENAI_KEY", "secret")
    from llmsec.exceptions import UnsafeTargetError

    with pytest.raises(UnsafeTargetError):
        ProviderAdapterTarget(_openai_config(), allow_external=False)


async def test_openai_request_shape_and_response_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_OPENAI_KEY", "secret")
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "hi there"}}]})

    target = ProviderAdapterTarget(
        _openai_config(), allow_external=True, transport=httpx.MockTransport(handler)
    )
    response = await target.send(endpoint="chat", prompt="hello")

    assert response.text == "hi there"
    assert captured["auth"] == "Bearer secret"
    assert str(captured["url"]).endswith("/v1/chat/completions")
    body = captured["body"]
    assert isinstance(body, dict)
    assert body["messages"][-1] == {"role": "user", "content": "hello"}
    await target.aclose()


async def test_anthropic_request_shape_and_response_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEST_ANTHROPIC_KEY", "secret")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("x-api-key") == "secret"
        assert str(request.url).endswith("/v1/messages")
        return httpx.Response(200, json={"content": [{"text": "hi from claude"}]})

    config = ProviderTargetConfig(
        base_url="https://api.anthropic.com",
        provider="anthropic",
        model="claude-test",
        auth_token_env="TEST_ANTHROPIC_KEY",
    )
    target = ProviderAdapterTarget(
        config, allow_external=True, transport=httpx.MockTransport(handler)
    )
    response = await target.send(endpoint="chat", prompt="hello")
    assert response.text == "hi from claude"
    await target.aclose()


async def test_document_turn_is_labeled_as_user_message(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_OPENAI_KEY", "secret")
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    target = ProviderAdapterTarget(
        _openai_config(), allow_external=True, transport=httpx.MockTransport(handler)
    )
    await target.send(
        endpoint="rag",
        prompt="summarize",
        history=[HistoryTurn(role="document", content="doc text")],
    )
    body = captured["body"]
    assert isinstance(body, dict)
    injected_message = body["messages"][0]
    assert injected_message["role"] == "user"
    assert "[DOCUMENT CONTENT]" in injected_message["content"]
    await target.aclose()


async def test_malformed_response_raises_target_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_OPENAI_KEY", "secret")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "shape"})

    target = ProviderAdapterTarget(
        _openai_config(), allow_external=True, transport=httpx.MockTransport(handler)
    )
    with pytest.raises(TargetError, match="Could not parse"):
        await target.send(endpoint="chat", prompt="hello")
    await target.aclose()
