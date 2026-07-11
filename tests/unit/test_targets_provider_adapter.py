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


async def test_gemini_request_shape_and_response_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_GEMINI_KEY", "secret")
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["api_key_header"] = request.headers.get("x-goog-api-key")
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200, json={"candidates": [{"content": {"parts": [{"text": "hi gemini"}]}}]}
        )

    config = ProviderTargetConfig(
        base_url="https://generativelanguage.googleapis.com",
        provider="gemini",
        model="gemini-1.5-flash",
        auth_token_env="TEST_GEMINI_KEY",
    )
    target = ProviderAdapterTarget(
        config, allow_external=True, transport=httpx.MockTransport(handler)
    )
    response = await target.send(endpoint="chat", prompt="hello")

    assert response.text == "hi gemini"
    assert captured["api_key_header"] == "secret"
    assert str(captured["url"]).endswith(":generateContent")
    body = captured["body"]
    assert isinstance(body, dict)
    assert body["contents"][-1] == {"role": "user", "parts": [{"text": "hello"}]}
    await target.aclose()


async def test_azure_openai_request_shape_and_response_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEST_AZURE_KEY", "secret")
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["api_key_header"] = request.headers.get("api-key")
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "hi azure"}}]})

    config = ProviderTargetConfig(
        base_url="https://my-resource.openai.azure.com",
        provider="azure_openai",
        model="my-gpt4o-deployment",
        auth_token_env="TEST_AZURE_KEY",
        api_version="2024-05-01-preview",
    )
    target = ProviderAdapterTarget(
        config, allow_external=True, transport=httpx.MockTransport(handler)
    )
    response = await target.send(endpoint="chat", prompt="hello")

    assert response.text == "hi azure"
    assert captured["api_key_header"] == "secret"
    url = str(captured["url"])
    assert "/openai/deployments/my-gpt4o-deployment/chat/completions" in url
    assert "api-version=2024-05-01-preview" in url
    body = captured["body"]
    assert isinstance(body, dict)
    assert "model" not in body  # Azure addresses the model via the deployment in the URL
    await target.aclose()


async def test_ollama_request_without_auth_env_var_omits_authorization_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TEST_OLLAMA_KEY", raising=False)
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"message": {"content": "hi ollama"}})

    config = ProviderTargetConfig(
        base_url="http://localhost:11434",
        provider="ollama",
        model="llama3",
        auth_token_env="TEST_OLLAMA_KEY",
    )
    # A missing env var is NOT a TargetError for ollama, unlike every other provider.
    target = ProviderAdapterTarget(
        config, allow_external=False, transport=httpx.MockTransport(handler)
    )
    response = await target.send(endpoint="chat", prompt="hello")

    assert response.text == "hi ollama"
    assert captured["auth"] is None
    body = captured["body"]
    assert isinstance(body, dict)
    assert body["stream"] is False
    await target.aclose()


async def test_ollama_request_includes_auth_header_when_env_var_is_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEST_OLLAMA_KEY", "secret")
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"message": {"content": "hi"}})

    config = ProviderTargetConfig(
        base_url="http://localhost:11434",
        provider="ollama",
        model="llama3",
        auth_token_env="TEST_OLLAMA_KEY",
    )
    target = ProviderAdapterTarget(
        config, allow_external=False, transport=httpx.MockTransport(handler)
    )
    await target.send(endpoint="chat", prompt="hello")

    assert captured["auth"] == "Bearer secret"
    await target.aclose()


async def test_mistral_request_shape_and_response_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEST_MISTRAL_KEY", "secret")
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"choices": [{"message": {"content": "hi mistral"}}]})

    config = ProviderTargetConfig(
        base_url="https://api.mistral.ai",
        provider="mistral",
        model="mistral-large-latest",
        auth_token_env="TEST_MISTRAL_KEY",
    )
    target = ProviderAdapterTarget(
        config, allow_external=True, transport=httpx.MockTransport(handler)
    )
    response = await target.send(endpoint="chat", prompt="hello")

    assert response.text == "hi mistral"
    assert captured["auth"] == "Bearer secret"
    assert str(captured["url"]).endswith("/v1/chat/completions")
    await target.aclose()


async def test_openrouter_request_shape_and_response_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEST_OPENROUTER_KEY", "secret")
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"choices": [{"message": {"content": "hi openrouter"}}]})

    config = ProviderTargetConfig(
        base_url="https://openrouter.ai/api/v1",
        provider="openrouter",
        model="openai/gpt-4o-mini",
        auth_token_env="TEST_OPENROUTER_KEY",
    )
    target = ProviderAdapterTarget(
        config, allow_external=True, transport=httpx.MockTransport(handler)
    )
    response = await target.send(endpoint="chat", prompt="hello")

    assert response.text == "hi openrouter"
    assert captured["auth"] == "Bearer secret"
    assert str(captured["url"]).endswith("/chat/completions")
    await target.aclose()


def test_schema_requires_aws_access_key_id_env_for_bedrock() -> None:
    with pytest.raises(ValidationError, match="aws_access_key_id_env"):
        ProviderTargetConfig(
            base_url="https://bedrock-runtime.us-east-1.amazonaws.com",
            provider="bedrock",
            model="anthropic.claude-3-haiku-20240307-v1:0",
            auth_token_env="TEST_AWS_SECRET",
        )


def test_bedrock_missing_aws_credentials_raises_target_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MISSING_AWS_SECRET", raising=False)
    monkeypatch.delenv("MISSING_AWS_ACCESS_KEY_ID", raising=False)
    config = ProviderTargetConfig(
        base_url="https://bedrock-runtime.us-east-1.amazonaws.com",
        provider="bedrock",
        model="anthropic.claude-3-haiku-20240307-v1:0",
        auth_token_env="MISSING_AWS_SECRET",
        aws_access_key_id_env="MISSING_AWS_ACCESS_KEY_ID",
    )
    with pytest.raises(TargetError, match="AWS credentials"):
        ProviderAdapterTarget(config, allow_external=True)


async def test_bedrock_request_is_sigv4_signed_and_response_parsed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEST_AWS_SECRET", "secretkey")
    monkeypatch.setenv("TEST_AWS_ACCESS_KEY_ID", "AKIAFAKEACCESSKEYID")
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers.get("authorization")
        captured["amz_date"] = request.headers.get("x-amz-date")
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200, json={"output": {"message": {"content": [{"text": "hi bedrock"}]}}}
        )

    config = ProviderTargetConfig(
        base_url="https://bedrock-runtime.us-east-1.amazonaws.com",
        provider="bedrock",
        model="anthropic.claude-3-haiku-20240307-v1:0",
        auth_token_env="TEST_AWS_SECRET",
        aws_access_key_id_env="TEST_AWS_ACCESS_KEY_ID",
        aws_region="us-east-1",
    )
    target = ProviderAdapterTarget(
        config, allow_external=True, transport=httpx.MockTransport(handler)
    )
    response = await target.send(endpoint="chat", prompt="hello")

    assert response.text == "hi bedrock"
    auth = str(captured["auth"])
    assert auth.startswith("AWS4-HMAC-SHA256 Credential=AKIAFAKEACCESSKEYID/")
    assert "SignedHeaders=" in auth
    assert "Signature=" in auth
    assert captured["amz_date"]
    body = captured["body"]
    assert isinstance(body, dict)
    assert body["messages"][-1]["content"][0]["text"] == "hello"
    await target.aclose()
