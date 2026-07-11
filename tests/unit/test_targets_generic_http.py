import json

import httpx
import pytest

from llmsec.exceptions import TargetError, UnsafeTargetError
from llmsec.models.target import GenericHttpTargetConfig
from llmsec.targets.base import HistoryTurn
from llmsec.targets.generic_http import GenericHttpTarget


async def test_send_extracts_reply_field() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/chat"
        return httpx.Response(200, json={"reply": "hello"})

    config = GenericHttpTargetConfig(base_url="http://localhost:8000")
    target = GenericHttpTarget(config, allow_external=False, transport=httpx.MockTransport(handler))
    response = await target.send(endpoint="chat", prompt="hi")
    assert response.text == "hello"
    assert response.status_code == 200
    await target.aclose()


async def test_send_extracts_nested_dot_path_field() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"reply": "nested"}})

    config = GenericHttpTargetConfig(base_url="http://localhost:8000", response_field="data.reply")
    target = GenericHttpTarget(config, allow_external=False, transport=httpx.MockTransport(handler))
    response = await target.send(endpoint="chat", prompt="hi")
    assert response.text == "nested"
    await target.aclose()


async def test_send_raises_on_missing_response_field() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "shape"})

    config = GenericHttpTargetConfig(base_url="http://localhost:8000")
    target = GenericHttpTarget(config, allow_external=False, transport=httpx.MockTransport(handler))
    with pytest.raises(TargetError, match="not found"):
        await target.send(endpoint="chat", prompt="hi")
    await target.aclose()


async def test_send_raises_target_error_on_http_error_status() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"reply": "boom"})

    config = GenericHttpTargetConfig(base_url="http://localhost:8000")
    target = GenericHttpTarget(config, allow_external=False, transport=httpx.MockTransport(handler))
    with pytest.raises(TargetError, match="500"):
        await target.send(endpoint="chat", prompt="hi")
    await target.aclose()


async def test_send_sends_history_and_request_field() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"reply": "ok"})

    config = GenericHttpTargetConfig(base_url="http://localhost:8000")
    target = GenericHttpTarget(config, allow_external=False, transport=httpx.MockTransport(handler))

    await target.send(
        endpoint="rag", prompt="hi", history=[HistoryTurn(role="document", content="doc content")]
    )
    body = captured["body"]
    assert isinstance(body, dict)
    assert body["message"] == "hi"
    assert body["history"] == [{"role": "document", "content": "doc content"}]
    await target.aclose()


def test_constructor_rejects_unsafe_external_target() -> None:
    config = GenericHttpTargetConfig(base_url="http://example.com")
    with pytest.raises(UnsafeTargetError):
        GenericHttpTarget(config, allow_external=False)


async def test_send_raises_target_error_on_timeout() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("simulated timeout")

    config = GenericHttpTargetConfig(base_url="http://localhost:8000")
    target = GenericHttpTarget(config, allow_external=False, transport=httpx.MockTransport(handler))
    with pytest.raises(TargetError, match="timed out"):
        await target.send(endpoint="chat", prompt="hi")
    await target.aclose()


async def test_send_extracts_field_through_a_list_index() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "openai-style reply"}}]}
        )

    config = GenericHttpTargetConfig(
        base_url="http://localhost:8000", response_field="choices.0.message.content"
    )
    target = GenericHttpTarget(config, allow_external=False, transport=httpx.MockTransport(handler))
    response = await target.send(endpoint="chat", prompt="hi")
    assert response.text == "openai-style reply"
    await target.aclose()


async def test_send_raises_on_out_of_range_list_index() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": []})

    config = GenericHttpTargetConfig(
        base_url="http://localhost:8000", response_field="choices.0.content"
    )
    target = GenericHttpTarget(config, allow_external=False, transport=httpx.MockTransport(handler))
    with pytest.raises(TargetError, match="out of range"):
        await target.send(endpoint="chat", prompt="hi")
    await target.aclose()


async def test_send_raises_when_path_segment_is_not_a_valid_list_index() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": ["not-a-dict"]})

    config = GenericHttpTargetConfig(
        base_url="http://localhost:8000", response_field="choices.first"
    )
    target = GenericHttpTarget(config, allow_external=False, transport=httpx.MockTransport(handler))
    with pytest.raises(TargetError, match="expected a list index"):
        await target.send(endpoint="chat", prompt="hi")
    await target.aclose()


async def test_send_raises_when_response_field_resolves_to_non_string() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"reply": {"nested": "not-a-string"}})

    config = GenericHttpTargetConfig(base_url="http://localhost:8000")
    target = GenericHttpTarget(config, allow_external=False, transport=httpx.MockTransport(handler))
    with pytest.raises(TargetError, match="did not resolve to a string"):
        await target.send(endpoint="chat", prompt="hi")
    await target.aclose()


async def test_send_raises_on_invalid_json_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=b"not json", headers={"content-type": "application/json"}
        )

    config = GenericHttpTargetConfig(base_url="http://localhost:8000")
    target = GenericHttpTarget(config, allow_external=False, transport=httpx.MockTransport(handler))
    with pytest.raises(TargetError, match="invalid JSON"):
        await target.send(endpoint="chat", prompt="hi")
    await target.aclose()


async def test_send_returns_raw_text_for_non_json_content_type() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=b"plain text reply", headers={"content-type": "text/plain"}
        )

    config = GenericHttpTargetConfig(base_url="http://localhost:8000")
    target = GenericHttpTarget(config, allow_external=False, transport=httpx.MockTransport(handler))
    response = await target.send(endpoint="chat", prompt="hi")
    assert response.text == "plain text reply"
    await target.aclose()
