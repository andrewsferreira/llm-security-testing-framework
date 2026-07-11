"""Target adapter that speaks the framework's own simple JSON envelope over HTTP.

POSTs `{request_field: prompt, history_field: [...]}}` to the configured endpoint and reads the
reply out of `response_field` (a dot path, e.g. "data.reply") in the JSON response. See
docs/target-integration.md for adapting a real API to this shape, or use
targets/provider_adapter.py to speak a real provider's native API instead.
"""

from __future__ import annotations

import os
import time
from typing import Any

import httpx

from llmsec.constants import MAX_HTTP_REDIRECTS, MAX_RESPONSE_BYTES
from llmsec.exceptions import TargetError
from llmsec.models.target import GenericHttpTargetConfig
from llmsec.targets.base import Endpoint, HistoryTurn, Target, TargetResponse
from llmsec.utils.url_safety import validate_target_url


def _extract_field(data: Any, dotted_path: str) -> str:
    current = data
    for part in dotted_path.split("."):
        if isinstance(current, dict):
            if part not in current:
                raise TargetError(f"Response field {dotted_path!r} not found in target response.")
            current = current[part]
        elif isinstance(current, list):
            try:
                index = int(part)
            except ValueError as exc:
                raise TargetError(
                    f"Response field {dotted_path!r} expected a list index at {part!r}."
                ) from exc
            try:
                current = current[index]
            except IndexError as exc:
                raise TargetError(
                    f"Response field {dotted_path!r}: index {index} out of range."
                ) from exc
        else:
            raise TargetError(f"Response field {dotted_path!r} could not be resolved.")
    if not isinstance(current, str):
        raise TargetError(f"Response field {dotted_path!r} did not resolve to a string.")
    return current


class GenericHttpTarget(Target[GenericHttpTargetConfig]):
    def __init__(
        self,
        config: GenericHttpTargetConfig,
        *,
        allow_external: bool,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """`transport` is a testing hook (e.g. httpx.MockTransport/ASGITransport); production
        callers should leave it unset so httpx uses a real network transport."""
        super().__init__(config)
        self._allow_external = allow_external
        validate_target_url(config.base_url, allow_external=allow_external)

        headers = dict(config.headers)
        if config.auth_token_env:
            token = os.environ.get(config.auth_token_env)
            if token:
                headers.setdefault("Authorization", f"Bearer {token}")

        self._client = httpx.AsyncClient(
            timeout=config.timeout_seconds,
            max_redirects=MAX_HTTP_REDIRECTS,
            headers=headers,
            transport=transport,
        )

    def _endpoint_path(self, endpoint: Endpoint) -> str:
        return {
            "chat": self.config.chat_endpoint,
            "agent": self.config.agent_endpoint,
            "rag": self.config.rag_endpoint,
        }[endpoint]

    async def send(
        self, *, endpoint: Endpoint, prompt: str, history: list[HistoryTurn] | None = None
    ) -> TargetResponse:
        url = self.config.endpoint_url(self._endpoint_path(endpoint))
        validate_target_url(url, allow_external=self._allow_external)

        payload = {
            self.config.request_field: prompt,
            self.config.history_field: [turn.model_dump() for turn in (history or [])],
        }

        started = time.monotonic()
        try:
            response = await self._client.post(url, json=payload)
        except httpx.TimeoutException as exc:
            raise TargetError(
                f"Request to {url} timed out after {self.config.timeout_seconds}s"
            ) from exc
        except httpx.HTTPError as exc:
            raise TargetError(f"Request to {url} failed: {exc}") from exc
        latency_ms = (time.monotonic() - started) * 1000

        for hop in (*response.history, response):
            validate_target_url(str(hop.url), allow_external=self._allow_external)

        if response.status_code >= 400:
            raise TargetError(f"Target {url} returned HTTP {response.status_code}")

        body = response.content[:MAX_RESPONSE_BYTES]
        content_type = response.headers.get("content-type", "")
        data: Any
        if "application/json" in content_type:
            try:
                data = httpx.Response(200, content=body).json()
            except ValueError as exc:
                raise TargetError(f"Target {url} returned invalid JSON.") from exc
        else:
            data = body.decode("utf-8", errors="replace")

        text = _extract_field(data, self.config.response_field) if isinstance(data, dict) else data

        return TargetResponse(
            text=text,
            raw=data,
            latency_ms=latency_ms,
            status_code=response.status_code,
        )

    async def aclose(self) -> None:
        await self._client.aclose()
