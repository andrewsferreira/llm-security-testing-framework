"""Optional adapter that speaks a real LLM provider's native chat API directly.

Entirely optional — never required to use this framework. Only used when
`target.type: provider` is set in a config file, and only works if the corresponding API key
env var is set (`auth_token_env`, e.g. OPENAI_API_KEY or ANTHROPIC_API_KEY). No provider SDK is
required: requests are made directly with httpx. Pointing this at a provider's public API also
requires `security.allow_external_targets: true`, since api.openai.com / api.anthropic.com are
not local/private hosts (see llmsec.utils.url_safety).

`document`/`tool` conversation turns (used to simulate indirect prompt injection) have no
native equivalent in these APIs' message roles, so they are sent as user messages labeled
"[DOCUMENT CONTENT]" / "[TOOL CONTENT]" — a reasonable but lossy approximation, documented here
rather than left implicit.
"""

from __future__ import annotations

import os
import time
from typing import Any

import httpx

from llmsec.constants import MAX_HTTP_REDIRECTS, MAX_RESPONSE_BYTES
from llmsec.exceptions import TargetError
from llmsec.models.target import ProviderTargetConfig
from llmsec.targets.base import Endpoint, HistoryTurn, Target, TargetResponse
from llmsec.utils.url_safety import validate_target_url

_ANTHROPIC_VERSION = "2023-06-01"
_DEFAULT_MAX_TOKENS = 1024


def _label_turn(turn: HistoryTurn) -> dict[str, str]:
    if turn.role == "user":
        return {"role": "user", "content": turn.content}
    return {"role": "user", "content": f"[{turn.role.upper()} CONTENT]\n{turn.content}"}


class ProviderAdapterTarget(Target[ProviderTargetConfig]):
    def __init__(
        self,
        config: ProviderTargetConfig,
        *,
        allow_external: bool,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """`transport` is a testing hook (e.g. httpx.MockTransport); production callers
        should leave it unset so httpx uses a real network transport.

        `provider`/`model`/`auth_token_env` being set is guaranteed by
        `ProviderTargetConfig`'s schema (see models/target.py) — nothing to re-check here.
        The one thing the schema can't guarantee is that the *environment variable itself* is
        actually set at runtime, which is checked below.
        """
        super().__init__(config)
        self._api_key = os.environ.get(config.auth_token_env)
        if not self._api_key:
            raise TargetError(
                f"Environment variable {config.auth_token_env!r} is not set; cannot call "
                f"the {config.provider} API."
            )

        self._allow_external = allow_external
        validate_target_url(config.base_url, allow_external=allow_external)

        self._client = httpx.AsyncClient(
            timeout=config.timeout_seconds,
            max_redirects=MAX_HTTP_REDIRECTS,
            transport=transport,
        )

    async def send(
        self, *, endpoint: Endpoint, prompt: str, history: list[HistoryTurn] | None = None
    ) -> TargetResponse:
        validate_target_url(self.config.base_url, allow_external=self._allow_external)
        messages = [_label_turn(turn) for turn in (history or [])] + [
            {"role": "user", "content": prompt}
        ]

        if self.config.provider == "openai":
            url, headers, body = self._openai_request(messages)
        else:
            url, headers, body = self._anthropic_request(messages)

        started = time.monotonic()
        try:
            response = await self._client.post(url, headers=headers, json=body)
        except httpx.TimeoutException as exc:
            raise TargetError(
                f"Request to {url} timed out after {self.config.timeout_seconds}s"
            ) from exc
        except httpx.HTTPError as exc:
            raise TargetError(f"Request to {url} failed: {exc}") from exc
        latency_ms = (time.monotonic() - started) * 1000

        if response.status_code >= 400:
            raise TargetError(f"{self.config.provider} API returned HTTP {response.status_code}")

        data: Any = httpx.Response(200, content=response.content[:MAX_RESPONSE_BYTES]).json()
        text = self._extract_text(data)

        return TargetResponse(
            text=text, raw=data, latency_ms=latency_ms, status_code=response.status_code
        )

    def _openai_request(
        self, messages: list[dict[str, str]]
    ) -> tuple[str, dict[str, str], dict[str, Any]]:
        url = self.config.endpoint_url("/v1/chat/completions")
        headers = {"Authorization": f"Bearer {self._api_key}"}
        full_messages = messages
        if self.config.system_prompt:
            full_messages = [{"role": "system", "content": self.config.system_prompt}] + messages
        body = {"model": self.config.model, "messages": full_messages}
        return url, headers, body

    def _anthropic_request(
        self, messages: list[dict[str, str]]
    ) -> tuple[str, dict[str, str], dict[str, Any]]:
        url = self.config.endpoint_url("/v1/messages")
        headers = {
            "x-api-key": self._api_key or "",
            "anthropic-version": _ANTHROPIC_VERSION,
        }
        body: dict[str, Any] = {
            "model": self.config.model,
            "max_tokens": _DEFAULT_MAX_TOKENS,
            "messages": messages,
        }
        if self.config.system_prompt:
            body["system"] = self.config.system_prompt
        return url, headers, body

    def _extract_text(self, data: dict[str, Any]) -> str:
        try:
            if self.config.provider == "openai":
                text = data["choices"][0]["message"]["content"]
            else:
                text = data["content"][0]["text"]
        except (KeyError, IndexError, TypeError) as exc:
            raise TargetError(
                f"Could not parse a reply out of the {self.config.provider} API response."
            ) from exc
        if not isinstance(text, str):
            raise TargetError(f"{self.config.provider} API reply was not a string.")
        return text

    async def aclose(self) -> None:
        await self._client.aclose()
