"""Optional adapter that speaks a real LLM provider's native API directly.

Entirely optional — never required to use this framework. Only used when
`target.type: provider` is set in a config file. No provider SDK is required: every request is
built and sent directly with `httpx` (including AWS SigV4 request signing for `bedrock`, done
by hand with stdlib `hmac`/`hashlib` rather than `boto3`). Pointing this at a provider's public
API also requires `security.allow_external_targets: true` for any non-local `base_url` (see
`llmsec.utils.url_safety`).

Eight providers are supported, each gated on its own credential environment variable(s) (never
required — the framework works with zero providers configured):

- `openai`, `anthropic`, `gemini`, `azure_openai`, `mistral`, `openrouter` — a single API key via
  `auth_token_env`. `TargetError` at construction time if that env var isn't set.
- `ollama` — for a local/self-hosted server, which typically has no auth at all. `auth_token_env`
  is still a required *field* (schema-level, for consistency), but an unset env var is not an
  error for this provider: the request is simply sent without an `Authorization` header. If your
  Ollama sits behind a reverse proxy that does require a bearer token, set the env var and it's
  used.
- `bedrock` — AWS SigV4, which is a different shape of credential entirely (access key ID +
  secret access key, optionally a session token, plus a region) rather than one bearer token.
  `auth_token_env` doubles as the secret access key's env var name; `aws_access_key_id_env`
  (required by the schema when `provider: bedrock`) names the paired access key ID env var.

`document`/`tool` conversation turns (used to simulate indirect prompt injection) have no native
equivalent in any of these APIs' message roles, so they are sent as user messages labeled
"[DOCUMENT CONTENT]" / "[TOOL CONTENT]" — a reasonable but lossy approximation, documented here
rather than left implicit, and applied uniformly across all 8 providers.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from llmsec.constants import MAX_HTTP_REDIRECTS, MAX_RESPONSE_BYTES
from llmsec.exceptions import TargetError
from llmsec.models.target import PROVIDERS_WITHOUT_REQUIRED_AUTH, ProviderTargetConfig
from llmsec.targets.base import Endpoint, HistoryTurn, Target, TargetResponse
from llmsec.utils.url_safety import validate_target_url

_ANTHROPIC_VERSION = "2023-06-01"
_DEFAULT_MAX_TOKENS = 1024
_BEDROCK_SERVICE = "bedrock"


def _label_turn(turn: HistoryTurn) -> dict[str, str]:
    if turn.role == "user":
        return {"role": "user", "content": turn.content}
    return {"role": "user", "content": f"[{turn.role.upper()} CONTENT]\n{turn.content}"}


@dataclass(frozen=True)
class _PreparedRequest:
    """What to send. Exactly one of `json_body`/`content` is set — `content` is used for
    `bedrock`, whose SigV4 signature is computed over the exact request bytes, so those bytes
    must be sent as-is rather than re-serialized by httpx's `json=` shorthand."""

    url: str
    headers: dict[str, str]
    json_body: dict[str, Any] | None = None
    content: bytes | None = None


def _aws_sigv4_headers(
    *,
    method: str,
    url: str,
    region: str,
    access_key_id: str,
    secret_access_key: str,
    session_token: str | None,
    payload: bytes,
) -> dict[str, str]:
    """Signs a request per AWS Signature Version 4 (stdlib-only, no botocore). Handles exactly
    the shape this adapter ever sends: a single POST with a JSON body and no query string."""
    parsed = httpx.URL(url)
    host = parsed.host
    canonical_uri = parsed.path or "/"
    now = datetime.now(UTC)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    payload_hash = hashlib.sha256(payload).hexdigest()
    headers_to_sign = {"content-type": "application/json", "host": host, "x-amz-date": amz_date}
    if session_token:
        headers_to_sign["x-amz-security-token"] = session_token

    signed_header_names = sorted(headers_to_sign)
    canonical_headers = "".join(f"{name}:{headers_to_sign[name]}\n" for name in signed_header_names)
    signed_headers = ";".join(signed_header_names)

    canonical_request = "\n".join(
        [method, canonical_uri, "", canonical_headers, signed_headers, payload_hash]
    )

    credential_scope = f"{date_stamp}/{region}/{_BEDROCK_SERVICE}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ]
    )

    def _hmac(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k_date = _hmac(f"AWS4{secret_access_key}".encode(), date_stamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, _BEDROCK_SERVICE)
    k_signing = _hmac(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key_id}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    headers = {
        "content-type": "application/json",
        "x-amz-date": amz_date,
        "Authorization": authorization,
    }
    if session_token:
        headers["x-amz-security-token"] = session_token
    return headers


def _with_system_prompt(
    messages: list[dict[str, str]], system_prompt: str | None
) -> list[dict[str, str]]:
    if not system_prompt:
        return messages
    return [{"role": "system", "content": system_prompt}, *messages]


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

        Credential resolution is provider-shaped: most providers need one API key
        (`auth_token_env`); `ollama` needs none by default; `bedrock` needs an AWS access key
        ID/secret pair (`aws_access_key_id_env`/`auth_token_env`) plus an optional session
        token. `provider`/`model` being set, and `aws_access_key_id_env` being set when
        `provider == "bedrock"`, are guaranteed by `ProviderTargetConfig`'s schema (see
        models/target.py) — nothing to re-check here. The one thing the schema can't
        guarantee is that the *environment variables themselves* are actually set at runtime,
        which is checked below.
        """
        super().__init__(config)
        self._allow_external = allow_external
        validate_target_url(config.base_url, allow_external=allow_external)

        self._api_key: str | None = None
        self._aws_access_key_id: str | None = None
        self._aws_secret_access_key: str | None = None
        self._aws_session_token: str | None = None

        if config.provider == "bedrock":
            self._aws_access_key_id = os.environ.get(config.aws_access_key_id_env or "")
            self._aws_secret_access_key = os.environ.get(config.auth_token_env)
            if config.aws_session_token_env:
                self._aws_session_token = os.environ.get(config.aws_session_token_env)
            if not self._aws_access_key_id or not self._aws_secret_access_key:
                raise TargetError(
                    f"AWS credentials are not fully set: expected environment variables "
                    f"{config.aws_access_key_id_env!r} and {config.auth_token_env!r} for the "
                    f"bedrock provider."
                )
        else:
            self._api_key = os.environ.get(config.auth_token_env)
            if not self._api_key and config.provider not in PROVIDERS_WITHOUT_REQUIRED_AUTH:
                raise TargetError(
                    f"Environment variable {config.auth_token_env!r} is not set; cannot call "
                    f"the {config.provider} API."
                )

        self._client = httpx.AsyncClient(
            timeout=config.timeout_seconds,
            max_redirects=MAX_HTTP_REDIRECTS,
            headers=dict(config.headers),
            transport=transport,
        )

    async def send(
        self, *, endpoint: Endpoint, prompt: str, history: list[HistoryTurn] | None = None
    ) -> TargetResponse:
        validate_target_url(self.config.base_url, allow_external=self._allow_external)
        messages = [_label_turn(turn) for turn in (history or [])] + [
            {"role": "user", "content": prompt}
        ]

        prepared = _BUILDERS[self.config.provider](self, messages)

        started = time.monotonic()
        try:
            if prepared.content is not None:
                response = await self._client.post(
                    prepared.url, headers=prepared.headers, content=prepared.content
                )
            else:
                response = await self._client.post(
                    prepared.url, headers=prepared.headers, json=prepared.json_body
                )
        except httpx.TimeoutException as exc:
            raise TargetError(
                f"Request to {prepared.url} timed out after {self.config.timeout_seconds}s"
            ) from exc
        except httpx.HTTPError as exc:
            raise TargetError(f"Request to {prepared.url} failed: {exc}") from exc
        latency_ms = (time.monotonic() - started) * 1000

        if response.status_code >= 400:
            raise TargetError(f"{self.config.provider} API returned HTTP {response.status_code}")

        data: Any = httpx.Response(200, content=response.content[:MAX_RESPONSE_BYTES]).json()
        text = _EXTRACTORS[self.config.provider](data, self.config.provider)

        return TargetResponse(
            text=text, raw=data, latency_ms=latency_ms, status_code=response.status_code
        )

    def _openai_request(self, messages: list[dict[str, str]]) -> _PreparedRequest:
        url = self.config.endpoint_url("/v1/chat/completions")
        headers = {"Authorization": f"Bearer {self._api_key}"}
        body = {
            "model": self.config.model,
            "messages": _with_system_prompt(messages, self.config.system_prompt),
        }
        return _PreparedRequest(url=url, headers=headers, json_body=body)

    def _anthropic_request(self, messages: list[dict[str, str]]) -> _PreparedRequest:
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
        return _PreparedRequest(url=url, headers=headers, json_body=body)

    def _gemini_request(self, messages: list[dict[str, str]]) -> _PreparedRequest:
        url = self.config.endpoint_url(f"/v1beta/models/{self.config.model}:generateContent")
        headers = {"x-goog-api-key": self._api_key or ""}
        body: dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": m["content"]}]} for m in messages]
        }
        if self.config.system_prompt:
            body["systemInstruction"] = {"parts": [{"text": self.config.system_prompt}]}
        return _PreparedRequest(url=url, headers=headers, json_body=body)

    def _azure_openai_request(self, messages: list[dict[str, str]]) -> _PreparedRequest:
        # Azure addresses models by deployment, not model name — `model` is the deployment name.
        url = self.config.endpoint_url(
            f"/openai/deployments/{self.config.model}/chat/completions"
            f"?api-version={self.config.api_version}"
        )
        headers = {"api-key": self._api_key or ""}
        body = {"messages": _with_system_prompt(messages, self.config.system_prompt)}
        return _PreparedRequest(url=url, headers=headers, json_body=body)

    def _ollama_request(self, messages: list[dict[str, str]]) -> _PreparedRequest:
        headers = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        body = {
            "model": self.config.model,
            "messages": _with_system_prompt(messages, self.config.system_prompt),
            "stream": False,
        }
        return _PreparedRequest(
            url=self.config.endpoint_url("/api/chat"), headers=headers, json_body=body
        )

    def _mistral_request(self, messages: list[dict[str, str]]) -> _PreparedRequest:
        url = self.config.endpoint_url("/v1/chat/completions")
        headers = {"Authorization": f"Bearer {self._api_key}"}
        body = {
            "model": self.config.model,
            "messages": _with_system_prompt(messages, self.config.system_prompt),
        }
        return _PreparedRequest(url=url, headers=headers, json_body=body)

    def _openrouter_request(self, messages: list[dict[str, str]]) -> _PreparedRequest:
        url = self.config.endpoint_url("/chat/completions")
        headers = {"Authorization": f"Bearer {self._api_key}"}
        body = {
            "model": self.config.model,
            "messages": _with_system_prompt(messages, self.config.system_prompt),
        }
        return _PreparedRequest(url=url, headers=headers, json_body=body)

    def _bedrock_request(self, messages: list[dict[str, str]]) -> _PreparedRequest:
        body: dict[str, Any] = {
            "messages": [{"role": "user", "content": [{"text": m["content"]}]} for m in messages]
        }
        if self.config.system_prompt:
            body["system"] = [{"text": self.config.system_prompt}]
        payload = json.dumps(body, separators=(",", ":")).encode()
        url = self.config.endpoint_url(f"/model/{self.config.model}/converse")
        headers = _aws_sigv4_headers(
            method="POST",
            url=url,
            region=self.config.aws_region,
            access_key_id=self._aws_access_key_id or "",
            secret_access_key=self._aws_secret_access_key or "",
            session_token=self._aws_session_token,
            payload=payload,
        )
        return _PreparedRequest(url=url, headers=headers, content=payload)

    async def aclose(self) -> None:
        await self._client.aclose()


def _extract_openai_compatible_text(data: dict[str, Any], provider: str) -> str:
    try:
        text = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise TargetError(f"Could not parse a reply out of the {provider} API response.") from exc
    if not isinstance(text, str):
        raise TargetError(f"{provider} API reply was not a string.")
    return text


def _extract_anthropic_text(data: dict[str, Any], provider: str) -> str:
    try:
        text = data["content"][0]["text"]
    except (KeyError, IndexError, TypeError) as exc:
        raise TargetError(f"Could not parse a reply out of the {provider} API response.") from exc
    if not isinstance(text, str):
        raise TargetError(f"{provider} API reply was not a string.")
    return text


def _extract_gemini_text(data: dict[str, Any], provider: str) -> str:
    try:
        text = data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError) as exc:
        raise TargetError(f"Could not parse a reply out of the {provider} API response.") from exc
    if not isinstance(text, str):
        raise TargetError(f"{provider} API reply was not a string.")
    return text


def _extract_ollama_text(data: dict[str, Any], provider: str) -> str:
    try:
        text = data["message"]["content"]
    except (KeyError, TypeError) as exc:
        raise TargetError(f"Could not parse a reply out of the {provider} API response.") from exc
    if not isinstance(text, str):
        raise TargetError(f"{provider} API reply was not a string.")
    return text


def _extract_bedrock_text(data: dict[str, Any], provider: str) -> str:
    try:
        text = data["output"]["message"]["content"][0]["text"]
    except (KeyError, IndexError, TypeError) as exc:
        raise TargetError(f"Could not parse a reply out of the {provider} API response.") from exc
    if not isinstance(text, str):
        raise TargetError(f"{provider} API reply was not a string.")
    return text


_BUILDERS: dict[str, Callable[[ProviderAdapterTarget, list[dict[str, str]]], _PreparedRequest]] = {
    "openai": ProviderAdapterTarget._openai_request,
    "anthropic": ProviderAdapterTarget._anthropic_request,
    "gemini": ProviderAdapterTarget._gemini_request,
    "azure_openai": ProviderAdapterTarget._azure_openai_request,
    "ollama": ProviderAdapterTarget._ollama_request,
    "mistral": ProviderAdapterTarget._mistral_request,
    "openrouter": ProviderAdapterTarget._openrouter_request,
    "bedrock": ProviderAdapterTarget._bedrock_request,
}

_EXTRACTORS: dict[str, Callable[[dict[str, Any], str], str]] = {
    "openai": _extract_openai_compatible_text,
    "azure_openai": _extract_openai_compatible_text,
    "mistral": _extract_openai_compatible_text,
    "openrouter": _extract_openai_compatible_text,
    "anthropic": _extract_anthropic_text,
    "gemini": _extract_gemini_text,
    "ollama": _extract_ollama_text,
    "bedrock": _extract_bedrock_text,
}
