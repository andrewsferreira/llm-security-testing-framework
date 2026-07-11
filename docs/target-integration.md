# Target Integration

llmsec can point at three kinds of target, selected by `target.type` in your config file.

## `generic_http` (the default — works with your own API)

This is what you'll use to scan your own chatbot/agent API. llmsec POSTs a small, fixed JSON
envelope and reads the reply out of a configurable field:

**Request** (to whichever of `chat_endpoint`/`agent_endpoint`/`rag_endpoint` applies):
```json
{
  "message": "<the prompt or the last conversation turn>",
  "history": [
    {"role": "user", "content": "..."},
    {"role": "document", "content": "..."}
  ]
}
```

**Response** — llmsec reads a dot-path field out of your JSON response:
```json
{"reply": "the model's response text"}
```

### Adapting to your API's shape

Everything about the envelope is configurable in `TargetConfig`:

```yaml
target:
  type: generic_http
  base_url: http://localhost:8000
  chat_endpoint: /api/v1/chat        # used for most categories
  agent_endpoint: /api/v1/agent      # used for tool_abuse / excessive_agency
  rag_endpoint: /api/v1/rag          # used for indirect_prompt_injection
  request_field: message             # the JSON field your API expects the prompt under
  history_field: history              # the JSON field your API expects prior turns under
  response_field: choices.0.message.content   # dot path into your JSON response
  timeout_seconds: 10
  headers:
    X-My-Header: some-value
  auth_token_env: MY_API_TOKEN        # name of an env var holding a bearer token
```

`response_field` supports both dict keys and list indices in the same dot path — e.g.
`choices.0.message.content` works against an OpenAI-Chat-Completions-shaped response, since
`_extract_field` in `targets/generic_http.py` walks each `.`-separated segment through whichever
of dict/list it finds.

If your API's request shape can't be matched by renaming a couple of fields (e.g., it expects a
full OpenAI-style `messages` array rather than `{message, history}`), you have two options:
adapt your API with a thin translation layer in front of it, or write a new `Target`
implementation (see below) — that's exactly what `provider_adapter.py` does for
OpenAI/Anthropic's own APIs.

### Safety guards that apply regardless of shape

- `security.allow_external_targets: false` (the default) restricts `base_url` to `localhost` or
  a literal loopback/private IP — see `docs/threat-model.md` for what this does and doesn't
  catch.
- Redirects are capped (`constants.MAX_HTTP_REDIRECTS`); response bodies are size-capped
  (`constants.MAX_RESPONSE_BYTES`).
- A missing/malformed `response_field` raises a clear `TargetError` rather than silently
  returning garbage.

## `mock` (development/testing only)

Calls `lab.app.agent.generate_reply` directly, in-process, no HTTP at all. This is what the
framework's own fast test suite uses; it requires the `lab/` package to be present alongside
`llmsec` (true in this repository, not true of an arbitrary `pip install llmsec`). Not something
you'd point at your own target — there's no "mock" version of an arbitrary API.

## `provider` (optional — talk to a real LLM provider's own API)

Entirely optional, and never required to use this framework. Speaks OpenAI's or Anthropic's
native chat-completions shape directly via `httpx` (no provider SDK dependency), for when you'd
rather point llmsec straight at a provider than stand up your own wrapper API:

```yaml
target:
  type: provider
  base_url: https://api.openai.com     # or https://api.anthropic.com
  provider: openai                      # or anthropic
  model: gpt-4o-mini
  auth_token_env: OPENAI_API_KEY
  system_prompt: "You are a customer support agent for Acme Corp."  # optional

security:
  allow_external_targets: true    # required: api.openai.com isn't a local/private host
```

Requires the named environment variable to actually be set (`TargetError` if not, at
construction time, before any request is made). `document`/`tool` conversation turns (used to
simulate indirect prompt injection) have no native equivalent in these APIs' message roles, so
they're sent as user messages labeled `[DOCUMENT CONTENT]` / `[TOOL CONTENT]` — a reasonable but
lossy approximation, called out here rather than left implicit.

## Writing a new `Target` from scratch

Implement `targets/base.py`'s `Target` class (one abstract method). `Target` is generic over
its config type — parameterize it with `BaseTargetConfig` if your target doesn't need any
type-specific fields, or define your own `BaseTargetConfig` subclass if it does (see
`models/target.py` for how `GenericHttpTargetConfig`/`MockTargetConfig`/`ProviderTargetConfig`
each do this):

```python
from llmsec.models.target import BaseTargetConfig
from llmsec.targets.base import Endpoint, HistoryTurn, Target, TargetResponse

class MyTarget(Target[BaseTargetConfig]):
    async def send(
        self, *, endpoint: Endpoint, prompt: str, history: list[HistoryTurn] | None = None
    ) -> TargetResponse:
        ...  # your integration logic — self.config is typed as BaseTargetConfig here
        return TargetResponse(text=..., raw=..., latency_ms=..., status_code=...)
```

`raw` should include a `tool_calls` list (see `policy` evaluator in
`docs/creating-test-cases.md`) if you want `tool_abuse`/`excessive_agency` cases to be
evaluable against your target. Register the type in `targets/build_target`
(`src/llmsec/targets/__init__.py`) so `target.type: my_target` resolves to it. See
`examples/custom_target.py` for a complete, runnable example.
