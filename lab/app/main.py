"""The lab FastAPI application: a deliberately fake, safe-to-attack chatbot/agent.

Toggle behavior with the LAB_MODE environment variable:
  - LAB_MODE=vulnerable (default): demonstrates unmitigated LLM security issues.
  - LAB_MODE=hardened: demonstrates the corresponding mitigations.

Nothing here performs real I/O — see lab/app/fake_data.py and lab/app/tools.py. This app exists
only to be scanned by llmsec locally; do not expose it on a public network.
"""

from __future__ import annotations

import os
import time
from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel, Field

from lab.app.agent import AgentReply, Message, generate_reply


def current_mode() -> Literal["vulnerable", "hardened"]:
    """Read LAB_MODE fresh on every call (not cached at import time).

    Caching this at module-import time is a footgun for tests: importlib.reload() mutates a
    module's namespace in place, so any previously constructed FastAPI app whose route
    handlers close over that same namespace would silently pick up the *new* value too,
    making two same-process TestClients (one per mode) collide. Reading the environment
    variable fresh avoids that entirely and needs no reload.
    """
    return (
        "hardened"
        if os.environ.get("LAB_MODE", "vulnerable").lower() == "hardened"
        else "vulnerable"
    )


FRAMEWORK_LAB_VERSION = "0.1.0"

app = FastAPI(
    title="llmsec lab",
    description="A deliberately vulnerable/hardened FastAPI chatbot for llmsec to scan locally.",
    version=FRAMEWORK_LAB_VERSION,
)

_request_count = 0
_started_at = time.monotonic()


class TurnIn(BaseModel):
    role: Literal["user", "tool", "document"]
    content: str


class ChatRequest(BaseModel):
    message: str = Field(min_length=1)
    history: list[TurnIn] = Field(default_factory=list)


class ToolCallOut(BaseModel):
    tool_name: str
    arguments: dict[str, str]
    authorized: bool
    reason: str


class ChatResponse(BaseModel):
    reply: str
    tool_calls: list[ToolCallOut] = Field(default_factory=list)
    mode: str


def _to_reply_response(reply: AgentReply, mode: str) -> ChatResponse:
    return ChatResponse(
        reply=reply.text,
        tool_calls=[
            ToolCallOut(
                tool_name=c.tool_name,
                arguments=c.arguments,
                authorized=c.authorized,
                reason=c.reason,
            )
            for c in reply.tool_calls
        ],
        mode=mode,
    )


def _handle_turn(endpoint: str, request: ChatRequest) -> ChatResponse:
    global _request_count
    _request_count += 1
    mode = current_mode()
    history = [Message(role=t.role, content=t.content) for t in request.history]
    reply = generate_reply(mode=mode, endpoint=endpoint, prompt=request.message, history=history)
    return _to_reply_response(reply, mode)


@app.post("/chat", response_model=ChatResponse)
def chat(request: ChatRequest) -> ChatResponse:
    """A plain conversational endpoint: direct prompt injection, jailbreak, system-prompt
    leakage, data exfiltration, and context-manipulation suites target this endpoint."""
    return _handle_turn("chat", request)


@app.post("/agent", response_model=ChatResponse)
def agent(request: ChatRequest) -> ChatResponse:
    """A tool-calling endpoint: tool-abuse and excessive-agency suites target this endpoint."""
    return _handle_turn("agent", request)


@app.post("/rag", response_model=ChatResponse)
def rag(request: ChatRequest) -> ChatResponse:
    """A retrieval-augmented endpoint: history entries with role="document" simulate content
    fetched from an external source, for indirect-prompt-injection suites."""
    return _handle_turn("rag", request)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": current_mode()}


@app.get("/version")
def version() -> dict[str, str]:
    return {"version": FRAMEWORK_LAB_VERSION, "mode": current_mode()}


@app.get("/metrics")
def metrics() -> str:
    uptime = time.monotonic() - _started_at
    lines = [
        "# HELP lab_requests_total Total number of chat/agent/rag requests handled.",
        "# TYPE lab_requests_total counter",
        f"lab_requests_total {_request_count}",
        "# HELP lab_uptime_seconds Seconds since the lab process started.",
        "# TYPE lab_uptime_seconds gauge",
        f"lab_uptime_seconds {uptime:.2f}",
    ]
    return "\n".join(lines) + "\n"
