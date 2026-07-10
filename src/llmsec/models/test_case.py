"""Typed model for a single security test case, as loaded from payloads/*.yaml."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackCategory(StrEnum):
    DIRECT_PROMPT_INJECTION = "direct_prompt_injection"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    JAILBREAK = "jailbreak"
    SYSTEM_PROMPT_LEAKAGE = "system_prompt_leakage"
    DATA_EXFILTRATION = "data_exfiltration"
    TOOL_ABUSE = "tool_abuse"
    CONTEXT_MANIPULATION = "context_manipulation"
    INSECURE_OUTPUT_HANDLING = "insecure_output_handling"
    EXCESSIVE_AGENCY = "excessive_agency"


class ConversationTurn(BaseModel):
    """One turn of a multi-turn test case, or one piece of injected external content.

    `injected_source` marks content that the test simulates as coming from something other
    than the direct user (a fetched document, a RAG chunk, a tool result), which is the
    mechanism indirect-prompt-injection test cases use.
    """

    model_config = ConfigDict(extra="forbid")

    role: Literal["user", "tool", "document"]
    content: str
    injected_source: str | None = None


class TestCase(BaseModel):
    """A single, YAML-defined security test case."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    category: AttackCategory
    description: str = Field(min_length=1)
    severity: Severity
    tags: list[str] = Field(default_factory=list)

    prompt: str | None = None
    conversation: list[ConversationTurn] | None = None

    expected_behavior: str = Field(min_length=1)
    failure_indicators: list[str] = Field(default_factory=list)
    success_indicators: list[str] = Field(default_factory=list)

    requires_multi_turn: bool = False
    requires_tools: bool = False

    references: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    timeout: float = Field(default=10.0, gt=0)
    evaluator_config: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_prompt_or_conversation(self) -> TestCase:
        if not self.prompt and not self.conversation:
            raise ValueError(
                f"Test case {self.id!r} must define either `prompt` or `conversation`."
            )
        if self.requires_multi_turn and (not self.conversation or len(self.conversation) < 2):
            raise ValueError(
                f"Test case {self.id!r} has requires_multi_turn=true but fewer than 2 "
                "conversation turns."
            )
        if not self.evaluator_config:
            raise ValueError(
                f"Test case {self.id!r} must define `evaluator_config` "
                "(how its result is evaluated)."
            )
        return self
