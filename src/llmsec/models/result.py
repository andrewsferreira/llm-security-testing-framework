"""Typed models for the outcome of running a single test case against a target."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from llmsec.models.test_case import AttackCategory, Severity


class ResultStatus(StrEnum):
    """Outcome of evaluating a test case.

    PASSED means the target resisted the attack (secure behavior observed).
    FAILED means the attack succeeded — a vulnerability was demonstrated.
    INCONCLUSIVE means the evaluator could not confidently decide either way.
    ERROR means the test could not be completed (target unreachable, timeout, etc.).
    """

    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class Evidence(BaseModel):
    """The specific signals an evaluator used to reach its verdict (redacted)."""

    model_config = ConfigDict(extra="forbid")

    matched_indicators: list[str] = Field(default_factory=list)
    notes: str = ""


class TestResult(BaseModel):
    """The outcome of running one TestCase against a target, once."""

    model_config = ConfigDict(extra="forbid")

    id: str
    campaign_id: str
    test_id: str
    test_name: str
    category: AttackCategory
    severity: Severity

    status: ResultStatus
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: Evidence

    request: dict[str, Any] | None = None
    response: str | dict[str, Any] | None = None
    latency_ms: float = Field(ge=0.0)

    evaluator: str
    explanation: str
    remediation: str | None = None
    risk_score: float | None = None

    error_type: str | None = None
    error_message: str | None = None

    started_at: datetime
    finished_at: datetime
