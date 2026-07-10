"""Turns a (TestCase, TargetResponse, EvaluationOutcome) triple into a stored TestResult.

The single choke point where redaction is applied to request/response payloads before they're
kept around in memory / written to a report, per security.redact_sensitive_values.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from llmsec.evaluators.base import EvaluationOutcome
from llmsec.models.result import Evidence, TestResult
from llmsec.models.test_case import TestCase
from llmsec.targets.base import TargetResponse
from llmsec.utils.identifiers import new_result_id
from llmsec.utils.redaction import redact_value


def build_result(
    *,
    campaign_id: str,
    test_case: TestCase,
    response: TargetResponse | None,
    outcome: EvaluationOutcome,
    evaluator_name: str,
    started_at: datetime,
    finished_at: datetime,
    redact: bool,
    extra_markers: tuple[str, ...] = (),
    error_type: str | None = None,
    error_message: str | None = None,
) -> TestResult:
    request_payload: dict[str, Any] = {"prompt": test_case.prompt} if test_case.prompt else {}
    if test_case.conversation:
        request_payload["conversation"] = [t.model_dump() for t in test_case.conversation]

    response_value: str | dict[str, Any] | None = None
    if response is not None:
        response_value = response.raw if response.raw is not None else response.text

    if redact:
        markers = (*extra_markers, *test_case.failure_indicators)
        request_payload = redact_value(request_payload, extra_markers=markers)
        response_value = redact_value(response_value, extra_markers=markers)

    return TestResult(
        id=new_result_id(),
        campaign_id=campaign_id,
        test_id=test_case.id,
        test_name=test_case.name,
        category=test_case.category,
        severity=test_case.severity,
        status=outcome.status,
        confidence=outcome.confidence,
        evidence=Evidence(
            matched_indicators=outcome.matched_indicators,
            notes=outcome.explanation,
        ),
        request=request_payload,
        response=response_value,
        latency_ms=response.latency_ms if response is not None else 0.0,
        evaluator=evaluator_name,
        explanation=outcome.explanation,
        remediation=outcome.remediation,
        error_type=error_type,
        error_message=error_message,
        started_at=started_at,
        finished_at=finished_at,
    )
