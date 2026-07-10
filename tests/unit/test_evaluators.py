import pytest

from llmsec.evaluators import get_evaluator, register_evaluator, registered_evaluator_names
from llmsec.evaluators.base import EvaluationOutcome
from llmsec.evaluators.keyword import KeywordEvaluator
from llmsec.exceptions import EvaluationError
from llmsec.models.result import ResultStatus
from llmsec.models.test_case import AttackCategory, Severity, TestCase
from llmsec.targets.base import TargetResponse


def _test_case(**overrides: object) -> TestCase:
    defaults: dict[str, object] = {
        "id": "T-1",
        "name": "Sample",
        "category": AttackCategory.SYSTEM_PROMPT_LEAKAGE,
        "description": "d",
        "severity": Severity.HIGH,
        "prompt": "p",
        "expected_behavior": "e",
        "failure_indicators": ["SECRET_MARKER"],
        "success_indicators": ["can't share"],
        "evaluator_config": {"type": "keyword"},
    }
    defaults.update(overrides)
    return TestCase.model_validate(defaults)


def _response(text: str) -> TargetResponse:
    return TargetResponse(text=text, latency_ms=1.0, status_code=200)


def test_keyword_evaluator_fails_on_marker_leak() -> None:
    outcome = KeywordEvaluator().evaluate(
        test_case=_test_case(), response=_response("here is SECRET_MARKER for you")
    )
    assert outcome.status == ResultStatus.FAILED
    assert outcome.matched_indicators == ["SECRET_MARKER"]
    assert outcome.confidence > 0.5


def test_keyword_evaluator_passes_on_refusal() -> None:
    outcome = KeywordEvaluator().evaluate(
        test_case=_test_case(), response=_response("Sorry, I can't share that.")
    )
    assert outcome.status == ResultStatus.PASSED


def test_keyword_evaluator_inconclusive_otherwise() -> None:
    outcome = KeywordEvaluator().evaluate(
        test_case=_test_case(), response=_response("Here is the weather forecast.")
    )
    assert outcome.status == ResultStatus.INCONCLUSIVE


def test_keyword_evaluator_is_case_insensitive() -> None:
    outcome = KeywordEvaluator().evaluate(
        test_case=_test_case(), response=_response("secret_marker leaked")
    )
    assert outcome.status == ResultStatus.FAILED


def test_keyword_evaluator_prioritizes_failure_over_success() -> None:
    outcome = KeywordEvaluator().evaluate(
        test_case=_test_case(),
        response=_response("I can't share much, but here is SECRET_MARKER anyway"),
    )
    assert outcome.status == ResultStatus.FAILED


def test_registry_lookup_of_registered_evaluator() -> None:
    assert "keyword" in registered_evaluator_names()
    assert get_evaluator("keyword") is not None


def test_registry_lookup_of_unknown_evaluator_raises() -> None:
    with pytest.raises(EvaluationError, match="Unknown evaluator type"):
        get_evaluator("does-not-exist")


def test_register_evaluator_makes_it_discoverable() -> None:
    class _AlwaysPass:
        def evaluate(self, *, test_case: TestCase, response: TargetResponse) -> EvaluationOutcome:
            return EvaluationOutcome(status=ResultStatus.PASSED, confidence=1.0, explanation="ok")

    register_evaluator("always-pass-test-only", _AlwaysPass())
    assert (
        get_evaluator("always-pass-test-only")
        .evaluate(test_case=_test_case(), response=_response("x"))
        .status
        == ResultStatus.PASSED
    )
