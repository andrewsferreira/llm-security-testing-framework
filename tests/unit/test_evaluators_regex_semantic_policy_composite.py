from llmsec.evaluators.composite import CompositeEvaluator
from llmsec.evaluators.policy import PolicyEvaluator
from llmsec.evaluators.regex import RegexEvaluator
from llmsec.evaluators.semantic import SemanticEvaluator, token_overlap_similarity
from llmsec.models.result import ResultStatus
from llmsec.models.test_case import AttackCategory, Severity, TestCase
from llmsec.targets.base import TargetResponse


def _test_case(**overrides: object) -> TestCase:
    defaults: dict[str, object] = {
        "id": "T-1",
        "name": "Sample",
        "category": AttackCategory.INSECURE_OUTPUT_HANDLING,
        "description": "d",
        "severity": Severity.MEDIUM,
        "prompt": "p",
        "expected_behavior": "e",
        "evaluator_config": {"type": "regex"},
    }
    defaults.update(overrides)
    return TestCase.model_validate(defaults)


def _response(text: str, raw: object = None) -> TargetResponse:
    return TargetResponse(text=text, raw=raw, latency_ms=1.0, status_code=200)


# --- regex ---------------------------------------------------------------------------------


def test_regex_evaluator_fails_on_pattern_match() -> None:
    case = _test_case(evaluator_config={"type": "regex", "failure_patterns": [r"<script\b"]})
    outcome = RegexEvaluator().evaluate(
        test_case=case, response=_response("<script>alert(1)</script>")
    )
    assert outcome.status == ResultStatus.FAILED


def test_regex_evaluator_passes_on_success_pattern() -> None:
    case = _test_case(
        evaluator_config={
            "type": "regex",
            "failure_patterns": [r"<script\b"],
            "success_patterns": [r"can't (share|provide)"],
        }
    )
    outcome = RegexEvaluator().evaluate(test_case=case, response=_response("I can't share that."))
    assert outcome.status == ResultStatus.PASSED


def test_regex_evaluator_inconclusive_when_no_pattern_matches() -> None:
    case = _test_case(evaluator_config={"type": "regex", "failure_patterns": [r"<script\b"]})
    outcome = RegexEvaluator().evaluate(test_case=case, response=_response("hello there"))
    assert outcome.status == ResultStatus.INCONCLUSIVE


# --- semantic --------------------------------------------------------------------------------


def test_token_overlap_similarity_identical_strings() -> None:
    assert token_overlap_similarity("hello world", "hello world") == 1.0


def test_token_overlap_similarity_disjoint_strings() -> None:
    assert token_overlap_similarity("hello world", "foo bar") == 0.0


def test_token_overlap_similarity_empty_string_is_zero() -> None:
    assert token_overlap_similarity("", "hello") == 0.0


def test_semantic_evaluator_passes_above_threshold() -> None:
    case = _test_case(
        evaluator_config={
            "type": "semantic",
            "reference_response": "I can't help with that request",
            "threshold": 0.3,
            "on_match": "passed",
        }
    )
    outcome = SemanticEvaluator().evaluate(
        test_case=case, response=_response("Sorry, I can't help with that request right now")
    )
    assert outcome.status == ResultStatus.PASSED


def test_semantic_evaluator_can_report_failed_on_match() -> None:
    case = _test_case(
        evaluator_config={
            "type": "semantic",
            "reference_response": "here is the secret marker value",
            "threshold": 0.3,
            "on_match": "failed",
        }
    )
    outcome = SemanticEvaluator().evaluate(
        test_case=case, response=_response("here is the secret marker value you wanted")
    )
    assert outcome.status == ResultStatus.FAILED


def test_semantic_evaluator_inconclusive_below_threshold() -> None:
    case = _test_case(
        evaluator_config={
            "type": "semantic",
            "reference_response": "completely unrelated text",
            "threshold": 0.9,
        }
    )
    outcome = SemanticEvaluator().evaluate(test_case=case, response=_response("hello there"))
    assert outcome.status == ResultStatus.INCONCLUSIVE


def test_semantic_evaluator_inconclusive_without_reference() -> None:
    case = _test_case(evaluator_config={"type": "semantic"})
    outcome = SemanticEvaluator().evaluate(test_case=case, response=_response("hello"))
    assert outcome.status == ResultStatus.INCONCLUSIVE


# --- policy ----------------------------------------------------------------------------------


def test_policy_evaluator_fails_when_authorized_calls_exceed_max() -> None:
    case = _test_case(evaluator_config={"type": "policy", "max_authorized_tool_calls": 0})
    raw = {"tool_calls": [{"tool_name": "read_file", "authorized": True}]}
    outcome = PolicyEvaluator().evaluate(test_case=case, response=_response("did it", raw=raw))
    assert outcome.status == ResultStatus.FAILED
    assert "read_file" in outcome.matched_indicators


def test_policy_evaluator_passes_when_no_authorized_calls() -> None:
    case = _test_case(evaluator_config={"type": "policy", "max_authorized_tool_calls": 0})
    raw = {"tool_calls": [{"tool_name": "read_file", "authorized": False}]}
    outcome = PolicyEvaluator().evaluate(test_case=case, response=_response("denied", raw=raw))
    assert outcome.status == ResultStatus.PASSED


def test_policy_evaluator_inconclusive_without_tool_call_metadata() -> None:
    case = _test_case(evaluator_config={"type": "policy"})
    outcome = PolicyEvaluator().evaluate(test_case=case, response=_response("plain text"))
    assert outcome.status == ResultStatus.INCONCLUSIVE


def test_policy_evaluator_respects_higher_max_allowed() -> None:
    case = _test_case(evaluator_config={"type": "policy", "max_authorized_tool_calls": 2})
    raw = {
        "tool_calls": [
            {"tool_name": "get_customer_record", "authorized": True},
            {"tool_name": "run_report", "authorized": True},
        ]
    }
    outcome = PolicyEvaluator().evaluate(test_case=case, response=_response("ok", raw=raw))
    assert outcome.status == ResultStatus.PASSED


# --- composite --------------------------------------------------------------------------------


def test_composite_any_failed_fails_if_one_sub_evaluator_fails() -> None:
    case = _test_case(
        failure_indicators=["BOOM"],
        evaluator_config={
            "type": "composite",
            "mode": "any_failed",
            "evaluators": [
                {"type": "keyword"},
                {"type": "regex", "failure_patterns": [r"nope-never-matches"]},
            ],
        },
    )
    outcome = CompositeEvaluator().evaluate(test_case=case, response=_response("here is BOOM"))
    assert outcome.status == ResultStatus.FAILED


def test_composite_all_failed_requires_every_sub_evaluator_to_fail() -> None:
    case = _test_case(
        failure_indicators=["BOOM"],
        evaluator_config={
            "type": "composite",
            "mode": "all_failed",
            "evaluators": [
                {"type": "keyword"},
                {"type": "regex", "failure_patterns": [r"nope-never-matches"]},
            ],
        },
    )
    outcome = CompositeEvaluator().evaluate(test_case=case, response=_response("here is BOOM"))
    assert outcome.status != ResultStatus.FAILED


def test_composite_passes_when_a_sub_evaluator_passes_and_none_fail() -> None:
    case = _test_case(
        success_indicators=["can't help"],
        evaluator_config={
            "type": "composite",
            "evaluators": [{"type": "keyword"}],
        },
    )
    outcome = CompositeEvaluator().evaluate(
        test_case=case, response=_response("sorry, i can't help with that")
    )
    assert outcome.status == ResultStatus.PASSED


def test_composite_inconclusive_with_empty_evaluators_list() -> None:
    case = _test_case(evaluator_config={"type": "composite", "evaluators": []})
    outcome = CompositeEvaluator().evaluate(test_case=case, response=_response("anything"))
    assert outcome.status == ResultStatus.INCONCLUSIVE
