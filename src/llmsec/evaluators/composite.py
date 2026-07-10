"""Combines multiple evaluators under one test case.

evaluator_config:
  type: composite
  mode: any_failed          # any_failed (default) | all_failed
  evaluators:
    - type: keyword
    - type: policy
      max_authorized_tool_calls: 0

Each entry in `evaluators` is a full evaluator_config for a sub-evaluator; it's applied against
a shallow copy of the test case whose `evaluator_config` is swapped for that entry, so
`test_case.failure_indicators`/`success_indicators` (used by keyword/regex) still apply as-is.
"""

from __future__ import annotations

from typing import Any

from llmsec.evaluators.base import EvaluationOutcome, get_evaluator
from llmsec.models.result import ResultStatus
from llmsec.models.test_case import TestCase
from llmsec.targets.base import TargetResponse


class CompositeEvaluator:
    def evaluate(self, *, test_case: TestCase, response: TargetResponse) -> EvaluationOutcome:
        config = test_case.evaluator_config
        mode = config.get("mode", "any_failed")
        sub_configs: list[dict[str, Any]] = config.get("evaluators", [])

        if not sub_configs:
            return EvaluationOutcome(
                status=ResultStatus.INCONCLUSIVE,
                confidence=0.0,
                explanation="evaluator_config.evaluators was empty; nothing to evaluate.",
            )

        outcomes: list[EvaluationOutcome] = []
        for sub_config in sub_configs:
            sub_case = test_case.model_copy(update={"evaluator_config": sub_config})
            evaluator = get_evaluator(sub_config["type"])
            outcomes.append(evaluator.evaluate(test_case=sub_case, response=response))

        failed = [o for o in outcomes if o.status == ResultStatus.FAILED]
        passed = [o for o in outcomes if o.status == ResultStatus.PASSED]

        is_failure = len(failed) == len(outcomes) if mode == "all_failed" else bool(failed)

        if is_failure:
            contributing = failed
            status = ResultStatus.FAILED
        elif passed:
            contributing = passed
            status = ResultStatus.PASSED
        else:
            contributing = outcomes
            status = ResultStatus.INCONCLUSIVE

        matched_indicators = [i for o in contributing for i in o.matched_indicators]
        confidence = max((o.confidence for o in contributing), default=0.0)
        explanation = " | ".join(o.explanation for o in contributing)
        remediation = next((o.remediation for o in contributing if o.remediation), None)

        return EvaluationOutcome(
            status=status,
            confidence=confidence,
            matched_indicators=matched_indicators,
            explanation=explanation,
            remediation=remediation,
        )
