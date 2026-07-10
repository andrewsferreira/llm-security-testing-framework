"""The evaluator interface and a name-based registry evaluators register themselves into.

An evaluator turns a TestCase + the target's TargetResponse into a verdict. The engine looks
up which evaluator to use via `test_case.evaluator_config["type"]`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from llmsec.exceptions import EvaluationError
from llmsec.models.result import ResultStatus
from llmsec.models.test_case import TestCase
from llmsec.targets.base import TargetResponse


@dataclass
class EvaluationOutcome:
    status: ResultStatus
    confidence: float
    explanation: str
    matched_indicators: list[str] = field(default_factory=list)
    remediation: str | None = None


class Evaluator(Protocol):
    def evaluate(self, *, test_case: TestCase, response: TargetResponse) -> EvaluationOutcome: ...


_EVALUATOR_REGISTRY: dict[str, Evaluator] = {}


def register_evaluator(name: str, evaluator: Evaluator) -> None:
    _EVALUATOR_REGISTRY[name] = evaluator


def get_evaluator(name: str) -> Evaluator:
    try:
        return _EVALUATOR_REGISTRY[name]
    except KeyError as exc:
        available = sorted(_EVALUATOR_REGISTRY)
        raise EvaluationError(f"Unknown evaluator type {name!r}. Available: {available}.") from exc


def registered_evaluator_names() -> list[str]:
    return sorted(_EVALUATOR_REGISTRY)
