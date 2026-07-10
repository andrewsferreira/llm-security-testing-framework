"""Evaluators turn a target's response into a pass/fail/inconclusive verdict.

Registered here by name so TestCase.evaluator_config["type"] can look them up. regex.py,
semantic.py, policy.py, and composite.py are added in Phase 5 alongside the attack payloads
that need them.
"""

from __future__ import annotations

from llmsec.evaluators.base import (
    EvaluationOutcome,
    Evaluator,
    get_evaluator,
    register_evaluator,
    registered_evaluator_names,
)
from llmsec.evaluators.keyword import KeywordEvaluator

register_evaluator("keyword", KeywordEvaluator())

__all__ = [
    "EvaluationOutcome",
    "Evaluator",
    "KeywordEvaluator",
    "get_evaluator",
    "register_evaluator",
    "registered_evaluator_names",
]
