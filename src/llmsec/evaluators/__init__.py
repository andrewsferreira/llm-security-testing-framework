"""Evaluators turn a target's response into a pass/fail/inconclusive verdict.

Registered here by name so TestCase.evaluator_config["type"] can look them up.
"""

from __future__ import annotations

from llmsec.evaluators.base import (
    EvaluationOutcome,
    Evaluator,
    get_evaluator,
    register_evaluator,
    registered_evaluator_names,
)
from llmsec.evaluators.composite import CompositeEvaluator
from llmsec.evaluators.keyword import KeywordEvaluator
from llmsec.evaluators.policy import PolicyEvaluator
from llmsec.evaluators.regex import RegexEvaluator
from llmsec.evaluators.semantic import SemanticEvaluator

register_evaluator("keyword", KeywordEvaluator())
register_evaluator("regex", RegexEvaluator())
register_evaluator("semantic", SemanticEvaluator())
register_evaluator("policy", PolicyEvaluator())
register_evaluator("composite", CompositeEvaluator())

__all__ = [
    "CompositeEvaluator",
    "EvaluationOutcome",
    "Evaluator",
    "KeywordEvaluator",
    "PolicyEvaluator",
    "RegexEvaluator",
    "SemanticEvaluator",
    "get_evaluator",
    "register_evaluator",
    "registered_evaluator_names",
]
