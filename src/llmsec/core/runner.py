"""Async execution of a set of TestCases against a Target: bounded concurrency, per-test
timeout, retry with backoff, an optional global rate limit, and stop-on-critical."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import Any

from llmsec.core.evidence import build_result
from llmsec.evaluators import EvaluationOutcome, get_evaluator
from llmsec.exceptions import TargetError
from llmsec.models.campaign import CampaignConfig
from llmsec.models.result import ResultStatus, TestResult
from llmsec.models.test_case import AttackCategory, Severity, TestCase
from llmsec.targets.base import Endpoint, HistoryTurn, Target, TargetResponse
from llmsec.utils.retry import retry_async

_AGENT_ENDPOINT_CATEGORIES: frozenset[AttackCategory] = frozenset(
    {AttackCategory.TOOL_ABUSE, AttackCategory.EXCESSIVE_AGENCY}
)
_RAG_ENDPOINT_CATEGORIES: frozenset[AttackCategory] = frozenset(
    {AttackCategory.INDIRECT_PROMPT_INJECTION}
)


def endpoint_for_category(category: AttackCategory) -> Endpoint:
    if category in _AGENT_ENDPOINT_CATEGORIES:
        return "agent"
    if category in _RAG_ENDPOINT_CATEGORIES:
        return "rag"
    return "chat"


class _RateLimiter:
    """Caps how often `wait()` returns to roughly `rate_per_second` calls/sec, shared across
    all concurrent workers."""

    def __init__(self, rate_per_second: float | None) -> None:
        self._min_interval = 1.0 / rate_per_second if rate_per_second else 0.0
        self._lock = asyncio.Lock()
        self._last_call: float | None = None

    async def wait(self) -> None:
        if self._min_interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            if self._last_call is not None:
                remaining = self._last_call + self._min_interval - now
                if remaining > 0:
                    await asyncio.sleep(remaining)
            self._last_call = time.monotonic()


async def _execute_test_case(target: Target[Any], test_case: TestCase) -> TargetResponse:
    endpoint = endpoint_for_category(test_case.category)

    if test_case.conversation and test_case.requires_multi_turn:
        history: list[HistoryTurn] = []
        response: TargetResponse | None = None
        for turn in test_case.conversation:
            response = await target.send(
                endpoint=endpoint, prompt=turn.content, history=list(history)
            )
            history.append(HistoryTurn(role=turn.role, content=turn.content))
        if response is None:
            # Unreachable in practice: TestCase validates requires_multi_turn implies a
            # non-empty conversation, but this avoids ever returning None to the caller.
            raise TargetError(f"Test case {test_case.id!r} has an empty conversation.")
        return response

    if test_case.conversation:
        *context_turns, final_turn = test_case.conversation
        history = [HistoryTurn(role=t.role, content=t.content) for t in context_turns]
        return await target.send(endpoint=endpoint, prompt=final_turn.content, history=history)

    return await target.send(endpoint=endpoint, prompt=test_case.prompt or "")


async def _run_one(
    target: Target[Any],
    test_case: TestCase,
    campaign_id: str,
    campaign_config: CampaignConfig,
    *,
    redact: bool,
    extra_markers: tuple[str, ...],
) -> TestResult:
    started_at = datetime.now(UTC)
    try:
        response = await retry_async(
            lambda: asyncio.wait_for(
                _execute_test_case(target, test_case), timeout=test_case.timeout
            ),
            retries=campaign_config.retry_count,
            backoff_seconds=campaign_config.retry_backoff_seconds,
            retry_on=(TargetError, TimeoutError),
        )
    except (TargetError, TimeoutError) as exc:
        finished_at = datetime.now(UTC)
        outcome = EvaluationOutcome(
            status=ResultStatus.ERROR, confidence=0.0, explanation=f"Execution error: {exc}"
        )
        return build_result(
            campaign_id=campaign_id,
            test_case=test_case,
            response=None,
            outcome=outcome,
            evaluator_name="none",
            started_at=started_at,
            finished_at=finished_at,
            redact=redact,
            extra_markers=extra_markers,
            error_type=type(exc).__name__,
            error_message=str(exc),
        )

    evaluator_type = test_case.evaluator_config.get("type", "keyword")
    outcome = get_evaluator(evaluator_type).evaluate(test_case=test_case, response=response)
    finished_at = datetime.now(UTC)
    return build_result(
        campaign_id=campaign_id,
        test_case=test_case,
        response=response,
        outcome=outcome,
        evaluator_name=evaluator_type,
        started_at=started_at,
        finished_at=finished_at,
        redact=redact,
        extra_markers=extra_markers,
    )


async def run_campaign_async(
    target: Target[Any],
    test_cases: list[TestCase],
    campaign_config: CampaignConfig,
    campaign_id: str,
    *,
    redact: bool,
    extra_markers: tuple[str, ...] = (),
) -> list[TestResult]:
    """Run every test case, bounded by `campaign_config.max_concurrency`, stopping early (but
    letting in-flight requests finish) once a CRITICAL failure is found if
    `campaign_config.stop_on_critical` is set. Results are returned in the same order as
    `test_cases`, regardless of completion order."""
    order = {tc.id: i for i, tc in enumerate(test_cases)}
    queue: asyncio.Queue[TestCase] = asyncio.Queue()
    for tc in test_cases:
        queue.put_nowait(tc)

    results: list[TestResult] = []
    results_lock = asyncio.Lock()
    stop_event = asyncio.Event()
    rate_limiter = _RateLimiter(campaign_config.rate_limit_per_second)

    async def worker() -> None:
        while not stop_event.is_set():
            try:
                test_case = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            await rate_limiter.wait()
            result = await _run_one(
                target,
                test_case,
                campaign_id,
                campaign_config,
                redact=redact,
                extra_markers=extra_markers,
            )
            async with results_lock:
                results.append(result)
            is_critical_finding = (
                result.status == ResultStatus.FAILED and result.severity == Severity.CRITICAL
            )
            if campaign_config.stop_on_critical and is_critical_finding:
                stop_event.set()
            queue.task_done()

    worker_count = max(1, min(campaign_config.max_concurrency, len(test_cases)))
    workers = [asyncio.create_task(worker()) for _ in range(worker_count)]
    await asyncio.gather(*workers)

    results.sort(key=lambda r: order[r.test_id])
    return results
