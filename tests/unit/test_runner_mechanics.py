"""Tests for the runner's execution mechanics (concurrency, retry, timeout, rate limit,
stop-on-critical) using a fully controllable fake Target rather than the lab app."""

from __future__ import annotations

import asyncio
import time

import pytest

from llmsec.core.runner import run_campaign_async
from llmsec.exceptions import TargetError
from llmsec.models.campaign import CampaignConfig
from llmsec.models.result import ResultStatus
from llmsec.models.target import GenericHttpTargetConfig
from llmsec.models.test_case import AttackCategory, Severity, TestCase
from llmsec.targets.base import Endpoint, HistoryTurn, Target, TargetResponse

_DUMMY_TARGET_CONFIG = GenericHttpTargetConfig(base_url="http://localhost:8000")


def _test_case(id_: str, **overrides: object) -> TestCase:
    defaults: dict[str, object] = {
        "id": id_,
        "name": f"case {id_}",
        "category": AttackCategory.JAILBREAK,
        "description": "d",
        "severity": Severity.LOW,
        "prompt": "hello",
        "expected_behavior": "e",
        "failure_indicators": ["BOOM"],
        "evaluator_config": {"type": "keyword"},
    }
    defaults.update(overrides)
    return TestCase.model_validate(defaults)


class _ConcurrencyTrackingTarget(Target[GenericHttpTargetConfig]):
    def __init__(self) -> None:
        self.in_flight = 0
        self.max_in_flight = 0
        self._lock = asyncio.Lock()

    async def send(
        self, *, endpoint: Endpoint, prompt: str, history: list[HistoryTurn] | None = None
    ) -> TargetResponse:
        async with self._lock:
            self.in_flight += 1
            self.max_in_flight = max(self.max_in_flight, self.in_flight)
        await asyncio.sleep(0.05)
        async with self._lock:
            self.in_flight -= 1
        return TargetResponse(text="ok", latency_ms=1.0, status_code=200)


async def test_concurrency_is_bounded_by_max_concurrency() -> None:
    target = _ConcurrencyTrackingTarget()
    test_cases = [_test_case(f"C-{i}") for i in range(10)]
    config = CampaignConfig(max_concurrency=3, retry_count=0)
    await run_campaign_async(target, test_cases, config, "camp-1", redact=True)
    assert target.max_in_flight <= 3


async def test_results_are_returned_in_original_order() -> None:
    target = _ConcurrencyTrackingTarget()
    test_cases = [_test_case(f"C-{i}") for i in range(5)]
    config = CampaignConfig(max_concurrency=5, retry_count=0)
    results = await run_campaign_async(target, test_cases, config, "camp-1", redact=True)
    assert [r.test_id for r in results] == [tc.id for tc in test_cases]


class _FlakyTarget(Target[GenericHttpTargetConfig]):
    def __init__(self, fail_times: int) -> None:
        self.fail_times = fail_times
        self.calls = 0

    async def send(
        self, *, endpoint: Endpoint, prompt: str, history: list[HistoryTurn] | None = None
    ) -> TargetResponse:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise TargetError("simulated failure")
        return TargetResponse(text="recovered", latency_ms=1.0, status_code=200)


async def test_retry_recovers_from_transient_failures() -> None:
    target = _FlakyTarget(fail_times=2)
    config = CampaignConfig(max_concurrency=1, retry_count=3, retry_backoff_seconds=0.0)
    results = await run_campaign_async(target, [_test_case("R-1")], config, "camp-1", redact=True)
    assert results[0].status == ResultStatus.INCONCLUSIVE  # "recovered" matches no indicator
    assert target.calls == 3


async def test_error_result_after_exhausting_retries() -> None:
    target = _FlakyTarget(fail_times=10)
    config = CampaignConfig(max_concurrency=1, retry_count=1, retry_backoff_seconds=0.0)
    results = await run_campaign_async(target, [_test_case("R-1")], config, "camp-1", redact=True)
    assert results[0].status == ResultStatus.ERROR
    assert results[0].error_type == "TargetError"
    assert target.calls == 2  # 1 initial attempt + 1 retry


class _SlowTarget(Target[GenericHttpTargetConfig]):
    async def send(
        self, *, endpoint: Endpoint, prompt: str, history: list[HistoryTurn] | None = None
    ) -> TargetResponse:
        await asyncio.sleep(1.0)
        return TargetResponse(text="too slow", latency_ms=1000.0, status_code=200)


async def test_per_test_timeout_produces_error_result() -> None:
    target = _SlowTarget(_DUMMY_TARGET_CONFIG)
    config = CampaignConfig(max_concurrency=1, retry_count=0)
    results = await run_campaign_async(
        target, [_test_case("T-1", timeout=0.05)], config, "camp-1", redact=True
    )
    assert results[0].status == ResultStatus.ERROR
    assert results[0].error_type == "TimeoutError"


class _AlwaysCriticalFailTarget(Target[GenericHttpTargetConfig]):
    async def send(
        self, *, endpoint: Endpoint, prompt: str, history: list[HistoryTurn] | None = None
    ) -> TargetResponse:
        return TargetResponse(text="BOOM leaked", latency_ms=1.0, status_code=200)


async def test_stop_on_critical_skips_remaining_test_cases() -> None:
    target = _AlwaysCriticalFailTarget(_DUMMY_TARGET_CONFIG)
    test_cases = [_test_case(f"S-{i}", severity=Severity.CRITICAL) for i in range(20)]
    config = CampaignConfig(max_concurrency=1, retry_count=0, stop_on_critical=True)
    results = await run_campaign_async(target, test_cases, config, "camp-1", redact=True)
    assert len(results) < len(test_cases)
    assert results[0].status == ResultStatus.FAILED


async def test_stop_on_critical_false_runs_everything() -> None:
    target = _AlwaysCriticalFailTarget(_DUMMY_TARGET_CONFIG)
    test_cases = [_test_case(f"S-{i}", severity=Severity.CRITICAL) for i in range(5)]
    config = CampaignConfig(max_concurrency=2, retry_count=0, stop_on_critical=False)
    results = await run_campaign_async(target, test_cases, config, "camp-1", redact=True)
    assert len(results) == len(test_cases)


async def test_rate_limit_spaces_out_requests() -> None:
    target = _ConcurrencyTrackingTarget()
    test_cases = [_test_case(f"RL-{i}") for i in range(3)]
    config = CampaignConfig(max_concurrency=3, retry_count=0, rate_limit_per_second=10.0)
    started = time.monotonic()
    await run_campaign_async(target, test_cases, config, "camp-1", redact=True)
    elapsed = time.monotonic() - started
    # 3 requests at 10/sec means at least ~0.2s of enforced spacing (2 intervals of 0.1s).
    assert elapsed >= 0.15


@pytest.mark.parametrize("max_concurrency", [1, 5])
async def test_empty_test_case_list_returns_empty_results(max_concurrency: int) -> None:
    target = _ConcurrencyTrackingTarget()
    config = CampaignConfig(max_concurrency=max_concurrency, retry_count=0)
    results = await run_campaign_async(target, [], config, "camp-1", redact=True)
    assert results == []
