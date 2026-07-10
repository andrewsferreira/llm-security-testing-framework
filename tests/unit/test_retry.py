import pytest

from llmsec.utils.retry import retry_async


async def test_retry_async_succeeds_on_first_try() -> None:
    calls = 0

    async def fn() -> str:
        nonlocal calls
        calls += 1
        return "ok"

    result = await retry_async(fn, retries=3, backoff_seconds=0.0)
    assert result == "ok"
    assert calls == 1


async def test_retry_async_retries_then_succeeds() -> None:
    calls = 0

    async def fn() -> str:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise ValueError("not yet")
        return "ok"

    result = await retry_async(fn, retries=3, backoff_seconds=0.0)
    assert result == "ok"
    assert calls == 3


async def test_retry_async_raises_after_exhausting_retries() -> None:
    calls = 0

    async def fn() -> str:
        nonlocal calls
        calls += 1
        raise ValueError("always fails")

    with pytest.raises(ValueError, match="always fails"):
        await retry_async(fn, retries=2, backoff_seconds=0.0)
    assert calls == 3


async def test_retry_async_only_retries_specified_exceptions() -> None:
    async def fn() -> str:
        raise KeyError("nope")

    with pytest.raises(KeyError):
        await retry_async(fn, retries=3, backoff_seconds=0.0, retry_on=(ValueError,))
