"""Small async retry helper with exponential backoff (no extra dependency)."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

logger = logging.getLogger("llmsec.retry")


async def retry_async[T](
    fn: Callable[[], Awaitable[T]],
    *,
    retries: int,
    backoff_seconds: float,
    retry_on: tuple[type[Exception], ...] = (Exception,),
) -> T:
    """Call `fn` up to `retries + 1` times, sleeping with exponential backoff between attempts.

    Re-raises the last exception if all attempts fail. `retries=0` means a single attempt with
    no retry.
    """
    attempt = 0
    while True:
        try:
            return await fn()
        except retry_on:
            if attempt >= retries:
                raise
            delay = backoff_seconds * (2**attempt)
            logger.debug("retrying after error", extra={"attempt": attempt, "delay_seconds": delay})
            await asyncio.sleep(delay)
            attempt += 1
