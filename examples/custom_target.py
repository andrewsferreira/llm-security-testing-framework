"""A minimal custom Target implementation, for integrating with something the generic HTTP
envelope can't express (see docs/target-integration.md for when you'd need this vs. just
configuring generic_http's field names).

This example simulates a target entirely in-memory so it's runnable with no network at all;
a real implementation would make an actual request inside `send`.

Run: python examples/custom_target.py
"""

from __future__ import annotations

import asyncio
import time

from llmsec.models.target import BaseTargetConfig
from llmsec.targets.base import Endpoint, HistoryTurn, Target, TargetResponse


class EchoTarget(Target[BaseTargetConfig]):
    """Toy target that just echoes the prompt back, prefixed by the endpoint name.

    Uses `BaseTargetConfig` directly (not one of the `generic_http`/`mock`/`provider`
    subtypes) since it doesn't need any type-specific fields — just `base_url`.
    """

    async def send(
        self, *, endpoint: Endpoint, prompt: str, history: list[HistoryTurn] | None = None
    ) -> TargetResponse:
        started = time.monotonic()
        # A real implementation would call an actual API here instead.
        text = f"[{endpoint}] echo: {prompt}"
        latency_ms = (time.monotonic() - started) * 1000
        return TargetResponse(
            text=text, raw={"echoed": prompt}, latency_ms=latency_ms, status_code=200
        )


async def main() -> None:
    target = EchoTarget(BaseTargetConfig(base_url="http://localhost:8000"))
    response = await target.send(endpoint="chat", prompt="hello there")
    print(f"text: {response.text}")
    print(f"raw:  {response.raw}")
    await target.aclose()


if __name__ == "__main__":
    asyncio.run(main())
