"""Target adapters: how the framework talks to the system under test."""

from __future__ import annotations

from typing import Any

from llmsec.exceptions import TargetError
from llmsec.models.target import (
    GenericHttpTargetConfig,
    MockTargetConfig,
    ProviderTargetConfig,
    TargetConfig,
)
from llmsec.targets.base import Endpoint, HistoryTurn, Target, TargetResponse
from llmsec.targets.generic_http import GenericHttpTarget
from llmsec.targets.mock_target import MockTarget
from llmsec.targets.provider_adapter import ProviderAdapterTarget

__all__ = [
    "Endpoint",
    "HistoryTurn",
    "Target",
    "TargetResponse",
    "GenericHttpTarget",
    "MockTarget",
    "ProviderAdapterTarget",
    "build_target",
]


def build_target(config: TargetConfig, *, allow_external: bool) -> Target[Any]:
    """Construct the right Target implementation for `config`'s concrete type.

    Dispatches on `isinstance` against the discriminated union's member types, rather than
    comparing `config.type` against `TargetType` — this way mypy narrows `config` to the
    concrete subtype in each branch, which the constructor call itself then relies on.
    """
    if isinstance(config, GenericHttpTargetConfig):
        return GenericHttpTarget(config, allow_external=allow_external)
    if isinstance(config, MockTargetConfig):
        return MockTarget(config)
    if isinstance(config, ProviderTargetConfig):
        return ProviderAdapterTarget(config, allow_external=allow_external)
    raise TargetError(f"Unknown target config type: {type(config).__name__!r}")
