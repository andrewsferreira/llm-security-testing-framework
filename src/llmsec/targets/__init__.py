"""Target adapters: how the framework talks to the system under test."""

from __future__ import annotations

from llmsec.exceptions import TargetError
from llmsec.models.target import TargetConfig, TargetType
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


def build_target(config: TargetConfig, *, allow_external: bool) -> Target:
    """Construct the right Target implementation for `config.type`."""
    if config.type == TargetType.GENERIC_HTTP:
        return GenericHttpTarget(config, allow_external=allow_external)
    if config.type == TargetType.MOCK:
        return MockTarget(config)
    if config.type == TargetType.PROVIDER:
        return ProviderAdapterTarget(config, allow_external=allow_external)
    raise TargetError(f"Unknown target type: {config.type!r}")
