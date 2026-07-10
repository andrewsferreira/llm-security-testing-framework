"""Framework-wide exception types."""

from __future__ import annotations


class LlmsecError(Exception):
    """Base class for all llmsec errors."""


class ConfigError(LlmsecError):
    """Raised when a configuration file fails to load or validate."""


class UnsafeTargetError(LlmsecError):
    """Raised when a target URL is rejected by the SSRF/safety guard."""


class TargetError(LlmsecError):
    """Raised when a target cannot be reached or returns an unusable response."""


class RegistryError(LlmsecError):
    """Raised when a test-case registry/payload file fails to load or validate."""


class EvaluationError(LlmsecError):
    """Raised when an evaluator cannot produce a verdict due to an internal error."""
