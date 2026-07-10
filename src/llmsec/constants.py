"""Central constants shared across the framework. No secrets belong here."""

from __future__ import annotations

from enum import IntEnum

FRAMEWORK_NAME = "llmsec"

SUPPORTED_REPORT_FORMATS: frozenset[str] = frozenset({"json", "markdown", "html", "sarif"})

DEFAULT_CONFIG_PATH = "configs/local.yaml"
DEFAULT_OUTPUT_DIR = "reports"
DEFAULT_REQUEST_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_CONCURRENCY = 5
DEFAULT_RETRY_COUNT = 2
DEFAULT_RETRY_BACKOFF_SECONDS = 1.0

# Response bodies larger than this are truncated before evaluation/storage — a defensive
# cap so a misbehaving or malicious target can't exhaust memory or bloat reports.
MAX_RESPONSE_BYTES = 512_000

# Hard cap on HTTP redirects followed by the generic HTTP target (SSRF hardening).
MAX_HTTP_REDIRECTS = 2


class ExitCode(IntEnum):
    """Process exit codes returned by the CLI. Documented in docs/architecture.md."""

    SUCCESS = 0
    FINDINGS = 1
    USAGE_ERROR = 2
    TARGET_ERROR = 3
