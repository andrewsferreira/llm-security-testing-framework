"""Campaign execution tuning and the runtime record of a completed campaign."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from llmsec.models.result import TestResult
from llmsec.models.target import TargetConfig


class CampaignConfig(BaseModel):
    """Execution tuning knobs for a scan run (the `campaign:` section of a config file)."""

    model_config = ConfigDict(extra="forbid")

    max_concurrency: int = Field(default=5, ge=1, le=50)
    retry_count: int = Field(default=2, ge=0, le=10)
    retry_backoff_seconds: float = Field(default=1.0, ge=0)
    rate_limit_per_second: float | None = Field(default=None, gt=0)
    stop_on_critical: bool = False


class Campaign(BaseModel):
    """The runtime record of a scan run: identity, target, and accumulated results."""

    model_config = ConfigDict(extra="forbid")

    id: str
    suite: str
    target: TargetConfig
    config: CampaignConfig
    framework_version: str

    started_at: datetime
    finished_at: datetime | None = None

    total_tests: int = 0
    results: list[TestResult] = Field(default_factory=list)

    @property
    def passed_count(self) -> int:
        return sum(1 for r in self.results if r.status == "passed")

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.results if r.status == "failed")

    @property
    def inconclusive_count(self) -> int:
        return sum(1 for r in self.results if r.status == "inconclusive")

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if r.status == "error")
