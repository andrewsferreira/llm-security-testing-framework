"""Aggregates every campaign report found under a directory into a single dashboard view.

Computed fresh from whatever `**/results.json` files exist under the given directory each time
this runs — no database, no persistent service. This was a deliberate design choice (see
`docs/architecture-review.md`'s "Open decisions"), not a placeholder for one: it keeps the
project's "no external services required" property intact, at the cost of scaling to however
many reports you're willing to point it at in one run (fine for a portfolio/CI-artifact use
case; a fleet running thousands of campaigns a day would want a real datastore instead).

Reuses `core/comparison.py`'s `build_comparison_entry` rather than duplicating it — a dashboard
is "the same per-campaign entry, for however many reports exist, sorted by time, plus an
aggregate rollup," not a fundamentally different computation.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict

from llmsec.core.comparison import ComparisonEntry, build_comparison_entry
from llmsec.core.scoring import SeverityDistribution
from llmsec.models.campaign import Campaign
from llmsec.models.test_case import AttackCategory


def discover_campaign_report_paths(reports_dir: Path) -> list[Path]:
    """Every `results.json` found anywhere under `reports_dir`, sorted for deterministic
    output. Doesn't validate their contents — that happens when each is loaded."""
    if not reports_dir.is_dir():
        return []
    return sorted(reports_dir.glob("**/results.json"))


class DashboardData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entries: list[ComparisonEntry]  # sorted by started_at, oldest first
    total_campaigns: int
    total_tests: int
    total_findings: int
    severity_distribution_total: SeverityDistribution
    category_distribution_total: dict[str, int]


def build_dashboard(campaigns: list[Campaign]) -> DashboardData:
    if not campaigns:
        raise ValueError("build_dashboard requires at least 1 campaign.")

    entries = sorted((build_comparison_entry(c) for c in campaigns), key=lambda e: e.started_at)

    severity_total = SeverityDistribution()
    category_total: dict[str, int] = dict.fromkeys((c.value for c in AttackCategory), 0)
    total_tests = 0
    total_findings = 0
    for entry in entries:
        total_tests += entry.total_tests
        total_findings += entry.failed
        for field in ("critical", "high", "medium", "low"):
            current = getattr(severity_total, field)
            setattr(
                severity_total,
                field,
                current + getattr(entry.severity_distribution_findings, field),
            )
        for category, count in entry.category_distribution_findings.items():
            category_total[category] = category_total.get(category, 0) + count

    return DashboardData(
        entries=entries,
        total_campaigns=len(entries),
        total_tests=total_tests,
        total_findings=total_findings,
        severity_distribution_total=severity_total,
        category_distribution_total=category_total,
    )
