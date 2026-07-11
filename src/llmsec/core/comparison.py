"""Compares multiple already-completed campaigns side by side — e.g. the same suite run
against several providers, or a lab's vulnerable vs. hardened mode. Reuses `core/scoring.py`'s
`summarize()` per campaign rather than duplicating its logic; this module only assembles the
per-campaign summaries into one comparison-shaped structure for `reporters/comparison_reporter.py`
to render.

`build_comparison_entry` is also reused by `core/dashboard.py` — a dashboard is, at its core,
"the same per-campaign entry this module builds, for however many reports exist, sorted by
time" rather than a fundamentally different computation.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from llmsec.core.scoring import SeverityDistribution, summarize
from llmsec.models.campaign import Campaign
from llmsec.models.target import ProviderTargetConfig


def campaign_label(campaign: Campaign) -> str:
    """A short human label for a campaign: `provider:model` for a provider target (the common
    case this view exists for — comparing providers), else the target's base URL."""
    target = campaign.target
    if isinstance(target, ProviderTargetConfig):
        return f"{target.provider}:{target.model}"
    return target.base_url


class ComparisonEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    campaign_id: str
    label: str
    suite: str
    started_at: datetime
    total_tests: int
    passed: int
    failed: int
    inconclusive: int
    errors: int
    severity_distribution_findings: SeverityDistribution
    category_distribution_findings: dict[str, int]
    average_finding_risk_score: float


class CampaignComparison(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entries: list[ComparisonEntry]
    # Union of every category that has a nonzero-possible slot across all entries, sorted —
    # what the comparison reporters iterate to build category-by-campaign tables/charts.
    categories: list[str]


def build_comparison_entry(campaign: Campaign) -> ComparisonEntry:
    summary = summarize(campaign)
    risk_scores = [f.risk_score for f in summary.findings if f.risk_score is not None]
    average_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0

    return ComparisonEntry(
        campaign_id=summary.campaign_id,
        label=campaign_label(campaign),
        suite=summary.suite,
        started_at=summary.started_at,
        total_tests=summary.total_tests,
        passed=summary.passed,
        failed=summary.failed,
        inconclusive=summary.inconclusive,
        errors=summary.errors,
        severity_distribution_findings=summary.severity_distribution_findings,
        category_distribution_findings=summary.category_distribution_findings,
        average_finding_risk_score=round(average_risk, 2),
    )


def compare_campaigns(campaigns: list[Campaign]) -> CampaignComparison:
    if len(campaigns) < 2:
        raise ValueError("compare_campaigns requires at least 2 campaigns to compare.")

    entries = [build_comparison_entry(campaign) for campaign in campaigns]
    categories: set[str] = set()
    for entry in entries:
        categories.update(entry.category_distribution_findings)

    return CampaignComparison(entries=entries, categories=sorted(categories))
