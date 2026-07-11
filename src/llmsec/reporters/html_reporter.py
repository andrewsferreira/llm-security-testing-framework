"""HTML report: a single self-contained page (local CSS only, no external stylesheets/fonts/
scripts) with client-side category/severity filtering via a small inline script. Jinja2's
autoescaping is on, which matters here specifically: some findings' evidence is itself
HTML/script/SQL payload text (insecure_output_handling), and it must render as inert text, not
be interpreted by the browser.
"""

from __future__ import annotations

import os
from importlib import resources
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from llmsec.attacks import ATTACK_CATALOG
from llmsec.core.scoring import CampaignSummary
from llmsec.models.campaign import Campaign
from llmsec.models.test_case import AttackCategory, Severity
from llmsec.reporters.charts import findings_timeline_svg, severity_bar_chart_svg

TEMPLATES_DIR_ENV_VAR = "LLMSEC_TEMPLATES_DIR"
_TEMPLATE_NAME = "report.html.j2"


def default_templates_dir() -> Path:
    override = os.environ.get(TEMPLATES_DIR_ENV_VAR)
    if override:
        return Path(override)

    packaged = resources.files("llmsec") / "templates"
    if packaged.is_dir():
        return Path(str(packaged))

    return Path(__file__).resolve().parents[3] / "templates"


def render(campaign: Campaign, summary: CampaignSummary) -> str:
    env = Environment(
        loader=FileSystemLoader(str(default_templates_dir())),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template(_TEMPLATE_NAME)
    return template.render(
        campaign=campaign,
        summary=summary,
        categories=sorted(c.value for c in AttackCategory),
        severities=[
            s.value for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        ],
        catalog={category.value: info for category, info in ATTACK_CATALOG.items()},
        severity_chart_svg=severity_bar_chart_svg(summary.severity_distribution_findings),
        timeline_svg=findings_timeline_svg(
            summary.findings,
            started_at=campaign.started_at,
            duration_seconds=summary.duration_seconds,
        ),
    )
