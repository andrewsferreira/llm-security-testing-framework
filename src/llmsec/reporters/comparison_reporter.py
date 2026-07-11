"""Renders a `CampaignComparison` (core/comparison.py) — 2+ campaigns run side by side, e.g.
different providers against the same suite, or a lab's vulnerable vs. hardened mode — into
Markdown or a self-contained HTML page (same "no external stylesheets/fonts/scripts" property
as the single-campaign HTML report).
"""

from __future__ import annotations

import json

from llmsec.core.comparison import CampaignComparison
from llmsec.reporters.charts import horizontal_bar_chart
from llmsec.reporters.html_reporter import default_templates_dir
from llmsec.utils.serialization import to_jsonable

_COMPARISON_TEMPLATE_NAME = "comparison.html.j2"

# Cycled across campaigns for chart bars — reuses the report page's own existing CSS custom
# properties rather than inventing new colors, so a themed color changes in exactly one place.
_PALETTE = ("--critical", "--high", "--medium", "--low", "--accent", "--pass")


def _color_for(index: int) -> str:
    return _PALETTE[index % len(_PALETTE)]


def render_json(comparison: CampaignComparison) -> str:
    return json.dumps(to_jsonable(comparison), indent=2, ensure_ascii=False) + "\n"


def render_markdown(comparison: CampaignComparison) -> str:
    lines: list[str] = []
    lines.append("# llmsec Campaign Comparison")
    lines.append("")
    lines.append(f"Comparing {len(comparison.entries)} campaign(s).")
    lines.append("")

    lines.append("## Overview")
    lines.append("")
    lines.append("| Label | Suite | Total | Passed | Failed | Inconclusive | Errors | Avg Risk |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for entry in comparison.entries:
        lines.append(
            f"| {entry.label} | {entry.suite} | {entry.total_tests} | {entry.passed} | "
            f"{entry.failed} | {entry.inconclusive} | {entry.errors} | "
            f"{entry.average_finding_risk_score:.2f} |"
        )
    lines.append("")

    header = "| Category | " + " | ".join(e.label for e in comparison.entries) + " |"
    sep = "| --- | " + " | ".join("---" for _ in comparison.entries) + " |"

    lines.append("## Findings by Category")
    lines.append("")
    lines.append(header)
    lines.append(sep)
    for category in comparison.categories:
        row = " | ".join(
            str(entry.category_distribution_findings.get(category, 0))
            for entry in comparison.entries
        )
        lines.append(f"| {category} | {row} |")
    lines.append("")

    lines.append("## Severity Distribution (findings only)")
    lines.append("")
    severity_header = "| Severity | " + " | ".join(e.label for e in comparison.entries) + " |"
    lines.append(severity_header)
    lines.append(sep)
    for field in ("critical", "high", "medium", "low"):
        row = " | ".join(
            str(getattr(entry.severity_distribution_findings, field))
            for entry in comparison.entries
        )
        lines.append(f"| {field} | {row} |")
    lines.append("")

    return "\n".join(lines) + "\n"


def render_html(comparison: CampaignComparison) -> str:
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(
        loader=FileSystemLoader(str(default_templates_dir())),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template(_COMPARISON_TEMPLATE_NAME)

    category_charts = {
        category: horizontal_bar_chart(
            [
                (
                    entry.label,
                    entry.category_distribution_findings.get(category, 0),
                    _color_for(i),
                )
                for i, entry in enumerate(comparison.entries)
            ]
        )
        for category in comparison.categories
    }
    overview_chart = horizontal_bar_chart(
        [(entry.label, entry.failed, _color_for(i)) for i, entry in enumerate(comparison.entries)]
    )

    return template.render(
        comparison=comparison,
        category_charts=category_charts,
        overview_chart=overview_chart,
    )
