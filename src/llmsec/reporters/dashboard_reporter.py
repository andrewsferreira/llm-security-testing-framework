"""Renders `DashboardData` (core/dashboard.py) — every campaign report found under a directory,
aggregated and sorted by time — into a single self-contained HTML page. Same "no external
stylesheets/fonts/scripts" property as every other HTML report in this project.
"""

from __future__ import annotations

from llmsec.core.dashboard import DashboardData
from llmsec.reporters.charts import horizontal_bar_chart, trend_chart_svg
from llmsec.reporters.html_reporter import default_templates_dir

_TEMPLATE_NAME = "dashboard.html.j2"


def render(dashboard: DashboardData) -> str:
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(
        loader=FileSystemLoader(str(default_templates_dir())),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template(_TEMPLATE_NAME)

    severity_chart = horizontal_bar_chart(
        [
            ("Critical", dashboard.severity_distribution_total.critical, "--critical"),
            ("High", dashboard.severity_distribution_total.high, "--high"),
            ("Medium", dashboard.severity_distribution_total.medium, "--medium"),
            ("Low", dashboard.severity_distribution_total.low, "--low"),
        ]
    )
    category_chart = horizontal_bar_chart(
        [
            (category, count, "--accent")
            for category, count in sorted(dashboard.category_distribution_total.items())
        ]
    )
    trend_svg = trend_chart_svg(dashboard.entries)

    return template.render(
        dashboard=dashboard,
        severity_chart=severity_chart,
        category_chart=category_chart,
        trend_svg=trend_svg,
    )
