"""Inline SVG chart helpers, shared by `html_reporter.py` and `comparison_reporter.py`.

CDN-free by construction — no charting library, no external script — matching the HTML report's
existing "no external stylesheets/fonts/scripts" property. Every chart is a plain `<svg>` string
built entirely from framework-controlled data (enum values, counts, elapsed seconds); any text
interpolated into it (a label, a test id) is run through `html.escape` as defense-in-depth, even
though none of it is untrusted target output today. Colors reference the
HTML report's own CSS custom properties (`var(--critical)` etc.) via inline `style` attributes
rather than hardcoded hex values, so the page's one color palette stays the single source of
truth — these SVGs are only ever embedded inline in that same HTML document, never loaded
standalone, so the custom properties resolve correctly.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from html import escape

from llmsec.core.scoring import SeverityDistribution
from llmsec.models.result import TestResult

_SEVERITY_CSS_VAR: dict[str, str] = {
    "critical": "--critical",
    "high": "--high",
    "medium": "--medium",
    "low": "--low",
}


def horizontal_bar_chart(rows: Sequence[tuple[str, int, str]], *, bar_area_width: int = 300) -> str:
    """`rows` is (label, count, css_color_var) triples, e.g. ("Critical", 3, "--critical")."""
    if not rows:
        return ""

    max_count = max((count for _, count, _ in rows), default=0) or 1
    row_height = 28
    label_width = 80
    height = row_height * len(rows) + 10
    width = label_width + bar_area_width + 50

    parts = [
        f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
        f'role="img" aria-label="Bar chart">'
    ]
    for i, (label, count, css_var) in enumerate(rows):
        y = i * row_height + 5
        bar_width = (count / max_count) * bar_area_width if count else 0.0
        text_y = y + row_height / 2 + 4
        parts.append(
            f'<text x="0" y="{text_y:.1f}" font-size="12" '
            f'style="fill:var(--muted)">{escape(label)}</text>'
        )
        parts.append(
            f'<rect x="{label_width}" y="{y}" width="{bar_width:.1f}" '
            f'height="{row_height - 8}" rx="3" style="fill:var({css_var})">'
            f"<title>{escape(label)}: {count}</title></rect>"
        )
        parts.append(
            f'<text x="{label_width + bar_width + 6:.1f}" y="{text_y:.1f}" '
            f'font-size="12" style="fill:var(--text)">{count}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def severity_bar_chart_svg(distribution: SeverityDistribution) -> str:
    rows = [
        ("Critical", distribution.critical, _SEVERITY_CSS_VAR["critical"]),
        ("High", distribution.high, _SEVERITY_CSS_VAR["high"]),
        ("Medium", distribution.medium, _SEVERITY_CSS_VAR["medium"]),
        ("Low", distribution.low, _SEVERITY_CSS_VAR["low"]),
    ]
    return horizontal_bar_chart(rows)


def findings_timeline_svg(
    findings: Sequence[TestResult], *, started_at: datetime, duration_seconds: float
) -> str:
    """A horizontal scatter of failed findings by elapsed time since campaign start, colored by
    severity. Empty string (nothing rendered) if there are no findings or no measurable
    duration — a zero-duration/instant campaign has nothing meaningful to place on a timeline."""
    if not findings or duration_seconds <= 0:
        return ""

    width, height = 600, 90
    axis_y = height - 25
    total_seconds = max(duration_seconds, 0.001)

    parts = [
        f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
        f'role="img" aria-label="Findings timeline">',
        f'<line x1="10" y1="{axis_y}" x2="{width - 10}" y2="{axis_y}" '
        f'style="stroke:var(--border)" stroke-width="1"/>',
    ]
    for finding in findings:
        elapsed = (finding.started_at - started_at).total_seconds()
        fraction = min(max(elapsed / total_seconds, 0.0), 1.0)
        x = 10 + fraction * (width - 20)
        css_var = _SEVERITY_CSS_VAR.get(finding.severity.value, "--muted")
        parts.append(
            f'<circle cx="{x:.1f}" cy="{axis_y}" r="5" style="fill:var({css_var})">'
            f"<title>{escape(finding.test_id)} ({escape(finding.severity.value)}) at "
            f"{elapsed:.1f}s</title></circle>"
        )
    parts.append(
        f'<text x="10" y="{height - 5}" font-size="11" style="fill:var(--muted)">0s</text>'
        f'<text x="{width - 55}" y="{height - 5}" font-size="11" '
        f'style="fill:var(--muted)">{total_seconds:.1f}s</text>'
    )
    parts.append("</svg>")
    return "".join(parts)
