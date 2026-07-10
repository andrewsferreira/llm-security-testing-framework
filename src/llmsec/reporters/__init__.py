"""Renders a Campaign + its CampaignSummary into one or more report formats on disk."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from llmsec.core.scoring import CampaignSummary, summarize
from llmsec.models.campaign import Campaign
from llmsec.reporters import html_reporter, json_reporter, markdown_reporter, sarif_reporter
from llmsec.utils.serialization import resolve_output_path

Renderer = Callable[[Campaign, CampaignSummary], str]

RENDERERS: dict[str, Renderer] = {
    "json": json_reporter.render,
    "markdown": markdown_reporter.render,
    "html": html_reporter.render,
    "sarif": sarif_reporter.render,
}

FILE_NAMES: dict[str, str] = {
    "json": "results.json",
    "markdown": "report.md",
    "html": "report.html",
    "sarif": "results.sarif",
}

__all__ = ["FILE_NAMES", "RENDERERS", "summarize", "write_reports"]


def write_reports(campaign: Campaign, *, formats: list[str], output_dir: Path) -> dict[str, Path]:
    """Render `campaign` in every requested format and write each to `output_dir`.

    Returns a mapping of format name -> path written.
    """
    summary = summarize(campaign)
    written: dict[str, Path] = {}
    for fmt in formats:
        renderer = RENDERERS[fmt]
        content = renderer(campaign, summary)
        path = resolve_output_path(output_dir, FILE_NAMES[fmt])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        written[fmt] = path
    return written
