"""Markdown report: executive summary, distributions, and per-finding evidence."""

from __future__ import annotations

from llmsec.core.scoring import CampaignSummary
from llmsec.models.campaign import Campaign
from llmsec.models.result import ResultStatus

_LIMITATIONS = (
    "- The lab target is a rule-based simulator, not a real LLM; results reflect the "
    "framework's mechanics, not any real model's behavior.\n"
    "- Evaluators are heuristic (keyword/regex/lexical-similarity/policy); INCONCLUSIVE "
    "results mean manual review is warranted, not that the target is safe.\n"
    "- Risk scores are a lab-specific heuristic (see docs/scoring-model.md), not an "
    "industry-standard metric.\n"
    "- SSRF/URL-safety guards are best-effort (see docs/threat-model.md), not a complete "
    "mitigation."
)


def _status_emoji(status: ResultStatus) -> str:
    return {
        ResultStatus.PASSED: "PASS",
        ResultStatus.FAILED: "FAIL",
        ResultStatus.INCONCLUSIVE: "INCONCLUSIVE",
        ResultStatus.ERROR: "ERROR",
    }[status]


def render(campaign: Campaign, summary: CampaignSummary) -> str:
    lines: list[str] = []
    lines.append(f"# llmsec Security Report — {summary.campaign_id}")
    lines.append("")
    lines.append(
        "**Use only against systems you own or are explicitly authorized to test.** "
        "See docs/ethical-use.md."
    )
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Target:** {summary.target_base_url}")
    lines.append(f"- **Suite:** {summary.suite}")
    lines.append(f"- **Framework version:** {summary.framework_version}")
    lines.append(f"- **Started:** {summary.started_at.isoformat()}")
    lines.append(f"- **Duration:** {summary.duration_seconds:.2f}s")
    lines.append(
        f"- **Total tests:** {summary.total_tests} "
        f"(passed {summary.passed}, failed {summary.failed}, "
        f"inconclusive {summary.inconclusive}, errors {summary.errors})"
    )
    lines.append("")

    lines.append("## Severity Distribution (findings only)")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for field in ("critical", "high", "medium", "low"):
        lines.append(f"| {field} | {getattr(summary.severity_distribution_findings, field)} |")
    lines.append("")

    lines.append("## Category Distribution (findings only)")
    lines.append("")
    lines.append("| Category | Findings |")
    lines.append("| --- | --- |")
    for category, count in sorted(summary.category_distribution_findings.items()):
        lines.append(f"| {category} | {count} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not summary.findings:
        lines.append("No findings — every test case resisted its attack in this campaign.")
        lines.append("")
    else:
        lines.append("| Risk | Severity | Category | Test | Name |")
        lines.append("| --- | --- | --- | --- | --- |")
        for finding in summary.findings:
            lines.append(
                f"| {finding.risk_score:.2f} | {finding.severity.value} | "
                f"{finding.category.value} | {finding.test_id} | {finding.test_name} |"
            )
        lines.append("")

        lines.append("### Evidence")
        lines.append("")
        for finding in summary.findings:
            lines.append(f"#### {finding.test_id} — {finding.test_name}")
            lines.append("")
            lines.append(f"- **Status:** {_status_emoji(finding.status)}")
            lines.append(f"- **Risk score:** {finding.risk_score:.2f}/10")
            lines.append(f"- **Evaluator:** {finding.evaluator}")
            if finding.evidence.matched_indicators:
                lines.append(
                    f"- **Matched indicators:** {', '.join(finding.evidence.matched_indicators)}"
                )
            lines.append(f"- **Explanation:** {finding.explanation}")
            if finding.remediation:
                lines.append(f"- **Remediation:** {finding.remediation}")
            lines.append("")

    lines.append("## Recommendations")
    lines.append("")
    if summary.recommendations:
        for rec in summary.recommendations:
            lines.append(f"- {rec}")
    else:
        lines.append("No specific recommendations — no findings in this campaign.")
    lines.append("")

    lines.append("## Limitations")
    lines.append("")
    lines.append(_LIMITATIONS)
    lines.append("")

    return "\n".join(lines) + "\n"
