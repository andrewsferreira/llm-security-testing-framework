"""SARIF 2.1.0 report, adapted from dynamic testing to a static-analysis-shaped format so
results can be consumed by GitHub code scanning and similar tooling.

Only FAILED results become SARIF "results" (a passing security test isn't a "finding" to
report). `artifactLocation` points at the payload YAML file for the test's category rather
than a specific line — this is dynamic testing, not static analysis, so there's no source
line to point to; see docs/scoring-model.md and docs/threat-model.md for this and other
documented limitations.
"""

from __future__ import annotations

import json
from typing import Any

from llmsec.core.scoring import CampaignSummary
from llmsec.models.campaign import Campaign
from llmsec.models.result import TestResult
from llmsec.models.test_case import Severity

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
_SARIF_LEVELS: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def _rule(finding: TestResult) -> dict[str, Any]:
    return {
        "id": finding.test_id,
        "name": finding.test_name.replace(" ", ""),
        "shortDescription": {"text": finding.test_name},
        "fullDescription": {"text": finding.explanation},
        "helpUri": "https://github.com/andrewsferreira/llm-security-testing-framework",
        "properties": {"category": finding.category.value, "severity": finding.severity.value},
    }


def _result(finding: TestResult, campaign: Campaign) -> dict[str, Any]:
    return {
        "ruleId": finding.test_id,
        "level": _SARIF_LEVELS[finding.severity],
        "message": {"text": finding.explanation},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f"payloads/{finding.category.value}.yaml"},
                    "region": {"startLine": 1},
                }
            }
        ],
        "properties": {
            "riskScore": finding.risk_score,
            "confidence": finding.confidence,
            "evaluator": finding.evaluator,
            "campaignId": campaign.id,
        },
    }


def render(campaign: Campaign, summary: CampaignSummary) -> str:
    findings = summary.findings
    rules = {finding.test_id: _rule(finding) for finding in findings}

    sarif = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "llmsec",
                        "informationUri": (
                            "https://github.com/andrewsferreira/llm-security-testing-framework"
                        ),
                        "version": campaign.framework_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": [_result(finding, campaign) for finding in findings],
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"
