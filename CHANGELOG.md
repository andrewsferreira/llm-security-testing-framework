# Changelog

All notable changes to this project are documented here. Format loosely follows [Keep a
Changelog](https://keepachangelog.com/).

## [0.1.0] — Unreleased

Initial portfolio release.

### Added
- CLI (`llmsec scan`, `list-tests`, `validate-config`, `report`, `version`) built on Typer.
- Async execution engine: bounded concurrency, per-test timeout, retry with backoff, optional
  rate limit, stop-on-critical.
- 9 attack-category test suites (65 payloads): direct/indirect prompt injection, jailbreak,
  system-prompt leakage, data exfiltration, tool abuse, context manipulation, insecure output
  handling, excessive agency.
- 5 evaluators: keyword, regex, lexical-similarity ("semantic"), tool-call policy, composite.
- 4 report formats: JSON, Markdown, HTML (self-contained, filterable), SARIF 2.1.0.
- A lab-specific risk-scoring model (severity × confidence × exploitability).
- Target adapters: generic HTTP (configurable JSON envelope), in-process mock (for fast tests),
  optional OpenAI/Anthropic-native provider adapter.
- A bundled lab (`lab/`): a rule-based, deterministic FastAPI chatbot/agent with vulnerable and
  hardened modes, six simulated tools, and a fully fictional data set.
- SSRF/URL-safety guard defaulting to local-only targets.
- Central redaction of secrets/PII in logs, evidence, and reports.
- Docker images (framework + lab, non-root, multi-stage) and a Docker Compose stack.
- GitHub Actions: CI (lint/type-check/test/build), security (Bandit SARIF, pip-audit, Gitleaks,
  Hadolint), and tag-triggered release (build + changelog + GitHub release; no automatic PyPI
  publish).
- Full documentation set: architecture, STRIDE threat model, scoring model, test-case authoring
  guide, target-integration guide, ethical-use policy, roadmap, and a portfolio demo script.
