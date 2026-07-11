# Changelog

All notable changes to this project are documented here. Format loosely follows [Keep a
Changelog](https://keepachangelog.com/).

## [Unreleased]

Enterprise-hardening pass on top of the 0.1.0 build — see `docs/architecture-review.md` and
`TASKS.md` for the full assessment and tracked backlog this is drawn from.

### Changed
- **`TargetConfig` is now a discriminated union** (`GenericHttpTargetConfig` /
  `MockTargetConfig` / `ProviderTargetConfig`) instead of one flat model with every target
  type's fields bolted on. `Target` is generic over its config type, so each concrete target's
  `self.config` is narrowed to its own subtype. `ProviderTargetConfig.provider`/`.model`/
  `.auth_token_env` are now required fields, validated at config-load time instead of at
  target-construction time.
- Fixed a real bug this refactor surfaced: a config's `target:` section that omits `type:`
  now still defaults to `generic_http` (documented behavior) via an explicit
  `model_validator(mode="before")` on `Config` — Pydantic discriminated unions require the
  discriminator field present in the input and don't support an implicit default variant.
- **The CLI is now Rich-based.** `version`, `validate-config`, `list-tests`, `scan`, and
  `report` all render through a new `Renderer` abstraction (`rendering.py`): colored tables and
  a live progress bar by default, or a single clean JSON object on stdout with `--json`.
  `scan` gained `--verbose`/`--debug` (default logging is now quiet — `WARNING` — instead of
  always `INFO`). `core/engine.py` no longer prints anything itself; it returns data and the
  CLI renders it, which is what makes `--json` a real separate code path instead of scraped
  human-readable text.
- **Provider adapter expanded from 2 to 8 providers**: `openai`, `anthropic` (existing) plus
  `gemini`, `azure_openai`, `ollama`, `mistral`, `bedrock`, `openrouter`. Each is optional and
  gated on its own credential env var — none required to use the framework. `ollama` is the one
  exception where a missing credential isn't an error (a default local install has no auth).
  `bedrock` uses real AWS SigV4 request signing, implemented by hand with stdlib
  `hmac`/`hashlib` (no `boto3` dependency) against the Bedrock Converse API, since its
  credential shape (access key ID + secret + region) doesn't fit the shared bearer-token model.
  `provider_adapter.py` was refactored from an if/elif dispatch to per-provider builder/
  extractor dispatch tables. Added a shared contract test, parametrized over all 8 providers,
  asserting each one's raw credential authenticates the request but never ends up in
  `TargetResponse`/reports or in any log record.
- **Added a dashboard**: `llmsec dashboard --reports-dir <dir> --output <path>` aggregates every
  `results.json` found recursively under a directory into one static, self-contained HTML page
  — overview cards, a findings-trend-over-time chart, a per-campaign table, and aggregate
  severity/category charts. Computed fresh each run from whatever reports exist on disk; no
  database, no persistent service (`core/dashboard.py` reuses `core/comparison.py`'s
  per-campaign entry logic rather than duplicating it).
- **Reporting enhancements**: OWASP + ATLAS mapping now surfaced per finding (not just per
  category) in JSON/Markdown/HTML. Added a **provider/campaign comparison view** —
  `core/comparison.py` + `reporters/comparison_reporter.py` + a new `llmsec compare --input
  <a> --input <b> [...]` CLI command — for comparing 2+ completed campaigns side by side (e.g.
  different providers, or a lab's vulnerable vs. hardened mode) across pass/fail counts,
  severity distribution, and category distribution. Added CDN-free inline SVG charts
  (`reporters/charts.py`, shared by the single-campaign and comparison HTML reports): a
  severity bar chart, a findings timeline, and per-category comparison bars — all colored via
  the page's own existing CSS custom properties, no charting library, no external script.
- **Added a MITRE ATLAS mapping alongside the existing OWASP LLM Top 10 mapping.**
  `AttackSuiteInfo` gained `atlas_technique_id`/`atlas_technique_name`/`atlas_tactic`, populated
  for all 9 attack categories against the public ATLAS matrix. Best-effort where ATLAS's
  attacker-TTP framing doesn't map precisely onto a category (documented in
  `attacks/base.py`). Surfaced in every reporter: a `framework_mappings` key in the JSON
  report, two new columns in the Markdown/HTML category-distribution table, and
  `owaspLlmReference`/`atlasTechniqueId`/`atlasTechniqueName`/`atlasTactic` rule properties in
  the SARIF report.

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
