# LLM Security Testing Framework

**A security testing framework for LLM-backed chatbots, agents, and tool-calling APIs.**

> **Use only against systems you own or are explicitly authorized to test.** See
> [`docs/ethical-use.md`](docs/ethical-use.md). By default this framework refuses to scan
> anything other than a local/private target (`security.allow_external_targets: false`) — that's
> a deliberate design choice, not a limitation to work around.

[![CI](https://github.com/andrewsferreira/llm-security-testing-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/andrewsferreira/llm-security-testing-framework/actions/workflows/ci.yml)
[![Security](https://github.com/andrewsferreira/llm-security-testing-framework/actions/workflows/security.yml/badge.svg)](https://github.com/andrewsferreira/llm-security-testing-framework/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](pyproject.toml)

## What this is

llmsec runs structured security test campaigns — prompt injection, jailbreaks, system-prompt
leakage, data exfiltration, tool abuse, context manipulation, insecure output handling, and
excessive agency — against LLM-backed HTTP targets, and produces JSON/Markdown/HTML/SARIF
reports. It ships with its own local, fully simulated target (a "vulnerable" and a "hardened"
mode of the same fake chatbot) so the whole thing runs and demonstrates something real with no
API keys, no external services, and no cost.

## The problem this addresses

LLM-backed applications introduce a class of security issues that don't map cleanly onto
traditional AppSec tooling: a SAST scanner doesn't catch "the model followed an instruction
embedded in a retrieved document," and a DAST scanner doesn't know what a refusal is supposed to
look like. The [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
names these risks; this project is a concrete, runnable way to test for several of them against
your own application, plus a from-scratch lab to demonstrate the difference between an
unmitigated and a mitigated target on the exact same test suite.

## Key capabilities

- **9 attack categories, 65 test cases** — direct & indirect prompt injection, jailbreak,
  system-prompt leakage, data exfiltration, tool abuse, context manipulation, insecure output
  handling, excessive agency. Test cases are YAML data (`payloads/*.yaml`), not code.
- **A bundled lab target** — a rule-based, deterministic FastAPI chatbot/agent with vulnerable
  and hardened modes, so every category has something real to demonstrate against, locally,
  for free.
- **5 pluggable evaluators** — keyword, regex, lexical-similarity ("semantic"), tool-call
  policy, and a composite combinator — each documented honestly about what it actually checks
  (see [`docs/scoring-model.md`](docs/scoring-model.md)).
- **An async execution engine** — bounded concurrency, per-test timeout, retry with backoff,
  optional rate limiting, and stop-on-critical.
- **4 report formats** — JSON, Markdown, a self-contained filterable HTML report, and SARIF
  2.1.0 (for GitHub code scanning).
- **A documented risk-scoring model** — explicit formula, explicitly labeled as a lab heuristic,
  not an industry standard.
- **Target-agnostic** — a configurable generic HTTP envelope for your own API, plus an optional
  adapter that speaks OpenAI's/Anthropic's native chat APIs directly.
- **SSRF-aware by default** — refuses non-local targets unless you explicitly opt in.
- **Fully containerized** — Docker images for both the framework and the lab, a Docker Compose
  stack, and GitHub Actions for CI, security scanning, and releases.

## Architecture

Three independently useful pieces: the **framework** (`src/llmsec/`, pip-installable, has a CLI),
the **lab** (`lab/`, a standalone FastAPI app, no dependency on the framework), and the
**payloads** (`payloads/*.yaml`, pure data). See [`docs/architecture.md`](docs/architecture.md)
for the full breakdown and a diagram of the execution flow.

```
llmsec CLI → engine → registry (loads payloads/*.yaml)
                     → runner (async execution) → target (HTTP) → lab / your API
                     → evaluators → evidence (redaction) → scoring → reporters
```

## Test categories

| Category | What it tests | OWASP LLM mapping |
| --- | --- | --- |
| Direct Prompt Injection | Explicit attempts to override/ignore/bypass instructions | LLM01 |
| Indirect Prompt Injection | Instructions embedded in untrusted content (documents, tool output) | LLM01 |
| Jailbreak | Roleplay, hypotheticals, encoding, authority impersonation, multi-turn escalation | LLM01 |
| System Prompt Leakage | Extracting hidden instructions, internal rules, tool descriptions | LLM07 |
| Data Exfiltration | Extracting in-context secrets directly, by transformation, or across turns | LLM02 |
| Tool Abuse | Unauthorized/out-of-scope tool calls, path traversal, disallowed destinations | LLM06 |
| Context Manipulation | Poisoning conversational memory, false facts, role/task redefinition | LLM01 |
| Insecure Output Handling | Whether output is dangerous if consumed unescaped downstream | LLM05 |
| Excessive Agency | Acting without confirmation, chaining unrequested actions | LLM06 |

## Quick start

```bash
git clone https://github.com/andrewsferreira/llm-security-testing-framework.git
cd llm-security-testing-framework
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Start the bundled lab (vulnerable mode) in the background
uvicorn lab.app.main:app --port 8000 &

# Scan it
llmsec scan --target http://localhost:8000 --suite all \
  --config configs/local.yaml --output reports/demo
```

That's the whole thing — no API keys required. See
[`docs/portfolio-demo.md`](docs/portfolio-demo.md) for a fuller walkthrough including the
hardened-mode comparison.

## Local installation

Requires Python 3.12+.

```bash
python3.12 -m venv .venv
source .venv/bin/activate          # .venv\Scripts\activate on Windows
pip install -e ".[dev]"
llmsec version
```

Run the checks CI runs:

```bash
ruff check . && ruff format --check .
mypy src/llmsec lab
pytest tests/ --cov=llmsec --cov-report=term-missing
bandit -r src lab -c pyproject.toml
pip-audit
```

## Using Docker

```bash
docker compose up -d lab                 # starts the lab target, waits for /health
docker compose run --rm scanner \
  llmsec scan --target http://lab:8000 --suite all \
  --config configs/docker.yaml --output reports
docker compose down
```

Switch the lab's mode with `LAB_MODE=hardened docker compose up -d lab`. `configs/docker.yaml`
documents why it sets `allow_external_targets: true` (the `lab` Compose hostname isn't a literal
loopback IP, even though it's just as contained as localhost within that network — see
[`docs/threat-model.md`](docs/threat-model.md)). Reports land in `./reports` on the host via a
bind mount.

## CLI examples

```bash
llmsec version
llmsec validate-config --config configs/local.yaml
llmsec list-tests
llmsec list-tests --category jailbreak
llmsec scan --target http://localhost:8000 --suite all --config configs/local.yaml --output reports/run-001
llmsec scan --target http://localhost:8000 --suite tool_abuse --config configs/local.yaml --output reports/run-002
llmsec report --input reports/run-001/campaign-.../results.json --format html --format markdown
llmsec compare --input reports/run-001/campaign-.../results.json --input reports/run-002/campaign-.../results.json
llmsec dashboard --reports-dir reports --output reports/dashboard.html
```

## Example result

```
Campaign campaign-20260101T000000Z-abc12345 (all): 65 test(s)
  passed:       0
  failed:       65
  inconclusive: 0
  errors:       0
  json      : reports/run-001/campaign-.../results.json
  markdown  : reports/run-001/campaign-.../report.md
  html      : reports/run-001/campaign-.../report.html
  sarif     : reports/run-001/campaign-.../results.sarif
```

Run the same suite against `LAB_MODE=hardened` and every one of those 65 becomes `passed`, with
`failed: 0` and exit code `0` instead of `1` — the same test suite, the same framework, showing a
real difference in target behavior.

## Example report

The HTML report is self-contained (no CDN, no external fonts/scripts) with category/severity
filters, an executive summary, severity/category distribution tables, and per-finding evidence
(redacted request/response, matched indicators, explanation, remediation). Generate one and open
it locally:

```bash
open reports/run-001/campaign-*/report.html   # macOS; xdg-open on Linux
```

## Scoring model

```
risk_score = severity_weight × confidence × exploitability     (rescaled to 0–10)
```

Explicitly documented as a lab-specific heuristic for ranking findings within one campaign, not
an industry-standard metric — full breakdown, including exactly how each evaluator sets its
`confidence`, in [`docs/scoring-model.md`](docs/scoring-model.md).

## Creating custom test cases

Test cases are YAML, validated against a Pydantic schema — no Python required to add one. See
[`docs/creating-test-cases.md`](docs/creating-test-cases.md) for the schema, the 5 evaluator
config shapes, and — importantly — how to verify a new payload actually triggers the intended
behavior against the bundled (rule-based) lab. `examples/custom_test.py` is a runnable example
of defining and evaluating a test case directly in Python instead.

## Creating a custom target

Implement one async method (`Target.send`) to integrate with anything the generic HTTP envelope
can't already express — see [`docs/target-integration.md`](docs/target-integration.md) and
`examples/custom_target.py` for a complete, runnable example.

## CI/CD integration

Three GitHub Actions workflows ship in this repo:

- **`.github/workflows/ci.yml`** — ruff, mypy, the full pytest suite with coverage, package build.
- **`.github/workflows/security.yml`** — Bandit (SARIF uploaded to code scanning), pip-audit,
  Gitleaks, Hadolint on both Dockerfiles.
- **`.github/workflows/release.yml`** — tag-triggered build + changelog + GitHub release. PyPI
  publishing is present but commented out and requires an explicit secret — never automatic.

The SARIF report format (`reporters/sarif_reporter.py`) is meant to plug into the same code
scanning pipeline these workflows use, alongside Bandit's own SARIF output.

## Limitations

Said plainly, not buried:

- **The bundled lab is a rule-based, deterministic simulator — not a real LLM.** It demonstrates
  the *mechanics* of detection (a marker leaking, a tool call executing unauthorized), not what
  a real model would actually do. See [`docs/creating-test-cases.md`](docs/creating-test-cases.md).
- **Evaluators are heuristic**, not formal verification. `INCONCLUSIVE` means "a human should
  look at this," not "safe." The `semantic` evaluator is lexical token-overlap, explicitly not
  embedding-based — see [`docs/scoring-model.md`](docs/scoring-model.md).
- **The risk score is a lab-specific heuristic**, not a comparable, industry-standard metric.
- **SSRF protection is a static host check**, not DNS-aware — it doesn't defend against DNS
  rebinding. See [`docs/threat-model.md`](docs/threat-model.md).
- **65 test cases is a solid demonstration set, not exhaustive coverage** of any of the 9
  categories.
- **Docker build/compose were validated with a real Docker runtime** (installed via
  `colima` for this project) during development — see `docs/threat-model.md` and the project's
  own commit history for exactly what was and wasn't tested live.
- This is a **portfolio project**, not a production security product. Read the code before
  trusting it with anything that matters.

## Roadmap

See [`docs/roadmap.md`](docs/roadmap.md) — a real embedding-based semantic evaluator, broader
payload coverage, a richer multi-turn conversation model, and DNS-aware SSRF checks are the
most likely next steps.

## Security

See [`SECURITY.md`](SECURITY.md) for how to report a vulnerability in the framework itself, and
[`docs/threat-model.md`](docs/threat-model.md) for the full STRIDE analysis of the scanner, the
lab, and how they're typically deployed together.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the dev setup and pre-PR checklist, and
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) for participation expectations.

## License

[MIT](LICENSE)

## Author

**Andrews Ferreira**

- GitHub: [github.com/andrewsferreira](https://github.com/andrewsferreira)
- Medium: [medium.com/@andrewsferreira](https://medium.com/@andrewsferreira)
