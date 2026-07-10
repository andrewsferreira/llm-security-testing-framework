# Contributing

Thanks for considering a contribution. This is a portfolio project, maintained as time allows —
response times may vary, but issues and PRs are welcome.

## Setup

```bash
git clone https://github.com/andrewsferreira/llm-security-testing-framework.git
cd llm-security-testing-framework
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a PR

```bash
ruff check .
ruff format --check .
mypy src/llmsec lab
pytest tests/ --cov=llmsec --cov-report=term-missing
bandit -r src lab -c pyproject.toml
pip-audit
```

All of the above run in CI (`.github/workflows/ci.yml`, `security.yml`); running them locally
first saves a round trip.

## Adding a new attack test case

See `docs/creating-test-cases.md` — it's data (YAML), not code, but it does need to actually
trigger the right behavior against the bundled lab; that doc explains how to verify that with
`tests/integration/test_all_payloads_against_lab.py`.

## Adding a new evaluator or target

See the relevant section of `docs/architecture.md`, plus `examples/custom_test.py` /
`examples/custom_target.py` for runnable starting points.

## Commit style

Plain, descriptive commit messages explaining *why*, not just *what* — no fixed convention
enforced, but look at `git log` for the tone this project uses.

## Reporting a security issue in the framework itself

See `SECURITY.md` — please don't open a public issue for that.
