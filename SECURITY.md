# Security Policy

## Reporting a vulnerability in this framework

If you find a security issue in llmsec itself (not in a target you've scanned with it), please
report it privately via [GitHub Security
Advisories](https://github.com/andrewsferreira/llm-security-testing-framework/security/advisories/new)
rather than opening a public issue. Include what you found, how to reproduce it, and its
potential impact.

This is a portfolio project without a formal SLA, but security reports will be prioritized over
other issues.

## Scope

In scope:
- The `llmsec` framework itself (`src/llmsec/`): the CLI, engine, targets, evaluators,
  reporters.
- The bundled lab (`lab/`), Dockerfiles, and GitHub Actions workflows.

Out of scope:
- Vulnerabilities in a *target* you scan with llmsec — report those to that target's own owner,
  following their disclosure process.
- The intentionally "vulnerable" behavior of the lab's `LAB_MODE=vulnerable` mode — that's the
  documented, deliberate purpose of that mode (see `lab/README.md`), not a bug.

## Supported versions

This project does not yet have a stable release line; security fixes land on `main`. Once
tagged releases exist, this section will list which are supported.

## A note on how this framework is meant to be used

llmsec is built to be used only against systems you own or are explicitly authorized to test —
see `docs/ethical-use.md`. It defaults to refusing non-local/private targets
(`security.allow_external_targets: false`) specifically to make scanning anything else a
deliberate action, not an accident.
