# Ethical Use

**Use this framework only against systems you own or are explicitly authorized to test.**

This applies regardless of how easy or tempting it is to point `--target` at something else.
`security.allow_external_targets` defaults to `false` specifically to make scanning anything
other than a local/private target a deliberate, visible configuration change — not an accident.

## What "authorized" means in practice

- You own the target, or
- You have explicit, documented permission from whoever does (a signed pentest engagement, a
  written go-ahead from the system owner, a bug bounty program's published scope), and
- Your testing stays within whatever scope/rate limits that authorization specifies.

If you're not sure whether you're authorized, you aren't — stop and go get clarity first.

## What this framework will not help you do

- Test systems you don't have permission to test. The local-only default and the SSRF/URL
  safety guard (`utils/url_safety.py`, `docs/threat-model.md`) exist to make that the default
  path, not an edge case.
- Cause real harm. Every "vulnerability" the bundled lab demonstrates is entirely simulated —
  fictional secrets (`SYSTEM_SECRET_MARKER_7F3A`, `FAKE_API_KEY_12345`, etc.), a fake customer
  database, a fake filesystem, tools that log a simulated action and return canned data instead
  of performing real I/O. Nothing in `lab/app` sends a real email, reads a real file, or makes a
  real HTTP request, in either mode. See `lab/README.md`.
- Execute anything derived from a target's output. The `insecure_output_handling` category
  *detects* whether a target hands back a dangerous-looking script/SQL fragment/shell command —
  it never runs, renders, or evaluates that output. There is no `eval`/`exec` anywhere in this
  codebase.

## Reporting and data handling

- `security.redact_sensitive_values` (on by default) strips secret-shaped strings from anything
  stored or reported — but treat `reports/` as sensitive regardless, especially against a real
  target. It contains request/response evidence, which may include content you don't want to
  share broadly even redacted.
- If you're testing a real target under a bug bounty or responsible disclosure program, follow
  that program's disclosure timeline and process — this framework produces evidence, not a
  disclosure workflow.

## Payloads are safe-by-construction, not defanged versions of something dangerous

The prompts in `payloads/*.yaml` are written to *demonstrate a technique* against a
security-testing lab, not to cause real-world harm if they somehow reached a production system.
They don't request or contain illegal content, real exploit code, or real malware. If you write
your own payloads to test a real target, keep them scoped the same way: testing *whether a
mitigation works*, not attempting to actually cause damage.

## If you find a real vulnerability

If you use this framework (or its ideas) and find a genuine vulnerability in a system you're
authorized to test, follow that system owner's responsible disclosure process. This project has
no relationship to any specific vendor's disclosure program.
