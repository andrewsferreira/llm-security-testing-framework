# Tasks

Tracks the enterprise-hardening initiative on top of the original `llmsec` build (9 commits,
242 tests/95% coverage, live-verified Docker + CI). See `docs/architecture-review.md` for the
Phase 1 assessment this backlog is derived from. Updated continuously as work lands — each item
is marked done/in-progress/pending with the reasoning behind its priority, not just a checkbox.

Execution order follows the dependency-ordered priority list in `docs/architecture-review.md`
§9, not the numeric phase labels from the original request (some of those phases have hard
prerequisites on others, e.g. providers depend on the config refactor).

## Phase 1 — Architecture Review

- [x] Full-repository assessment (strengths, weaknesses, code smells, missing enterprise
      features, maintainability score, scalability, security). **Delivered as
      `docs/architecture-review.md`. No code changed in this phase, as instructed.**

## Phase A — `TargetConfig` discriminated union *(do first: blocks clean provider expansion)* ✅ DONE

- [x] Split `TargetConfig` into a discriminated union keyed on `type`
      (`GenericHttpTargetConfig`, `MockTargetConfig`, `ProviderTargetConfig`), each carrying only
      the fields it actually uses, instead of one flat model with every type's optional fields
      bolted on.
- [x] `Target` is now generic over its config type (`Target[TConfig: BaseTargetConfig]`, PEP 695
      syntax), so each concrete target's `self.config` is narrowed to its own subtype instead of
      the full union — `GenericHttpTarget(Target[GenericHttpTargetConfig])`,
      `MockTarget(Target[MockTargetConfig])`, `ProviderAdapterTarget(Target[ProviderTargetConfig])`.
- [x] `ProviderTargetConfig.provider`/`.model`/`.auth_token_env` are now required fields (not
      optional with a manual runtime check) — a misconfigured provider target now fails at
      config-validation time instead of at `ProviderAdapterTarget` construction time. Removed the
      now-redundant manual `None` checks from `provider_adapter.py`.
- [x] `targets/build_target` dispatches via `isinstance` against the union's concrete member
      types (so mypy narrows the branch), not `config.type ==` comparisons.
- [x] Updated every config YAML/test/example constructing a `TargetConfig` directly (23 files) to
      use the correct concrete subtype for what they're actually testing.
- [x] **Found and fixed a real bug this refactor surfaced**: Pydantic discriminated unions
      require the discriminator field (`type`) to be present in the input — there's no implicit
      "default variant" when it's entirely absent, unlike the old flat model where `type`
      defaulted to `generic_http`. Added a `model_validator(mode="before")` on `Config` that
      injects `type: generic_http` when a config's `target:` section omits it, preserving the
      documented "generic_http is the default" behavior. Covered by an explicit regression test
      (`test_target_type_defaults_to_generic_http_when_omitted`), not just incidental fixture
      coverage.
- [x] Full test suite stayed the contract: 244 tests (2 new), 95% coverage, ruff/mypy strict/
      bandit/pip-audit clean, verified against a real running lab (not just unit tests) before
      and after.

## Phase B — Professional CLI (Rich) ✅ DONE

- [x] Adopted `rich` (already a declared dependency) for tables, colors, and a live progress
      bar during `scan` — a `Renderer` ABC (`rendering.py`) with two implementations,
      `RichRenderer` (default) and `JsonRenderer` (`--json`).
- [x] `--verbose` / `--debug` flags on `scan`, distinct from the previous fixed `INFO` logging
      level (default is now `WARNING`, i.e. quiet; `--verbose` → `INFO`; `--debug` → `DEBUG`).
- [x] `--json` output mode on `version`, `validate-config`, `list-tests`, `scan`, and `report` —
      one JSON object per command on stdout, safe to pipe into `jq`/CI steps.
- [x] `core/engine.py` no longer prints anything — `run_campaign`/`regenerate_reports` return
      data (`Campaign`, `dict[str, Path]`) and the CLI renders it via the chosen `Renderer`.
      This is exactly the separation `docs/architecture-review.md` flagged as missing.
- [x] `core/runner.run_campaign_async` gained an optional `on_result` callback, invoked
      synchronously as each `TestResult` completes, which is what drives the live progress bar
      (and is a no-op in `--json` mode, keeping stdout a single clean JSON document).
- [x] CLI binary name: **decided, stays `llmsec`** — no rename.
- [x] Verified with a real pseudo-TTY run against the live lab (progress bar renders, severity/
      status tables color-coded, `--json`/`--verbose` behave as documented) — not just unit
      tests. 263 tests (18 new), ~95% coverage, ruff/mypy strict/bandit/pip-audit clean.

## Phase C — MITRE ATLAS mapping

- [ ] Extend `attacks/base.py`'s `AttackSuiteInfo` with ATLAS technique ID/name/tactic fields,
      mirroring the existing OWASP LLM Top 10 field.
- [ ] Surface both mappings in every reporter (JSON/Markdown/HTML/SARIF).

## Phase D — Provider expansion *(after Phase A)*

- [ ] Gemini, Azure OpenAI, Ollama, Mistral, Bedrock, OpenRouter adapters — each optional, each
      gated on its own credential env var, none required to use the framework (matches the
      existing OpenAI/Anthropic adapter's already-reviewed-and-approved philosophy).
- [ ] A shared contract test asserting no provider adapter ever logs/persists its raw
      credential, run against every provider adapter uniformly.

## Phase E — Reporting enhancements *(after C, D)*

- [ ] Surface OWASP + ATLAS mapping per finding in reports.
- [ ] Provider comparison view (when multiple campaigns/providers are supplied).
- [ ] Charts/timeline — inline SVG or vanilla JS only, no CDN (keeps the existing HTML report's
      "no external scripts" property).

## Phase F — Dashboard *(after E)*

- [ ] Static, CDN-free HTML dashboard aggregating whatever `reports/*/results.json` files it's
      pointed at — computed fresh each run, no database, no persistent service. Keeps the
      project's "no external services required" property intact.

## Phase G — GitHub/OSS polish *(no dependencies — can land anytime)*

- [ ] `.github/dependabot.yml`
- [ ] `.github/CODEOWNERS`
- [ ] `.github/ISSUE_TEMPLATE/*`, `.github/pull_request_template.md`
- [ ] `.pre-commit-config.yaml` (ruff + mypy locally, mirroring CI)

## Phase H — Golden/regression tests

- [ ] Formalize named golden-transcript fixtures with fixed seeds on top of the existing
      lab-integration test pattern (`tests/integration/test_all_payloads_against_lab.py` already
      does something close to this; make it an explicit, documented contract).

## Phase I — Documentation rewrite *(deliberately last)*

- [ ] Update `README.md`, `docs/architecture.md`, and add plugin-development/API docs once the
      structure above has actually settled — documenting a moving target wastes the rewrite.

## Phase J — Article + demo script *(final step)*

- [ ] Technical article: architecture, design decisions, OWASP+ATLAS, benchmarking, and an
      honest comparison against Garak/PyRIT/DeepTeam (strengths and gaps both ways, not just
      favorable framing).
- [ ] Demo script (narration + exact commands + expected output). **Note:** this ships as a
      written script/storyboard, not an actual recorded video — recording/narrating audio or
      video is outside what I can produce.

---

## Open decisions that need your input before the affected phase starts

- ~~**CLI rename (`llmsec` → `llmstest`)**~~ — **Decided: keep `llmsec`.** The repo, package
  name, and entry point stay as already published; no rename in Phase B.
- **Persistence for the dashboard/trend view:** confirmed default is "no database, read
  whatever `reports/` directories you point it at" (Phase F) — flag here if you'd rather have a
  real historical store (SQLite) instead.
