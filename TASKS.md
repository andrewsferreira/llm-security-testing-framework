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

## Phase C — MITRE ATLAS mapping ✅ DONE

- [x] Extended `attacks/base.py`'s `AttackSuiteInfo` with `atlas_technique_id`/
      `atlas_technique_name`/`atlas_tactic` fields, mirroring the existing OWASP LLM Top 10
      field. Populated for all 9 categories against the public ATLAS matrix
      (https://atlas.mitre.org). **Honest caveat, documented in `attacks/base.py`'s
      docstring:** ATLAS models attacker TTPs, so the prompt-injection-family categories
      (direct/indirect injection, jailbreak, context manipulation) map closely (`AML.T0051`
      family, `AML.T0054`), while consumer-side categories (insecure output handling,
      excessive agency) use the closest applicable "Impact"-tactic technique (`AML.T0048`
      External Harms and its `.002` User Harm sub-technique) rather than a precise match —
      flagged as best-effort, not a compliance-grade mapping.
- [x] Surfaced both mappings in every reporter:
      - **JSON**: new top-level `framework_mappings` key (category -> owasp/atlas fields).
      - **Markdown/HTML**: the existing "Category Distribution" table gained OWASP LLM Top 10
        and MITRE ATLAS columns.
      - **SARIF**: each rule's `properties` gained `owaspLlmReference`/`atlasTechniqueId`/
        `atlasTechniqueName`/`atlasTactic`.
- [x] Verified with a real live scan (not just unit tests) — `llmsec scan` against the lab,
      inspected the generated `report.md`/`report.html`/`results.json` directly. 269 tests
      (6 new), ruff/mypy strict/bandit/pip-audit clean.

## Phase D — Provider expansion *(after Phase A)* ✅ DONE

- [x] Added Gemini, Azure OpenAI, Ollama, Mistral, Bedrock, OpenRouter adapters alongside the
      existing OpenAI/Anthropic pair (8 providers total) — each optional, each gated on its own
      credential env var, none required to use the framework.
      - `provider_adapter.py` refactored from an if/elif dispatch to per-provider
        `_BUILDERS`/`_EXTRACTORS` dispatch tables (a request-builder + a response-extractor
        function per provider), so adding a 9th provider means adding one table entry each, not
        growing a conditional chain.
      - **`ollama`** is the one provider where a missing credential is *not* an error — a
        default local Ollama install has no auth at all. `auth_token_env` is still a required
        schema field for consistency, but an unset env var just omits the `Authorization`
        header rather than raising.
      - **`azure_openai`** reuses `model` as the deployment name (how Azure actually addresses
        models) and gained an `api_version` field (default `2024-02-15-preview`).
      - **`bedrock`** is the one provider whose credential shape doesn't fit "one bearer
        token": AWS SigV4 needs an access key ID + secret key pair (+ optional session token) +
        region. Implemented real SigV4 request signing by hand with stdlib `hmac`/`hashlib` (no
        `boto3` dependency, consistent with the project's no-mandatory-SDK philosophy) against
        the Bedrock Converse API. `ProviderTargetConfig` gained `aws_access_key_id_env`
        (required — enforced by a `model_validator` — whenever `provider: bedrock`),
        `aws_session_token_env` (optional), and `aws_region`.
      - `ProviderName` extended to the 8-way `Literal`; `PROVIDERS_WITHOUT_REQUIRED_AUTH`
        (currently just `{"ollama"}`) added to `models/target.py` as the single source of truth
        for that exception.
- [x] Added a shared contract test
      (`tests/unit/test_provider_credentials_contract.py`), parametrized over all 8 providers:
      each provider's raw credential is confirmed to authenticate the outgoing request, then
      asserted absent from `TargetResponse.text`/`.raw` (what actually flows into
      `TestResult`/reports via `core/evidence.py`) and absent from every captured log record.
      Bedrock's SigV4 case is asserted differently (a derived signature is present, not the raw
      secret — the whole point of SigV4 is that the secret itself never goes over the wire).
- [x] Verified end-to-end through the real CLI, not just unit tests: `llmsec validate-config`
      against a `gemini` config (accepted) and an intentionally-incomplete `bedrock` config
      (correctly rejected at config-validation time with a clear error naming the missing
      field). 286 tests (17 new), ruff/mypy strict/bandit/pip-audit clean, ~94% coverage.

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
