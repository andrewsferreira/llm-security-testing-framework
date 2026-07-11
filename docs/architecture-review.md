# Architecture Review — Phase 1

**Status:** Assessment only. Nothing in this document has been implemented yet, per the
explicit instruction that Phase 1 is review-before-action. See `TASKS.md` for the tracked,
prioritized backlog this review produces.

**Scope:** the repository as it stands after the initial 9-commit build (`llmsec` framework,
`lab/` target, 65 payloads, 242 tests/95% coverage, Docker + CI verified live). This review
evaluates it against an "enterprise open-source AI security framework" bar, not against its own
original (already-met) acceptance criteria.

---

## 1. Current strengths

- **Clean three-way separation** (framework / lab / payloads) with no circular dependency
  between them — the framework doesn't require the lab, the lab doesn't require the framework.
  This is the single best architectural decision in the codebase and should be preserved through
  every later phase.
- **Data-driven test cases.** Attack logic is YAML validated against a Pydantic schema, not
  scattered across Python modules. Adding a payload never requires a code change.
- **A real async engine**, not a toy loop: bounded concurrency via a worker pool over
  `asyncio.Queue`, per-test timeout, retry with backoff, optional rate limiting, and
  stop-on-critical that lets in-flight requests finish instead of cancelling them mid-air.
- **Honest self-documentation.** The `semantic` evaluator is labeled as lexical token-overlap,
  not embeddings. The SSRF guard's DNS-rebinding gap is written down, not hidden. The lab is
  explicitly a rule-based simulator. This matters more for an AI-security portfolio than almost
  anything else in the repo — overclaiming capability is the single most common flaw in security
  tooling, and this codebase actively avoids it.
- **Verified, not just written, infrastructure.** Docker images, Compose stack, and all 3 GitHub
  Actions workflows have real, live-verified runs (including catching and fixing a genuine
  Gitleaks CI bug post-push) — not just local syntax checks.
- **Strong baseline engineering hygiene:** mypy strict passes across `src/`, `lab/`, `examples/`;
  242 tests at 95% coverage, all asserting specific outcomes (not smoke tests); Bandit/pip-audit
  clean; ~1:1 test-to-source line ratio (2,881 / 2,813 lines).
- **A real threat model** (STRIDE) scoped to the framework itself, not a generic template.
- **OWASP LLM Top 10 mapping already exists**, per category, in `attacks/base.py` — a real
  foundation for Phase 5/6 of the new scope, not a from-scratch addition.

## 2. Current weaknesses / architecture issues

- **`TargetConfig` is a flat field bag.** `provider`, `model`, and `system_prompt` only apply
  when `type == "provider"`, but they live as optional fields on the same Pydantic model used by
  `generic_http` and `mock`. This is fine at 3 target types; it will not survive 8 provider
  integrations without becoming an unreadable, weakly-validated blob. **This needs to be a
  discriminated union (or per-type subclasses) before Phase 7 (providers) starts, not after.**
- **No plugin system.** Evaluators and targets register themselves via side-effecting module-level
  calls into a shared mutable dict (`_EVALUATOR_REGISTRY`, `targets/__init__.py`'s `build_target`
  if/elif chain). Fine for 5 evaluators and 3 targets maintained in-tree; not fine for a stated
  goal of "future providers through plugins" — there's no entry-point discovery, no namespacing,
  no conflict detection beyond last-write-wins on a dict key.
- **No historical/cross-campaign persistence.** Every `llmsec scan` is a one-off; there is no
  concept of comparing today's run to last week's. A "dashboard" or "risk trend" feature has
  nothing to read from without deciding on a persistence layer first (even a simple SQLite file
  would do — this is a real decision point, not a detail).
- **CLI has no Rich/progress/table output** — Typer's default plain-text output only. Verbose and
  debug modes don't exist as distinct concepts today (there's `configure_logging(level=INFO)`,
  hardcoded).
- **`core/engine.py` prints directly to stdout** (`print(...)`) rather than routing through the
  logging framework or a renderer abstraction — this will fight with a Rich-based CLI (progress
  bars and raw `print()` calls interleave badly) and makes a clean `--json` output mode harder to
  retrofit than if output were centralized from the start.
- **No MITRE ATLAS mapping at all** (OWASP LLM Top 10 exists; ATLAS does not). Additive, not
  risky, but currently zero coverage.
- **Reporting has no charts/timeline** — the HTML report is a single static snapshot (tables +
  filters), not a data visualization surface. Recharts/Chart.js-equivalent would need to stay
  CDN-free per the project's own existing "no external scripts" constraint, which narrows the
  options (inline SVG/vanilla-JS charts, not a charting library import).

## 3. Code smells / technical debt

- `evaluators/semantic.py` naming is a known, documented tension (it's lexical, not embedding-
  based) — living with the name today is fine because it's clearly labeled, but if a real
  embedding evaluator is added later (roadmap item), the naming should be revisited so
  `semantic` doesn't end up meaning two different things.
- Deferred imports inside CLI command bodies (`from llmsec.core.engine import run_campaign`
  inside the function) — a deliberate startup-time optimization, but it obscures the module
  dependency graph at a glance. Worth a comment explaining why, at minimum.
- Category names are duplicated across three places: the `AttackCategory` enum, the
  `attacks/*.py` metadata modules, and each payload file's `category:` field. Low risk today
  (Pydantic validates the payload field against the enum, so they can't silently drift), but
  worth being aware of before adding a fourth place (MITRE ATLAS metadata) that also needs to
  stay in sync.
- No dependency-injection container. Manual wiring (`build_target`, `get_evaluator`) is
  appropriate at current scale; flagged only because a real plugin system in Phase 7 will make
  manual if/elif dispatch increasingly awkward.

## 4. Missing "enterprise" features

- Multi-provider abstraction (2 of the 8 requested providers exist today: a shared
  OpenAI/Anthropic-native adapter).
- MITRE ATLAS mapping.
- Cross-campaign dashboard / trend view.
- `.github/dependabot.yml` (absent), `CODEOWNERS` (absent), issue/PR templates (absent),
  `.pre-commit-config.yaml` (absent) — all standard "this repo is run like a real OSS project"
  signals a Staff/Principal reviewer will look for in the first 30 seconds.
- SBOM / provenance attestation in the release workflow.
- Golden/regression test fixtures with fixed seeds (today's tests assert against the
  deterministic rule-based lab, which is *similar* to golden testing but isn't formalized as
  named golden files with an explicit "this is our regression baseline" contract).

## 5. Maintainability score

**8.5/10 for the scope that exists today.** Strong typing, strong test coverage, consistent
module boundaries, documentation that matches the code. The score is capped below 9 by the
`TargetConfig` flat-field-bag issue and the registry-dict-as-plugin-system issue — both are
exactly the kind of thing that's cheap to fix now and expensive to fix after 6 more providers
and a plugin marketplace get bolted onto them.

## 6. Scalability concerns

- Single-process `asyncio` execution is appropriate for hundreds of test cases against a handful
  of targets; it is not the bottleneck at any scale this project will actually reach as a
  portfolio/OSS tool, and re-architecting for distributed execution would be solving a problem
  this project doesn't have. **Not a priority.**
- Report rendering holds the full campaign in memory (Jinja2 render of the whole `Campaign`
  object). Fine through thousands of results; would need pagination only if campaigns grow by
  orders of magnitude beyond current payload counts. **Not a priority.**
- The real scalability question is **data model, not compute**: a dashboard/trend feature needs
  a decision on where historical results live (flat JSON files on disk vs. SQLite vs. nothing —
  i.e., a dashboard that reads whatever `reports/` directories you point it at, computed fresh
  each time, no database at all). The last option keeps the project's "no external services
  required" property intact and is the recommended default — see prioritization below.

## 7. Security issues (of the framework's own code — not what it tests for)

- Already well-handled: redaction, SSRF-by-default-deny, no `eval`/`exec`, non-root Docker users,
  Bandit/pip-audit/Gitleaks in CI (the last one just fixed for real on this repo's own initial
  push).
- **New concern introduced by the requested scope, not present today:** 6 additional provider
  integrations means 6 additional credential types to handle consistently. The existing 2
  providers do this correctly (`auth_token_env` names an env var; the token is never logged,
  never written to a config file, never present in redaction bypass paths). **Every new provider
  must follow the identical pattern — this should be a documented, enforced convention (a
  contract test asserting "no provider adapter ever logs or persists its raw token"), not
  something re-derived per provider.**
- **A plugin system is a new trust boundary that doesn't exist today.** If third-party
  evaluators/targets become loadable, that is inherently arbitrary Python code execution — there
  is no sandboxing story, and there shouldn't be a false impression of one. This needs an explicit
  statement in the plugin-development docs: *plugins are trusted code, not sandboxed, review them
  like you'd review a dependency.*

## 8. A constraint worth flagging now, not discovering later

**Phase 15 asks for a "Demo Video" with narration and a recording sequence.** I can write a demo
script, narration text, exact terminal commands, and expected output — the same kind of artifact
`docs/portfolio-demo.md` already is. I cannot record actual video or audio. That phase will ship
as a polished script/storyboard, not a video file.

## 9. Prioritized order of work

This is the order Phase 2 onward should actually happen in, independent of the numeric phase
labels in the original request, because some phases have hard prerequisites on others:

1. **`TargetConfig` → discriminated union** (blocks Phase 7 cleanly; do this first, it's a
   contained refactor with full test coverage already in place to catch regressions).
2. **CLI overhaul (Rich, tables, progress, `--json`, `--verbose`)** — self-contained, high
   portfolio-visibility, no dependency on other phases.
3. **MITRE ATLAS mapping** — additive metadata, mirrors the existing OWASP catalog shape.
4. **Provider expansion** (Gemini, Azure OpenAI, Ollama, Mistral, Bedrock, OpenRouter) — after
   \#1, each as an optional extra (matching the existing "never required" philosophy already
   established for OpenAI/Anthropic), each with its own credential-handling contract test per
   the security note above.
5. **Reporting enhancements** (OWASP+ATLAS mapping surfaced in-report, provider comparison,
   inline SVG/vanilla-JS charts, CDN-free) — depends on \#3 and \#4 existing to have something to
   render.
6. **Dashboard** — a static, CDN-free HTML page that aggregates whatever `reports/*/results.json`
   files it's pointed at, computed fresh, no database. Depends on \#5.
7. **GitHub/OSS polish** (Dependabot, CODEOWNERS, issue/PR templates, pre-commit) — mechanical,
   zero risk, can happen anytime; doing it now costs nothing and immediately improves the
   first-30-seconds reviewer impression.
8. **Golden/regression test formalization** — extend the existing lab-integration-test pattern
   into named golden fixtures with fixed seeds.
9. **Documentation rewrite** — deliberately last, so it documents the settled architecture rather
   than needing a second pass after \#1–\#6 change things.
10. **Article + demo script** — final step, once everything it describes is real and tested.

`TASKS.md` tracks each of these as discrete, checkable items with rationale, and will be updated
as work lands.
