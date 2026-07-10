# Roadmap

Things this project could reasonably grow into, roughly in order of how much they'd add for
the effort. None of this is promised or scheduled — it's a portfolio project maintained as time
allows.

## Likely next

- **A real embedding-based semantic evaluator.** `evaluators/semantic.py` is explicitly a
  lexical/token-overlap heuristic today (see `docs/scoring-model.md`). A second evaluator
  registered under a different name (e.g. `embedding-semantic`) that calls a local embedding
  model or an API would be a natural, backward-compatible addition behind the same `Evaluator`
  protocol.
- **More payload coverage per category.** 65 test cases across 9 categories is a solid
  demonstration set, not exhaustive. Categories like `jailbreak` and `context_manipulation` in
  particular could grow significantly without changing any code.
- **A richer multi-turn model.** Right now, `requires_multi_turn` test cases send each user
  turn in sequence but don't feed the target's own prior replies back into `history` (see the
  simplification noted in `docs/creating-test-cases.md`). Extending `HistoryTurn` to support an
  `assistant`/`model` role and threading real prior responses through would make multi-turn
  tests more faithful.
- **DNS-aware SSRF checks.** `utils/url_safety.py` is explicitly documented as a static,
  literal-host check (see `docs/threat-model.md`). Resolving hostnames at request time and
  re-checking the resolved IP (with care around TOCTOU/rebinding) would close that gap.

## Plausible later

- **A `list-suites` CLI command** surfacing `attacks.ATTACK_CATALOG` (title, description, OWASP
  mapping) directly, rather than only through `list-tests`.
- **Parallel campaign comparison** — a CLI command that runs the same suite against two targets
  (or two configs) and diffs the results, instead of comparing two separately-generated reports
  by hand as the current demo does.
- **A pluggable rate-limiter strategy** beyond the current fixed requests/second cap (e.g.
  token-bucket with burst allowance).
- **Additional target adapters** for other common agent-framework response shapes (LangChain,
  LlamaIndex callback formats) alongside the existing generic HTTP envelope and the OpenAI/
  Anthropic-native provider adapter.

## Explicitly not planned

- **Making the lab a real LLM.** The lab is deliberately a fast, free, deterministic simulator —
  see `docs/creating-test-cases.md` and `docs/threat-model.md` for why that's a documented
  design choice, not a shortcut to fix later.
- **Automatic exploitation or remediation.** This is a detection/reporting framework. It will
  never execute model output or attempt to "fix" a target automatically.
- **Claiming production-readiness.** See the Limitations sections in `README.md` and
  `docs/threat-model.md` — this is a portfolio/lab project, presented as exactly that.
