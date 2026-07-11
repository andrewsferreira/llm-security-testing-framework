# Extending llmsec

The three real extension points in this framework, plus the Python API surface for using it as
a library instead of (or alongside) its CLI. Honest framing up front: there is no dynamic
plugin-discovery mechanism here (no entry points, no `plugins/` directory that gets auto-loaded)
— extension means importing llmsec's modules and either registering something by name
(evaluators) or editing a small dict (reporters), or implementing a protocol and wiring it in
yourself (targets). That's a deliberate reflection of where this project actually is, not a
gap this doc papers over.

## 1. Custom targets

The most-used extension point — anything that isn't the bundled lab. Implement `Target`'s one
abstract method (`send`) in `targets/base.py`. Full guide: `docs/target-integration.md`
(including when you don't need this at all — the `generic_http` target's configurable field
names cover most of your-own-HTTP-API cases without writing any Python). Runnable example:
`examples/custom_target.py`.

```bash
python examples/custom_target.py
```

If you want your target reachable via `target.type: <name>` in a YAML config (not just
constructed directly in Python), you'd also add a config model to `models/target.py`'s
discriminated union and a branch in `targets/build_target` — see how `GenericHttpTargetConfig`/
`MockTargetConfig`/`ProviderTargetConfig` do this today.

## 2. Custom evaluators

A genuine runtime registry, unlike reporters below: implement the `Evaluator` protocol
(`evaluators/base.py` — one method, `evaluate`, taking a `TestCase` + `TargetResponse` and
returning an `EvaluationOutcome`) and call `register_evaluator("your-name", YourEvaluator())`.
No changes to llmsec's own source required — do this from your own script, a conftest.py, or
anywhere that runs before you reference `"your-name"` in a `evaluator_config: {type: ...}`.
Runnable example: `examples/custom_evaluator.py` (a deliberately simple length-based heuristic,
registered and exercised against both lab modes so you can see it actually reach a different
verdict in each).

```bash
python examples/custom_evaluator.py
```

See `docs/creating-test-cases.md` for the `evaluator_config` shapes the 5 built-in evaluators
(`keyword`, `regex`, `semantic`, `policy`, `composite`) expect — a new evaluator's config shape
is entirely up to you; `evaluator_config` is a free-form dict beyond its required `type` key.

## 3. Custom report formats

Less pluggable than evaluators today, documented as such rather than oversold: `RENDERERS`/
`FILE_NAMES` in `reporters/__init__.py` are plain dicts, not a registry function. Adding a
format means writing a `render(campaign: Campaign, summary: CampaignSummary) -> str` function
(see `reporters/json_reporter.py` for the shortest example) and adding one entry to each dict —
a small, direct edit to `reporters/__init__.py` itself, not something you wire up from outside
the package the way you can with evaluators. `reporters/charts.py` has reusable, CDN-free inline
SVG chart helpers if your format is HTML-based.

## Python API surface

Everything `llmsec`'s CLI does is built on public functions/classes you can import directly.
Two levels, from lowest to highest:

- **Low-level** — assemble a campaign yourself: `core.registry.load_all_test_cases` +
  `select_suite`, `targets.build_target` (or construct a `Target` directly, e.g. `MockTarget`),
  `core.runner.run_campaign_async`, then build a `models.campaign.Campaign` and call
  `reporters.write_reports`. See `examples/sample_campaign.py` — this is exactly the pipeline
  `llmsec scan` runs, minus the CLI/config-file layer.
- **High-level** — `core.engine.run_campaign(cfg, suite=..., test_cases=...)` is what the CLI
  itself calls: given a loaded `Config` and a resolved test-case list, it builds the target,
  runs the campaign, and writes reports in one call, returning `(Campaign, dict[str, Path])`.
  Load `cfg` with `config.load_config(path)`, same as the CLI does.

Other public entry points worth knowing about:

| Need | Function/class |
| --- | --- |
| Load & validate a YAML config | `config.load_config` |
| Load/filter test cases | `core.registry.load_all_test_cases`, `select_suite` |
| Look up an evaluator by name | `evaluators.get_evaluator` |
| Score one campaign | `core.scoring.summarize` |
| Regenerate reports from a saved `results.json` | `core.engine.load_campaign_from_json`, `regenerate_reports` |
| Compare 2+ campaigns | `core.comparison.compare_campaigns` |
| Aggregate every report under a directory | `core.dashboard.build_dashboard`, `discover_campaign_report_paths` |
| The attack-category reference catalog (title, OWASP + ATLAS mapping) | `attacks.ATTACK_CATALOG` |

All of these are plain, synchronous or `async def` functions operating on Pydantic models — no
hidden global state beyond the evaluator registry (`evaluators/base.py`'s module-level dict),
which is populated once at import time (`evaluators/__init__.py`) and safe to add to afterward.
