# Golden transcript fixtures

`vulnerable.json` / `hardened.json` pin the **full** result shape — not just pass/fail — for one
representative test case per attack category (the `-001` case in each `payloads/*.yaml` file),
run against the bundled lab in each mode. This is a stricter, complementary contract to
`tests/integration/test_all_payloads_against_lab.py`, which only asserts every payload resolves
to the *right status* (FAILED in vulnerable mode, PASSED in hardened mode) across the *entire*
payload set. That test would not catch a regression that kept the status correct but silently
changed *why* — a different matched indicator, a wrong risk score, a reworded explanation, an
evaluator swapped for a different one that happens to agree on this input. The golden test
(`tests/integration/test_golden_transcripts.py`) does catch that, for this smaller, deliberately
curated set.

## What's pinned, and why

For each of the 9 golden test IDs, per mode: `category`, `severity`, `status`, `confidence`,
`evidence.matched_indicators`, `evidence.notes`, `response` (the lab's exact reply — the lab is a
rule-based simulator with no randomness or timestamps in its output, so this is safe to pin
exactly), `explanation`, `remediation`, and `risk_score`.

**Not pinned:** `id` (a fresh UUID per run), `campaign_id`, `started_at`/`finished_at`, and
`latency_ms` — these are inherently run-specific, not business logic, and pinning them would
make the fixture flaky for reasons that have nothing to do with a real regression.

## "Fixed seeds"

The original backlog item for this phase said "fixed seeds" — worth being explicit that the lab
(`lab/app/`) has no randomness anywhere in its request handling (no `random`, no
timestamp-dependent branching); it's already a deterministic rule-based simulator by design (see
`docs/architecture.md`). So there is no seed to fix — determinism was true before this phase and
remains true after it. The contribution here is formalizing *which* outputs are guaranteed
stable and pinning them explicitly, not adding determinism that was missing.

## Updating these fixtures

Only regenerate them when a change to the lab, an evaluator, or the scoring model
**intentionally** changes one of these 9 cases' behavior — a golden test failing is meant to make
you stop and check that the change was deliberate, not to be silenced reflexively. If it was
deliberate:

```bash
python scripts/regenerate_golden_fixtures.py
git diff tests/fixtures/golden/  # review every changed field before committing
```
