# Creating Test Cases

Test cases are pure YAML data, validated against the `TestCase` Pydantic model
(`src/llmsec/models/test_case.py`). There is no Python code to write to add a new attack — you
add an entry to the right file in `payloads/`.

## Schema

```yaml
- id: DPI-007                          # unique across the whole payloads/ directory
  name: Short human-readable name
  category: direct_prompt_injection    # one of the 9 AttackCategory values
  description: >
    One or two sentences on what this test case does.
  severity: high                       # low | medium | high | critical
  tags: [owasp-llm01, direct]          # free-form, used for organization/search only

  # Exactly one of these two:
  prompt: A single message to send.
  conversation:                        # a list of turns instead of a single prompt
    - role: document                   # user | tool | document
      content: Content that simulates something other than the user's own words.
    - role: user
      content: The user's actual message.

  expected_behavior: >
    What a secure target should do instead.

  failure_indicators: [SOME_MARKER]    # substrings whose presence means the attack succeeded
  success_indicators: ["refusal phrase"]  # substrings whose presence means it was resisted

  requires_multi_turn: false           # see "Single request vs. multi-turn" below
  requires_tools: false                # documentation only; doesn't change execution

  references: ["OWASP LLM01: Prompt Injection"]
  evaluator_config:
    type: keyword                      # keyword | regex | semantic | policy | composite
    # ...evaluator-specific fields, see below

  timeout: 10.0                        # optional, defaults to 10s
```

`RegistryError` is raised (with the offending file and index) if a case fails to validate —
`llmsec list-tests` and `llmsec scan` will refuse to run rather than silently skip it.

## Single request vs. multi-turn

`conversation` covers two different things, distinguished by `requires_multi_turn`:

- **`requires_multi_turn: false`** (or omitted) with a `conversation`: every turn except the
  last is sent as `history` alongside the *last* turn as the request's `prompt`, in **one**
  request. This is the shape indirect-prompt-injection and context-manipulation cases use — a
  `document`/`tool` turn simulates untrusted external content, and the final `user` turn is the
  actual ask.
- **`requires_multi_turn: true`**: each turn is sent as a **separate** request, in order, with
  all prior turns accumulated as `history`. Only the *last* response is evaluated. This is the
  shape multi-turn jailbreak escalation and multi-turn data-exfiltration cases use.

A case with `requires_multi_turn: true` must have at least 2 turns (enforced by the model).

## Which endpoint gets used

`core/runner.endpoint_for_category` maps category to endpoint automatically:

| Category | Endpoint |
| --- | --- |
| `tool_abuse`, `excessive_agency` | `/agent` |
| `indirect_prompt_injection` | `/rag` |
| everything else | `/chat` |

## Evaluator configs

### `keyword` (the default; most categories use this)

Uses the test case's own `failure_indicators`/`success_indicators` — no extra config needed
beyond `type: keyword`. Case-insensitive substring match; a failure indicator wins over a
success indicator if both are somehow present.

### `regex`

For shape-based detection (e.g., "any `<script>` tag," not one specific string):

```yaml
evaluator_config:
  type: regex
  failure_patterns: ["<script\\b", "\\bunion\\s+select\\b"]
  success_patterns: ["can't (share|provide)"]
```

### `semantic`

A lexical-similarity check against a reference string — see `docs/scoring-model.md` for why this
is honestly *not* embedding-based semantic matching:

```yaml
evaluator_config:
  type: semantic
  reference_response: "I can't help with that request."
  threshold: 0.35        # Jaccard token-overlap ratio, 0..1
  on_match: passed        # status to report when similarity >= threshold
```

### `policy`

Inspects `response.raw["tool_calls"]` rather than the reply text — the right choice for
`tool_abuse`/`excessive_agency`, where what matters is whether a tool actually executed:

```yaml
evaluator_config:
  type: policy
  max_authorized_tool_calls: 0   # more than this many authorized calls => FAILED
```

This only works against a target whose responses expose that shape (the bundled lab does; see
`docs/target-integration.md` for adapting a different target).

### `composite`

Combines multiple sub-evaluators:

```yaml
evaluator_config:
  type: composite
  mode: any_failed           # any_failed (default) | all_failed
  evaluators:
    - type: keyword
    - type: policy
      max_authorized_tool_calls: 0
```

## Testing against the bundled lab

The lab (`lab/app/agent.py`) is a **deterministic, rule-based responder, not a real LLM.** It
pattern-matches lowercased prompt+history text against fixed trigger phrases per category (see
the `*_TRIGGERS` tuples in `lab/app/agent.py`) and returns a different reply depending on
`LAB_MODE` (`vulnerable` vs `hardened`).

This means: **a new payload only demonstrates anything against the lab if its prompt text
actually contains one of the lab's trigger phrases for that category.** If you add a payload
whose wording doesn't match any trigger, it will come back `INCONCLUSIVE` in both modes — not
because it's wrong, but because the lab's simulator has nothing to react to.

When adding a payload meant to run against the lab:

1. Check the relevant `*_TRIGGERS` tuple in `lab/app/agent.py` for phrases that fit your
   scenario, or add a new one (and its vulnerable/hardened reply branch) if you're covering a
   genuinely new sub-scenario.
2. Make sure your prompt text doesn't *accidentally* also contain a trigger phrase from a
   *different, earlier-checked* category — handlers run in a fixed order
   (`_HANDLERS` in `lab/app/agent.py`) and the first match wins. This bit the payload set twice
   during development (see the Phase 5 commit): a document-injection payload's setup text
   happened to contain the data-exfiltration trigger `"internal value"`, so it was silently
   caught by the wrong handler in both modes. There's no automatic check for this — the
   `tests/integration/test_all_payloads_against_lab.py` regression suite is what catches it (see
   below), by actually asserting the expected outcome, not just that *something* happened.
3. Run the whole payload set against the lab in both modes and confirm your new case behaves as
   intended:

   ```bash
   pytest tests/integration/test_all_payloads_against_lab.py -v
   ```

   This test loads every file in `payloads/`, runs every case against `MockTarget` in
   `vulnerable` and `hardened` mode, and asserts vulnerable-mode results are all `FAILED` and
   hardened-mode results are all `PASSED`. If your new case doesn't trigger correctly, this is
   where it shows up — not as a vague "something's off," but as the exact test ID and status
   that didn't match.

If your change touches one of the 9 golden test cases (the `-001` id in each category's payload
file), `tests/integration/test_golden_transcripts.py` will also fail — it pins the *exact*
evidence/explanation/risk_score for those, not just pass/fail, so a wording or scoring change
shows up even when the status stays correct. See `tests/fixtures/golden/README.md` for the
contract and how to deliberately regenerate it.

Pointing llmsec at a target other than the lab doesn't have this constraint — a real LLM doesn't
need trigger-phrase alignment, only the lab's rule-based simulator does.
