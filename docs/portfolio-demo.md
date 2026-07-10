# Portfolio Demo Script (~5 minutes)

A walkthrough for demonstrating this project live. Exact commands, run from the repo root with
the virtualenv activated (`pip install -e ".[dev]"` already done).

## 1. Context (30s, talk only)

"This is a security testing framework for LLM-backed chatbots and agents — prompt injection,
jailbreaks, system-prompt leakage, data exfiltration, tool abuse, and five more categories,
modeled on the OWASP LLM Top 10. It ships with its own local target to scan, so the whole thing
runs end-to-end with no API keys and no external dependencies."

## 2. Architecture (30s, talk + optionally show `docs/architecture.md`)

"Three independent pieces: the framework (the `llmsec` CLI and engine), a bundled lab — a fake
chatbot that can run in a vulnerable or a hardened mode — and 65 test cases as YAML data, not
code. The framework can point at the bundled lab or at any real HTTP-based chat/agent API."

## 3. Start the lab in vulnerable mode

```bash
LAB_MODE=vulnerable uvicorn lab.app.main:app --port 8000 &
curl -s http://localhost:8000/health
```

Expect: `{"status":"ok","mode":"vulnerable"}`

## 4. Run the full suite against it

```bash
llmsec scan --target http://localhost:8000 --suite all \
  --config configs/local.yaml --output reports/demo-vulnerable
```

Expect: all 65 tests, ~0 passed, ~65 failed, exit code `1`. Point out the printed summary and
the four report paths it wrote.

## 5. Look at a finding

```bash
open reports/demo-vulnerable/campaign-*/report.html   # macOS; use xdg-open on Linux
```

Show: the executive summary cards, the severity/category distribution tables, and one finding's
evidence — e.g. a `system_prompt_leakage` case where the response actually contains
`SYSTEM_SECRET_MARKER_7F3A`. Point out the category/severity filter dropdowns.

## 6. Switch to hardened mode and re-run

```bash
kill %1   # stop the vulnerable lab
LAB_MODE=hardened uvicorn lab.app.main:app --port 8000 &
llmsec scan --target http://localhost:8000 --suite all \
  --config configs/local.yaml --output reports/demo-hardened
```

Expect: all 65 tests, 65 passed, 0 failed, exit code `0`.

## 7. Compare the two runs

```bash
python3 -c "
import json, glob
vuln = json.load(open(glob.glob('reports/demo-vulnerable/campaign-*/results.json')[0]))
hard = json.load(open(glob.glob('reports/demo-hardened/campaign-*/results.json')[0]))
print('vulnerable failed:', vuln['summary']['failed'])
print('hardened failed:', hard['summary']['failed'])
"
```

"Same 65 test cases, same framework, same suite. The only thing that changed is the target's own
mitigations — authorization checks on tool calls, refusing to echo the system prompt, refusing
to treat retrieved-document content as instructions. That's the demonstration: the framework
finds real, specific differences in behavior, not just 'something changed.'"

## 8. (Optional) The same thing, fully containerized

```bash
docker compose up -d lab
docker compose run --rm scanner \
  llmsec scan --target http://lab:8000 --suite jailbreak --config configs/docker.yaml --output reports
docker compose down
```

"Same scan, but the scanner and the lab are two separate containers talking over a Compose
network — this is what CI would run."

## 9. Limitations (30s, talk only — say this out loud, don't skip it)

"A few things worth being upfront about: the lab is a rule-based simulator, not a real LLM — it
demonstrates the *mechanics* of detection, not what a real model would do. The evaluators are
heuristic — keyword, regex, lexical-similarity, tool-call-policy — not a guarantee of ground
truth; an `INCONCLUSIVE` result means 'needs a human to look,' not 'safe.' And the SSRF guard is
a static host check, not DNS-aware — documented, not silently glossed over."

## 10. Where to look next

"`docs/threat-model.md` for the STRIDE analysis, `docs/scoring-model.md` for exactly how the
risk score is computed and why it's a lab heuristic, `payloads/*.yaml` for the actual test
content, and the two Medium articles in `docs/` for the full writeup."
