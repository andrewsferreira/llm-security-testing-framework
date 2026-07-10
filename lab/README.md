# llmsec lab

A deliberately fake, safe-to-attack chatbot/agent used as the default target for the `llmsec`
framework's test suite. **Do not expose it on a public network** — it's designed to be scanned
by security tools, not to be a real application.

## What it is

A FastAPI app (`lab/app/main.py`) whose "LLM" (`lab/app/agent.py`) is a deterministic,
rule-based responder: it pattern-matches lowercased prompt/history text against fixed trigger
phrases and returns a different reply depending on `LAB_MODE`. It is **not** a real language
model, and it never calls one — see `docs/creating-test-cases.md` for exactly why and what that
means for writing new test payloads.

## Modes

Controlled by the `LAB_MODE` environment variable, read fresh on every request (not cached at
startup):

- `LAB_MODE=vulnerable` (default) — demonstrates unmitigated behavior for each of the 9 attack
  categories: leaks its fictional system-prompt marker, discloses fictional secrets, follows
  instructions embedded in "retrieved document" content, executes tool calls without
  authorization checks, chains multiple sensitive actions without confirmation.
- `LAB_MODE=hardened` — demonstrates the corresponding mitigation for each: refuses to disclose
  its configuration, treats untrusted content as data rather than instructions, enforces a tool
  allowlist with per-argument authorization (ownership checks, path containment, destination
  allowlists), and requires explicit confirmation before "sensitive" actions.

## Nothing here does real I/O, in either mode

- `lab/app/fake_data.py` holds only fictional secrets (`SYSTEM_SECRET_MARKER_7F3A`,
  `FAKE_API_KEY_12345`, a fake customer database, a fake in-memory filesystem, canned fake URL
  content) — nothing that resembles a real credential.
- `lab/app/tools.py`'s six simulated tools (`get_customer_record`, `send_email`, `read_file`,
  `fetch_url`, `run_report`, `update_profile`) never touch a real file, network, or mail server —
  they only read/return from the fake data above and report `{"simulated": true, ...}`.
- `lab/app/policies.py` implements the authorization logic (allowlist, ownership checks, path
  containment, confirmation-for-sensitive-actions) that the hardened mode enforces and the
  vulnerable mode skips.

## Endpoints

| Endpoint | Used for |
| --- | --- |
| `POST /chat` | Direct prompt injection, jailbreak, system-prompt leakage, data exfiltration, context manipulation |
| `POST /agent` | Tool abuse, excessive agency |
| `POST /rag` | Indirect prompt injection |
| `GET /health` | `{"status": "ok", "mode": "..."}` |
| `GET /version` | `{"version": "...", "mode": "..."}` |
| `GET /metrics` | Prometheus-text request counter/uptime |

## Running it standalone

```bash
uvicorn lab.app.main:app --port 8000          # vulnerable mode (default)
LAB_MODE=hardened uvicorn lab.app.main:app --port 8000
```

Or via Docker: `docker build -f lab/Dockerfile -t llmsec-lab . && docker run -p 8000:8000
llmsec-lab`, or `docker compose up lab` from the repo root.
