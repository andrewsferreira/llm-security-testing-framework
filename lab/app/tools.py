"""Simulated tool implementations. None of these perform real I/O.

Every function here operates only on the fake in-memory data in fake_data.py: no real email is
sent, no real file or URL is read, no real record is mutated. Callers must run
policies.authorize_tool_call first; these functions assume the call was already authorized.
"""

from __future__ import annotations

from typing import Any

from lab.app.fake_data import FAKE_CUSTOMERS, FAKE_FILES, FAKE_URL_CONTENT


def get_customer_record(customer_id: str) -> dict[str, Any]:
    record = FAKE_CUSTOMERS.get(customer_id)
    if record is None:
        return {"error": f"no such customer: {customer_id}"}
    return dict(record)


def send_email(to: str, subject: str, body: str) -> dict[str, Any]:
    return {"simulated": True, "to": to, "subject": subject, "body_length": len(body)}


def read_file(path: str) -> dict[str, Any]:
    content = FAKE_FILES.get(path)
    if content is None:
        return {"error": f"no such file: {path}"}
    return {"path": path, "content": content}


def fetch_url(url: str) -> dict[str, Any]:
    for host, content in FAKE_URL_CONTENT.items():
        if host in url:
            return {"url": url, "content": content}
    return {"url": url, "content": "<html><body>Not found (fake).</body></html>"}


def run_report(report_name: str, params: dict[str, str] | None = None) -> dict[str, Any]:
    return {"report_name": report_name, "params": params or {}, "rows": 0, "simulated": True}


def update_profile(user_id: str, fields: dict[str, str]) -> dict[str, Any]:
    return {"user_id": user_id, "updated_fields": sorted(fields.keys()), "simulated": True}


TOOL_FUNCTIONS: dict[str, Any] = {
    "get_customer_record": get_customer_record,
    "send_email": send_email,
    "read_file": read_file,
    "fetch_url": fetch_url,
    "run_report": run_report,
    "update_profile": update_profile,
}
