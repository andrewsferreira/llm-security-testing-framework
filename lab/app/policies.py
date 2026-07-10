"""Authorization policy for the lab's simulated tools.

`hardened` mode enforces an allowlist, per-tool argument validation (ownership checks, path
containment, destination allowlists), and a confirmation requirement for sensitive actions.
`vulnerable` mode intentionally skips these checks so the corresponding attack suites have
something real to detect — see docs/threat-model.md for why this is safe (everything downstream
is simulated; see tools.py).
"""

from __future__ import annotations

from dataclasses import dataclass

from lab.app.fake_data import FAKE_CUSTOMERS, FAKE_FILES

ALL_TOOLS: frozenset[str] = frozenset(
    {
        "get_customer_record",
        "send_email",
        "read_file",
        "fetch_url",
        "run_report",
        "update_profile",
    }
)

# Tools whose effects are "sensitive" (would matter if this were real) and therefore require
# explicit confirmation before executing in hardened mode.
SENSITIVE_TOOLS: frozenset[str] = frozenset({"send_email", "update_profile"})

ALLOWED_URL_HOSTS: frozenset[str] = frozenset({"docs.example.invalid"})


@dataclass
class AuthorizationDecision:
    allowed: bool
    reason: str
    requires_confirmation: bool = False


@dataclass
class ToolCallRequest:
    tool_name: str
    arguments: dict[str, str]
    requesting_user: str = "alice"
    confirmed: bool = False


def _is_contained_path(path: str) -> bool:
    """True if `path` resolves to one of the known virtual files without escaping via `..`."""
    return path in FAKE_FILES and ".." not in path.split("/")


def authorize_tool_call(mode: str, request: ToolCallRequest) -> AuthorizationDecision:
    if request.tool_name not in ALL_TOOLS:
        return AuthorizationDecision(False, f"Unknown tool: {request.tool_name!r}")

    if mode == "vulnerable":
        return AuthorizationDecision(True, "vulnerable mode: no authorization checks applied")

    # hardened mode below
    if request.tool_name in SENSITIVE_TOOLS and not request.confirmed:
        return AuthorizationDecision(
            False,
            f"{request.tool_name} requires explicit user confirmation before executing",
            requires_confirmation=True,
        )

    if request.tool_name == "get_customer_record":
        customer_id = request.arguments.get("customer_id", "")
        record = FAKE_CUSTOMERS.get(customer_id)
        if record is None:
            return AuthorizationDecision(False, f"Unknown customer_id: {customer_id!r}")
        if record["owner"] != request.requesting_user:
            return AuthorizationDecision(
                False,
                f"{request.requesting_user} is not authorized to access {customer_id}'s record",
            )
        return AuthorizationDecision(True, "owner matches requesting user")

    if request.tool_name == "read_file":
        path = request.arguments.get("path", "")
        if not _is_contained_path(path):
            return AuthorizationDecision(False, f"Path not allowed: {path!r}")
        if path.startswith("internal/"):
            return AuthorizationDecision(False, f"Path is not user-accessible: {path!r}")
        return AuthorizationDecision(True, "path is within the public allowlist")

    if request.tool_name == "fetch_url":
        url = request.arguments.get("url", "")
        if not any(host in url for host in ALLOWED_URL_HOSTS):
            return AuthorizationDecision(False, f"URL host not allowlisted: {url!r}")
        return AuthorizationDecision(True, "URL host is allowlisted")

    if request.tool_name == "send_email":
        to = request.arguments.get("to", "")
        if not to.endswith("@example.invalid"):
            return AuthorizationDecision(False, f"Recipient domain not allowed: {to!r}")
        return AuthorizationDecision(True, "recipient domain allowed and action confirmed")

    if request.tool_name == "update_profile":
        target_user = request.arguments.get("user_id", "")
        if target_user != request.requesting_user:
            return AuthorizationDecision(
                False, f"{request.requesting_user} cannot update another user's profile"
            )
        return AuthorizationDecision(True, "user may update their own profile")

    if request.tool_name == "run_report":
        return AuthorizationDecision(True, "run_report has no sensitive side effects")

    return AuthorizationDecision(False, "no matching policy rule")
