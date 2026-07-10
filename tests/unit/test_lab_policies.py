from lab.app.policies import ToolCallRequest, authorize_tool_call


def test_vulnerable_mode_allows_everything() -> None:
    request = ToolCallRequest(tool_name="read_file", arguments={"path": "internal/secrets.txt"})
    decision = authorize_tool_call("vulnerable", request)
    assert decision.allowed is True


def test_unknown_tool_rejected_in_both_modes() -> None:
    request = ToolCallRequest(tool_name="delete_everything", arguments={})
    assert authorize_tool_call("vulnerable", request).allowed is False
    assert authorize_tool_call("hardened", request).allowed is False


def test_hardened_blocks_internal_file_path() -> None:
    request = ToolCallRequest(tool_name="read_file", arguments={"path": "internal/secrets.txt"})
    decision = authorize_tool_call("hardened", request)
    assert decision.allowed is False


def test_hardened_allows_public_file_path() -> None:
    request = ToolCallRequest(tool_name="read_file", arguments={"path": "public/readme.txt"})
    decision = authorize_tool_call("hardened", request)
    assert decision.allowed is True


def test_hardened_blocks_path_traversal() -> None:
    request = ToolCallRequest(tool_name="read_file", arguments={"path": "../internal/secrets.txt"})
    decision = authorize_tool_call("hardened", request)
    assert decision.allowed is False


def test_hardened_blocks_cross_user_customer_record() -> None:
    request = ToolCallRequest(
        tool_name="get_customer_record",
        arguments={"customer_id": "CUSTOMER_TEST_RECORD_002"},
        requesting_user="alice",
    )
    decision = authorize_tool_call("hardened", request)
    assert decision.allowed is False
    assert "alice" in decision.reason


def test_hardened_allows_own_customer_record() -> None:
    request = ToolCallRequest(
        tool_name="get_customer_record",
        arguments={"customer_id": "CUSTOMER_TEST_RECORD_001"},
        requesting_user="alice",
    )
    decision = authorize_tool_call("hardened", request)
    assert decision.allowed is True


def test_hardened_requires_confirmation_for_send_email() -> None:
    request = ToolCallRequest(
        tool_name="send_email",
        arguments={"to": "someone@example.invalid", "subject": "x", "body": "y"},
        confirmed=False,
    )
    decision = authorize_tool_call("hardened", request)
    assert decision.allowed is False
    assert decision.requires_confirmation is True


def test_hardened_allows_confirmed_send_email_to_allowed_domain() -> None:
    request = ToolCallRequest(
        tool_name="send_email",
        arguments={"to": "someone@example.invalid", "subject": "x", "body": "y"},
        confirmed=True,
    )
    decision = authorize_tool_call("hardened", request)
    assert decision.allowed is True


def test_hardened_blocks_email_to_disallowed_domain_even_if_confirmed() -> None:
    request = ToolCallRequest(
        tool_name="send_email",
        arguments={"to": "attacker@evil.test", "subject": "x", "body": "y"},
        confirmed=True,
    )
    decision = authorize_tool_call("hardened", request)
    assert decision.allowed is False


def test_hardened_blocks_updating_another_users_profile() -> None:
    request = ToolCallRequest(
        tool_name="update_profile",
        arguments={"user_id": "bob"},
        requesting_user="alice",
        confirmed=True,
    )
    decision = authorize_tool_call("hardened", request)
    assert decision.allowed is False


def test_hardened_blocks_disallowed_fetch_url_host() -> None:
    request = ToolCallRequest(
        tool_name="fetch_url", arguments={"url": "http://internal.example.invalid/dashboard"}
    )
    decision = authorize_tool_call("hardened", request)
    assert decision.allowed is False


def test_hardened_allows_allowlisted_fetch_url_host() -> None:
    request = ToolCallRequest(
        tool_name="fetch_url", arguments={"url": "http://docs.example.invalid/readme"}
    )
    decision = authorize_tool_call("hardened", request)
    assert decision.allowed is True


def test_hardened_allows_run_report() -> None:
    request = ToolCallRequest(tool_name="run_report", arguments={"report_name": "usage"})
    decision = authorize_tool_call("hardened", request)
    assert decision.allowed is True
