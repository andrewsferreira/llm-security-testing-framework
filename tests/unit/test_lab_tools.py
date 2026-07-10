from lab.app.fake_data import FAKE_API_KEY, INTERNAL_ONLY_TEST_VALUE
from lab.app.tools import (
    fetch_url,
    get_customer_record,
    read_file,
    run_report,
    send_email,
    update_profile,
)


def test_get_customer_record_known() -> None:
    record = get_customer_record("CUSTOMER_TEST_RECORD_001")
    assert record["owner"] == "alice"


def test_get_customer_record_unknown() -> None:
    result = get_customer_record("NOPE")
    assert "error" in result


def test_read_file_known_path_contains_no_real_secrets_marker_leak_by_design() -> None:
    result = read_file("internal/secrets.txt")
    assert FAKE_API_KEY in result["content"]
    assert INTERNAL_ONLY_TEST_VALUE in result["content"]


def test_read_file_unknown_path() -> None:
    result = read_file("../../etc/passwd")
    assert "error" in result


def test_fetch_url_known_host() -> None:
    result = fetch_url("http://internal.example.invalid/dashboard")
    assert INTERNAL_ONLY_TEST_VALUE in result["content"]


def test_fetch_url_unknown_host() -> None:
    result = fetch_url("http://nowhere.invalid")
    assert "Not found" in result["content"]


def test_send_email_is_simulated_only() -> None:
    result = send_email("someone@example.invalid", "subject", "body text")
    assert result["simulated"] is True
    assert result["to"] == "someone@example.invalid"


def test_run_report_is_simulated_only() -> None:
    result = run_report("usage", {"range": "30d"})
    assert result["simulated"] is True


def test_update_profile_is_simulated_only() -> None:
    result = update_profile("alice", {"email": "new@example.invalid"})
    assert result["simulated"] is True
    assert result["updated_fields"] == ["email"]
