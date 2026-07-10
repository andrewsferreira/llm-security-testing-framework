from llmsec.utils.redaction import redact_text, redact_value


def test_redacts_email() -> None:
    text = "Contact TEST_USER_EMAIL@example.invalid for help."
    assert "example.invalid" not in redact_text(text)
    assert "[REDACTED]" in redact_text(text)


def test_redacts_bearer_token() -> None:
    text = "Authorization: Bearer abcdEFGH12345678"
    assert "abcdEFGH12345678" not in redact_text(text)


def test_redacts_openai_style_key() -> None:
    text = "key=sk-abcdefghijklmnopqrstuvwx"
    assert "sk-abcdefghijklmnopqrstuvwx" not in redact_text(text)


def test_redacts_explicit_marker() -> None:
    text = "leaked SYSTEM_SECRET_MARKER_7F3A in the response"
    result = redact_text(text, extra_markers=["SYSTEM_SECRET_MARKER_7F3A"])
    assert "SYSTEM_SECRET_MARKER_7F3A" not in result


def test_leaves_ordinary_text_untouched() -> None:
    text = "The weather today is sunny and 21 degrees."
    assert redact_text(text) == text


def test_redact_value_recurses_into_nested_structures() -> None:
    data = {
        "user": "TEST_USER_EMAIL@example.invalid",
        "history": [{"note": "Bearer abcdEFGH12345678"}],
    }
    redacted = redact_value(data)
    assert redacted["user"] == "[REDACTED]"
    assert redacted["history"][0]["note"] == "[REDACTED]"


def test_redact_value_passes_through_non_strings() -> None:
    assert redact_value(42) == 42
    assert redact_value(None) is None
    assert redact_value(True) is True
