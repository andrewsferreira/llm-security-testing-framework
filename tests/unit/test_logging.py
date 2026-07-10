import json
import logging

from llmsec.logging import bind_context, configure_logging, get_logger


def test_configure_logging_emits_json_lines(capsys: object) -> None:
    configure_logging(level=logging.INFO, json_output=True)
    logger = get_logger("test")
    logger.info("hello world")

    captured = capsys.readouterr()  # type: ignore[attr-defined]
    line = captured.err.strip().splitlines()[-1]
    payload = json.loads(line)
    assert payload["message"] == "hello world"
    assert payload["logger"] == "llmsec.test"
    assert payload["level"] == "INFO"


def test_bind_context_merges_structured_fields(capsys: object) -> None:
    configure_logging(level=logging.INFO, json_output=True)
    logger = get_logger("engine")
    adapter = bind_context(logger, campaign_id="campaign-1", test_id="SPI-001", latency_ms=12.5)
    adapter.info("ran test case")

    captured = capsys.readouterr()  # type: ignore[attr-defined]
    line = captured.err.strip().splitlines()[-1]
    payload = json.loads(line)
    assert payload["campaign_id"] == "campaign-1"
    assert payload["test_id"] == "SPI-001"
    assert payload["latency_ms"] == 12.5


def test_get_logger_namespaces_under_llmsec() -> None:
    logger = get_logger("foo")
    assert logger.name == "llmsec.foo"
