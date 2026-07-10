import pytest

from llmsec.exceptions import UnsafeTargetError
from llmsec.utils.url_safety import is_local_target, validate_target_url


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://192.168.1.5:8000",
        "http://10.0.0.5:8000",
        "http://[::1]:8000",
    ],
)
def test_local_targets_are_allowed_without_external_flag(url: str) -> None:
    assert is_local_target(url)
    validate_target_url(url, allow_external=False)


def test_public_hostname_rejected_by_default() -> None:
    with pytest.raises(UnsafeTargetError):
        validate_target_url("http://example.com", allow_external=False)


def test_public_hostname_allowed_when_flag_set() -> None:
    validate_target_url("http://example.com", allow_external=True)


def test_non_http_scheme_rejected_even_when_external_allowed() -> None:
    with pytest.raises(UnsafeTargetError):
        validate_target_url("ftp://example.com", allow_external=True)


def test_missing_hostname_rejected() -> None:
    with pytest.raises(UnsafeTargetError):
        validate_target_url("http://", allow_external=True)
