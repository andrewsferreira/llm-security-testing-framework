import pytest

from llmsec.models.target import GenericHttpTargetConfig, MockTargetConfig, ProviderTargetConfig
from llmsec.targets import GenericHttpTarget, MockTarget, ProviderAdapterTarget, build_target


def test_build_target_generic_http() -> None:
    target = build_target(
        GenericHttpTargetConfig(base_url="http://localhost:8000"), allow_external=False
    )
    assert isinstance(target, GenericHttpTarget)


def test_build_target_mock() -> None:
    target = build_target(MockTargetConfig(base_url="http://localhost:8000"), allow_external=False)
    assert isinstance(target, MockTarget)


def test_build_target_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOME_KEY", "secret")
    config = ProviderTargetConfig(
        base_url="https://api.openai.com",
        provider="openai",
        model="gpt-test",
        auth_token_env="SOME_KEY",
    )
    target = build_target(config, allow_external=True)
    assert isinstance(target, ProviderAdapterTarget)
