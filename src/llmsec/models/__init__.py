"""Typed data models used across the framework."""

from llmsec.models.campaign import Campaign, CampaignConfig
from llmsec.models.result import Evidence, ResultStatus, TestResult
from llmsec.models.target import (
    GenericHttpTargetConfig,
    MockTargetConfig,
    ProviderTargetConfig,
    TargetConfig,
    TargetType,
)
from llmsec.models.test_case import AttackCategory, ConversationTurn, Severity, TestCase

__all__ = [
    "AttackCategory",
    "Campaign",
    "CampaignConfig",
    "ConversationTurn",
    "Evidence",
    "GenericHttpTargetConfig",
    "MockTargetConfig",
    "ProviderTargetConfig",
    "ResultStatus",
    "Severity",
    "TargetConfig",
    "TargetType",
    "TestCase",
    "TestResult",
]
