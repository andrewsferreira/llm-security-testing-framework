"""Loading and validating YAML configuration files (configs/*.yaml)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from llmsec.constants import DEFAULT_OUTPUT_DIR, SUPPORTED_REPORT_FORMATS
from llmsec.exceptions import ConfigError
from llmsec.models.campaign import CampaignConfig
from llmsec.models.target import TargetConfig
from llmsec.utils.url_safety import validate_target_url


class ReportingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    formats: list[str] = Field(default_factory=lambda: ["json", "markdown"])
    output_directory: str = DEFAULT_OUTPUT_DIR

    @field_validator("formats")
    @classmethod
    def _check_formats(cls, formats: list[str]) -> list[str]:
        unknown = set(formats) - SUPPORTED_REPORT_FORMATS
        if unknown:
            raise ValueError(
                f"Unsupported report format(s): {sorted(unknown)}. "
                f"Supported: {sorted(SUPPORTED_REPORT_FORMATS)}."
            )
        if not formats:
            raise ValueError("reporting.formats must not be empty.")
        return formats


class SecurityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    redact_sensitive_values: bool = True
    allow_external_targets: bool = False


class Config(BaseModel):
    """The fully validated contents of a configs/*.yaml file."""

    model_config = ConfigDict(extra="forbid")

    target: TargetConfig
    campaign: CampaignConfig = Field(default_factory=CampaignConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)

    @model_validator(mode="after")
    def _check_target_is_safe(self) -> Config:
        validate_target_url(
            self.target.base_url, allow_external=self.security.allow_external_targets
        )
        return self


def _format_validation_error(path: Path, exc: ValidationError) -> str:
    lines = [f"Invalid configuration in {path}:"]
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"])
        lines.append(f"  - {location}: {error['msg']}")
    return "\n".join(lines)


def load_config(path: str | Path) -> Config:
    """Load and validate a YAML config file, raising ConfigError with a readable message."""
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"Configuration file not found: {config_path}")

    try:
        raw: Any = yaml.safe_load(config_path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Could not parse YAML in {config_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(
            f"Configuration in {config_path} must be a YAML mapping at the top level."
        )

    try:
        return Config.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(_format_validation_error(config_path, exc)) from exc
    except Exception as exc:  # e.g. UnsafeTargetError raised from the model_validator above
        raise ConfigError(f"Invalid configuration in {config_path}: {exc}") from exc
