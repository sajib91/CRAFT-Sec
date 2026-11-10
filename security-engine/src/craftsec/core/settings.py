"""Typed environment configuration for the CRAFT-Sec engine.

Secrets are read from the environment or a local ``.env`` file and are never
included in redacted configuration output.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
Device = Literal["auto", "cpu", "cuda", "mps"]
SandboxBackend = Literal["docker", "process", "none"]


class Settings(BaseSettings):
    """Environment-backed runtime settings.

    Environment variables use the ``CRAFTSEC_`` prefix, for example
    ``CRAFTSEC_DEVICE=cpu``. A Hugging Face token is accepted as either
    ``CRAFTSEC_HF_TOKEN`` or the conventional ``HF_TOKEN`` and is redacted from
    serialized output.
    """

    model_config = SettingsConfigDict(
        env_prefix="CRAFTSEC_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    log_level: LogLevel = "INFO"
    data_dir: Path = Path(".craftsec-data")
    log_dir: Path = Path(".craftsec-data/logs")

    model_id: str | None = None
    model_revision: str | None = None
    device: Device = "auto"
    gpu_concurrency: int = Field(default=1, ge=1, le=8)

    sae_manifest: Path | None = None

    sandbox_backend: SandboxBackend = "docker"
    sandbox_timeout_seconds: int = Field(default=900, ge=1, le=86_400)

    semgrep_path: str = "semgrep"
    bandit_path: str = "bandit"
    codeql_path: str | None = None
    joern_path: str | None = None

    hf_token: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("CRAFTSEC_HF_TOKEN", "HF_TOKEN"),
    )

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalize_log_level(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value

    @field_validator("device", "sandbox_backend", mode="before")
    @classmethod
    def _normalize_lowercase(cls, value: object) -> object:
        return value.lower() if isinstance(value, str) else value

    def ensure_directories(self) -> None:
        """Create local data and log directories, including parents."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def redacted(self) -> dict[str, object]:
        """Return JSON-safe settings with secrets removed."""
        data = self.model_dump(mode="json")
        data.pop("hf_token", None)
        return data
