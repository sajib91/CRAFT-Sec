from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from craftsec.core.settings import Settings

ENV_VARS = [
    "CRAFTSEC_LOG_LEVEL",
    "CRAFTSEC_DATA_DIR",
    "CRAFTSEC_LOG_DIR",
    "CRAFTSEC_MODEL_ID",
    "CRAFTSEC_MODEL_REVISION",
    "CRAFTSEC_DEVICE",
    "CRAFTSEC_GPU_CONCURRENCY",
    "CRAFTSEC_SAE_MANIFEST",
    "CRAFTSEC_SANDBOX_BACKEND",
    "CRAFTSEC_SANDBOX_TIMEOUT_SECONDS",
    "CRAFTSEC_SEMGREP_PATH",
    "CRAFTSEC_BANDIT_PATH",
    "CRAFTSEC_CODEQL_PATH",
    "CRAFTSEC_JOERN_PATH",
    "CRAFTSEC_HF_TOKEN",
    "HF_TOKEN",
]


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def test_defaults() -> None:
    settings = Settings(_env_file=None)

    assert settings.log_level == "INFO"
    assert settings.device == "auto"
    assert settings.sandbox_backend == "docker"
    assert settings.gpu_concurrency == 1
    assert settings.semgrep_path == "semgrep"
    assert settings.hf_token is None


def test_environment_overrides(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CRAFTSEC_LOG_LEVEL", "debug")
    monkeypatch.setenv("CRAFTSEC_DEVICE", "CPU")
    monkeypatch.setenv("CRAFTSEC_SANDBOX_BACKEND", "process")
    monkeypatch.setenv("CRAFTSEC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("CRAFTSEC_GPU_CONCURRENCY", "2")

    settings = Settings(_env_file=None)

    assert settings.log_level == "DEBUG"
    assert settings.device == "cpu"
    assert settings.sandbox_backend == "process"
    assert settings.data_dir == tmp_path / "data"
    assert settings.gpu_concurrency == 2


def test_invalid_values_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CRAFTSEC_SANDBOX_BACKEND", "magic")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)

    monkeypatch.setenv("CRAFTSEC_SANDBOX_BACKEND", "none")
    monkeypatch.setenv("CRAFTSEC_GPU_CONCURRENCY", "0")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_hf_token_is_accepted_and_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HF_TOKEN", "test-token-value")

    settings = Settings(_env_file=None)

    assert settings.hf_token is not None
    assert settings.hf_token.get_secret_value() == "test-token-value"
    assert "hf_token" not in settings.redacted()
    assert "test-token-value" not in str(settings.redacted())


def test_prefixed_hf_token_is_supported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CRAFTSEC_HF_TOKEN", "prefixed-token")

    settings = Settings(_env_file=None)

    assert settings.hf_token is not None
    assert settings.hf_token.get_secret_value() == "prefixed-token"


def test_dotenv_loading(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "CRAFTSEC_LOG_LEVEL=warning\nCRAFTSEC_DEVICE=cpu\n",
        encoding="utf-8",
    )

    settings = Settings(_env_file=env_file)

    assert settings.log_level == "WARNING"
    assert settings.device == "cpu"


def test_ensure_directories(tmp_path: Path) -> None:
    settings = Settings(
        _env_file=None,
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs" / "nested",
    )

    settings.ensure_directories()

    assert (tmp_path / "data").is_dir()
    assert (tmp_path / "logs" / "nested").is_dir()
