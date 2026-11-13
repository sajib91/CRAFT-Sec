from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from craftsec.core.settings import Settings

ENV_VARS = [
    "CRAFTSEC_LOG_LEVEL",
    "CRAFTSEC_DATA_DIR",
    "CRAFTSEC_LOG_DIR",
    "CRAFTSEC_HOST",
    "CRAFTSEC_PORT",
    "CRAFTSEC_CORS_ORIGINS",
    "CRAFTSEC_WORKSPACE_ROOTS",
    "CRAFTSEC_MAX_REQUEST_BYTES",
    "CRAFTSEC_MAX_FILE_BYTES",
    "CRAFTSEC_MAX_WORKSPACE_FILES",
    "CRAFTSEC_API_TOKEN",
    "CRAFTSEC_ENGINE_TOKEN",
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
    assert settings.host == "127.0.0.1"
    assert settings.port == 8765
    assert settings.cors_origins == []
    assert settings.workspace_roots
    assert settings.max_request_bytes == 2 * 1024 * 1024
    assert settings.max_file_bytes == 1024 * 1024
    assert settings.max_workspace_files == 50_000
    assert settings.api_token is None


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


def test_http_settings_from_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CRAFTSEC_HOST", "localhost")
    monkeypatch.setenv("CRAFTSEC_PORT", "9000")
    monkeypatch.setenv("CRAFTSEC_CORS_ORIGINS", "http://localhost:3000,https://example.com")
    monkeypatch.setenv(
        "CRAFTSEC_WORKSPACE_ROOTS",
        f"{tmp_path / 'one'},{tmp_path / 'two'}",
    )
    monkeypatch.setenv("CRAFTSEC_MAX_REQUEST_BYTES", "4096")
    monkeypatch.setenv("CRAFTSEC_MAX_FILE_BYTES", "2048")
    monkeypatch.setenv("CRAFTSEC_MAX_WORKSPACE_FILES", "10")

    settings = Settings(_env_file=None)

    assert settings.host == "localhost"
    assert settings.port == 9000
    assert settings.cors_origins == ["http://localhost:3000", "https://example.com"]
    assert settings.workspace_roots == [tmp_path / "one", tmp_path / "two"]
    assert settings.max_request_bytes == 4096
    assert settings.max_file_bytes == 2048
    assert settings.max_workspace_files == 10


def test_cors_origins_accept_a_json_array_and_are_normalized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "CRAFTSEC_CORS_ORIGINS",
        '["HTTP://localhost:3000/", "http://localhost:3000"]',
    )

    settings = Settings(_env_file=None)

    assert settings.cors_origins == ["http://localhost:3000"]


def test_empty_cors_origins_and_workspace_roots_are_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CRAFTSEC_CORS_ORIGINS", "")
    monkeypatch.setenv("CRAFTSEC_WORKSPACE_ROOTS", "")

    settings = Settings(_env_file=None)

    assert settings.cors_origins == []
    assert settings.workspace_roots == []


@pytest.mark.parametrize(
    "origin",
    [
        "*",
        "ftp://example.com",
        "http://user:password@example.com",
        "http://example.com/path",
        "http://example.com?query=1",
    ],
)
def test_unsafe_cors_origins_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    origin: str,
) -> None:
    monkeypatch.setenv("CRAFTSEC_CORS_ORIGINS", origin)

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_invalid_http_limits_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CRAFTSEC_PORT", "70000")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)

    monkeypatch.setenv("CRAFTSEC_PORT", "8765")
    monkeypatch.setenv("CRAFTSEC_MAX_REQUEST_BYTES", "10")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)

    monkeypatch.setenv("CRAFTSEC_MAX_REQUEST_BYTES", "4096")
    monkeypatch.setenv("CRAFTSEC_MAX_WORKSPACE_FILES", "0")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_api_token_is_accepted_under_both_names_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CRAFTSEC_API_TOKEN", "api-secret-value")

    settings = Settings(_env_file=None)

    assert settings.api_token is not None
    assert settings.api_token.get_secret_value() == "api-secret-value"
    assert "api_token" not in settings.redacted()
    assert "api-secret-value" not in str(settings.redacted())

    monkeypatch.delenv("CRAFTSEC_API_TOKEN")
    monkeypatch.setenv("CRAFTSEC_ENGINE_TOKEN", "engine-secret-value")
    settings = Settings(_env_file=None)
    assert settings.api_token is not None
    assert settings.api_token.get_secret_value() == "engine-secret-value"
