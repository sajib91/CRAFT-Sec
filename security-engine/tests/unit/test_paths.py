from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from craftsec.core.errors import (
    NotFoundAppError,
    ResourceLimitAppError,
    SecurityAppError,
    UnsupportedMediaAppError,
    ValidationAppError,
)
from craftsec.core.paths import (
    ensure_allowed_root,
    enumerate_workspace_sources,
    inspect_source_file,
    inspect_source_text,
    resolve_file,
    validate_selection,
)
from craftsec.core.settings import Settings


@pytest.fixture
def workspace(tmp_path: Path) -> tuple[Path, Settings]:
    root = tmp_path / "root"
    root.mkdir()
    settings = Settings(_env_file=None, workspace_roots=[root], max_file_bytes=1024)
    return root, settings


def test_ensure_allowed_root_accepts_the_root_and_nested_directories(
    workspace: tuple[Path, Settings],
) -> None:
    root, settings = workspace
    nested = root / "src"
    nested.mkdir()

    assert ensure_allowed_root(root, settings) == root.resolve()
    assert ensure_allowed_root(nested, settings) == nested.resolve()


def test_ensure_allowed_root_rejects_paths_outside_the_allowlist(
    workspace: tuple[Path, Settings],
    tmp_path: Path,
) -> None:
    _, settings = workspace
    outside = tmp_path / "outside"
    outside.mkdir()

    with pytest.raises(SecurityAppError) as error:
        ensure_allowed_root(outside, settings)

    assert error.value.code == "E_ROOT_NOT_ALLOWED"


def test_ensure_allowed_root_rejects_missing_and_non_directory_paths(
    workspace: tuple[Path, Settings],
) -> None:
    root, settings = workspace

    with pytest.raises(NotFoundAppError):
        ensure_allowed_root(root / "missing", settings)

    file = root / "file.py"
    file.write_text("value = 1\n", encoding="utf-8")
    with pytest.raises(NotFoundAppError):
        ensure_allowed_root(file, settings)


def test_resolve_file_accepts_relative_paths(workspace: tuple[Path, Settings]) -> None:
    root, settings = workspace
    file = root / "app.py"
    file.write_text("value = 1\n", encoding="utf-8")

    assert resolve_file(root, "app.py", settings) == file.resolve()


def test_resolve_file_rejects_escaping_paths_and_symlinks(
    workspace: tuple[Path, Settings],
    tmp_path: Path,
) -> None:
    root, settings = workspace
    outside = tmp_path / "outside.py"
    outside.write_text("SECRET = 1\n", encoding="utf-8")

    with pytest.raises(SecurityAppError) as error:
        resolve_file(root, outside, settings)
    assert error.value.code == "E_PATH_OUTSIDE_WORKSPACE"

    link = root / "link.py"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlinks are unavailable on this platform")

    with pytest.raises(SecurityAppError) as error:
        resolve_file(root, link, settings)
    assert error.value.code == "E_PATH_OUTSIDE_WORKSPACE"


def test_inspect_source_file_returns_content_metadata(workspace: tuple[Path, Settings]) -> None:
    root, settings = workspace
    file = root / "app.py"
    data = b"print('hello')\n"
    file.write_bytes(data)

    snapshot = inspect_source_file(root, "app.py", settings)

    assert snapshot.path == file.resolve()
    assert snapshot.size == len(data)
    assert snapshot.sha256 == hashlib.sha256(data).hexdigest()
    assert snapshot.text == data.decode("utf-8")
    assert snapshot.language_id == "python"
    assert snapshot.uri == file.resolve().as_uri()


def test_inspect_source_file_rejects_binary_invalid_utf8_and_oversized_files(
    workspace: tuple[Path, Settings],
) -> None:
    root, settings = workspace
    (root / "binary.py").write_bytes(b"value = 1\x00")
    (root / "invalid.py").write_bytes(b"\xff\xfe")
    (root / "large.py").write_text("x" * 2048, encoding="utf-8")

    with pytest.raises(UnsupportedMediaAppError):
        inspect_source_file(root, "binary.py", settings)
    with pytest.raises(UnsupportedMediaAppError):
        inspect_source_file(root, "invalid.py", settings)
    with pytest.raises(ResourceLimitAppError) as error:
        inspect_source_file(root, "large.py", settings)
    assert error.value.code == "E_FILE_TOO_LARGE"


def test_inspect_source_text_hashes_the_supplied_buffer_instead_of_the_disk_copy(
    workspace: tuple[Path, Settings],
) -> None:
    root, settings = workspace
    file = root / "app.py"
    file.write_text("saved = True\n", encoding="utf-8")
    supplied = "print('unsaved')\n"
    data = supplied.encode("utf-8")

    snapshot = inspect_source_text(root, "app.py", supplied, settings)

    assert snapshot.path == file.resolve()
    assert snapshot.uri == file.resolve().as_uri()
    assert snapshot.size == len(data)
    assert snapshot.sha256 == hashlib.sha256(data).hexdigest()
    assert snapshot.text == supplied
    assert snapshot.language_id == "python"
    assert snapshot.sha256 != hashlib.sha256(file.read_bytes()).hexdigest()


def test_inspect_source_text_rejects_binary_oversized_and_unencodable_text(
    workspace: tuple[Path, Settings],
) -> None:
    root, settings = workspace
    (root / "app.py").write_text("saved = True\n", encoding="utf-8")

    with pytest.raises(UnsupportedMediaAppError):
        inspect_source_text(root, "app.py", "value = 1\x00", settings)
    with pytest.raises(UnsupportedMediaAppError):
        inspect_source_text(root, "app.py", "\ud800", settings)
    with pytest.raises(ResourceLimitAppError) as error:
        inspect_source_text(root, "app.py", "x" * 2048, settings)
    assert error.value.code == "E_FILE_TOO_LARGE"


def test_inspect_source_text_still_requires_an_existing_contained_path(
    workspace: tuple[Path, Settings],
    tmp_path: Path,
) -> None:
    root, settings = workspace
    outside = tmp_path / "outside.py"
    outside.write_text("outside = True\n", encoding="utf-8")

    with pytest.raises(NotFoundAppError):
        inspect_source_text(root, "missing.py", "value = 1\n", settings)
    with pytest.raises(SecurityAppError) as error:
        inspect_source_text(root, outside, "value = 1\n", settings)
    assert error.value.code == "E_PATH_OUTSIDE_WORKSPACE"


def test_validate_selection_accepts_a_contained_range() -> None:
    validate_selection("first\nsecond\n", 0, 0, 1, 6)


def test_validate_selection_rejects_out_of_file_positions() -> None:
    with pytest.raises(ValidationAppError):
        validate_selection("first\n", 9, 0, 9, 1)
    with pytest.raises(ValidationAppError):
        validate_selection("first\n", 0, 99, 0, 100)


def test_enumerate_workspace_sources_skips_ignored_symlinks_and_non_sources(
    workspace: tuple[Path, Settings],
    tmp_path: Path,
) -> None:
    root, settings = workspace
    package = root / "src"
    package.mkdir()
    source = package / "util.js"
    source.write_text("export const value = 1;\n", encoding="utf-8")
    (root / "README.md").write_text("# docs\n", encoding="utf-8")
    ignored = root / "node_modules"
    ignored.mkdir()
    (ignored / "dependency.js").write_text("value\n", encoding="utf-8")

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "external.py").write_text("value = 1\n", encoding="utf-8")
    link = root / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        link = None

    files = enumerate_workspace_sources(root, settings)

    assert [file.path for file in files] == [source]
    assert files[0].language_id == "javascript"
    assert files[0].size == source.stat().st_size
    if link is not None:
        assert all(not file.path.is_relative_to(link) for file in files)
