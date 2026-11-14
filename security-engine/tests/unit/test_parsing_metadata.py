from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from craftsec.parsing import SupportedLanguage, extract_repository_metadata


def _write(root: Path, relative: str, content: str | bytes) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def test_extracts_repository_totals_languages_and_hashes(tmp_path) -> None:
    app_text = "def alpha():\n    pass\n\nclass C:\n    def method(self):\n        pass\n"
    web_text = "export function beta() {}\nconst gamma = () => 1;\n"
    _write(tmp_path, "pkg/app.py", app_text)
    _write(tmp_path, "web.js", web_text)

    metadata = extract_repository_metadata(tmp_path)

    assert metadata.root == str(tmp_path.resolve())
    assert metadata.file_count == 2
    assert metadata.skipped_count == 0
    assert metadata.skipped_files == ()
    assert metadata.language_counts == {"javascript": 1, "python": 1}
    assert metadata.truncated is False
    assert metadata.warnings == ()
    assert metadata.files_with_syntax_errors == 0
    assert [file.path for file in metadata.files] == ["web.js", "pkg/app.py"]

    by_path = {file.path: file for file in metadata.files}
    app = by_path["pkg/app.py"]
    assert app.language is SupportedLanguage.PYTHON
    assert app.size_bytes == len(app_text.encode("utf-8"))
    assert app.sha256 == hashlib.sha256(app_text.encode("utf-8")).hexdigest()
    assert app.line_count == 6
    assert app.function_count == 2
    assert app.class_count == 1
    assert app.syntax_error_count == 0
    assert app.parse_ok is True

    web = by_path["web.js"]
    assert web.language is SupportedLanguage.JAVASCRIPT
    assert web.function_count == 2
    assert web.class_count == 0
    assert web.parse_ok is True

    assert metadata.total_bytes == len(app_text.encode("utf-8")) + len(web_text.encode("utf-8"))
    assert metadata.total_lines == 8
    assert metadata.total_functions == 4
    assert metadata.total_classes == 1

    without_hashes = extract_repository_metadata(tmp_path, include_hashes=False)
    assert all(file.sha256 is None for file in without_hashes.files)


def test_ignored_directories_are_not_walked(tmp_path) -> None:
    _write(tmp_path, "src/kept.py", "x = 1\n")
    for ignored in ("node_modules", "__pycache__", ".venv", "build", "dist"):
        _write(tmp_path, f"{ignored}/ignored.js", "const x = 1;\n")

    metadata = extract_repository_metadata(tmp_path)

    assert [file.path for file in metadata.files] == ["src/kept.py"]
    assert metadata.skipped_files == ()
    assert metadata.language_counts == {"python": 1}


def test_reports_each_skipped_file_reason(tmp_path) -> None:
    _write(tmp_path, "big.py", "x = '" + "a" * 20 + "'\n")
    _write(tmp_path, "bin.py", b"a = 1\x00")
    _write(tmp_path, "latin.py", b"x = '\xff'\n")
    _write(tmp_path, "small.py", "x = 1\n")
    _write(tmp_path, "types.ts", "const x = 1;\n")
    _write(tmp_path, "README.md", "# Not source\n")

    metadata = extract_repository_metadata(tmp_path, max_file_bytes=20)

    assert {skipped.path: skipped.reason for skipped in metadata.skipped_files} == {
        "big.py": "too_large",
        "bin.py": "binary",
        "latin.py": "invalid_utf8",
        "types.ts": "unsupported_language",
    }
    assert [file.path for file in metadata.files] == ["small.py"]
    assert metadata.file_count == 1
    assert metadata.total_bytes == 6
    assert metadata.total_lines == 1
    assert metadata.total_functions == 0
    assert metadata.total_classes == 0


def test_syntax_errors_are_reported_without_dropping_the_file(tmp_path) -> None:
    _write(tmp_path, "bad.py", "def broken(:\n    return 1\n")
    _write(tmp_path, "good.js", "function good() {}\n")

    metadata = extract_repository_metadata(tmp_path)

    by_path = {file.path: file for file in metadata.files}
    bad = by_path["bad.py"]
    assert bad.parse_ok is False
    assert bad.syntax_error_count >= 1
    assert bad.function_count == 1
    assert by_path["good.js"].parse_ok is True
    assert metadata.files_with_syntax_errors == 1
    assert metadata.file_count == 2


def test_truncates_after_max_files_and_reports_a_warning(tmp_path) -> None:
    for name in ("a.py", "b.py", "c.py", "d.py"):
        _write(tmp_path, name, "x = 1\n")

    metadata = extract_repository_metadata(tmp_path, max_files=2)

    assert metadata.truncated is True
    assert metadata.file_count == 2
    assert [file.path for file in metadata.files] == ["a.py", "b.py"]
    assert len(metadata.warnings) == 1
    assert "stopped after 2" in metadata.warnings[0]


def test_truncation_counts_candidates_that_are_skipped(tmp_path) -> None:
    _write(tmp_path, "a.py", "x = 1\n")
    _write(tmp_path, "b.ts", "const x = 1;\n")
    _write(tmp_path, "c.py", "y = 2\n")

    metadata = extract_repository_metadata(tmp_path, max_files=2)

    assert metadata.truncated is True
    assert metadata.file_count == 1
    assert [file.path for file in metadata.files] == ["a.py"]
    assert [(skipped.path, skipped.reason) for skipped in metadata.skipped_files] == [
        ("b.ts", "unsupported_language")
    ]


def test_includes_supported_python_variants(tmp_path) -> None:
    _write(tmp_path, "types.pyi", "def stub() -> None: ...\n")
    _write(tmp_path, "window.pyw", "x = 1\n")

    metadata = extract_repository_metadata(tmp_path)

    assert [(file.path, file.language) for file in metadata.files] == [
        ("types.pyi", SupportedLanguage.PYTHON),
        ("window.pyw", SupportedLanguage.PYTHON),
    ]
    assert metadata.total_functions == 1


def test_skips_symlinked_files_and_directories(tmp_path) -> None:
    _write(tmp_path, "real.py", "x = 1\n")
    _write(tmp_path, "real_dir/item.py", "y = 2\n")
    try:
        os.symlink(tmp_path / "real.py", tmp_path / "link.py")
        os.symlink(tmp_path / "real_dir", tmp_path / "alias", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this platform")

    metadata = extract_repository_metadata(tmp_path)

    assert [file.path for file in metadata.files] == ["real.py", "real_dir/item.py"]
    assert metadata.skipped_files == ()


def test_empty_repository_returns_empty_totals(tmp_path) -> None:
    metadata = extract_repository_metadata(tmp_path)

    assert metadata.file_count == 0
    assert metadata.skipped_count == 0
    assert metadata.language_counts == {}
    assert metadata.total_bytes == 0
    assert metadata.total_lines == 0
    assert metadata.total_functions == 0
    assert metadata.total_classes == 0
    assert metadata.files_with_syntax_errors == 0
    assert metadata.truncated is False
    assert metadata.warnings == ()


def test_rejects_invalid_roots_and_limits(tmp_path) -> None:
    _write(tmp_path, "a.py", "x = 1\n")

    with pytest.raises(ValueError, match="does not exist"):
        extract_repository_metadata(tmp_path / "missing")
    with pytest.raises(ValueError, match="must be a directory"):
        extract_repository_metadata(tmp_path / "a.py")
    with pytest.raises(ValueError, match="max_files"):
        extract_repository_metadata(tmp_path, max_files=0)
    with pytest.raises(ValueError, match="max_file_bytes"):
        extract_repository_metadata(tmp_path, max_file_bytes=0)
