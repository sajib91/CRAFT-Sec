#!/usr/bin/env python3
"""Validate the CRAFT-Sec monorepo scaffold.

This is a structural check only. It does not import or execute application
code, and it makes no claim about research functionality.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PACKAGES = [
    "api",
    "artifacts",
    "contracts",
    "core",
    "counterfactual",
    "db",
    "detection",
    "evaluation",
    "experiments",
    "explain",
    "features",
    "ingestion",
    "models",
    "observability",
    "parsing",
    "program_analysis",
    "repair",
    "sae",
    "sandbox",
    "static",
    "steering",
    "verification",
]

REQUIRED_DIRS = [
    "docs",
    "docs/adr",
    ".vscode",
    "scripts",
    "shared",
    "shared/schemas",
    "shared/generated",
    "shared/fixtures",
    "research",
    "research/configs",
    "research/datasets",
    "research/evaluation",
    "research/experiments",
    "research/protocols",
    "benchmarks",
    "benchmarks/configs",
    "benchmarks/datasets",
    "benchmarks/harness",
    "benchmarks/tasks",
    "benchmarks/results",
    "vscode-extension",
    "vscode-extension/src",
    "vscode-extension/src/api",
    "vscode-extension/src/backend",
    "vscode-extension/src/commands",
    "vscode-extension/src/jobs",
    "vscode-extension/src/logging",
    "vscode-extension/src/security",
    "vscode-extension/src/views",
    "vscode-extension/src/webviews",
    "vscode-extension/src/workspace",
    "vscode-extension/media",
    "vscode-extension/test",
    "vscode-extension/test/unit",
    "vscode-extension/test/integration",
    "vscode-extension/test/fixtures",
    "security-engine",
    "security-engine/migrations",
    "security-engine/src",
    "security-engine/src/craftsec",
    "security-engine/tests",
    "security-engine/tests/unit",
    "security-engine/tests/integration",
    "security-engine/tests/contract",
    "security-engine/tests/fixtures",
]

REQUIRED_FILES = [
    "README.md",
    ".gitignore",
    ".env.example",
    ".editorconfig",
    ".prettierignore",
    ".prettierrc.json",
    ".nvmrc",
    ".python-version",
    "package.json",
    "package-lock.json",
    ".vscode/launch.json",
    ".vscode/extensions.json",
    "docs/README.md",
    "docs/architecture.md",
    "docs/development-setup.md",
    "docs/research-alignment.md",
    "docs/adr/README.md",
    "scripts/README.md",
    "scripts/check_structure.py",
    "scripts/dev.py",
    "scripts/dev.js",
    "shared/README.md",
    "shared/schemas/README.md",
    "shared/schemas/VERSION",
    "shared/generated/README.md",
    "research/README.md",
    "research/datasets/README.md",
    "research/evaluation/README.md",
    "benchmarks/README.md",
    "benchmarks/harness/README.md",
    "benchmarks/datasets/README.md",
    "vscode-extension/package.json",
    "vscode-extension/README.md",
    "vscode-extension/src/extension.js",
    "vscode-extension/src/constants.js",
    "vscode-extension/src/api/securityEngineService.js",
    "vscode-extension/src/commands/index.js",
    "vscode-extension/src/commands/definitions.js",
    "vscode-extension/src/commands/registry.js",
    "vscode-extension/src/commands/validation.js",
    "vscode-extension/src/commands/runEngineCommand.js",
    "vscode-extension/src/commands/registerEngineCommand.js",
    "vscode-extension/src/commands/scanCommands.js",
    "vscode-extension/src/commands/analysisCommands.js",
    "vscode-extension/src/commands/repairCommands.js",
    "vscode-extension/src/commands/dashboardCommand.js",
    "vscode-extension/src/commands/utilityCommands.js",
    "vscode-extension/src/config.js",
    "vscode-extension/src/logging/output.js",
    "vscode-extension/src/views/statusBar.js",
    "vscode-extension/src/webviews/sidebarView.js",
    "vscode-extension/src/webviews/sidebarHtml.js",
    "vscode-extension/src/webviews/csp.js",
    "vscode-extension/src/webviews/html.js",
    "vscode-extension/src/webviews/dashboardModel.js",
    "vscode-extension/src/webviews/dashboardHtml.js",
    "vscode-extension/src/webviews/dashboardPanel.js",
    "vscode-extension/media/activitybar.svg",
    "vscode-extension/media/icon.png",
    "vscode-extension/media/sidebar.css",
    "vscode-extension/media/sidebar.js",
    "vscode-extension/media/dashboard.css",
    "vscode-extension/media/dashboard.js",
    "vscode-extension/eslint.config.js",
    "vscode-extension/.vscodeignore",
    "vscode-extension/test/unit/commands.test.js",
    "vscode-extension/test/unit/manifest.test.js",
    "vscode-extension/test/unit/securityEngineService.test.js",
    "vscode-extension/test/unit/sidebar.test.js",
    "vscode-extension/test/unit/dashboardModel.test.js",
    "vscode-extension/test/unit/dashboardHtml.test.js",
    "vscode-extension/test/unit/dashboardPanel.test.js",
    "vscode-extension/test/unit/dashboardClient.test.js",
    "vscode-extension/test/integration/runTest.js",
    "vscode-extension/test/integration/index.js",
    "security-engine/pyproject.toml",
    "security-engine/requirements.txt",
    "security-engine/README.md",
    "security-engine/LIMITATIONS.md",
    "security-engine/migrations/README.md",
    "security-engine/src/craftsec/core/settings.py",
    "security-engine/tests/conftest.py",
    "security-engine/tests/unit/test_settings.py",
    "security-engine/tests/fixtures/README.md",
]

MUST_NOT_EXIST = [
    # Documentation lives under docs/; stale root copies create drift.
    "architecture.md",
    "research-alignment.md",
]

SKIP_DIR_NAMES = {
    ".git",
    "node_modules",
    ".venv",
    ".vscode-test",
    "dist",
    "build",
    "__pycache__",
}


def find_typescript_files() -> list[Path]:
    """Return TypeScript sources anywhere in the repository."""
    found: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in {".ts", ".tsx"}:
            continue
        relative = path.relative_to(ROOT)
        if any(part in SKIP_DIR_NAMES for part in relative.parts):
            continue
        found.append(path)
    return sorted(found)


def validate_extension_manifest() -> list[str]:
    """Check that the VS Code manifest points at a JavaScript entry point."""
    errors: list[str] = []
    manifest_path = ROOT / "vscode-extension" / "package.json"
    if not manifest_path.is_file():
        return errors

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"vscode-extension/package.json is invalid JSON: {exc}"]

    main = manifest.get("main")
    if not isinstance(main, str) or not main.endswith(".js"):
        errors.append("vscode-extension/package.json main must be a .js file")
        return errors

    if not (ROOT / "vscode-extension" / main).is_file():
        errors.append(f"vscode-extension manifest main does not exist: {main}")

    return errors


def main() -> int:
    missing_dirs = [path for path in REQUIRED_DIRS if not (ROOT / path).is_dir()]
    missing_files = [path for path in REQUIRED_FILES if not (ROOT / path).is_file()]
    stale_paths = [path for path in MUST_NOT_EXIST if (ROOT / path).exists()]

    missing_package_files = [
        f"security-engine/src/craftsec/{package}/__init__.py"
        for package in PACKAGES
        if not (ROOT / "security-engine" / "src" / "craftsec" / package / "__init__.py").is_file()
    ]

    typescript_files = find_typescript_files()
    manifest_errors = validate_extension_manifest()

    problems: list[str] = []
    problems.extend(f"missing directory: {path}" for path in missing_dirs)
    problems.extend(f"missing file: {path}" for path in missing_files)
    problems.extend(f"stale root path: {path}" for path in stale_paths)
    problems.extend(f"missing package marker: {path}" for path in missing_package_files)
    problems.extend(
        f"TypeScript source is forbidden: {path.relative_to(ROOT)}" for path in typescript_files
    )
    problems.extend(manifest_errors)

    print("CRAFT-Sec structure check")
    print(f"Root: {ROOT}")
    print(f"Required directories: {len(REQUIRED_DIRS)}")
    print(f"Required files: {len(REQUIRED_FILES)}")

    if problems:
        print(f"\n{len(problems)} problem(s) found:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print("\nStructure OK. No TypeScript sources detected.")
    print("Note: this checks layout only; no application functionality exists yet.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
