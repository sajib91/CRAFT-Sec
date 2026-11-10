#!/usr/bin/env python3
"""Cross-platform development task runner for CRAFT-Sec.

Examples:
    python3 scripts/dev.py setup --cpu --with-analyzers
    python3 scripts/dev.py lint
    python3 scripts/dev.py test
    python3 scripts/dev.py build
"""

from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "security-engine"
SCRIPTS = ROOT / "scripts"
VENV = ROOT / ".venv"
TORCH_CPU_INDEX = "https://download.pytorch.org/whl/cpu"
MIN_PYTHON = (3, 11)
MAX_PYTHON_EXCLUSIVE = (3, 15)
MIN_NODE = (22, 13)


def fail(message: str) -> None:
    raise SystemExit(f"Error: {message}")


def run(command: list[str], cwd: Path = ROOT) -> None:
    printable = " ".join(str(part) for part in command)
    print(f"\n$ {printable}")
    try:
        subprocess.run(command, cwd=cwd, check=True)
    except FileNotFoundError as exc:
        fail(f"command not found: {command[0]} ({exc})")
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.returncode) from exc


def venv_python() -> Path | None:
    candidates = [
        VENV / "Scripts" / "python.exe",  # Windows
        VENV / "bin" / "python",  # macOS / Linux
    ]
    return next((path for path in candidates if path.is_file()), None)


def require_venv() -> Path:
    python = venv_python()
    if python is None:
        fail(
            "virtual environment not found. Run `npm run setup` or `python3 scripts/dev.py setup`."
        )
    return python


def resolve_python(value: str | None) -> str:
    candidate = value or sys.executable
    resolved = shutil.which(candidate)
    if resolved is None:
        fail(f"Python interpreter not found: {candidate}")
    return resolved


def python_version(executable: str) -> tuple[int, int]:
    output = subprocess.check_output(
        [
            executable,
            "-c",
            "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')",
        ],
        text=True,
    ).strip()
    major, minor = output.split(".", 1)
    return int(major), int(minor)


def require_python(executable: str) -> None:
    version = python_version(executable)
    if version < MIN_PYTHON or version >= MAX_PYTHON_EXCLUSIVE:
        fail(
            f"Python {version[0]}.{version[1]} is unsupported. "
            f"Use >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]} and < "
            f"{MAX_PYTHON_EXCLUSIVE[0]}.{MAX_PYTHON_EXCLUSIVE[1]}."
        )


def npm_command() -> str:
    candidate = shutil.which("npm")
    if candidate is None:
        fail("npm not found. Install Node.js 22.13+ or 24+ from https://nodejs.org/.")
    return candidate


def node_version() -> tuple[int, int, int]:
    output = subprocess.check_output(["node", "--version"], text=True).strip().lstrip("v")
    parts = output.split(".")
    while len(parts) < 3:
        parts.append("0")
    return int(parts[0]), int(parts[1]), int(parts[2])


def require_node() -> None:
    version = node_version()
    supported = (version[0] == MIN_NODE[0] and version[1] >= MIN_NODE[1]) or version[0] >= 24
    if not supported:
        fail(
            f"Node.js {version[0]}.{version[1]}.{version[2]} is unsupported. "
            "Use Node.js 22.13+ or 24+ (24 LTS recommended)."
        )


def create_env_file() -> None:
    env_path = ROOT / ".env"
    example = ROOT / ".env.example"
    if env_path.exists():
        print("\n.env already exists; leaving it unchanged.")
        return
    if not example.is_file():
        fail(".env.example is missing")
    shutil.copyfile(example, env_path)
    print(f"\nCreated {env_path} from .env.example. Review it before running analyses.")


def setup(args: argparse.Namespace) -> None:
    interpreter = resolve_python(args.python)
    require_python(interpreter)
    version = python_version(interpreter)
    print(f"Using Python {version[0]}.{version[1]}: {interpreter}")

    if not VENV.exists():
        run([interpreter, "-m", "venv", str(VENV)])
    else:
        print(f"Reusing existing virtual environment: {VENV}")

    python = require_venv()
    require_python(str(python))
    run([str(python), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"])

    if args.static_only:
        extras = ["dev"]
    else:
        extras = ["dev", "ml"]
    if args.with_analyzers:
        extras.append("analyzers")

    if "ml" in extras and args.cpu:
        run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--upgrade",
                "torch",
                "--index-url",
                TORCH_CPU_INDEX,
            ]
        )

    spec = f".[{','.join(extras)}]"
    run([str(python), "-m", "pip", "install", "-e", spec], cwd=ENGINE)

    if not args.skip_node:
        require_node()
        run([npm_command(), "install"], cwd=ROOT)

    create_env_file()

    print("\nSetup complete.")
    if args.static_only:
        print("Installed static-only Python environment (no PyTorch/Transformers).")
    else:
        print("Installed core, development, and ML dependencies. No models were downloaded.")
    if args.with_analyzers:
        print("Installed Semgrep and Bandit into the project virtual environment.")
    else:
        print("Semgrep/Bandit were not installed. Add --with-analyzers for the optional analyzers.")
    print("Next: npm run doctor && npm run test")


def installed_packages(python: Path) -> None:
    script = """
from importlib import metadata

for name in [
    "fastapi", "uvicorn", "pydantic", "pydantic-settings", "sqlalchemy",
    "alembic", "numpy", "pandas", "torch", "transformers", "safetensors",
    "tree-sitter", "tree-sitter-python", "tree-sitter-javascript",
    "tree-sitter-typescript", "pytest", "semgrep", "bandit", "ruff",
]:
    try:
        print(f"{name}=={metadata.version(name)}")
    except metadata.PackageNotFoundError:
        print(f"{name}: not installed")
"""
    try:
        subprocess.run([str(python), "-c", script], check=False)
    except FileNotFoundError:
        print("Virtual environment interpreter is missing.")


def tool_version(command: str, arguments: list[str], label: str | None = None) -> None:
    name = label or command
    path = shutil.which(command) if not Path(command).is_file() else command
    if path is None:
        print(f"{name}: not installed")
        return
    try:
        result = subprocess.run(
            [path, *arguments], capture_output=True, text=True, timeout=60, check=False
        )
        output = (result.stdout or result.stderr).strip().splitlines()
        print(f"{name}: {output[0] if output else 'installed'}")
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"{name}: installed but not runnable ({exc})")


def doctor(_: argparse.Namespace | None = None) -> None:
    print("CRAFT-Sec development environment")
    print(f"Platform: {platform.platform()}")
    print(f"Machine: {platform.machine()}")
    print(f"Project: {ROOT}")

    try:
        node = subprocess.check_output(["node", "--version"], text=True).strip()
        print(f"Node.js: {node}")
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("Node.js: not installed")

    try:
        print(f"npm: {subprocess.check_output([npm_command(), '--version'], text=True).strip()}")
    except SystemExit:
        print("npm: not installed")

    python = venv_python()
    if python is None:
        print("Python: no project virtual environment (run setup)")
    else:
        version = subprocess.check_output(
            [str(python), "-c", "import sys; print(sys.version.split()[0])"], text=True
        ).strip()
        print(f"Python (venv): {version}")
        print("\nPython packages:")
        installed_packages(python)

    print("\nOptional analyzers:")
    analyzer_paths: dict[str, str] = {}
    for name in ("semgrep", "bandit"):
        installed = shutil.which(name, path=str(python.parent)) if python else None
        analyzer_paths[name] = installed or name
    tool_version(analyzer_paths["semgrep"], ["--version"], label="semgrep")
    tool_version(analyzer_paths["bandit"], ["--version"], label="bandit")

    print("\nOptional sandbox:")
    tool_version("docker", ["--version"])

    print(f"\n.env: {'present' if (ROOT / '.env').is_file() else 'missing (run setup)'}")
    print("Model downloads: not performed by setup or doctor.")


def structure_check(_: argparse.Namespace | None = None) -> None:
    run([sys.executable, str(ROOT / "scripts" / "check_structure.py")], cwd=ROOT)


def lint(_: argparse.Namespace | None = None) -> None:
    python = require_venv()
    run([str(python), "-m", "ruff", "check", "src", "tests", str(SCRIPTS)], cwd=ENGINE)
    run([npm_command(), "--workspace", "vscode-extension", "run", "lint"], cwd=ROOT)


def format_code(_: argparse.Namespace | None = None) -> None:
    python = require_venv()
    run([str(python), "-m", "ruff", "format", "src", "tests", str(SCRIPTS)], cwd=ENGINE)
    run([npm_command(), "--workspace", "vscode-extension", "run", "format"], cwd=ROOT)


def format_check(_: argparse.Namespace | None = None) -> None:
    python = require_venv()
    run(
        [str(python), "-m", "ruff", "format", "--check", "src", "tests", str(SCRIPTS)],
        cwd=ENGINE,
    )
    run(
        [npm_command(), "--workspace", "vscode-extension", "run", "format:check"],
        cwd=ROOT,
    )


def test(_: argparse.Namespace | None = None) -> None:
    python = require_venv()
    run([str(python), "-m", "pytest"], cwd=ENGINE)
    run([npm_command(), "--workspace", "vscode-extension", "run", "test"], cwd=ROOT)


def build(_: argparse.Namespace | None = None) -> None:
    python = require_venv()
    run([str(python), "-m", "build", "--wheel", "--outdir", "dist"], cwd=ENGINE)
    run([npm_command(), "--workspace", "vscode-extension", "run", "package"], cwd=ROOT)
    print("\nBuild artifacts:")
    print(f"  Python wheel: {ENGINE / 'dist'}")
    print(f"  VSIX: {ROOT / 'vscode-extension'}")


def check(_: argparse.Namespace | None = None) -> None:
    structure_check()
    lint()
    format_check()
    test()


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    subparsers = root.add_subparsers(dest="command", required=True)

    setup_parser = subparsers.add_parser(
        "setup", help="create the virtual environment and install dependencies"
    )
    setup_parser.add_argument("--python", help="Python interpreter used to create the venv")
    setup_parser.add_argument(
        "--cpu",
        action="store_true",
        help="install the CPU-only PyTorch wheel before installing the project",
    )
    setup_parser.add_argument(
        "--with-analyzers",
        action="store_true",
        help="install the optional Semgrep and Bandit dependencies",
    )
    setup_parser.add_argument(
        "--static-only",
        action="store_true",
        help="skip PyTorch/Transformers for a lightweight static-analysis environment",
    )
    setup_parser.add_argument("--skip-node", action="store_true", help="skip npm install")
    setup_parser.set_defaults(func=setup)

    for name, function, help_text in [
        ("doctor", doctor, "print tool, package, and optional dependency status"),
        ("structure-check", structure_check, "validate the repository layout"),
        ("lint", lint, "run Ruff and ESLint"),
        ("format", format_code, "format Python and JavaScript"),
        ("format-check", format_check, "check formatting without writing"),
        ("test", test, "run Pytest and extension unit tests"),
        ("build", build, "build the Python wheel and VSIX"),
        ("check", check, "run structure, lint, format, and tests"),
    ]:
        command = subparsers.add_parser(name, help=help_text)
        command.set_defaults(func=function)

    return root


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    args = parser().parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
