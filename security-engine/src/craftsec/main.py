"""Executable entry point for the local CRAFT-Sec engine."""

from __future__ import annotations

import argparse

import uvicorn

from craftsec.api.app import create_app
from craftsec.config import get_settings
from craftsec.core.logging import configure_logging

app = create_app()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the local CRAFT-Sec FastAPI engine.")
    parser.add_argument("--host", help="Bind host (default: CRAFTSEC_HOST or 127.0.0.1).")
    parser.add_argument(
        "--port",
        type=int,
        help="Bind port (default: CRAFTSEC_PORT or 8765; use 0 for an ephemeral port).",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    settings = get_settings()
    updates = {
        key: value
        for key, value in {"host": args.host, "port": args.port}.items()
        if value is not None
    }
    if updates:
        settings = settings.model_copy(update=updates)

    settings.ensure_directories()
    configure_logging(settings)
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        access_log=False,
    )


if __name__ == "__main__":
    main()
