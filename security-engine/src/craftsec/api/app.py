"""FastAPI application factory and middleware composition."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi

from craftsec import __version__
from craftsec.api.middleware import (
    BearerTokenMiddleware,
    RequestContextMiddleware,
    RequestSizeLimitMiddleware,
    register_exception_handlers,
)
from craftsec.api.routes import api_router
from craftsec.config import (
    API_PREFIX,
    API_VERSION,
    REQUEST_ID_HEADER,
    SERVICE_NAME,
    get_settings,
)
from craftsec.core.logging import configure_logging
from craftsec.core.orchestrator import Orchestrator
from craftsec.core.settings import Settings

OPENAPI_TAGS = [
    {
        "name": "system",
        "description": "Liveness and explicit capability discovery.",
    },
    {
        "name": "scan",
        "description": "File and workspace inspection with explicit evidence-stage status.",
    },
    {
        "name": "detection",
        "description": "Evidence fusion and vulnerability detection.",
    },
    {
        "name": "explanation",
        "description": "Evidence graphs for backend findings.",
    },
    {
        "name": "features",
        "description": "Genuine model/SAE feature extraction when configured.",
    },
    {
        "name": "counterfactual",
        "description": "Model-internal feature interventions, not real-world causality.",
    },
    {
        "name": "prevention",
        "description": "Explicit opt-in activation steering and paired evaluation.",
    },
    {
        "name": "repair",
        "description": "Repair proposals for explicit user review; no automatic writes.",
    },
    {
        "name": "verification",
        "description": "Independent security and functional verification.",
    },
]

DESCRIPTION = """
Local-first CRAFT-Sec security engine API.

Every operation reports what actually ran. When a model, SAE artifact, analyzer,
detector, repair generator, or sandbox is not implemented or configured, the
corresponding stage is `unavailable` and the response contains no invented
findings, scores, features, effects, patches, or verdicts.

Operation responses use `status` values `completed`, `partial`, `unavailable`,
or `failed`. Clients must not treat `unavailable` as a clean scan.
""".strip()


def create_app(
    settings: Settings | None = None,
    orchestrator: Orchestrator | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    logger = configure_logging(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.started_at = time.monotonic()
        logger.info(
            "CRAFT-Sec engine started.",
            extra={"operation": "startup", "path": API_PREFIX},
        )
        yield
        logger.info(
            "CRAFT-Sec engine stopped.",
            extra={"operation": "shutdown", "path": API_PREFIX},
        )

    app = FastAPI(
        title="CRAFT-Sec Security Engine API",
        description=DESCRIPTION,
        version=__version__,
        openapi_tags=OPENAPI_TAGS,
        openapi_url="/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.orchestrator = orchestrator or Orchestrator(settings)
    app.state.started_at = time.monotonic()

    # Middleware order: the last added runs first. Request context is outermost
    # so every response, including CORS preflight, carries the request ID. CORS
    # wraps auth and size-limit responses so errors keep the allowlist headers.
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    token = settings.api_token.get_secret_value() if settings.api_token else None
    app.add_middleware(BearerTokenMiddleware, token=token, api_prefix="/api/")
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", REQUEST_ID_HEADER],
            expose_headers=[REQUEST_ID_HEADER],
            max_age=600,
        )
    app.add_middleware(RequestContextMiddleware)

    register_exception_handlers(app)
    app.include_router(api_router)

    def openapi_schema() -> dict[str, object]:
        """Document the RFC 9457 media type that error handlers actually send."""
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title,
            version=app.version,
            openapi_version=app.openapi_version,
            description=app.description,
            routes=app.routes,
            tags=app.openapi_tags,
            servers=app.servers,
        )
        components = schema.setdefault("components", {})
        components.setdefault("securitySchemes", {})["BearerAuth"] = {
            "type": "http",
            "scheme": "bearer",
            "description": (
                "Optional per-launch token. Required only when CRAFTSEC_API_TOKEN is configured."
            ),
        }
        for path_item in schema.get("paths", {}).values():
            for operation in path_item.values():
                if not isinstance(operation, dict):
                    continue
                for status, response in operation.get("responses", {}).items():
                    if status.startswith("2") or not isinstance(response, dict):
                        continue
                    content = response.get("content")
                    if content and "application/json" in content:
                        content["application/problem+json"] = content.pop("application/json")
        app.openapi_schema = schema
        return schema

    app.openapi = openapi_schema  # type: ignore[method-assign]

    @app.get("/", include_in_schema=False)
    def index() -> dict[str, str]:
        return {
            "service": SERVICE_NAME,
            "apiVersion": API_VERSION,
            "docs": "/docs",
            "openapi": "/openapi.json",
        }

    return app


app = create_app()
