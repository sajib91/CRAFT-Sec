"""Versioned API router composition."""

from __future__ import annotations

from fastapi import APIRouter

from craftsec.api.routes import (
    counterfactual,
    detection,
    explanation,
    features,
    health,
    prevention,
    repair,
    scan,
    verification,
)
from craftsec.config import API_PREFIX

api_router = APIRouter(prefix=API_PREFIX)
api_router.include_router(health.router)
api_router.include_router(scan.router)
api_router.include_router(detection.router)
api_router.include_router(explanation.router)
api_router.include_router(features.router)
api_router.include_router(counterfactual.router)
api_router.include_router(prevention.router)
api_router.include_router(repair.router)
api_router.include_router(verification.router)

__all__ = ["api_router"]
