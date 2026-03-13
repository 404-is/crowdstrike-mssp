"""
main.py — FalconGuard MSSP Platform · FastAPI Application

Start with:
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

Production:
    uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
"""

import logging
import time
from contextlib import asynccontextmanager
from typing import Dict

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings, CLIENT_REGISTRY, all_clients, CLOUD_BASE_URLS
from models.schemas import TokenHealthResponse

# ── Route imports ─────────────────────────────────────────────────────────────
from routes.overview   import router as overview_router
from routes.detections import router as detections_router
from routes.hosts      import router as hosts_router
from routes.incidents  import router as incidents_router
from routes.intel       import router as intel_router
from routes.ai_insights import router as ai_router

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("falconguard")


# ── Lifespan (startup / shutdown) ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── STARTUP ──────────────────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("  FalconGuard MSSP Platform — Starting")
    logger.info("=" * 60)

    if not CLIENT_REGISTRY:
        logger.warning(
            "No clients loaded from environment. "
            "Populate CLIENT_N_* variables in .env and restart."
        )
    else:
        logger.info(f"  Loaded {len(CLIENT_REGISTRY)} client tenant(s):")
        for slug, cfg in CLIENT_REGISTRY.items():
            logger.info(f"    [{cfg.tier.upper()}] {cfg.name} ({cfg.cid}) — {cfg.cloud}")


    # Pre-warm tokens for all clients on startup (non-blocking)
    import asyncio
    async def _prewarm():
        tasks = [token_manager.get_token(cfg) for cfg in all_clients()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        ok  = sum(1 for r in results if not isinstance(r, Exception))
        err = sum(1 for r in results if isinstance(r, Exception))
        logger.info(f"  Token pre-warm: {ok} ok, {err} failed")
    await _prewarm()

    logger.info("  API ready.")
    logger.info("=" * 60)

    yield   # ← app runs here

    # ── SHUTDOWN ─────────────────────────────────────────────────────────────
    logger.info("FalconGuard MSSP — Shutting down")


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title=       "FalconGuard MSSP API",
    description= "Multi-tenant CrowdStrike management platform for MSSPs",
    version=     "1.0.0",
    docs_url=    "/docs",
    redoc_url=   "/redoc",
    lifespan=    lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# CORS — in dev mode allow all origins so frontend.html works from
# file://, localhost, 127.0.0.1, or any port without configuration.
# Set APP_ENV=production in .env to restrict to CORS_ORIGINS list.
_cors_origins = ["*"] if settings.app_env != "production" else settings.cors_origins_list

app.add_middleware(
    CORSMiddleware,
    allow_origins=     _cors_origins,
    allow_credentials= False,   # must be False when allow_origins=["*"]
    allow_methods=     ["*"],
    allow_headers=     ["*"],
)


# ── Request timing middleware ─────────────────────────────────────────────────
@app.middleware("http")
async def add_timing_header(request: Request, call_next):
    start = time.monotonic()
    response = await call_next(request)
    elapsed_ms = round((time.monotonic() - start) * 1000, 1)
    response.headers["X-Response-Time-Ms"] = str(elapsed_ms)
    return response


# ── Global exception handler ──────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "type": type(exc).__name__},
    )


# ── Routers ───────────────────────────────────────────────────────────────────
API_PREFIX = "/api/v1"

app.include_router(overview_router,    prefix=API_PREFIX)
app.include_router(detections_router,  prefix=API_PREFIX)
app.include_router(hosts_router,       prefix=API_PREFIX)
app.include_router(incidents_router,   prefix=API_PREFIX)
app.include_router(intel_router,       prefix=API_PREFIX)
app.include_router(ai_router,          prefix=API_PREFIX)


# ── Health & Utility Endpoints ────────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health():
    """Basic health check. Returns OK if the service is running."""
    return {
        "status":       "ok",
        "env":          settings.app_env,
        "clients_loaded": len(CLIENT_REGISTRY),
    }


@app.get("/health/tokens", response_model=TokenHealthResponse, tags=["System"])
async def token_health():
    """
    Shows the token cache status for all client tenants.
    Useful for debugging auth issues.
    """
    return TokenHealthResponse(tokens=token_manager.token_status())


@app.get("/api/v1/clients", tags=["Clients"])
async def list_clients():
    """
    Returns the registered client list (no secrets).
    Used by the frontend to populate the client selector.
    """
    return [
        {
            "slug":     cfg.slug,
            "name":     cfg.name,
            "cid":      cfg.cid,
            "cloud":    cfg.cloud,
            "tier":     cfg.tier,
            "industry": cfg.industry,
            "base_url": cfg.base_url,
        }
        for cfg in all_clients()
    ]


@app.get("/api/v1/clouds", tags=["System"])
async def list_clouds():
    """Returns all supported CrowdStrike cloud environments and their base URLs."""
    return CLOUD_BASE_URLS


@app.get("/", tags=["System"])
async def root():
    return {
        "service":  "FalconGuard MSSP API",
        "version":  "1.0.0",
        "docs":     "/docs",
        "health":   "/health",
        "clients":  len(CLIENT_REGISTRY),
    }
