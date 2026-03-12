"""
routes/overview.py — Command Center aggregated view

Pulls data across ALL managed client tenants in parallel.
Powers the Command Center KPI strip and client health matrix.
"""

import asyncio
import logging
from typing import List, Tuple

from fastapi import APIRouter, HTTPException

from config import all_clients, ClientConfig
from services.crowdstrike import CrowdStrikeClient
from models.schemas import (
    OverviewResponse, OverviewKPIs, ClientSummary, APIError
)

router = APIRouter(prefix="/overview", tags=["Overview"])
logger = logging.getLogger("falconguard.overview")

# Severity mapping from CrowdStrike integer values
SEVERITY_MAP = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


# ── Per-client data fetcher ────────────────────────────────────────────────

async def _fetch_client_summary(cfg: ClientConfig) -> Tuple[ClientSummary, List[APIError]]:
    """
    Fetches sensor count and 24h detection summary for one client tenant.
    Returns (ClientSummary, errors). Never raises — errors are captured.
    """
    errors: List[APIError] = []
    cs = CrowdStrikeClient(cfg)

    online_sensors = 0
    total_sensors  = 0
    critical_count = 0
    high_count     = 0
    total_dets     = 0
    status         = "unknown"

    try:
        # ── Sensor count ──────────────────────────────────────────────────
        # Query all devices, then filter by reduced_functionality_mode != true
        host_resp = await cs.get(
            "/devices/queries/devices/v1",
            params={"limit": 1, "filter": "status:'normal'"}
        )
        total_meta  = host_resp.get("meta", {}).get("pagination", {})
        total_sensors = total_meta.get("total", 0)

        online_resp = await cs.get(
            "/devices/queries/devices/v1",
            params={"limit": 1, "filter": "status:'normal'+last_seen:>='now-1h'"}
        )
        online_sensors = online_resp.get("meta", {}).get("pagination", {}).get("total", 0)

        # ── Detection counts (last 24h) ────────────────────────────────────
        # CrowdStrike alerts API — filter by created_timestamp
        for severity_int, severity_name in [(4, "Critical"), (3, "High")]:
            det_resp = await cs.get(
                "/alerts/queries/alerts/v2",
                params={
                    "limit":  1,
                    "filter": f"severity:{severity_int}+created_timestamp:>='now-24h'",
                }
            )
            count = det_resp.get("meta", {}).get("pagination", {}).get("total", 0)
            if severity_int == 4:
                critical_count = count
            else:
                high_count = count

        all_det_resp = await cs.get(
            "/alerts/queries/alerts/v2",
            params={"limit": 1, "filter": "created_timestamp:>='now-24h'"}
        )
        total_dets = all_det_resp.get("meta", {}).get("pagination", {}).get("total", 0)

        # ── Derive status ──────────────────────────────────────────────────
        if critical_count > 0:
            status = "under_attack"
        elif high_count > 0:
            status = "monitoring"
        else:
            status = "protected"

    except Exception as e:
        logger.error(f"Failed to fetch summary for {cfg.name}: {e}")
        errors.append(APIError(code=500, message=str(e)))

    finally:
        await cs.close()

    health_pct = round((online_sensors / total_sensors * 100), 1) if total_sensors > 0 else 0.0

    return ClientSummary(
        slug=           cfg.slug,
        name=           cfg.name,
        cid=            cfg.cid,
        cloud=          cfg.cloud,
        tier=           cfg.tier,
        industry=       cfg.industry,
        online_sensors= online_sensors,
        total_sensors=  total_sensors,
        health_pct=     health_pct,
        det_24h=        total_dets,
        critical_count= critical_count,
        high_count=     high_count,
        status=         status,
    ), errors


# ── Routes ─────────────────────────────────────────────────────────────────

@router.get("", response_model=OverviewResponse)
async def get_overview():
    """
    Aggregated view across all managed tenants.
    Runs all client fetches in parallel for speed.
    """
    clients = all_clients()
    if not clients:
        raise HTTPException(status_code=503, detail="No clients configured")

    # Fetch all clients concurrently
    results = await asyncio.gather(
        *[_fetch_client_summary(cfg) for cfg in clients],
        return_exceptions=True,
    )

    summaries: List[ClientSummary] = []
    all_errors: List[APIError]     = []

    for result in results:
        if isinstance(result, Exception):
            logger.error(f"Client fetch exception: {result}")
            all_errors.append(APIError(code=500, message=str(result)))
        else:
            summary, errors = result
            summaries.append(summary)
            all_errors.extend(errors)

    # Aggregate KPIs
    total_online  = sum(s.online_sensors or 0 for s in summaries)
    total_sensors = sum(s.total_sensors  or 0 for s in summaries)
    total_crit    = sum(s.critical_count or 0 for s in summaries)
    total_high    = sum(s.high_count     or 0 for s in summaries)
    total_dets    = sum(s.det_24h        or 0 for s in summaries)
    under_attack  = sum(1 for s in summaries if s.status == "under_attack")
    open_incidents = 0  # fetched separately via /incidents endpoint

    coverage_pct = round(total_online / total_sensors * 100, 1) if total_sensors > 0 else 0.0

    kpis = OverviewKPIs(
        total_clients=        len(summaries),
        online_sensors=       total_online,
        total_sensors=        total_sensors,
        coverage_pct=         coverage_pct,
        critical_dets_24h=    total_crit,
        high_dets_24h=        total_high,
        total_dets_24h=       total_dets,
        open_incidents=       open_incidents,
        clients_under_attack= under_attack,
    )

    return OverviewResponse(kpis=kpis, clients=summaries, errors=all_errors)
