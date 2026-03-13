"""
routes/overview.py — Command Center KPIs via FalconPy

FalconPy calls:
    Alerts.query_alerts_v2   — severity counts
    Hosts.query_devices_by_filter — online/total sensor counts
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter

from config import all_clients, ClientConfig
from services.falcon_client import FalconAlerts, FalconHosts, total as sdk_total
from models.schemas import (
    OverviewResponse, OverviewKPIs, ClientSummary, APIError,
)

router = APIRouter(prefix="/overview", tags=["Overview"])
logger = logging.getLogger("falconguard.overview")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _rfc3339(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _range_fql(since: datetime, until: datetime, field: str = "updated_timestamp") -> str:
    return f"{field}:>='{_rfc3339(since)}'+{field}:<='{_rfc3339(until)}'"


async def _client_stats(cfg: ClientConfig) -> dict:
    """Fetch KPI data for one client — runs all queries concurrently."""
    now      = _now()
    since_24 = now - timedelta(hours=24)
    since_1  = now - timedelta(hours=1)

    fa = FalconAlerts(cfg)
    fh = FalconHosts(cfg)

    try:
        (r_crit, r_high, r_total, r_sensors_online, r_sensors_all) = await asyncio.gather(
            # Critical alerts last 24h
            fa.query(_range_fql(since_24, now) + "+severity:4", limit=1),
            # High alerts last 24h
            fa.query(_range_fql(since_24, now) + "+severity:3", limit=1),
            # All alerts last 24h
            fa.query(_range_fql(since_24, now), limit=1),
            # Sensors seen in last 1h (online)
            fh.query(f"last_seen:>='{_rfc3339(since_1)}'", limit=1),
            # All sensors ever
            fh.query("", limit=1),
            return_exceptions=True,
        )

        def _safe_total(r) -> int:
            if isinstance(r, Exception): return 0
            return sdk_total(r)

        crit_count   = _safe_total(r_crit)
        high_count   = _safe_total(r_high)
        total_dets   = _safe_total(r_total)
        online_sens  = _safe_total(r_sensors_online)
        total_sens   = _safe_total(r_sensors_all)

        # Health pct
        health_pct = round(online_sens / total_sens * 100, 1) if total_sens > 0 else 0.0

        # Simple status derivation
        if crit_count > 0:
            status = "under_attack"
        elif high_count > 0:
            status = "monitoring"
        else:
            status = "protected"

        return {
            "cfg":           cfg,
            "critical_count": crit_count,
            "high_count":     high_count,
            "det_24h":        total_dets,
            "online_sensors": online_sens,
            "total_sensors":  total_sens,
            "health_pct":     health_pct,
            "status":         status,
        }

    except Exception as e:
        logger.error(f"[{cfg.name}] Stats fetch failed: {e}")
        return {
            "cfg": cfg, "critical_count": 0, "high_count": 0,
            "det_24h": 0, "online_sensors": 0, "total_sensors": 0,
            "health_pct": 0.0, "status": "unknown",
        }


@router.get("", response_model=OverviewResponse)
async def get_overview():
    """Aggregate KPIs across all managed tenants."""
    clients = all_clients()
    if not clients:
        return OverviewResponse(
            kpis=OverviewKPIs(
                total_clients=0, online_sensors=0, total_sensors=0,
                coverage_pct=0.0, critical_dets_24h=0, high_dets_24h=0,
                total_dets_24h=0, open_incidents=0, clients_under_attack=0,
            ),
            clients=[],
        )

    stats_list = await asyncio.gather(
        *[_client_stats(c) for c in clients], return_exceptions=True
    )

    client_summaries: List[ClientSummary] = []
    total_crit = total_high = total_dets = online_sens = total_sens = under_attack = 0

    for stats in stats_list:
        if isinstance(stats, Exception):
            logger.error(f"Client stats exception: {stats}")
            continue

        cfg: ClientConfig = stats["cfg"]
        client_summaries.append(ClientSummary(
            slug=           cfg.slug,
            name=           cfg.name,
            cid=            cfg.cid,
            cloud=          cfg.cloud,
            tier=           cfg.tier,
            industry=       cfg.industry,
            online_sensors= stats["online_sensors"],
            total_sensors=  stats["total_sensors"],
            health_pct=     stats["health_pct"],
            det_24h=        stats["det_24h"],
            critical_count= stats["critical_count"],
            high_count=     stats["high_count"],
            status=         stats["status"],
        ))
        total_crit   += stats["critical_count"]
        total_high   += stats["high_count"]
        total_dets   += stats["det_24h"]
        online_sens  += stats["online_sensors"]
        total_sens   += stats["total_sensors"]
        if stats["status"] == "under_attack":
            under_attack += 1

    coverage_pct = round(online_sens / total_sens * 100, 1) if total_sens > 0 else 0.0

    kpis = OverviewKPIs(
        total_clients=        len(client_summaries),
        online_sensors=       online_sens,
        total_sensors=        total_sens,
        coverage_pct=         coverage_pct,
        critical_dets_24h=    total_crit,
        high_dets_24h=        total_high,
        total_dets_24h=       total_dets,
        open_incidents=       under_attack,    # proxy: clients with active critical/high alerts
        clients_under_attack= under_attack,
    )

    return OverviewResponse(kpis=kpis, clients=client_summaries)


@router.get("/debug/timestamp")
async def debug_timestamp():
    """Returns sample FQL filters for the current UTC time — useful for testing."""
    now = _now()
    return {
        "now_utc":           now.isoformat(),
        "now_rfc3339":       _rfc3339(now),
        "since_1h":          _rfc3339(now - timedelta(hours=1)),
        "since_24h":         _rfc3339(now - timedelta(hours=24)),
        "fql_alerts_24h":    _range_fql(now - timedelta(hours=24), now),
        "fql_sensors_1h":    f"last_seen:>='{_rfc3339(now - timedelta(hours=1))}'",
    }
