"""
routes/intel.py — IOC & Vulnerability endpoints via FalconPy

FalconPy calls:
    IOCManagement.indicator_search_v1(filter, limit)
    IOCManagement.indicator_get_v1(ids)
    SpotlightVulnerabilities (if subscribed)
"""

import asyncio
import logging
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Query

from config import get_client, all_clients
from services.falcon_client import FalconIOC
from models.schemas import IOC, APIError, PaginationMeta

router = APIRouter(prefix="", tags=["Intel"])
logger = logging.getLogger("falconguard.intel")


def _map_ioc(raw: dict) -> IOC:
    return IOC(
        id=          raw.get("id"),
        type=        raw.get("type", "unknown"),
        value=       raw.get("value", ""),
        action=      raw.get("action", "detect"),
        severity=    raw.get("severity"),
        description= raw.get("description"),
        source=      raw.get("source"),
        created_by=  raw.get("created_by"),
        created_on=  raw.get("created_on") or raw.get("created_timestamp"),
        expiration=  raw.get("expiration"),
        tags=        raw.get("tags") or [],
    )


@router.get("/iocs")
async def list_iocs(
    client:  Optional[str] = Query(None, description="Client slug to filter by"),
    type:    Optional[str] = Query(None, description="IOC type: sha256|md5|domain|ipv4|ipv6"),
    limit:   int           = Query(100,  ge=1, le=500),
):
    """Custom IOCs across all clients (or one client)."""
    clients = [get_client(client)] if client else all_clients()
    clients = [c for c in clients if c]

    results = await asyncio.gather(
        *[_fetch_iocs(c, type, limit) for c in clients],
        return_exceptions=True,
    )

    all_iocs, all_errors = [], []
    for r in results:
        if isinstance(r, Exception):
            all_errors.append(APIError(code=500, message=str(r)))
        else:
            iocs, errs = r
            all_iocs.extend(iocs)
            all_errors.extend(errs)

    return {
        "iocs":   [i.model_dump() for i in all_iocs],
        "total":  len(all_iocs),
        "errors": [e.model_dump() for e in all_errors],
    }


async def _fetch_iocs(cfg, ioc_type: Optional[str], limit: int):
    try:
        fql = ""
        if ioc_type:
            fql = f"type:'{ioc_type}'"
        fi = FalconIOC(cfg)
        raws, errs, _ = await fi.search_and_get(fql, limit=limit)
        api_errors = [APIError(code=e.get("code",0), message=e.get("message",""))
                      for e in errs]
        return [_map_ioc(r) for r in raws], api_errors
    except Exception as e:
        logger.error(f"[{cfg.name}] IOC fetch error: {e}")
        return [], [APIError(code=500, message=str(e))]
