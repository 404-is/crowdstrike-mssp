"""
routes/hosts.py — Host / Sensor endpoints via FalconPy

FalconPy calls:
    Hosts.query_devices_by_filter(filter, limit, sort, offset)
    Hosts.get_device_details(ids)
    Hosts.perform_action(action_name, ids, body)
"""

import asyncio
import logging
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from config import get_client, all_clients
from services.falcon_client import FalconHosts, errors as sdk_errors
from models.schemas import Host, HostList, APIError, PaginationMeta

router = APIRouter(prefix="/hosts", tags=["Hosts"])
logger = logging.getLogger("falconguard.hosts")


def _map_host(raw: dict) -> Host:
    return Host(
        device_id=          raw.get("device_id", ""),
        hostname=           raw.get("hostname"),
        local_ip=           raw.get("local_ip"),
        os_version=         raw.get("os_version"),
        platform_name=      raw.get("platform_name"),
        agent_version=      raw.get("agent_version"),
        status=             raw.get("status", "normal"),
        last_seen=          raw.get("last_seen"),
        first_seen=         raw.get("first_seen"),
        containment_status= raw.get("containment_status", "normal"),
    )


@router.get("", response_model=HostList)
async def list_all_hosts(
    limit:  int           = Query(100, ge=1, le=500),
    filter: Optional[str] = Query(None, description="FQL filter (e.g. status:'contained')"),
):
    """All hosts across all clients."""
    results = await asyncio.gather(
        *[_fetch_client_hosts(c, filter or "", limit) for c in all_clients()],
        return_exceptions=True,
    )
    all_hosts, all_errors = [], []
    for r in results:
        if isinstance(r, Exception):
            all_errors.append(APIError(code=500, message=str(r)))
        else:
            hosts, errs = r
            all_hosts.extend(hosts)
            all_errors.extend(errs)

    return HostList(
        hosts=all_hosts,
        meta=PaginationMeta(total=len(all_hosts), limit=limit),
        errors=all_errors,
    )


@router.get("/{client_slug}", response_model=HostList)
async def list_client_hosts(
    client_slug: str,
    limit:  int           = Query(100, ge=1, le=500),
    filter: Optional[str] = Query(None),
):
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(404, f"Client '{client_slug}' not found")

    hosts, errs = await _fetch_client_hosts(cfg, filter or "", limit)
    return HostList(
        hosts=hosts,
        meta=PaginationMeta(total=len(hosts), limit=limit),
        errors=errs,
    )


async def _fetch_client_hosts(cfg, fql: str, limit: int):
    try:
        fh = FalconHosts(cfg)
        hosts_raw, errs, _ = await fh.query_and_get(fql, limit=limit)
        api_errors = [APIError(code=e.get("code",0), message=e.get("message",""))
                      for e in errs]
        return [_map_host(r) for r in hosts_raw], api_errors
    except Exception as e:
        logger.error(f"[{cfg.name}] Host fetch error: {e}")
        return [], [APIError(code=500, message=str(e))]


class ContainRequest(BaseModel):
    device_ids: List[str]
    action:     str = "contain"   # contain | lift_containment


@router.post("/{client_slug}/contain")
async def contain_hosts(client_slug: str, body: ContainRequest):
    """Contain or lift containment on one or more hosts."""
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(404, f"Client '{client_slug}' not found")

    if body.action not in ("contain", "lift_containment"):
        raise HTTPException(400, "action must be 'contain' or 'lift_containment'")

    fh   = FalconHosts(cfg)
    resp = await fh.action(body.device_ids, body.action)
    errs = sdk_errors(resp)
    if errs:
        raise HTTPException(400, detail=errs)

    return {
        "success":    True,
        "action":     body.action,
        "device_ids": body.device_ids,
    }
