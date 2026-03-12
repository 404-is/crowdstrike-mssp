"""
routes/hosts.py — Host management endpoints

Covers:
  - /hosts/{client}                GET paginated host list
  - /hosts/{client}/search         GET filtered host search
  - /hosts/{client}/{device_id}    GET single host detail
  - /hosts/{client}/contain        POST contain one or more hosts
  - /hosts/{client}/lift           POST lift containment
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from config import get_client
from services.crowdstrike import CrowdStrikeClient
from models.schemas import Host, HostList, ContainRequest, ContainResponse, APIError, PaginationMeta

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
        assigned_policies=  [
            p.get("policy_id", "") for p in raw.get("policies", [])
        ],
        containment_status= raw.get("containment_status", "normal"),
    )


# ── Routes ──────────────────────────────────────────────────────────────────

@router.get("/{client_slug}", response_model=HostList)
async def list_hosts(
    client_slug: str,
    limit:       int           = Query(100, ge=1, le=5000),
    offset:      int           = Query(0, ge=0),
    hostname:    Optional[str] = Query(None),
    status:      Optional[str] = Query(None, description="normal | contained | containment_pending"),
    platform:    Optional[str] = Query(None, description="Windows | Mac | Linux"),
):
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Client '{client_slug}' not found")

    cs = CrowdStrikeClient(cfg)
    try:
        fql_parts = []
        if hostname:
            fql_parts.append(f"hostname:*'{hostname}'*")
        if status:
            fql_parts.append(f"status:'{status}'")
        if platform:
            fql_parts.append(f"platform_name:'{platform}'")
        fql = "+".join(fql_parts) if fql_parts else ""

        params = {"limit": limit, "offset": offset}
        if fql:
            params["filter"] = fql

        # Step 1 — query IDs
        id_resp = await cs.get("/devices/queries/devices/v1", params=params)
        ids     = id_resp.get("resources", [])
        total   = id_resp.get("meta", {}).get("pagination", {}).get("total", 0)

        if not ids:
            return HostList(hosts=[], meta=PaginationMeta(total=total, offset=offset, limit=limit))

        # Step 2 — fetch entities in batches of 100
        hosts: List[Host] = []
        for i in range(0, len(ids), 100):
            batch = ids[i:i+100]
            entity_resp = await cs.get(
                "/devices/entities/devices/v2",
                params={"ids": batch}
            )
            hosts.extend([_map_host(r) for r in entity_resp.get("resources", [])])

        return HostList(
            hosts=hosts,
            meta=PaginationMeta(total=total, offset=offset, limit=limit),
        )

    finally:
        await cs.close()


@router.get("/{client_slug}/{device_id}", response_model=Host)
async def get_host(client_slug: str, device_id: str):
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Client '{client_slug}' not found")

    cs = CrowdStrikeClient(cfg)
    try:
        resp = await cs.get("/devices/entities/devices/v2", params={"ids": [device_id]})
        resources = resp.get("resources", [])
        if not resources:
            raise HTTPException(status_code=404, detail=f"Host '{device_id}' not found")
        return _map_host(resources[0])
    finally:
        await cs.close()


# ── Host Actions ──────────────────────────────────────────────────────────────

class HostActionRequest(BaseModel):
    device_ids: List[str]
    action:     str = "contain"    # contain | lift_containment

@router.post("/{client_slug}/action", response_model=ContainResponse)
async def host_action(client_slug: str, body: HostActionRequest):
    """
    Contain or lift containment on one or more hosts.
    Action: 'contain' | 'lift_containment'
    
    CrowdStrike docs: POST /devices/entities/devices-actions/v2
    Containing a host stops all network comms except to CrowdStrike cloud.
    """
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Client '{client_slug}' not found")

    if body.action not in ("contain", "lift_containment"):
        raise HTTPException(status_code=400, detail="action must be 'contain' or 'lift_containment'")

    cs = CrowdStrikeClient(cfg)
    try:
        resp = await cs.post(
            "/devices/entities/devices-actions/v2",
            json={
                "action_parameters": [{"name": "action_name", "value": body.action}],
                "ids": body.device_ids,
            }
        )
        errors = [APIError(code=e.get("code",0), message=e.get("message",""))
                  for e in resp.get("errors", [])]
        success = len(errors) == 0

        logger.info(
            f"Host action '{body.action}' on {len(body.device_ids)} hosts "
            f"for {cfg.name} — success={success}"
        )

        return ContainResponse(
            success=    success,
            device_ids= body.device_ids,
            action=     body.action,
            errors=     errors,
        )
    finally:
        await cs.close()
