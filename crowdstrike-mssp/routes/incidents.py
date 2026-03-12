"""
routes/incidents.py — Incident management endpoints

Covers:
  - /incidents                     GET all incidents across clients
  - /incidents/{client}            GET incidents for one client
  - /incidents/{client}/{id}       GET single incident detail
  - /incidents/{client}/{id}       PATCH update incident
"""

import asyncio
import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from config import get_client, all_clients
from services.crowdstrike import CrowdStrikeClient
from models.schemas import Incident, IncidentList, APIError, PaginationMeta

router = APIRouter(prefix="/incidents", tags=["Incidents"])
logger = logging.getLogger("falconguard.incidents")

STATUS_MAP = {
    20: "New",
    25: "Reopened",
    30: "In Progress",
    40: "Closed",
}


def _map_incident(raw: dict, client_name: str, client_slug: str) -> Incident:
    status_int = raw.get("status", 20)
    score      = raw.get("score", 0)

    # Derive integer severity from score
    if score >= 80:
        severity, severity_name = 4, "Critical"
    elif score >= 50:
        severity, severity_name = 3, "High"
    elif score >= 25:
        severity, severity_name = 2, "Medium"
    elif score > 0:
        severity, severity_name = 1, "Low"
    else:
        severity, severity_name = 0, "Unknown"

    # Try to extract adversary from tags (CrowdStrike often tags CARBON SPIDER etc)
    tags = raw.get("tags", [])
    adversary = next(
        (t.replace("Adversary/", "").replace("actor/", "") for t in tags
         if "spider" in t.lower() or "bear" in t.lower() or "panda" in t.lower()
         or "kitten" in t.lower() or "adversary" in t.lower() or "actor" in t.lower()),
        None
    )

    return Incident(
        incident_id=         raw.get("incident_id", ""),
        client_name=         client_name,
        client_slug=         client_slug,
        status=              status_int,
        status_name=         STATUS_MAP.get(status_int, "Unknown"),
        severity=            severity,
        severity_name=       severity_name,
        adversary=           adversary,
        name=                raw.get("name"),
        description=         raw.get("description"),
        start=               raw.get("start"),
        end=                 raw.get("end"),
        modified_timestamp=  raw.get("modified_timestamp"),
        hosts=               raw.get("hosts", []),
        users=               raw.get("users", []),
        tactics=             raw.get("tactics", []),
        techniques=          raw.get("techniques", []),
        objectives=          raw.get("objectives", []),
        assigned_to=         raw.get("assigned_to"),
        tags=                tags,
        score=               score,
    )


# ── Routes ──────────────────────────────────────────────────────────────────

@router.get("", response_model=IncidentList)
async def list_all_incidents(
    status: Optional[int] = Query(None, description="20=New 25=Reopened 30=InProgress 40=Closed"),
    hours:  int           = Query(168, ge=1, le=8760, description="Lookback hours (default 7d)"),
    limit:  int           = Query(50, ge=1, le=500),
):
    """All incidents across all managed tenants."""

    async def _fetch(cfg):
        cs = CrowdStrikeClient(cfg)
        try:
            fql_parts = [f"start:>='now-{hours}h'"]
            if status:
                fql_parts.append(f"status:{status}")
            fql = "+".join(fql_parts)

            id_resp = await cs.get(
                "/incidents/queries/incidents/v1",
                params={"filter": fql, "limit": limit, "sort": "start|desc"}
            )
            ids = id_resp.get("resources", [])
            if not ids:
                return [], []

            entity_resp = await cs.post(
                "/incidents/entities/incidents/GET/v1",
                json={"ids": ids}
            )
            raws   = entity_resp.get("resources", [])
            errors = [APIError(code=e.get("code",0), message=e.get("message",""))
                      for e in entity_resp.get("errors", [])]
            return [_map_incident(r, cfg.name, cfg.slug) for r in raws], errors

        except Exception as e:
            logger.error(f"Incident fetch failed for {cfg.name}: {e}")
            return [], [APIError(code=500, message=str(e))]
        finally:
            await cs.close()

    results = await asyncio.gather(*[_fetch(c) for c in all_clients()])
    all_incidents: List[Incident] = []
    all_errors:    List[APIError]  = []

    for incs, errs in results:
        all_incidents.extend(incs)
        all_errors.extend(errs)

    all_incidents.sort(key=lambda i: i.start or "", reverse=True)

    return IncidentList(
        incidents=all_incidents,
        meta=PaginationMeta(total=len(all_incidents), limit=limit),
        errors=all_errors,
    )


@router.get("/{client_slug}", response_model=IncidentList)
async def list_client_incidents(
    client_slug: str,
    status:      Optional[int] = Query(None),
    hours:       int           = Query(168, ge=1, le=8760),
    limit:       int           = Query(100, ge=1, le=500),
    offset:      int           = Query(0, ge=0),
):
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Client '{client_slug}' not found")

    cs = CrowdStrikeClient(cfg)
    try:
        fql_parts = [f"start:>='now-{hours}h'"]
        if status:
            fql_parts.append(f"status:{status}")

        id_resp = await cs.get(
            "/incidents/queries/incidents/v1",
            params={
                "filter": "+".join(fql_parts),
                "limit":  limit,
                "offset": offset,
                "sort":   "start|desc",
            }
        )
        ids   = id_resp.get("resources", [])
        total = id_resp.get("meta", {}).get("pagination", {}).get("total", 0)

        if not ids:
            return IncidentList(incidents=[], meta=PaginationMeta(total=total))

        entity_resp = await cs.post(
            "/incidents/entities/incidents/GET/v1",
            json={"ids": ids}
        )
        raws = entity_resp.get("resources", [])
        return IncidentList(
            incidents=[_map_incident(r, cfg.name, cfg.slug) for r in raws],
            meta=PaginationMeta(total=total, offset=offset, limit=limit),
        )
    finally:
        await cs.close()


@router.get("/{client_slug}/{incident_id}", response_model=Incident)
async def get_incident(client_slug: str, incident_id: str):
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Client '{client_slug}' not found")

    cs = CrowdStrikeClient(cfg)
    try:
        resp = await cs.post(
            "/incidents/entities/incidents/GET/v1",
            json={"ids": [incident_id]}
        )
        resources = resp.get("resources", [])
        if not resources:
            raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
        return _map_incident(resources[0], cfg.name, cfg.slug)
    finally:
        await cs.close()


# ── Update incident ──────────────────────────────────────────────────────────

class IncidentUpdate(BaseModel):
    status:      Optional[int]  = None    # 20 | 25 | 30 | 40
    assigned_to: Optional[str]  = None
    tags:        Optional[List[str]] = None
    name:        Optional[str]  = None
    description: Optional[str]  = None
    comment:     Optional[str]  = None

@router.patch("/{client_slug}/{incident_id}")
async def update_incident(client_slug: str, incident_id: str, body: IncidentUpdate):
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Client '{client_slug}' not found")

    payload = {"ids": [incident_id]}
    if body.status is not None:
        payload["status"] = body.status
    if body.assigned_to:
        payload["assigned_to"] = body.assigned_to
    if body.tags is not None:
        payload["tags"] = {"action": "set", "values": body.tags}
    if body.name:
        payload["name"] = body.name
    if body.description:
        payload["description"] = body.description
    if body.comment:
        payload["comment"] = body.comment

    cs = CrowdStrikeClient(cfg)
    try:
        resp = await cs.patch("/incidents/entities/incident-actions/v1", json=payload)
        errors = resp.get("errors", [])
        if errors:
            raise HTTPException(status_code=400, detail=errors)
        return {"success": True, "incident_id": incident_id}
    finally:
        await cs.close()
