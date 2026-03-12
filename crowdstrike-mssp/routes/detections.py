"""
routes/detections.py — Detection & Alert endpoints

Covers:
  - /detections              GET all detections across all clients
  - /detections/{client}     GET detections for one client
  - /detections/{client}/{id} GET single detection detail
  - /detections/{client}/{id}/assign  PATCH assign analyst
  - /detections/{client}/{id}/status  PATCH update status
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from config import get_client, all_clients
from services.crowdstrike import CrowdStrikeClient
from models.schemas import Detection, DetectionList, APIError, PaginationMeta

router = APIRouter(prefix="/detections", tags=["Detections"])
logger = logging.getLogger("falconguard.detections")

SEVERITY_NAMES = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


def _map_detection(raw: dict, client_name: str, client_slug: str) -> Detection:
    """Maps CrowdStrike raw alert/detection object to our schema."""
    behaviors = raw.get("behaviors", [{}])
    first_behavior = behaviors[0] if behaviors else {}

    severity = raw.get("max_severity", 0)
    return Detection(
        id=            raw.get("detection_id") or raw.get("composite_id", ""),
        client_name=   client_name,
        client_slug=   client_slug,
        severity=      severity,
        severity_name= SEVERITY_NAMES.get(severity, "Unknown"),
        status=        raw.get("status", "new"),
        description=   first_behavior.get("description", raw.get("description", "")),
        host_name=     raw.get("hostname") or first_behavior.get("hostname"),
        host_id=       raw.get("device", {}).get("device_id"),
        username=      first_behavior.get("user_name"),
        tactic=        first_behavior.get("tactic"),
        technique=     first_behavior.get("technique"),
        technique_id=  first_behavior.get("technique_id"),
        timestamp=     raw.get("created_timestamp") or first_behavior.get("timestamp"),
        falcon_action= first_behavior.get("pattern_disposition_description"),
    )


# ── Routes ──────────────────────────────────────────────────────────────────

@router.get("", response_model=DetectionList)
async def list_all_detections(
    severity:  Optional[int]  = Query(None, ge=1, le=4, description="Filter: 1=Low 2=Med 3=High 4=Crit"),
    status:    Optional[str]  = Query(None, description="new | in_progress | true_positive | false_positive | ignored"),
    hours:     int            = Query(24, ge=1, le=720, description="Lookback window in hours"),
    limit:     int            = Query(50, ge=1, le=500),
):
    """
    Returns detections across ALL managed clients.
    Each client is queried in parallel.
    """
    import asyncio

    async def _fetch_for_client(cfg):
        cs = CrowdStrikeClient(cfg)
        try:
            fql_parts = [f"created_timestamp:>='now-{hours}h'"]
            if severity:
                fql_parts.append(f"severity:{severity}")
            if status:
                fql_parts.append(f"status:'{status}'")
            fql = "+".join(fql_parts)

            # Step 1: get IDs
            id_resp = await cs.get(
                "/detects/queries/detects/v1",
                params={"filter": fql, "limit": limit, "sort": "first_behavior.timestamp|desc"}
            )
            ids = id_resp.get("resources", [])
            if not ids:
                return [], []

            # Step 2: get entities
            entity_resp = await cs.post(
                "/detects/entities/summaries/GET/v1",
                json={"ids": ids}
            )
            raws   = entity_resp.get("resources", [])
            errors = entity_resp.get("errors", [])
            dets   = [_map_detection(r, cfg.name, cfg.slug) for r in raws]
            errs   = [APIError(code=e.get("code", 0), message=e.get("message", "")) for e in errors]
            return dets, errs
        except Exception as e:
            logger.error(f"Detection fetch failed for {cfg.name}: {e}")
            return [], [APIError(code=500, message=str(e))]
        finally:
            await cs.close()

    results = await asyncio.gather(*[_fetch_for_client(c) for c in all_clients()])
    all_dets:  List[Detection] = []
    all_errors: List[APIError]  = []

    for dets, errs in results:
        all_dets.extend(dets)
        all_errors.extend(errs)

    # Sort combined list by severity desc then timestamp desc
    all_dets.sort(key=lambda d: (-d.severity, d.timestamp or ""), reverse=False)

    return DetectionList(
        detections=all_dets,
        meta=PaginationMeta(total=len(all_dets), limit=limit),
        errors=all_errors,
    )


@router.get("/{client_slug}", response_model=DetectionList)
async def list_client_detections(
    client_slug: str,
    severity:    Optional[int] = Query(None, ge=1, le=4),
    status:      Optional[str] = Query(None),
    hours:       int           = Query(24, ge=1, le=720),
    limit:       int           = Query(100, ge=1, le=500),
    offset:      int           = Query(0, ge=0),
):
    """Detections for a single client tenant."""
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Client '{client_slug}' not found")

    cs = CrowdStrikeClient(cfg)
    try:
        fql_parts = [f"created_timestamp:>='now-{hours}h'"]
        if severity:
            fql_parts.append(f"severity:{severity}")
        if status:
            fql_parts.append(f"status:'{status}'")
        fql = "+".join(fql_parts)

        id_resp = await cs.get(
            "/detects/queries/detects/v1",
            params={
                "filter": fql,
                "limit":  limit,
                "offset": offset,
                "sort":   "first_behavior.timestamp|desc",
            }
        )
        ids   = id_resp.get("resources", [])
        total = id_resp.get("meta", {}).get("pagination", {}).get("total", 0)
        errors = [APIError(code=e.get("code",0), message=e.get("message",""))
                  for e in id_resp.get("errors", [])]

        if not ids:
            return DetectionList(detections=[], meta=PaginationMeta(total=total), errors=errors)

        entity_resp = await cs.post(
            "/detects/entities/summaries/GET/v1",
            json={"ids": ids}
        )
        raws = entity_resp.get("resources", [])
        dets = [_map_detection(r, cfg.name, cfg.slug) for r in raws]

        return DetectionList(
            detections=dets,
            meta=PaginationMeta(total=total, offset=offset, limit=limit),
            errors=errors,
        )

    finally:
        await cs.close()


# ── Update detection status or assignee ─────────────────────────────────────

class DetectionUpdate(BaseModel):
    status:      Optional[str] = None    # new | in_progress | true_positive | false_positive | ignored
    assigned_to: Optional[str] = None
    comment:     Optional[str] = None

@router.patch("/{client_slug}/{detection_id}")
async def update_detection(client_slug: str, detection_id: str, body: DetectionUpdate):
    """Update detection status or assignee in Falcon."""
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Client '{client_slug}' not found")

    payload = {"ids": [detection_id]}
    if body.status:
        payload["status"] = body.status
    if body.assigned_to:
        payload["assigned_to_uid"] = body.assigned_to
    if body.comment:
        payload["comment"] = body.comment

    cs = CrowdStrikeClient(cfg)
    try:
        resp = await cs.patch("/detects/entities/detects/v2", json=payload)
        errors = resp.get("errors", [])
        if errors:
            raise HTTPException(status_code=400, detail=errors)
        return {"success": True, "detection_id": detection_id}
    finally:
        await cs.close()
