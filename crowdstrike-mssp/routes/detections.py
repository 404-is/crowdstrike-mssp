"""
routes/detections.py — Detection & Alert endpoints via FalconPy

FalconPy calls:
    Alerts.query_alerts_v2(filter, limit, sort, offset)
    Alerts.get_alerts_v2(composite_ids)
    Alerts.update_alerts_v3(composite_ids, action_parameters)

Filter format (RFC 3339 with microseconds, both bounds):
    updated_timestamp:>='2026-03-13T08:16:07.539959Z'
    +updated_timestamp:<='2026-03-13T08:21:09.659903Z'
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from config import get_client, all_clients
from services.falcon_client import FalconAlerts, errors as sdk_errors
from models.schemas import Detection, DetectionList, APIError, PaginationMeta

router = APIRouter(prefix="/detections", tags=["Detections"])
logger = logging.getLogger("falconguard.detections")

SEV_NAMES = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

# Stateful delta poll cursors per client slug
_poll_cursors: Dict[str, datetime] = {}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _rfc3339(dt: datetime) -> str:
    """RFC 3339 with microseconds — exact format CrowdStrike console uses."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _range_fql(since: datetime, until: datetime,
               field: str = "updated_timestamp") -> str:
    """
    Range filter with both bounds — matches CrowdStrike console requests:
      updated_timestamp:>='T1'+updated_timestamp:<='T2'
    """
    return f"{field}:>='{_rfc3339(since)}'+{field}:<='{_rfc3339(until)}'"


def _norm_sev(raw) -> int:
    if isinstance(raw, int):  return max(1, min(4, raw))
    if isinstance(raw, str):
        return {"critical":4, "high":3, "medium":2, "low":1}.get(raw.lower(), 1)
    return 1


def _map_alert(raw: dict, client_name: str, client_slug: str) -> Detection:
    """Map a raw CrowdStrike alert entity to our Detection schema."""
    sev     = _norm_sev(raw.get("severity", 1))
    device  = raw.get("device") or {}

    # Behaviors array holds process tree, cmdline, network, IOC data
    behaviors = raw.get("behaviors") or []
    b0        = behaviors[0] if behaviors else {}

    # Extract process details from first behavior
    cmdline  = b0.get("cmdline") or b0.get("command_line") or raw.get("cmdline")
    filepath = b0.get("filepath") or b0.get("filename")
    sha256   = b0.get("sha256") or b0.get("parent_sha256") or raw.get("sha256")

    # Network accesses — may be top-level or inside behaviors
    networks = raw.get("network_accesses") or []
    if not networks:
        for b in behaviors:
            networks.extend(b.get("network_accesses") or [])

    return Detection(
        id=              raw.get("composite_id") or raw.get("id", ""),
        client_name=     client_name,
        client_slug=     client_slug,
        severity=        sev,
        severity_name=   SEV_NAMES.get(sev, "Unknown"),
        status=          raw.get("status", "new"),
        description=     (raw.get("description")
                          or raw.get("display_name")
                          or b0.get("display_name")
                          or "Detection"),
        host_name=       (raw.get("hostname")
                          or device.get("hostname")
                          or device.get("device_id", "")),
        host_id=         device.get("device_id"),
        username=        (raw.get("user_name")
                          or (raw.get("grandparent_details") or {}).get("user_name")
                          or b0.get("user_name")),
        tactic=          raw.get("tactic") or b0.get("tactic"),
        technique=       raw.get("technique") or b0.get("technique"),
        technique_id=    raw.get("technique_id") or b0.get("technique_id"),
        timestamp=       raw.get("timestamp") or raw.get("created_timestamp"),
        falcon_action=   (raw.get("pattern_disposition_description")
                          or b0.get("pattern_disposition_description")),
        behaviors=       behaviors,
        network_accesses= networks,
        ioc_type=        raw.get("ioc_type") or b0.get("ioc_type"),
        ioc_value=       raw.get("ioc_value") or b0.get("ioc_value"),
        parent_process=  b0.get("parent_details", {}).get("parent_process_graph_id"),
        cmdline=         cmdline,
        filepath=        filepath,
        sha256=          sha256,
        local_ip=        device.get("local_ip"),
        adversary_ids=   raw.get("adversary_ids") or [],
        pattern_id=      raw.get("pattern_id"),
        raw=             raw,
    )


async def _fetch_client(cfg, since: datetime, until: datetime,
                         severity: Optional[int], limit: int,
                         sort: str = "updated_timestamp|desc"):
    """Fetch + map detections for one client using FalconPy."""
    try:
        fql = _range_fql(since, until)
        if severity:
            fql += f"+severity:{severity}"

        logger.info(f"[{cfg.name}] query_alerts_v2 FQL: {fql}")
        fa = FalconAlerts(cfg)
        raws, errs, count = await fa.query_and_get(fql, limit=limit, sort=sort)

        dets = [_map_alert(r, cfg.name, cfg.slug) for r in raws]
        api_errors = [APIError(code=e.get("code", 0), message=e.get("message", ""))
                      for e in errs]
        logger.info(f"[{cfg.name}] {len(dets)} detections (total={count})")
        return dets, api_errors, count

    except Exception as e:
        logger.error(f"[{cfg.name}] Detection fetch failed: {e}")
        return [], [APIError(code=500, message=str(e))], 0


# ── Routes ───────────────────────────────────────────────────────────────────

@router.get("", response_model=DetectionList)
async def list_all_detections(
    severity: Optional[int] = Query(None, ge=1, le=4),
    hours:    int           = Query(24,  ge=1, le=720),
    limit:    int           = Query(200, ge=1, le=500),
):
    """All alerts across all clients for the past N hours."""
    until  = _now()
    since  = until - timedelta(hours=hours)

    results = await asyncio.gather(
        *[_fetch_client(c, since, until, severity, limit) for c in all_clients()],
        return_exceptions=True,
    )

    all_dets, all_errors = [], []
    for r in results:
        if isinstance(r, Exception):
            all_errors.append(APIError(code=500, message=str(r)))
        else:
            dets, errs, _ = r
            all_dets.extend(dets)
            all_errors.extend(errs)

    all_dets.sort(key=lambda d: (-d.severity, d.timestamp or ""))
    return DetectionList(
        detections=all_dets,
        meta=PaginationMeta(total=len(all_dets), limit=limit),
        errors=all_errors,
    )


@router.get("/poll", response_model=DetectionList)
async def poll_detections(
    window_minutes: int = Query(6,   ge=1, le=60),
    limit:          int = Query(100, ge=1, le=500),
):
    """
    Delta poll — only alerts updated since last call per client.
    Stateful cursor: advances after each successful poll so nothing is missed.
    """
    until   = _now()
    clients = all_clients()

    async def _delta(c):
        since = _poll_cursors.get(c.slug, until - timedelta(minutes=window_minutes))
        dets, errs, _ = await _fetch_client(
            c, since, until, None, limit, sort="updated_timestamp|asc"
        )
        _poll_cursors[c.slug] = until
        return dets, errs

    results = await asyncio.gather(*[_delta(c) for c in clients],
                                   return_exceptions=True)
    all_dets, all_errors = [], []
    for r in results:
        if isinstance(r, Exception):
            all_errors.append(APIError(code=500, message=str(r)))
        else:
            dets, errs = r
            all_dets.extend(dets)
            all_errors.extend(errs)

    all_dets.sort(key=lambda d: (-d.severity, d.timestamp or ""))
    return DetectionList(
        detections=all_dets,
        meta=PaginationMeta(total=len(all_dets), limit=limit),
        errors=all_errors,
    )


@router.get("/{client_slug}", response_model=DetectionList)
async def list_client_detections(
    client_slug: str,
    severity:    Optional[int] = Query(None, ge=1, le=4),
    hours:       int           = Query(24, ge=1, le=720),
    limit:       int           = Query(200, ge=1, le=500),
):
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(404, f"Client '{client_slug}' not found")

    until = _now()
    since = until - timedelta(hours=hours)
    dets, errs, total_count = await _fetch_client(cfg, since, until, severity, limit)

    return DetectionList(
        detections=dets,
        meta=PaginationMeta(total=total_count, limit=limit),
        errors=errs,
    )


class DetectionUpdate(BaseModel):
    status:      Optional[str] = None   # new | in_progress | closed | true_positive | false_positive
    assigned_to: Optional[str] = None   # user UUID
    comment:     Optional[str] = None
    add_tag:     Optional[str] = None
    remove_tag:  Optional[str] = None


@router.patch("/{client_slug}/{detection_id}")
async def update_detection(
    client_slug:  str,
    detection_id: str,
    body:         DetectionUpdate,
):
    """Update alert via PATCH /alerts/entities/alerts/v3 (non-deprecated)."""
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(404, f"Client '{client_slug}' not found")

    action_params = []
    if body.status:      action_params.append({"name": "update_status",    "value": body.status})
    if body.assigned_to: action_params.append({"name": "assign_to_uuid",   "value": body.assigned_to})
    if body.comment:     action_params.append({"name": "append_comment",   "value": body.comment})
    if body.add_tag:     action_params.append({"name": "add_tag",          "value": body.add_tag})
    if body.remove_tag:  action_params.append({"name": "remove_tag",       "value": body.remove_tag})

    if not action_params:
        return {"success": True, "message": "No changes specified"}

    fa   = FalconAlerts(cfg)
    resp = await fa.update([detection_id], action_params)
    errs = sdk_errors(resp)
    if errs:
        raise HTTPException(400, detail=errs)

    return {"success": True, "detection_id": detection_id}
