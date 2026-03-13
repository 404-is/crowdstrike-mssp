"""
routes/incidents.py — Synthesize Incidents from Alerts API via FalconPy

/incidents/ API requires the Incidents scope — which not all API clients have.
We synthesize incidents by grouping High/Critical alerts from the Alerts API:
  - Same host + same primary tactic
  - Within a 2-hour sliding window

FalconPy calls:
    Alerts.query_alerts_v2(filter, limit, sort)
    Alerts.get_alerts_v2(composite_ids)
    Alerts.update_alerts_v3(composite_ids, action_parameters)
"""

import asyncio
import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from config import get_client, all_clients
from services.falcon_client import FalconAlerts, errors as sdk_errors
from models.schemas import Incident, IncidentList, APIError, PaginationMeta

router = APIRouter(prefix="/incidents", tags=["Incidents"])
logger = logging.getLogger("falconguard.incidents")

_poll_cursors: Dict[str, datetime] = {}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _rfc3339(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _range_fql(since: datetime, until: datetime,
               field: str = "updated_timestamp") -> str:
    return f"{field}:>='{_rfc3339(since)}'+{field}:<='{_rfc3339(until)}'"


def _norm_sev(raw) -> int:
    if isinstance(raw, int):  return max(1, min(4, raw))
    if isinstance(raw, str):
        return {"critical":4,"high":3,"medium":2,"low":1}.get(raw.lower(), 1)
    return 1


def _ts(alert: dict) -> datetime:
    """Parse alert timestamp to datetime."""
    raw = alert.get("timestamp") or alert.get("created_timestamp") or ""
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)


def _stable_id(parts: List[str]) -> str:
    """Deterministic short incident ID (SHA1 of host+tactic+window)."""
    raw = "|".join(sorted(p for p in parts if p))
    return "INC-" + hashlib.sha1(raw.encode()).hexdigest()[:12].upper()


# ── Alert → Incident grouping ────────────────────────────────────────────────

def _group_into_incidents(
    alerts: List[Dict[str, Any]],
    client_name: str,
    client_slug: str,
    min_severity: int   = 2,
    window_hours: float = 2.0,
) -> List[Incident]:
    """
    Groups related alerts into synthetic incidents.

    Grouping key:  host_identifier + primary_tactic
    Time window:   alerts within `window_hours` on the same host+tactic
                   are merged into a single incident.
    """
    relevant = [a for a in alerts if _norm_sev(a.get("severity", 1)) >= min_severity]
    if not relevant:
        return []

    # First pass: bucket by host + tactic
    buckets: Dict[str, List[dict]] = defaultdict(list)
    for alert in relevant:
        device = alert.get("device") or {}
        host   = (alert.get("hostname")
                  or device.get("hostname")
                  or device.get("device_id")
                  or "unknown")
        behaviors = alert.get("behaviors") or []
        tactic = (alert.get("tactic")
                  or (behaviors[0].get("tactic") if behaviors else None)
                  or "unknown")
        buckets[f"{host}||{tactic}"].append(alert)

    incidents: List[Incident] = []

    for bucket_key, bucket in buckets.items():
        bucket.sort(key=_ts)

        # Second pass: split into time windows within each bucket
        windows: List[List[dict]] = []
        window: List[dict] = []
        window_start: Optional[datetime] = None

        for alert in bucket:
            t = _ts(alert)
            if window_start is None:
                window_start = t
                window = [alert]
            elif (t - window_start).total_seconds() <= window_hours * 3600:
                window.append(alert)
            else:
                windows.append(window)
                window, window_start = [alert], t
        if window:
            windows.append(window)

        for group in windows:
            if not group:
                continue

            # Aggregate across all alerts in window
            sevs       = [_norm_sev(a.get("severity", 1)) for a in group]
            max_sev    = max(sevs)
            sev_name   = {4:"Critical",3:"High",2:"Medium",1:"Low"}.get(max_sev,"Unknown")

            hosts = list({
                (a.get("hostname") or (a.get("device") or {}).get("hostname") or "")
                for a in group
            } - {""})
            host_ids = list({
                (a.get("device") or {}).get("device_id","") for a in group
            } - {""})
            users = list({
                (a.get("user_name")
                 or (a.get("grandparent_details") or {}).get("user_name")
                 or "")
                for a in group
            } - {""})
            tactics = list({
                t for a in group
                for t in (
                    ([a.get("tactic")] if a.get("tactic") else []) +
                    [b.get("tactic","") for b in (a.get("behaviors") or [])]
                ) if t
            })
            techniques = list({
                t for a in group
                for t in (
                    ([a.get("technique")] if a.get("technique") else []) +
                    [b.get("technique","") for b in (a.get("behaviors") or [])]
                ) if t
            })
            all_behaviors = [b for a in group for b in (a.get("behaviors") or [])]
            all_networks  = [n for a in group for n in (a.get("network_accesses") or [])]
            tags = list({tag for a in group for tag in (a.get("tags") or [])})
            adv_ids = list({adv for a in group for adv in (a.get("adversary_ids") or [])})

            first_ts = _ts(group[0]).isoformat()
            last_ts  = _ts(group[-1]).isoformat()

            # Derive status from constituent alert statuses
            statuses = [a.get("status", "new").lower() for a in group]
            if all(s in ("closed","resolved") for s in statuses):
                status_int, status_name = 40, "Closed"
            elif any(s in ("in_progress","assigned") for s in statuses):
                status_int, status_name = 30, "In Progress"
            else:
                status_int, status_name = 20, "New"

            # Human-readable name
            host_str   = hosts[0] if hosts else bucket_key.split("||")[0]
            tactic_str = (tactics[0].replace("_"," ").title()
                          if tactics else "Suspicious Activity")
            n = len(group)
            name = f"{tactic_str} — {host_str} ({n} alert{'s' if n != 1 else ''})"

            # Build description from behavior disposition
            desc_parts = []
            for b in all_behaviors[:3]:
                part = b.get("display_name") or b.get("pattern_disposition_description") or ""
                cmd  = b.get("cmdline","")
                if cmd:  part += f": {cmd[:80]}"
                if part: desc_parts.append(part)
            description = "; ".join(desc_parts) or group[0].get("description","")

            inc_id = _stable_id([
                hosts[0] if hosts else bucket_key,
                tactics[0] if tactics else "unknown",
                first_ts[:16],
            ])

            incidents.append(Incident(
                incident_id=        inc_id,
                client_name=        client_name,
                client_slug=        client_slug,
                status=             status_int,
                status_name=        status_name,
                severity=           max_sev,
                severity_name=      sev_name,
                adversary=          adv_ids[0] if adv_ids else None,
                name=               name,
                description=        description,
                start=              first_ts,
                end=                last_ts if status_int == 40 else None,
                modified_timestamp= last_ts,
                hosts=              hosts,
                users=              users,
                tactics=            tactics,
                techniques=         techniques,
                objectives=         [],
                assigned_to=        None,
                tags=               tags,
                score=              round(sum(sevs) / len(sevs) * 25),
            ))

    incidents.sort(key=lambda i: (-i.severity, i.start or ""))
    return incidents


async def _fetch_alerts(cfg, since: datetime, until: datetime, limit: int):
    """Fetch raw alerts for incident synthesis via FalconPy."""
    try:
        fql = _range_fql(since, until)
        logger.info(f"[{cfg.name}] Incidents alerts FQL: {fql}")
        fa = FalconAlerts(cfg)
        raws, errs, count = await fa.query_and_get(fql, limit=limit,
                                                    sort="updated_timestamp|desc")
        api_errors = [APIError(code=e.get("code",0), message=e.get("message",""))
                      for e in errs]
        return raws, api_errors, count
    except Exception as e:
        logger.error(f"[{cfg.name}] Alert fetch for incidents failed: {e}")
        return [], [APIError(code=500, message=str(e))], 0


# ── Routes ───────────────────────────────────────────────────────────────────

@router.get("", response_model=IncidentList)
async def list_all_incidents(
    status: Optional[int] = Query(None),
    hours:  int           = Query(168, ge=1, le=8760),
    limit:  int           = Query(200, ge=1, le=500),
):
    """Synthesize incidents from alerts across all tenants — last N hours."""
    until   = _now()
    since   = until - timedelta(hours=hours)
    clients = all_clients()

    results = await asyncio.gather(
        *[_fetch_alerts(c, since, until, limit) for c in clients],
        return_exceptions=True,
    )

    all_incidents, all_errors = [], []
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            all_errors.append(APIError(code=500, message=str(r)))
        else:
            raws, errs, _ = r
            incidents = _group_into_incidents(raws, clients[i].name, clients[i].slug)
            if status is not None:
                incidents = [inc for inc in incidents if inc.status == status]
            all_incidents.extend(incidents)
            all_errors.extend(errs)

    all_incidents.sort(key=lambda i: (-i.severity, i.start or ""))
    return IncidentList(
        incidents=all_incidents,
        meta=PaginationMeta(total=len(all_incidents), limit=limit),
        errors=all_errors,
    )


@router.get("/poll", response_model=IncidentList)
async def poll_incidents(
    window_minutes: int = Query(10, ge=1, le=120),
    limit:          int = Query(200, ge=1, le=500),
):
    """Delta poll: re-synthesize from alerts updated in the last N minutes."""
    until   = _now()
    clients = all_clients()

    results = await asyncio.gather(
        *[_fetch_alerts(
              c,
              _poll_cursors.get(f"inc_{c.slug}", until - timedelta(minutes=window_minutes)),
              until, limit)
          for c in clients],
        return_exceptions=True,
    )

    all_incidents, all_errors = [], []
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            all_errors.append(APIError(code=500, message=str(r)))
        else:
            raws, errs, _ = r
            all_incidents.extend(
                _group_into_incidents(raws, clients[i].name, clients[i].slug)
            )
            all_errors.extend(errs)
            _poll_cursors[f"inc_{clients[i].slug}"] = until

    all_incidents.sort(key=lambda i: (-i.severity, i.start or ""))
    return IncidentList(
        incidents=all_incidents,
        meta=PaginationMeta(total=len(all_incidents), limit=limit),
        errors=all_errors,
    )


@router.get("/{client_slug}", response_model=IncidentList)
async def list_client_incidents(
    client_slug: str,
    status:  Optional[int] = Query(None),
    hours:   int           = Query(168, ge=1, le=8760),
    limit:   int           = Query(200, ge=1, le=500),
):
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(404, f"Client '{client_slug}' not found")

    until = _now()
    since = until - timedelta(hours=hours)
    raws, errs, _ = await _fetch_alerts(cfg, since, until, limit)
    incidents = _group_into_incidents(raws, cfg.name, cfg.slug)
    if status is not None:
        incidents = [i for i in incidents if i.status == status]

    return IncidentList(
        incidents=incidents,
        meta=PaginationMeta(total=len(incidents), limit=limit),
        errors=errs,
    )


@router.get("/{client_slug}/{incident_id}", response_model=Incident)
async def get_incident(client_slug: str, incident_id: str):
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(404, f"Client '{client_slug}' not found")

    until = _now()
    since = until - timedelta(hours=168)
    raws, _, _ = await _fetch_alerts(cfg, since, until, 500)
    for inc in _group_into_incidents(raws, cfg.name, cfg.slug):
        if inc.incident_id == incident_id:
            return inc

    raise HTTPException(404, f"Incident '{incident_id}' not found")


class IncidentUpdate(BaseModel):
    status:        Optional[str]       = None
    assigned_to:   Optional[str]       = None
    comment:       Optional[str]       = None
    tags:          Optional[List[str]] = None
    composite_ids: Optional[List[str]] = None   # underlying alert IDs


@router.patch("/{client_slug}/{incident_id}")
async def update_incident(client_slug: str, incident_id: str, body: IncidentUpdate):
    """Update underlying alerts via PATCH /alerts/entities/alerts/v3."""
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(404, f"Client '{client_slug}' not found")

    composite_ids = body.composite_ids
    if not composite_ids:
        # Re-fetch the window to find underlying alert IDs
        until = _now()
        since = until - timedelta(hours=168)
        raws, _, _ = await _fetch_alerts(cfg, since, until, 500)
        composite_ids = [
            a.get("composite_id") or a.get("id","") for a in raws
            if a.get("composite_id") or a.get("id")
        ][:50]

    if not composite_ids:
        raise HTTPException(404, "No alerts found for this incident")

    action_params = []
    if body.status:
        action_params.append({"name": "update_status",  "value": body.status})
    if body.assigned_to:
        action_params.append({"name": "assign_to_uuid", "value": body.assigned_to})
    if body.comment:
        action_params.append({"name": "append_comment", "value": body.comment})
    for tag in (body.tags or []):
        action_params.append({"name": "add_tag",        "value": tag})

    if not action_params:
        return {"success": True, "message": "No changes specified"}

    fa   = FalconAlerts(cfg)
    resp = await fa.update(composite_ids, action_params)
    errs = sdk_errors(resp)
    if errs:
        raise HTTPException(400, detail=errs)

    return {"success": True, "incident_id": incident_id,
            "alerts_updated": len(composite_ids)}
