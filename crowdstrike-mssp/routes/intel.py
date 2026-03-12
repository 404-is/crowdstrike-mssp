"""
routes/intel.py — IOC Management + Vulnerability Spotlight endpoints

Covers:
  - /iocs/{client}              GET custom IOC list
  - /iocs/{client}              POST create IOC
  - /iocs/{client}/{id}         DELETE remove IOC
  - /vulns/{client}             GET vulnerability summary
  - /vulns/{client}/detail      GET full vuln list with pagination
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from config import get_client
from services.crowdstrike import CrowdStrikeClient
from models.schemas import IOC, VulnSummary, APIError

router = APIRouter(tags=["Intel"])
logger = logging.getLogger("falconguard.intel")


# ─── IOC Management ────────────────────────────────────────────────────────────

@router.get("/iocs/{client_slug}", response_model=List[IOC])
async def list_iocs(
    client_slug: str,
    ioc_type:    Optional[str] = Query(None, description="sha256|md5|domain|ipv4|ipv6|url"),
    limit:       int           = Query(100, ge=1, le=2000),
    offset:      int           = Query(0, ge=0),
):
    """Lists custom IOCs for a client tenant."""
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Client '{client_slug}' not found")

    cs = CrowdStrikeClient(cfg)
    try:
        params: dict = {"limit": limit, "offset": offset}
        if ioc_type:
            params["filter"] = f"type:'{ioc_type}'"

        # Step 1: query IOC IDs
        id_resp = await cs.get("/iocs/queries/indicators/v1", params=params)
        ids     = id_resp.get("resources", [])
        if not ids:
            return []

        # Step 2: fetch IOC entities
        entity_resp = await cs.get("/iocs/entities/indicators/v1", params={"ids": ids})
        raws = entity_resp.get("resources", [])

        return [
            IOC(
                id=          r.get("id"),
                type=        r.get("type", ""),
                value=       r.get("value", ""),
                action=      r.get("action", "detect"),
                severity=    r.get("severity"),
                description= r.get("description"),
                source=      r.get("source"),
                created_by=  r.get("created_by"),
                created_on=  r.get("created_on"),
                expiration=  r.get("expiration"),
                tags=        r.get("tags", []),
            )
            for r in raws
        ]
    finally:
        await cs.close()


class CreateIOCRequest(BaseModel):
    type:        str                # sha256 | md5 | domain | ipv4 | ipv6 | url
    value:       str
    action:      str = "detect"     # detect | prevent | no_action
    severity:    Optional[str] = "medium"
    description: Optional[str] = None
    source:      Optional[str] = "FalconGuard MSSP"
    tags:        List[str]     = []
    expiration:  Optional[str] = None   # RFC3339


@router.post("/iocs/{client_slug}", response_model=IOC)
async def create_ioc(client_slug: str, body: CreateIOCRequest):
    """Creates a custom IOC in the client's Falcon environment."""
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Client '{client_slug}' not found")

    cs = CrowdStrikeClient(cfg)
    try:
        payload = {
            "indicators": [{
                "type":        body.type,
                "value":       body.value,
                "action":      body.action,
                "severity":    body.severity,
                "description": body.description or "",
                "source":      body.source or "FalconGuard MSSP",
                "tags":        body.tags,
                **({"expiration": body.expiration} if body.expiration else {}),
            }]
        }

        resp = await cs.post("/iocs/entities/indicators/v1", json=payload)
        errors = resp.get("errors", [])
        if errors:
            raise HTTPException(status_code=400, detail=errors)

        created = resp.get("resources", [{}])[0]
        return IOC(
            id=    created.get("id"),
            type=  body.type,
            value= body.value,
            action=body.action,
        )
    finally:
        await cs.close()


@router.delete("/iocs/{client_slug}/{ioc_id}")
async def delete_ioc(client_slug: str, ioc_id: str):
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Client '{client_slug}' not found")

    cs = CrowdStrikeClient(cfg)
    try:
        resp = await cs.delete("/iocs/entities/indicators/v1", params={"ids": [ioc_id]})
        errors = resp.get("errors", [])
        if errors:
            raise HTTPException(status_code=400, detail=errors)
        return {"success": True, "deleted_id": ioc_id}
    finally:
        await cs.close()


# ─── Vulnerability Spotlight ────────────────────────────────────────────────────

@router.get("/vulns/{client_slug}/summary", response_model=VulnSummary)
async def get_vuln_summary(client_slug: str):
    """Returns aggregated vulnerability counts by severity for a client."""
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Client '{client_slug}' not found")

    cs = CrowdStrikeClient(cfg)
    try:
        summary = VulnSummary(client_slug=client_slug)
        for sev in ("critical", "high", "medium", "low"):
            resp = await cs.get(
                "/spotlight/queries/vulnerabilities/v1",
                params={
                    "filter": f"cve.severity:'{sev.upper()}'+status:'open'",
                    "limit":  1,
                }
            )
            count = resp.get("meta", {}).get("pagination", {}).get("total", 0)
            setattr(summary, sev, count)

        summary.total = summary.critical + summary.high + summary.medium + summary.low
        return summary

    finally:
        await cs.close()


@router.get("/vulns/{client_slug}/detail")
async def get_vuln_detail(
    client_slug: str,
    severity:    Optional[str] = Query(None, description="CRITICAL|HIGH|MEDIUM|LOW"),
    limit:       int           = Query(100, ge=1, le=400),
    offset:      int           = Query(0, ge=0),
):
    """Returns vulnerability details with CVE info."""
    cfg = get_client(client_slug)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Client '{client_slug}' not found")

    cs = CrowdStrikeClient(cfg)
    try:
        fql_parts = ["status:'open'"]
        if severity:
            fql_parts.append(f"cve.severity:'{severity.upper()}'")

        id_resp = await cs.get(
            "/spotlight/queries/vulnerabilities/v1",
            params={
                "filter": "+".join(fql_parts),
                "limit":  limit,
                "offset": offset,
                "sort":   "cve.base_score|desc",
            }
        )
        ids   = id_resp.get("resources", [])
        total = id_resp.get("meta", {}).get("pagination", {}).get("total", 0)

        if not ids:
            return {"vulns": [], "total": total}

        entity_resp = await cs.get(
            "/spotlight/entities/vulnerabilities/v2",
            params={"ids": ids}
        )

        return {
            "vulns":  entity_resp.get("resources", []),
            "total":  total,
            "offset": offset,
            "limit":  limit,
        }
    finally:
        await cs.close()
