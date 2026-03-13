"""
routes/ai_insights.py — LLaMA 3 AI Insights via Ollama

FalconPy calls:
    Alerts.get_alerts_v2(composite_ids)
    Alerts.query_alerts_v2(filter, limit)
    Hosts.get_device_details(ids)
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from config import get_client, ClientConfig
from services.falcon_client import FalconAlerts, FalconHosts, resources, errors
from services.rtr import investigate_host

router = APIRouter(prefix="/ai", tags=["AI Insights"])
logger = logging.getLogger("falconguard.ai")

OLLAMA_URL     = os.getenv("OLLAMA_URL",   "http://localhost:11434")
OLLAMA_MODEL   = os.getenv("OLLAMA_MODEL", "llama3")
OLLAMA_TIMEOUT = 120


# ── Ollama ────────────────────────────────────────────────────────────────────

async def _query_llama(prompt: str, system_prompt: str = "") -> str:
    payload = {
        "model":  OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": 1500, "top_p": 0.9},
    }
    if system_prompt:
        payload["system"] = system_prompt

    async with httpx.AsyncClient(timeout=httpx.Timeout(OLLAMA_TIMEOUT)) as client:
        try:
            resp = await client.post(f"{OLLAMA_URL}/api/generate", json=payload)
            resp.raise_for_status()
            return resp.json().get("response", "").strip()
        except httpx.ConnectError:
            raise HTTPException(503, "Ollama not running. Start with: ollama serve")
        except httpx.TimeoutException:
            raise HTTPException(504, "LLaMA inference timed out")


# ── Context fetching via FalconPy ─────────────────────────────────────────────

async def _fetch_context(cfg: ClientConfig, incident_id: str) -> Dict[str, Any]:
    """
    Build analysis context using only Alerts API + Hosts API (FalconPy).
    Works for both composite alert IDs and synthetic INC-* incident IDs.
    """
    def _rfc3339(dt):
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

    now   = datetime.now(timezone.utc)
    since = now - timedelta(hours=168)
    context: Dict[str, Any] = {}

    fa = FalconAlerts(cfg)
    fh = FalconHosts(cfg)

    try:
        if not incident_id.startswith("INC-"):
            # Direct composite alert ID
            resp = await fa.get([incident_id])
            alerts = resources(resp)
            if alerts:
                a = alerts[0]
                context["incident"] = {
                    "incident_id": incident_id,
                    "description": a.get("description", ""),
                    "status":      a.get("status", "new"),
                    "score":       max(1, min(4, a.get("severity", 1))) * 25,
                    "tactics":     [a.get("tactic")] if a.get("tactic") else [],
                    "techniques":  [a.get("technique")] if a.get("technique") else [],
                    "hosts":       [(a.get("device") or {}).get("device_id", "")],
                }
                context["behaviors"]     = a.get("behaviors") or []
                context["recent_alerts"] = alerts
        else:
            # Synthetic INC-* — aggregate from full window
            fql = (f"updated_timestamp:>='{_rfc3339(since)}'"
                   f"+updated_timestamp:<='{_rfc3339(now)}'")
            raws, _, _ = await fa.query_and_get(fql, limit=500)
            if raws:
                def _ns(r): return max(1, min(4, r)) if isinstance(r,int) else {"critical":4,"high":3,"medium":2,"low":1}.get(str(r).lower(),1)
                sevs       = [_ns(a.get("severity",1)) for a in raws]
                context["incident"] = {
                    "incident_id": incident_id,
                    "description": raws[0].get("description",""),
                    "status":      "new",
                    "score":       round(sum(sevs)/len(sevs)*25),
                    "tactics":     list({a.get("tactic","") for a in raws} - {""}),
                    "techniques":  list({a.get("technique","") for a in raws} - {""}),
                    "hosts":       list({(a.get("device") or {}).get("device_id","") for a in raws} - {""}),
                }
                context["behaviors"]     = [b for a in raws for b in (a.get("behaviors") or [])][:30]
                context["recent_alerts"] = raws[:20]

        # Enrich with host device details
        host_ids = (context.get("incident") or {}).get("hosts", [])[:5]
        if host_ids:
            try:
                hr = await fh.get(host_ids)
                context["hosts"] = resources(hr)
            except Exception:
                pass

    except Exception as e:
        logger.error(f"Context fetch failed: {e}")
        context["fetch_error"] = str(e)

    return context


def _build_prompt(context: Dict[str, Any], rtr_data: Dict[str, str]) -> str:
    inc       = context.get("incident", {})
    behaviors = context.get("behaviors", [])
    hosts     = context.get("hosts", [])
    alerts    = context.get("recent_alerts", [])

    host_lines = [
        f"  - {h.get('hostname','?')} | OS: {h.get('os_version','?')} "
        f"| Containment: {h.get('containment_status','normal')} "
        f"| Last seen: {h.get('last_seen','?')}"
        for h in hosts
    ]
    beh_lines = [
        f"  - [{b.get('tactic','?')} / {b.get('technique','?')}] "
        f"{b.get('display_name','?')} on user {b.get('user_name','?')} | "
        f"CMD: {b.get('cmdline','N/A')[:80]}"
        for b in behaviors[:10]
    ]
    alert_lines = [
        f"  - Sev {a.get('severity','?')}: {a.get('description','?')} "
        f"at {a.get('created_timestamp','?')}"
        for a in alerts[:8]
    ]

    rtr_section = ""
    if rtr_data and "error" not in rtr_data:
        rtr_section = "\n\nLIVE HOST DATA (RTR):\n"
        for k, v in rtr_data.items():
            if v and not v.startswith("["):
                rtr_section += f"\n{k.upper()}:\n{v[:1200]}\n"

    return f"""You are a Tier 3 SOC analyst at an MSSP. Analyze this CrowdStrike alert group.

INCIDENT:
  ID: {inc.get('incident_id','Unknown')}
  Score: {inc.get('score',0)}/100
  Tactics: {', '.join(inc.get('tactics',[]) or ['Unknown'])}
  Techniques: {', '.join(inc.get('techniques',[]) or ['Unknown'])}
  Hosts affected: {len(hosts)}
  Description: {inc.get('description','N/A')}

AFFECTED HOSTS:
{chr(10).join(host_lines) or '  No host data'}

BEHAVIORS ({len(beh_lines)} of {len(behaviors)}):
{chr(10).join(beh_lines) or '  No behavior data'}

RECENT ALERTS:
{chr(10).join(alert_lines) or '  No alert data'}{rtr_section}

## THREAT ASSESSMENT
[2-3 sentences: what is happening, confidence, likely threat actor/malware]

## ATTACK CHAIN RECONSTRUCTION
[Step-by-step breakdown based on evidence]

## IMMEDIATE ACTIONS REQUIRED
[Numbered list, most urgent first]

## PERSISTENCE & LATERAL MOVEMENT RISK
[Assessment of persistence and spread risk]

## RECOMMENDED THREAT HUNT QUERIES
[2-3 FQL queries to hunt related activity]

## EXECUTIVE SUMMARY (2 sentences)
[Non-technical summary for client briefing]
"""


# ── Routes ────────────────────────────────────────────────────────────────────

class IncidentAnalysisRequest(BaseModel):
    client_slug:   str
    incident_id:   str
    run_rtr:       bool = False
    rtr_device_id: Optional[str] = None


class AnalysisResponse(BaseModel):
    incident_id:   str
    client_name:   str
    model:         str
    analysis:      str
    context_used:  Dict[str, int]
    elapsed_secs:  float
    rtr_collected: bool


@router.post("/analyze-incident", response_model=AnalysisResponse)
async def analyze_incident(req: IncidentAnalysisRequest):
    cfg = get_client(req.client_slug)
    if not cfg:
        raise HTTPException(404, f"Client '{req.client_slug}' not found")

    start   = time.monotonic()
    context = await _fetch_context(cfg, req.incident_id)

    rtr_data, rtr_collected = {}, False
    if req.run_rtr and req.rtr_device_id:
        try:
            rtr_data      = await investigate_host(cfg, req.rtr_device_id)
            rtr_collected = True
        except Exception as e:
            logger.error(f"RTR failed (continuing): {e}")
            rtr_data = {"error": str(e)}

    prompt = _build_prompt(context, rtr_data)
    system = (
        "You are an elite cybersecurity analyst specializing in incident response. "
        "Work for an MSSP managing enterprise clients. Analysis must be precise, "
        "actionable, and based strictly on the evidence provided. "
        "Never fabricate IOCs or attribution not supported by the data."
    )
    analysis = await _query_llama(prompt, system)
    elapsed  = round(time.monotonic() - start, 2)

    return AnalysisResponse(
        incident_id=   req.incident_id,
        client_name=   cfg.name,
        model=         OLLAMA_MODEL,
        analysis=      analysis,
        context_used={
            "behaviors":    len(context.get("behaviors", [])),
            "hosts":        len(context.get("hosts", [])),
            "alerts":       len(context.get("recent_alerts", [])),
            "rtr_commands": sum(1 for v in rtr_data.values() if not str(v).startswith("[")),
        },
        elapsed_secs=  elapsed,
        rtr_collected= rtr_collected,
    )


class TriageRequest(BaseModel):
    detection_description: str
    severity:              int
    tactic:                Optional[str] = None
    technique:             Optional[str] = None
    hostname:              Optional[str] = None
    username:              Optional[str] = None
    command_line:          Optional[str] = None


@router.post("/triage-detection")
async def triage_detection(req: TriageRequest):
    prompt = f"""Quick SOC triage for this CrowdStrike detection:

Severity: {req.severity}/4 | Tactic: {req.tactic or 'Unknown'} | Technique: {req.technique or 'Unknown'}
Host: {req.hostname or 'Unknown'} | User: {req.username or 'Unknown'}
Command: {req.command_line or 'N/A'}
Description: {req.detection_description}

1. TRUE POSITIVE / FALSE POSITIVE (confidence %)
2. If TP: immediate containment step (1 sentence)
3. Priority: P1/P2/P3/P4
4. One follow-up investigation step
"""
    start  = time.monotonic()
    result = await _query_llama(prompt)
    return {"triage": result, "elapsed_secs": round(time.monotonic()-start, 2),
            "model": OLLAMA_MODEL}


@router.get("/health")
async def ai_health():
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp   = await client.get(f"{OLLAMA_URL}/api/tags")
            resp.raise_for_status()
            models = resp.json().get("models", [])
            names  = [m.get("name","") for m in models]
            avail  = any(OLLAMA_MODEL in n for n in names)
            return {
                "ollama_running": True, "model": OLLAMA_MODEL,
                "model_available": avail, "available_models": names,
                "status": "ready" if avail else "model_not_pulled",
            }
    except httpx.ConnectError:
        return {
            "ollama_running": False, "model": OLLAMA_MODEL,
            "model_available": False, "status": "ollama_not_running",
            "setup_hint": "Install Ollama then: ollama serve && ollama pull llama3",
        }
