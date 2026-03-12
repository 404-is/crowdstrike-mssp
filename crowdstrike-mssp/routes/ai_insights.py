"""
routes/ai_insights.py — LLaMA 3 AI Insights via Ollama

Aggregates CrowdStrike incident + host data and runs it through
a locally-hosted LLaMA 3 model (via Ollama) to generate analyst insights.

Prerequisites:
  1. Install Ollama:  https://ollama.com/download
  2. Pull the model:  ollama pull llama3
  3. Ollama runs at:  http://localhost:11434  (default)

Endpoints:
  POST /ai/analyze-incident   — full incident deep-dive
  POST /ai/triage-detection   — quick single-detection triage
  GET  /ai/health             — check if Ollama is reachable
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from config import get_client, ClientConfig
from services.crowdstrike import CrowdStrikeClient
from services.rtr import investigate_host

router = APIRouter(prefix="/ai", tags=["AI Insights"])
logger = logging.getLogger("falconguard.ai")

# Ollama config — override with OLLAMA_URL env var if needed
import os
OLLAMA_URL   = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
OLLAMA_TIMEOUT = 120  # seconds — LLaMA can be slow on first inference


# ── Ollama client ─────────────────────────────────────────────────────────────

async def _query_llama(prompt: str, system_prompt: str = "") -> str:
    """
    Sends a prompt to the local Ollama LLaMA 3 instance.
    Returns the generated text or raises on failure.
    """
    payload = {
        "model":  OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,     # low temp = more factual, less creative
            "num_predict": 1500,    # max tokens in response
            "top_p": 0.9,
        }
    }
    if system_prompt:
        payload["system"] = system_prompt

    async with httpx.AsyncClient(timeout=httpx.Timeout(OLLAMA_TIMEOUT)) as client:
        try:
            resp = await client.post(f"{OLLAMA_URL}/api/generate", json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "").strip()
        except httpx.ConnectError:
            raise HTTPException(
                status_code=503,
                detail=(
                    "Ollama is not running. "
                    "Start it with: ollama serve   "
                    "Then pull the model: ollama pull llama3"
                )
            )
        except httpx.TimeoutException:
            raise HTTPException(
                status_code=504,
                detail="LLaMA inference timed out. Try a smaller model or check GPU/CPU load."
            )


# ── Data aggregation helpers ──────────────────────────────────────────────────

async def _fetch_incident_context(cfg: ClientConfig, incident_id: str) -> Dict[str, Any]:
    """Fetches full incident data + related detections + affected host details."""
    cs = CrowdStrikeClient(cfg)
    context: Dict[str, Any] = {}

    try:
        # Incident details
        inc_resp = await cs.post(
            "/incidents/entities/incidents/GET/v1",
            json={"ids": [incident_id]}
        )
        incidents = inc_resp.get("resources", [])
        if incidents:
            context["incident"] = incidents[0]

        # Related behaviors/detections
        beh_resp = await cs.get(
            "/incidents/queries/behaviors/v1",
            params={"filter": f"incident_id:'{incident_id}'", "limit": 20}
        )
        beh_ids = beh_resp.get("resources", [])
        if beh_ids:
            beh_detail = await cs.post(
                "/incidents/entities/behaviors/GET/v1",
                json={"ids": beh_ids[:20]}
            )
            context["behaviors"] = beh_detail.get("resources", [])

        # Affected hosts
        inc_data = context.get("incident", {})
        host_ids = inc_data.get("hosts", [])[:5]  # limit to 5 hosts for context
        if host_ids:
            host_resp = await cs.get(
                "/devices/entities/devices/v2",
                params={"ids": host_ids}
            )
            context["hosts"] = host_resp.get("resources", [])

        # Recent alerts for these hosts
        if host_ids:
            host_ids_joined = "','".join(host_ids)
            fql = f"device_id:['{host_ids_joined}']"
            alert_resp = await cs.get(
                "/alerts/queries/alerts/v2",
                params={"filter": fql, "limit": 10, "sort": "created_timestamp|desc"}
            )
            alert_ids = alert_resp.get("resources", [])
            if alert_ids:
                alert_detail = await cs.get(
                    "/alerts/entities/alerts/v2",
                    params={"ids": alert_ids[:10]}
                )
                context["recent_alerts"] = alert_detail.get("resources", [])

    except Exception as e:
        logger.error(f"Failed to fetch incident context: {e}")
        context["fetch_error"] = str(e)
    finally:
        await cs.close()

    return context


def _build_incident_prompt(context: Dict[str, Any], rtr_data: Dict[str, str]) -> str:
    """Builds the LLaMA prompt from aggregated incident + RTR data."""

    inc      = context.get("incident", {})
    behaviors = context.get("behaviors", [])
    hosts    = context.get("hosts", [])
    alerts   = context.get("recent_alerts", [])

    # Extract key fields
    inc_id       = inc.get("incident_id", "Unknown")
    status       = inc.get("status", 0)
    status_name  = {20:"New",25:"Reopened",30:"In Progress",40:"Closed"}.get(status,"Unknown")
    tactics      = list(set(inc.get("tactics", [])))
    techniques   = list(set(inc.get("techniques", [])))
    score        = inc.get("score", 0)

    host_summaries = []
    for h in hosts:
        host_summaries.append(
            f"  - {h.get('hostname','?')} | OS: {h.get('os_version','?')} | "
            f"Containment: {h.get('containment_status','normal')} | "
            f"Last seen: {h.get('last_seen','?')}"
        )

    behavior_summaries = []
    for b in behaviors[:10]:
        behavior_summaries.append(
            f"  - [{b.get('tactic','?')} / {b.get('technique','?')}] "
            f"{b.get('description','?')} on {b.get('hostname','?')} "
            f"by user {b.get('user_name','?')}"
        )

    alert_summaries = []
    for a in alerts[:8]:
        alert_summaries.append(
            f"  - Severity {a.get('severity','?')}: {a.get('description','?')} "
            f"at {a.get('created_timestamp','?')}"
        )

    rtr_section = ""
    if rtr_data and "error" not in rtr_data:
        rtr_section = "\n\nLIVE HOST INVESTIGATION DATA (from Real Time Response):\n"
        if rtr_data.get("ps"):
            rtr_section += f"\nRunning Processes (top section):\n{rtr_data['ps'][:1500]}\n"
        if rtr_data.get("netstat"):
            rtr_section += f"\nNetwork Connections:\n{rtr_data['netstat'][:1500]}\n"
        if rtr_data.get("reg"):
            rtr_section += f"\nAutorun Registry Keys:\n{rtr_data['reg'][:800]}\n"
        if rtr_data.get("schtasks"):
            rtr_section += f"\nScheduled Tasks:\n{rtr_data['schtasks'][:800]}\n"

    prompt = f"""You are a Tier 3 SOC analyst at an MSSP. Analyze the following CrowdStrike Falcon incident and provide a structured threat assessment.

INCIDENT SUMMARY:
  ID: {inc_id}
  Status: {status_name}
  Score: {score}/100
  Tactics observed: {', '.join(tactics) if tactics else 'Unknown'}
  Techniques observed: {', '.join(techniques) if techniques else 'Unknown'}
  Affected hosts: {len(hosts)}
  Description: {inc.get('description', 'No description')}

AFFECTED HOSTS:
{chr(10).join(host_summaries) if host_summaries else '  No host data available'}

OBSERVED BEHAVIORS ({len(behavior_summaries)} of {len(behaviors)}):
{chr(10).join(behavior_summaries) if behavior_summaries else '  No behavior data available'}

RECENT ALERTS:
{chr(10).join(alert_summaries) if alert_summaries else '  No alert data available'}
{rtr_section}

Provide your analysis in this exact structure:

## THREAT ASSESSMENT
[2-3 sentences on what is happening, confidence level, and likely threat actor or malware family]

## ATTACK CHAIN RECONSTRUCTION
[Step-by-step breakdown of how the attacker moved through the environment based on the evidence]

## IMMEDIATE ACTIONS REQUIRED
[Numbered list of specific containment and remediation steps, most urgent first]

## PERSISTENCE & LATERAL MOVEMENT RISK
[Assessment of whether attacker has established persistence and risk of spreading]

## RECOMMENDED THREAT HUNT QUERIES
[2-3 specific FQL queries to hunt for related activity in other client environments]

## EXECUTIVE SUMMARY (2 sentences)
[Non-technical summary suitable for a client briefing]
"""
    return prompt


# ── Routes ────────────────────────────────────────────────────────────────────

class IncidentAnalysisRequest(BaseModel):
    client_slug:  str
    incident_id:  str
    run_rtr:      bool = False      # set True to also collect live host data via RTR
    rtr_device_id: Optional[str] = None   # required if run_rtr=True


class AnalysisResponse(BaseModel):
    incident_id:   str
    client_name:   str
    model:         str
    analysis:      str
    context_used:  Dict[str, int]   # summary of how much data was fed in
    elapsed_secs:  float
    rtr_collected: bool


@router.post("/analyze-incident", response_model=AnalysisResponse)
async def analyze_incident(req: IncidentAnalysisRequest):
    """
    Deep-dive incident analysis using LLaMA 3.
    
    Fetches: incident details, behaviors, host info, recent alerts.
    Optionally: runs RTR on a host to collect live process/network data.
    Sends everything to the local LLaMA 3 instance for AI analysis.
    """
    cfg = get_client(req.client_slug)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Client '{req.client_slug}' not found")

    start = time.monotonic()

    # 1. Collect CrowdStrike data
    logger.info(f"Fetching incident context: {req.incident_id} for {cfg.name}")
    context = await _fetch_incident_context(cfg, req.incident_id)

    # 2. Optionally run RTR host investigation
    rtr_data: Dict[str, str] = {}
    rtr_collected = False
    if req.run_rtr and req.rtr_device_id:
        logger.info(f"Running RTR investigation on {req.rtr_device_id}")
        try:
            rtr_data = await investigate_host(cfg, req.rtr_device_id)
            rtr_collected = True
        except Exception as e:
            logger.error(f"RTR investigation failed (continuing without it): {e}")
            rtr_data = {"error": str(e)}

    # 3. Build prompt
    prompt = _build_incident_prompt(context, rtr_data)

    # 4. Query LLaMA 3
    logger.info(f"Sending to LLaMA 3 — prompt length: {len(prompt)} chars")
    system_prompt = (
        "You are an elite cybersecurity analyst specializing in incident response and threat hunting. "
        "You work for an MSSP managing multiple enterprise clients. "
        "Your analysis is precise, actionable, and based strictly on the evidence provided. "
        "Never fabricate IOCs or attribution that isn't supported by the data."
    )
    analysis = await _query_llama(prompt, system_prompt)

    elapsed = round(time.monotonic() - start, 2)
    logger.info(f"AI analysis complete in {elapsed}s for {req.incident_id}")

    return AnalysisResponse(
        incident_id=   req.incident_id,
        client_name=   cfg.name,
        model=         OLLAMA_MODEL,
        analysis=      analysis,
        context_used={
            "behaviors":  len(context.get("behaviors", [])),
            "hosts":      len(context.get("hosts", [])),
            "alerts":     len(context.get("recent_alerts", [])),
            "rtr_commands": len([v for v in rtr_data.values() if not v.startswith("[")]),
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
    """
    Quick AI triage for a single detection.
    Fast — no API calls, just feeds the detection data to LLaMA.
    """
    prompt = f"""As a SOC analyst, quickly triage this CrowdStrike detection:

Severity: {req.severity}/4
Description: {req.detection_description}
Tactic: {req.tactic or 'Unknown'}
Technique: {req.technique or 'Unknown'}
Host: {req.hostname or 'Unknown'}
User: {req.username or 'Unknown'}
Command: {req.command_line or 'Not available'}

Provide:
1. TRUE POSITIVE / FALSE POSITIVE assessment with confidence %
2. If TP: immediate containment recommendation (1 sentence)
3. Priority level: P1/P2/P3/P4
4. One follow-up investigation step
"""
    start = time.monotonic()
    result = await _query_llama(prompt)
    return {
        "triage":       result,
        "elapsed_secs": round(time.monotonic() - start, 2),
        "model":        OLLAMA_MODEL,
    }


@router.get("/health")
async def ai_health():
    """Check if Ollama is running and LLaMA 3 is available."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            # Check Ollama is up
            resp = await client.get(f"{OLLAMA_URL}/api/tags")
            resp.raise_for_status()
            models = resp.json().get("models", [])
            model_names = [m.get("name", "") for m in models]
            llama_available = any(OLLAMA_MODEL in n for n in model_names)

            return {
                "ollama_running":   True,
                "ollama_url":       OLLAMA_URL,
                "model":            OLLAMA_MODEL,
                "model_available":  llama_available,
                "available_models": model_names,
                "status":           "ready" if llama_available else "model_not_pulled",
                "setup_hint":       None if llama_available else f"Run: ollama pull {OLLAMA_MODEL}",
            }
    except httpx.ConnectError:
        return {
            "ollama_running":  False,
            "ollama_url":      OLLAMA_URL,
            "model":           OLLAMA_MODEL,
            "model_available": False,
            "status":          "ollama_not_running",
            "setup_hint":      "Install Ollama from https://ollama.com then run: ollama serve",
        }
