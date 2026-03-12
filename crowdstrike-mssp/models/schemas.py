"""
models/schemas.py — FalconGuard API Response Models
All responses the backend sends to the frontend are typed here.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


# ── Common ─────────────────────────────────────────────────────────────────

class APIError(BaseModel):
    code:    int
    message: str

class PaginationMeta(BaseModel):
    total:  int = 0
    offset: int = 0
    limit:  int = 100


# ── Client / Tenant ────────────────────────────────────────────────────────

class ClientSummary(BaseModel):
    slug:           str
    name:           str
    cid:            str
    cloud:          str
    tier:           str
    industry:       str
    online_sensors: Optional[int] = None
    total_sensors:  Optional[int] = None
    health_pct:     Optional[float] = None
    det_24h:        Optional[int] = None
    critical_count: Optional[int] = None
    high_count:     Optional[int] = None
    status:         str = "unknown"    # protected | monitoring | under_attack | unknown


class ClientDetail(ClientSummary):
    hosts:             List[Dict] = []
    policy_compliance: Dict[str, Any] = {}
    vulnerability_summary: Dict[str, int] = {}


# ── Detections / Alerts ────────────────────────────────────────────────────

class Detection(BaseModel):
    id:              str
    client_name:     str
    client_slug:     str
    severity:        int           # 1-4 (informational → critical)
    severity_name:   str           # Low / Medium / High / Critical
    status:          str
    description:     str
    host_name:       Optional[str] = None
    host_id:         Optional[str] = None
    username:        Optional[str] = None
    tactic:          Optional[str] = None
    technique:       Optional[str] = None
    technique_id:    Optional[str] = None
    timestamp:       Optional[str] = None
    falcon_action:   Optional[str] = None   # killed / blocked / detected


class DetectionList(BaseModel):
    detections: List[Detection]
    meta:       PaginationMeta
    errors:     List[APIError] = []


# ── Hosts ──────────────────────────────────────────────────────────────────

class Host(BaseModel):
    device_id:         str
    hostname:          Optional[str] = None
    local_ip:          Optional[str] = None
    os_version:        Optional[str] = None
    platform_name:     Optional[str] = None
    agent_version:     Optional[str] = None
    status:            str = "normal"       # normal | contained | containment_pending
    last_seen:         Optional[str] = None
    first_seen:        Optional[str] = None
    assigned_policies: List[str] = []
    containment_status: str = "normal"


class HostList(BaseModel):
    hosts:  List[Host]
    meta:   PaginationMeta
    errors: List[APIError] = []


# ── Incidents ──────────────────────────────────────────────────────────────

class Incident(BaseModel):
    incident_id:    str
    client_name:    str
    client_slug:    str
    status:         int           # 20=New, 25=Reopened, 30=In Progress, 40=Closed
    status_name:    str
    severity:       int = 0       # derived: 4=Critical(80+), 3=High(50+), 2=Med(25+), 1=Low
    severity_name:  str = "Unknown"
    name:           Optional[str] = None
    description:    Optional[str] = None
    adversary:      Optional[str] = None   # populated from CrowdStrike threat intel tags
    start:          Optional[str] = None
    end:            Optional[str] = None
    modified_timestamp: Optional[str] = None
    hosts:          List[str] = []
    users:          List[str] = []
    tactics:        List[str] = []
    techniques:     List[str] = []
    objectives:     List[str] = []
    assigned_to:    Optional[str] = None
    tags:           List[str] = []
    score:          int = 0


class IncidentList(BaseModel):
    incidents: List[Incident]
    meta:      PaginationMeta
    errors:    List[APIError] = []


# ── IOCs ───────────────────────────────────────────────────────────────────

class IOC(BaseModel):
    id:          Optional[str] = None
    type:        str            # sha256 | md5 | domain | ipv4 | ipv6 | url
    value:       str
    action:      str = "detect" # detect | prevent | no_action
    severity:    Optional[str] = None
    description: Optional[str] = None
    source:      Optional[str] = None
    created_by:  Optional[str] = None
    created_on:  Optional[str] = None
    expiration:  Optional[str] = None
    tags:        List[str] = []


# ── Vulnerabilities ────────────────────────────────────────────────────────

class VulnSummary(BaseModel):
    client_slug:  str
    critical:     int = 0
    high:         int = 0
    medium:       int = 0
    low:          int = 0
    total:        int = 0


# ── Overview (Command Center) ──────────────────────────────────────────────

class OverviewKPIs(BaseModel):
    total_clients:      int
    online_sensors:     int
    total_sensors:      int
    coverage_pct:       float
    critical_dets_24h:  int
    high_dets_24h:      int
    total_dets_24h:     int
    open_incidents:     int
    clients_under_attack: int
    mttd_avg_minutes:   Optional[float] = None

class OverviewResponse(BaseModel):
    kpis:    OverviewKPIs
    clients: List[ClientSummary]
    errors:  List[APIError] = []


# ── Host Actions ───────────────────────────────────────────────────────────

class ContainRequest(BaseModel):
    client_slug: str
    device_ids:  List[str]
    action:      str = "contain"   # contain | lift_containment


class ContainResponse(BaseModel):
    success:     bool
    device_ids:  List[str]
    action:      str
    errors:      List[APIError] = []


# ── Token Health ───────────────────────────────────────────────────────────

class TokenHealthResponse(BaseModel):
    tokens: Dict[str, Dict]   # slug → {cloud, seconds_remaining, expired}
