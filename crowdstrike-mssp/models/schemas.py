"""
models/schemas.py — FalconGuard API Response Models
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class APIError(BaseModel):
    code:    int
    message: str

class PaginationMeta(BaseModel):
    total:  int = 0
    offset: int = 0
    limit:  int = 100


class ClientSummary(BaseModel):
    slug:           str
    name:           str
    cid:            str
    cloud:          str
    tier:           str
    industry:       str
    online_sensors: Optional[int]   = None
    total_sensors:  Optional[int]   = None
    health_pct:     Optional[float] = None
    det_24h:        Optional[int]   = None
    critical_count: Optional[int]   = None
    high_count:     Optional[int]   = None
    status:         str = "unknown"


class ClientDetail(ClientSummary):
    hosts:                 List[Dict] = []
    policy_compliance:     Dict[str, Any] = {}
    vulnerability_summary: Dict[str, int] = {}


class Detection(BaseModel):
    id:              str
    client_name:     str
    client_slug:     str
    severity:        int
    severity_name:   str
    status:          str
    description:     str
    host_name:       Optional[str] = None
    host_id:         Optional[str] = None
    username:        Optional[str] = None
    tactic:          Optional[str] = None
    technique:       Optional[str] = None
    technique_id:    Optional[str] = None
    timestamp:       Optional[str] = None
    falcon_action:   Optional[str] = None
    # Rich alert fields from /alerts/entities/alerts/v2
    behaviors:       List[Dict]    = []   # process tree, cmdlines, file paths
    network_accesses: List[Dict]   = []   # network connections from behaviors
    ioc_type:        Optional[str] = None
    ioc_value:       Optional[str] = None
    parent_process:  Optional[str] = None
    cmdline:         Optional[str] = None
    filepath:        Optional[str] = None
    sha256:          Optional[str] = None
    local_ip:        Optional[str] = None
    adversary_ids:   List[str]     = []
    pattern_id:      Optional[str] = None
    raw:             Optional[Dict] = None  # full raw alert for frontend use


class DetectionList(BaseModel):
    detections: List[Detection]
    meta:       PaginationMeta
    errors:     List[APIError] = []


class Host(BaseModel):
    device_id:          str
    hostname:           Optional[str] = None
    local_ip:           Optional[str] = None
    os_version:         Optional[str] = None
    platform_name:      Optional[str] = None
    agent_version:      Optional[str] = None
    status:             str = "normal"
    last_seen:          Optional[str] = None
    first_seen:         Optional[str] = None
    assigned_policies:  List[str] = []
    containment_status: str = "normal"


class HostList(BaseModel):
    hosts:  List[Host]
    meta:   PaginationMeta
    errors: List[APIError] = []


class Incident(BaseModel):
    incident_id:        str
    client_name:        str
    client_slug:        str
    status:             int
    status_name:        str
    severity:           int = 0
    severity_name:      str = "Unknown"
    name:               Optional[str] = None
    description:        Optional[str] = None
    adversary:          Optional[str] = None
    start:              Optional[str] = None
    end:                Optional[str] = None
    modified_timestamp: Optional[str] = None
    hosts:              List[str] = []
    users:              List[str] = []
    tactics:            List[str] = []
    techniques:         List[str] = []
    objectives:         List[str] = []
    assigned_to:        Optional[str] = None
    tags:               List[str] = []
    score:              int = 0


class IncidentList(BaseModel):
    incidents: List[Incident]
    meta:      PaginationMeta
    errors:    List[APIError] = []


class IOC(BaseModel):
    id:          Optional[str] = None
    type:        str
    value:       str
    action:      str = "detect"
    severity:    Optional[str] = None
    description: Optional[str] = None
    source:      Optional[str] = None
    created_by:  Optional[str] = None
    created_on:  Optional[str] = None
    expiration:  Optional[str] = None
    tags:        List[str] = []


class VulnSummary(BaseModel):
    client_slug: str
    critical:    int = 0
    high:        int = 0
    medium:      int = 0
    low:         int = 0
    total:       int = 0


class OverviewKPIs(BaseModel):
    total_clients:        int
    online_sensors:       int
    total_sensors:        int
    coverage_pct:         float
    critical_dets_24h:    int
    high_dets_24h:        int
    total_dets_24h:       int
    open_incidents:       int
    clients_under_attack: int
    mttd_avg_minutes:     Optional[float] = None


class OverviewResponse(BaseModel):
    kpis:    OverviewKPIs
    clients: List[ClientSummary]
    errors:  List[APIError] = []


class ContainRequest(BaseModel):
    client_slug: str
    device_ids:  List[str]
    action:      str = "contain"


class ContainResponse(BaseModel):
    success:    bool
    device_ids: List[str]
    action:     str
    errors:     List[APIError] = []


class TokenHealthResponse(BaseModel):
    tokens: Dict[str, Dict]
