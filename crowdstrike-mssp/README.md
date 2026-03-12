# FalconGuard MSSP — Python Backend

FastAPI backend that bridges the FalconGuard dashboard with real CrowdStrike
Falcon data across multiple client tenants on mixed clouds.

---

## Project Structure

```
falconguard/
├── main.py                   ← FastAPI app, startup/shutdown, routers
├── config.py                 ← Client registry loaded from .env
├── requirements.txt
├── .env.example              ← Copy to .env and fill in credentials
│
├── auth/
│   └── token_manager.py      ← OAuth2 token cache with auto-refresh per CID
│
├── services/
│   └── crowdstrike.py        ← Authenticated httpx client with rate-limit handling
│
├── models/
│   └── schemas.py            ← Pydantic response models
│
└── routes/
    ├── overview.py           ← /api/v1/overview    (all clients aggregated)
    ├── detections.py         ← /api/v1/detections  (alerts across all clients)
    ├── hosts.py              ← /api/v1/hosts        (host inventory + containment)
    ├── incidents.py          ← /api/v1/incidents    (incident management)
    └── intel.py              ← /api/v1/iocs + /api/v1/vulns
```

---

## Setup

### 1. Clone and install dependencies

```bash
cd falconguard
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure clients

Copy the example env file and fill in real CrowdStrike credentials:

```bash
cp .env.example .env
```

Edit `.env`. Each client needs 6 fields:

```env
CLIENT_1_NAME=AcmeCorp Financial
CLIENT_1_CID=AC-2024-0047
CLIENT_1_CLIENT_ID=<from Falcon console>
CLIENT_1_CLIENT_SECRET=<from Falcon console>
CLIENT_1_CLOUD=us-1
CLIENT_1_TIER=enterprise
```

Supported clouds: `us-1` | `us-2` | `eu-1` | `us-gov-1` | `us-gov-2`

Add `CLIENT_2_*`, `CLIENT_3_*` etc. for each managed tenant.

### 3. Create API Clients in CrowdStrike Falcon

For each client tenant, create an API client with these scopes:

| Scope                  | Read | Write |
|------------------------|------|-------|
| Alerts                 | ✓    |       |
| Detections             | ✓    | ✓     |
| Hosts                  | ✓    | ✓     |
| Incidents              | ✓    | ✓     |
| IOC Management         | ✓    | ✓     |
| Vulnerabilities        | ✓    |       |
| Real time response     | ✓    | ✓     |
| Event streams          | ✓    |       |
| Flight control (MSSP)  | ✓    | ✓     |

Path: **Falcon console → Support & Resources → API Clients and Keys → Create API client**

### 4. Run the server

```bash
# Development (auto-reload)
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Production (multi-worker)
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

---

## API Reference

Once running, full docs at:
- Swagger UI: http://localhost:8000/docs
- ReDoc:      http://localhost:8000/redoc

### Core Endpoints

| Method | Path                                      | Description                           |
|--------|-------------------------------------------|---------------------------------------|
| GET    | /health                                   | Service health check                  |
| GET    | /health/tokens                            | Token cache status (debug)            |
| GET    | /api/v1/clients                           | List all registered clients           |
| GET    | /api/v1/overview                          | Aggregated KPIs across all clients    |
| GET    | /api/v1/detections                        | All detections (all clients)          |
| GET    | /api/v1/detections/{client_slug}          | Detections for one client             |
| PATCH  | /api/v1/detections/{client}/{id}          | Update detection status/assignee      |
| GET    | /api/v1/hosts/{client_slug}               | Host inventory                        |
| POST   | /api/v1/hosts/{client_slug}/action        | Contain / lift containment            |
| GET    | /api/v1/incidents                         | All incidents (all clients)           |
| GET    | /api/v1/incidents/{client_slug}           | Incidents for one client              |
| PATCH  | /api/v1/incidents/{client}/{id}           | Update incident                       |
| GET    | /api/v1/iocs/{client_slug}                | List custom IOCs                      |
| POST   | /api/v1/iocs/{client_slug}                | Create IOC                            |
| DELETE | /api/v1/iocs/{client_slug}/{id}           | Delete IOC                            |
| GET    | /api/v1/vulns/{client_slug}/summary       | Vulnerability counts by severity      |
| GET    | /api/v1/vulns/{client_slug}/detail        | Full vulnerability list               |

### Query Parameters

Most list endpoints support:
- `limit` / `offset` — pagination
- `hours` — lookback window (e.g. `?hours=24`)
- `severity` — filter by severity (1=Low to 4=Critical)
- `status` — filter by detection/incident status

---

## Multi-Cloud Notes

- Each client credential is tied to the cloud where that CID lives
- The token manager routes auth requests to the correct cloud base URL automatically
- CrowdStrike 308 cross-cloud redirects are followed automatically by httpx
- US-GOV-1 and US-GOV-2 do NOT support cross-cloud redirects per the docs

---

## Rate Limiting

CrowdStrike enforces:
- **6,000 req/min per CID** for authenticated requests
- **300 req/min per source IP** for auth token requests

The backend handles both automatically:
- Tokens cached for 25min (refreshed 5min before expiry)
- 429 responses trigger exponential backoff + retry
- Rate limit headers (`X-RateLimit-Remaining`) are monitored and logged

---

## Token Pre-warming

On startup, the server pre-acquires tokens for all configured clients.
This means the first dashboard load is fast — no auth latency.

---

## Connecting the Frontend

Update the FalconGuard HTML dashboard to point to this backend:

```javascript
const API_BASE = "http://localhost:8000/api/v1";

// Example: load command center KPIs
const resp = await fetch(`${API_BASE}/overview`);
const data = await resp.json();
```

CORS is pre-configured for localhost:3000 and localhost:8080.
Add your frontend origin to `CORS_ORIGINS` in `.env`.
