"""
config.py — FalconGuard MSSP Configuration
Loads all client credentials and app settings from environment variables.
Supports dynamic client registration (CLIENT_1 through CLIENT_N).
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import re
from typing import Dict, List, Optional
from pydantic import BaseModel, SecretStr
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────
#  CrowdStrike Cloud Base URLs
# ─────────────────────────────────────────────
CLOUD_BASE_URLS: Dict[str, str] = {
    "us-1":     "https://api.crowdstrike.com",
    "us-2":     "https://api.us-2.crowdstrike.com",
    "eu-1":     "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
    "us-gov-2": "https://api.us-gov-2.crowdstrike.mil",
}

VALID_CLOUDS = set(CLOUD_BASE_URLS.keys())
VALID_TIERS  = {"enterprise", "premium", "standard"}


# ─────────────────────────────────────────────
#  Client Model
# ─────────────────────────────────────────────
class ClientConfig(BaseModel):
    """Represents a single managed CrowdStrike tenant."""
    name:          str
    cid:           str
    client_id:     str
    client_secret: str          # stored in memory; never logged or returned via API
    cloud:         str          # one of CLOUD_BASE_URLS keys
    tier:          str
    industry:      str = "Unknown"

    @property
    def base_url(self) -> str:
        return CLOUD_BASE_URLS[self.cloud]

    @property
    def slug(self) -> str:
        """URL-safe identifier derived from CID."""
        return self.cid.lower().replace("-", "_")


# ─────────────────────────────────────────────
#  App Settings
# ─────────────────────────────────────────────
class AppSettings(BaseSettings):
    app_env:        str = "development"
    app_secret_key: str = "change-me"
    log_level:      str = "INFO"
    cors_origins:   str = "http://localhost:3000"

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",")]

    class Config:
        env_file = ".env"
        extra = "ignore"


# ─────────────────────────────────────────────
#  Client Registry — auto-discovered from env
# ─────────────────────────────────────────────
def _load_clients() -> Dict[str, ClientConfig]:
    """
    Scans environment for CLIENT_N_* variables and builds registry.
    Keys are CID slugs. Fails loudly on bad cloud values.
    """
    clients: Dict[str, ClientConfig] = {}
    indices: set = set()

    for key in os.environ:
        m = re.match(r"^CLIENT_(\d+)_NAME$", key)
        if m:
            indices.add(int(m.group(1)))

    for n in sorted(indices):
        def _get(field: str, default: str = "") -> str:
            return os.environ.get(f"CLIENT_{n}_{field}", default).strip()

        cloud = _get("CLOUD", "us-1").lower()
        tier  = _get("TIER",  "standard").lower()

        if cloud not in VALID_CLOUDS:
            raise ValueError(
                f"CLIENT_{n}_CLOUD='{cloud}' is invalid. "
                f"Must be one of: {sorted(VALID_CLOUDS)}"
            )

        cfg = ClientConfig(
            name=          _get("NAME"),
            cid=           _get("CID"),
            client_id=     _get("CLIENT_ID"),
            client_secret= _get("CLIENT_SECRET"),
            cloud=         cloud,
            tier=          tier if tier in VALID_TIERS else "standard",
            industry=      _get("INDUSTRY", "Unknown"),
        )

        if not cfg.name or not cfg.cid or not cfg.client_id or not cfg.client_secret:
            raise ValueError(f"CLIENT_{n} is missing required fields (NAME, CID, CLIENT_ID, CLIENT_SECRET)")

        clients[cfg.slug] = cfg

    return clients


# ─────────────────────────────────────────────
#  Singletons
# ─────────────────────────────────────────────
settings = AppSettings()
CLIENT_REGISTRY: Dict[str, ClientConfig] = _load_clients()


def get_client(cid_slug: str) -> Optional[ClientConfig]:
    return CLIENT_REGISTRY.get(cid_slug)


def all_clients() -> List[ClientConfig]:
    return list(CLIENT_REGISTRY.values())
