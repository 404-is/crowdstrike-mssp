"""
services/crowdstrike.py — CrowdStrike API HTTP Client

Wraps httpx with:
  - Automatic bearer token injection
  - Rate-limit header monitoring + backoff
  - 401 → token invalidation + single retry
  - 308 cross-cloud redirect following
  - Structured logging of every request
  - Per-cloud base URL routing
"""

import logging
import time
import asyncio
from typing import Any, Dict, List, Optional, Tuple

import httpx

from config import ClientConfig
from auth.token_manager import token_manager

logger = logging.getLogger("falconguard.cs_client")

REQUEST_TIMEOUT  = 30
RATE_LIMIT_HEADER = "X-RateLimit-Remaining"
MAX_RETRIES       = 2


class CrowdStrikeClient:
    """
    Async HTTP client for a single CrowdStrike tenant.
    Instantiate per-request or share per-CID — both are safe.
    """

    def __init__(self, client_config: ClientConfig):
        self.cfg = client_config
        self._http = httpx.AsyncClient(
            base_url=client_config.base_url,
            timeout=httpx.Timeout(REQUEST_TIMEOUT),
            follow_redirects=True,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )

    async def close(self):
        await self._http.aclose()

    # ── Core Request Method ────────────────────────────────────────────────

    async def request(
        self,
        method:  str,
        path:    str,
        params:  Optional[Dict]  = None,
        json:    Optional[Dict]  = None,
        data:    Optional[Dict]  = None,
        retried: bool            = False,
    ) -> Dict[str, Any]:
        """
        Makes an authenticated request.
        Handles 401 (re-auth once) and 429 (rate limit backoff).
        Returns parsed JSON response dict.
        """
        token = await token_manager.get_token(self.cfg)
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept":        "application/json",
            "Content-Type":  "application/json",
        }

        try:
            resp = await self._http.request(
                method,
                path,
                params=params,
                json=json,
                data=data,
                headers=headers,
            )

            # Log rate-limit headroom
            remaining = resp.headers.get(RATE_LIMIT_HEADER)
            if remaining and int(remaining) < 500:
                logger.warning(
                    f"Rate limit low: {remaining} remaining",
                    extra={"client": self.cfg.name, "path": path}
                )

            # 401 — token expired mid-session, refresh once
            if resp.status_code == 401 and not retried:
                logger.info(f"401 on {path} for {self.cfg.name} — refreshing token")
                await token_manager.invalidate(self.cfg.slug)
                return await self.request(method, path, params=params,
                                          json=json, data=data, retried=True)

            # 429 — rate limited
            if resp.status_code == 429:
                retry_after_epoch = int(resp.headers.get("X-RateLimit-RetryAfter", 0))
                wait = max(retry_after_epoch - int(time.time()), 2)
                logger.warning(f"429 rate limited on {path}, waiting {wait}s")
                await asyncio.sleep(wait)
                return await self.request(method, path, params=params,
                                          json=json, data=data, retried=True)

            resp.raise_for_status()
            return resp.json()

        except httpx.TimeoutException:
            logger.error(f"Timeout: {method} {path} for {self.cfg.name}")
            raise
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP {e.response.status_code} on {path}: {e}")
            raise

    # ── Convenience Methods ────────────────────────────────────────────────

    async def get(self, path: str, params: Optional[Dict] = None) -> Dict:
        return await self.request("GET", path, params=params)

    async def post(self, path: str, json: Optional[Dict] = None,
                   data: Optional[Dict] = None) -> Dict:
        return await self.request("POST", path, json=json, data=data)

    async def patch(self, path: str, json: Optional[Dict] = None) -> Dict:
        return await self.request("PATCH", path, json=json)

    async def delete(self, path: str, params: Optional[Dict] = None) -> Dict:
        return await self.request("DELETE", path, params=params)

    # ── Pagination Helper ──────────────────────────────────────────────────

    async def paginate_ids(
        self,
        query_path: str,
        entity_path: str,
        params: Optional[Dict] = None,
        max_ids: int = 500,
    ) -> List[Dict]:
        """
        CrowdStrike two-step pagination:
          1. GET query endpoint → returns list of IDs
          2. GET/POST entity endpoint → returns full objects for those IDs

        Handles offset-based pagination automatically.
        """
        params = params or {}
        all_ids: List[str] = []
        offset   = 0
        limit    = min(params.pop("limit", 100), 500)

        while len(all_ids) < max_ids:
            params.update({"limit": limit, "offset": offset})
            resp = await self.get(query_path, params=params)

            meta      = resp.get("meta", {})
            resources = resp.get("resources", [])
            errors    = resp.get("errors", [])

            if errors:
                logger.warning(f"Errors in paginate_ids ({query_path}): {errors}")

            if not resources:
                break

            all_ids.extend(resources)

            total = meta.get("pagination", {}).get("total", 0)
            offset += len(resources)
            if offset >= total or offset >= max_ids:
                break

        if not all_ids:
            return []

        # Fetch entities in batches of 100 (CS API limit)
        entities: List[Dict] = []
        for i in range(0, len(all_ids), 100):
            batch = all_ids[i:i+100]
            entity_resp = await self.get(entity_path, params={"ids": batch})
            entities.extend(entity_resp.get("resources", []))

        return entities
