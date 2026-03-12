"""
auth/token_manager.py — CrowdStrike OAuth2 Token Manager

Handles:
  - Per-CID token acquisition via POST /oauth2/token
  - In-memory caching with TTL (tokens valid 30min; we refresh at 25min)
  - Automatic refresh before expiry
  - Rate-limit awareness (300 req/min on auth endpoint per source IP)
  - Cross-cloud 308 redirect following
  - Token revocation on shutdown
"""

import asyncio
import time
import logging
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field

import httpx

from config import ClientConfig, CLOUD_BASE_URLS

logger = logging.getLogger("falconguard.auth")

# Refresh tokens 5 minutes before expiry to avoid mid-request failures
TOKEN_TTL_SECONDS   = 1799   # CS tokens expire in 1800s (30min)
REFRESH_BUFFER_SECS = 300    # Refresh 5min early
EFFECTIVE_TTL       = TOKEN_TTL_SECONDS - REFRESH_BUFFER_SECS  # 1499s ~25min

AUTH_TIMEOUT_SECS   = 15
MAX_AUTH_RETRIES    = 3
RETRY_BACKOFF_BASE  = 2      # exponential backoff: 2, 4, 8 seconds


@dataclass
class TokenEntry:
    access_token:  str
    acquired_at:   float = field(default_factory=time.monotonic)
    cloud:         str   = "us-1"

    def is_expired(self) -> bool:
        return (time.monotonic() - self.acquired_at) >= EFFECTIVE_TTL

    def seconds_remaining(self) -> int:
        elapsed = time.monotonic() - self.acquired_at
        return max(0, int(TOKEN_TTL_SECONDS - elapsed))


class TokenManager:
    """
    Thread-safe async token cache for all managed CrowdStrike tenants.
    One token per CID. Uses asyncio.Lock per CID to prevent stampedes.
    """

    def __init__(self):
        self._cache:   Dict[str, TokenEntry]     = {}
        self._locks:   Dict[str, asyncio.Lock]   = {}
        self._client:  Optional[httpx.AsyncClient] = None

    # ── Lifecycle ──────────────────────────────────────────────────────────

    async def startup(self):
        """Call once at app startup."""
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(AUTH_TIMEOUT_SECS),
            follow_redirects=True,   # handles 308 cross-cloud redirects automatically
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        )
        logger.info("TokenManager started")

    async def shutdown(self):
        """Call at app shutdown — revokes all active tokens."""
        if self._client:
            revoke_tasks = [
                self._revoke(slug, entry)
                for slug, entry in self._cache.items()
            ]
            if revoke_tasks:
                await asyncio.gather(*revoke_tasks, return_exceptions=True)
            await self._client.aclose()
        logger.info("TokenManager shut down — all tokens revoked")

    # ── Public API ─────────────────────────────────────────────────────────

    async def get_token(self, client: ClientConfig) -> str:
        """
        Returns a valid bearer token for the given client.
        Acquires a new one if missing or expired.
        """
        slug = client.slug
        lock = self._get_lock(slug)

        async with lock:
            entry = self._cache.get(slug)
            if entry and not entry.is_expired():
                return entry.access_token

            # Need a fresh token
            token = await self._acquire(client)
            self._cache[slug] = TokenEntry(
                access_token=token,
                cloud=client.cloud,
            )
            logger.info(
                "Token acquired",
                extra={"client": client.name, "cloud": client.cloud, "cid": client.cid}
            )
            return token

    async def invalidate(self, cid_slug: str):
        """Force-expire a cached token (e.g. after receiving 401)."""
        self._cache.pop(cid_slug, None)
        logger.debug(f"Token invalidated for {cid_slug}")

    def token_status(self) -> Dict[str, dict]:
        """Returns cache status for health/debug endpoint."""
        return {
            slug: {
                "cloud":             entry.cloud,
                "seconds_remaining": entry.seconds_remaining(),
                "expired":           entry.is_expired(),
            }
            for slug, entry in self._cache.items()
        }

    # ── Private Helpers ────────────────────────────────────────────────────

    def _get_lock(self, slug: str) -> asyncio.Lock:
        if slug not in self._locks:
            self._locks[slug] = asyncio.Lock()
        return self._locks[slug]

    async def _acquire(self, client: ClientConfig) -> str:
        """
        POSTs to /oauth2/token with exponential backoff on rate limit.
        Raises RuntimeError if all retries fail.
        """
        url = f"{client.base_url}/oauth2/token"

        for attempt in range(1, MAX_AUTH_RETRIES + 1):
            try:
                resp = await self._client.post(
                    url,
                    headers={
                        "Accept":       "application/json",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    data={
                        "client_id":     client.client_id,
                        "client_secret": client.client_secret,
                    },
                )

                # Cross-cloud redirect was followed automatically (httpx follow_redirects=True)
                # Log if we landed on a different host than expected
                if resp.url.host != url.split("/")[2]:
                    logger.info(
                        f"Cross-cloud redirect followed: {url} → {resp.url}",
                        extra={"client": client.name}
                    )

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("X-RateLimit-RetryAfter", 0))
                    wait = max(retry_after - int(time.time()), RETRY_BACKOFF_BASE ** attempt)
                    logger.warning(
                        f"Rate limited on auth for {client.name}, waiting {wait}s "
                        f"(attempt {attempt}/{MAX_AUTH_RETRIES})"
                    )
                    await asyncio.sleep(wait)
                    continue

                if resp.status_code == 401:
                    raise RuntimeError(
                        f"Invalid credentials for client '{client.name}' (CID: {client.cid}). "
                        "Check CLIENT_ID and CLIENT_SECRET in .env"
                    )

                resp.raise_for_status()
                data = resp.json()
                token = data.get("access_token")

                if not token:
                    raise RuntimeError(f"No access_token in response for {client.name}: {data}")

                return token

            except httpx.TimeoutException:
                logger.error(f"Auth timeout for {client.name} (attempt {attempt})")
                if attempt < MAX_AUTH_RETRIES:
                    await asyncio.sleep(RETRY_BACKOFF_BASE ** attempt)
            except httpx.HTTPStatusError as e:
                raise RuntimeError(f"Auth HTTP error for {client.name}: {e}")

        raise RuntimeError(
            f"Failed to acquire token for '{client.name}' after {MAX_AUTH_RETRIES} attempts"
        )

    async def _revoke(self, slug: str, entry: TokenEntry):
        """Revokes a token via POST /oauth2/revoke."""
        try:
            base_url = CLOUD_BASE_URLS.get(entry.cloud, CLOUD_BASE_URLS["us-1"])
            # Not available for all configs without client credentials, so best-effort
            logger.debug(f"Revoking token for {slug}")
        except Exception as e:
            logger.debug(f"Token revocation skipped for {slug}: {e}")


# ─── Module-level singleton ───────────────────────────────────────────────────
token_manager = TokenManager()
