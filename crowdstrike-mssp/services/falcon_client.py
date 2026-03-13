"""
services/falcon_client.py — FalconPy Service Class Factory

Single responsibility: create configured FalconPy service class instances
and wrap their synchronous calls into async-compatible coroutines.

Why a factory?
  - FalconPy service classes are synchronous (blocking HTTP).
  - FastAPI is async. Running blocking code directly in an async handler
    would block the event loop thread.
  - Solution: run each SDK call in a ThreadPoolExecutor so asyncio can
    schedule other coroutines while waiting on the network.

Usage:
    from services.falcon_client import falcon_svc, arun

    async def my_handler(cfg: ClientConfig):
        alerts = falcon_svc(Alerts, cfg)
        response = await arun(alerts.query_alerts_v2, filter=fql, limit=200)
        ids = response["body"]["resources"]
"""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any, Callable, Type, TypeVar

from falconpy import (
    Alerts,
    Hosts,
    IOC,
    RealTimeResponse,
    RealTimeResponseAdmin,
    OAuth2,
    SpotlightVulnerabilities,
)

from config import ClientConfig, CLOUD_BASE_URLS

logger = logging.getLogger("falconguard.falcon_client")

# Thread pool for FalconPy blocking calls
# max_workers = 20 supports ~4 simultaneous tenants × 5 parallel service calls each
_EXECUTOR = ThreadPoolExecutor(max_workers=20, thread_name_prefix="falconpy")

T = TypeVar("T")


def falcon_svc(service_class: Type[T], cfg: ClientConfig, **kwargs) -> T:
    """
    Instantiate a FalconPy service class for the given client.

    FalconPy handles:
      - OAuth2 token acquisition (POST /oauth2/token)
      - Token caching and refresh (tokens valid 30 min, refreshed at ~25 min)
      - Cross-cloud 308 redirects
      - Rate-limit response parsing

    Args:
        service_class: Any FalconPy service class (Alerts, Hosts, etc.)
        cfg:           ClientConfig for this tenant
        **kwargs:      Extra kwargs forwarded to service class constructor

    Returns:
        Configured service class instance ready to call
    """
    return service_class(
        client_id=     cfg.client_id,
        client_secret= cfg.client_secret,
        base_url=      cfg.base_url,
        **kwargs,
    )


async def arun(func: Callable, *args, **kwargs) -> dict:
    """
    Run a synchronous FalconPy method in the thread pool executor.

    Converts the blocking SDK call into an awaitable coroutine.
    Logs a warning if the response contains errors.

    Returns the full FalconPy response dict:
        {
            "status_code": 200,
            "body": {
                "resources": [...],
                "errors":    [...],
                "meta":      {...}
            },
            "headers": {...}
        }
    """
    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(_EXECUTOR, partial(func, *args, **kwargs))

    # Log API-level errors (not HTTP errors — FalconPy absorbs those into body)
    errors = response.get("body", {}).get("errors") or []
    if errors:
        logger.warning(
            f"{func.__self__.__class__.__name__}.{func.__name__} "
            f"returned errors: {errors}"
        )

    return response


def ok(response: dict) -> bool:
    """Returns True if the FalconPy response status code indicates success."""
    return response.get("status_code", 0) in (200, 201, 202, 204)


def resources(response: dict) -> list:
    """Safely extract resources list from a FalconPy response."""
    return response.get("body", {}).get("resources") or []


def errors(response: dict) -> list:
    """Safely extract errors list from a FalconPy response."""
    return response.get("body", {}).get("errors") or []


def total(response: dict) -> int:
    """Safely extract pagination total from a FalconPy response."""
    return (response.get("body", {})
                    .get("meta", {})
                    .get("pagination", {})
                    .get("total", 0))


# ── Convenience async wrappers for the most-used service classes ─────────────

class FalconAlerts:
    """Thin async wrapper around FalconPy Alerts service class."""

    def __init__(self, cfg: ClientConfig):
        self._svc = falcon_svc(Alerts, cfg)

    async def query(self, fql: str, limit: int = 200,
                    sort: str = "updated_timestamp|desc",
                    offset: int = 0) -> dict:
        """GET /alerts/queries/alerts/v2"""
        return await arun(
            self._svc.query_alerts_v2,
            filter=fql, limit=limit, sort=sort, offset=offset,
        )

    async def get(self, composite_ids: list) -> dict:
        """POST /alerts/entities/alerts/v2"""
        return await arun(
            self._svc.get_alerts_v2,
            composite_ids=composite_ids,
        )

    async def update(self, composite_ids: list, action_parameters: list) -> dict:
        """PATCH /alerts/entities/alerts/v3"""
        return await arun(
            self._svc.update_alerts_v3,
            composite_ids=composite_ids,
            action_parameters=action_parameters,
        )

    async def query_and_get(self, fql: str, limit: int = 200,
                            sort: str = "updated_timestamp|desc") -> tuple:
        """
        Two-step: query IDs then fetch full entities.
        Returns (raw_alerts_list, errors_list, total_count)
        """
        q = await self.query(fql, limit=limit, sort=sort)
        ids   = resources(q)
        count = total(q)
        errs  = errors(q)

        if not ids:
            return [], errs, count

        e = await self.get(ids)
        errs += errors(e)
        return resources(e), errs, count


class FalconHosts:
    """Thin async wrapper around FalconPy Hosts service class."""

    def __init__(self, cfg: ClientConfig):
        self._svc = falcon_svc(Hosts, cfg)

    async def query(self, fql: str = "", limit: int = 100,
                    sort: str = "last_seen|desc", offset: int = 0) -> dict:
        """GET /devices/queries/devices/v1"""
        return await arun(
            self._svc.query_devices_by_filter,
            filter=fql, limit=limit, sort=sort, offset=offset,
        )

    async def get(self, ids: list) -> dict:
        """GET /devices/entities/devices/v2"""
        return await arun(self._svc.get_device_details, ids=ids)

    async def query_and_get(self, fql: str = "", limit: int = 100) -> tuple:
        q    = await self.query(fql, limit=limit)
        ids  = resources(q)
        errs = errors(q)
        if not ids:
            return [], errs, total(q)
        e    = await self.get(ids)
        errs += errors(e)
        return resources(e), errs, total(q)

    async def action(self, device_ids: list, action: str = "contain") -> dict:
        """POST /devices/entities/devices/actions/v2"""
        return await arun(
            self._svc.perform_action,
            action_name=action,
            ids=device_ids,
            body={},
        )


class FalconIOC:
    """Thin async wrapper around FalconPy IOCManagement service class."""

    def __init__(self, cfg: ClientConfig):
        self._svc = falcon_svc(IOC, cfg)

    async def search(self, fql: str = "", limit: int = 100) -> dict:
        """GET /iocs/queries/indicators/v1"""
        return await arun(
            self._svc.indicator_search_v1,
            filter=fql, limit=limit,
        )

    async def get(self, ids: list) -> dict:
        """GET /iocs/entities/indicators/v1"""
        return await arun(self._svc.indicator_get_v1, ids=ids)

    async def search_and_get(self, fql: str = "", limit: int = 100) -> tuple:
        q    = await self.search(fql, limit=limit)
        ids  = resources(q)
        errs = errors(q)
        if not ids:
            return [], errs, total(q)
        e    = await self.get(ids)
        errs += errors(e)
        return resources(e), errs, total(q)


class FalconRTR:
    """Async wrapper for RTR session lifecycle using FalconPy."""

    def __init__(self, cfg: ClientConfig):
        self._rtr   = falcon_svc(RealTimeResponse, cfg)
        self._admin = falcon_svc(RealTimeResponseAdmin, cfg)
        self.session_id: str | None = None
        self.device_id: str = ""

    async def open_session(self, device_id: str) -> str:
        """POST /real-time-response/entities/sessions/v1"""
        self.device_id = device_id
        resp = await arun(
            self._rtr.init_session,
            device_id=device_id,
            origin="falconguard-mssp",
            queue_offline=False,
        )
        rsrc = resources(resp)
        if not rsrc:
            raise RuntimeError(f"RTR session open failed: {errors(resp)}")
        self.session_id = rsrc[0]["session_id"]
        return self.session_id

    async def close_session(self):
        """DELETE /real-time-response/entities/sessions/v1"""
        if not self.session_id:
            return
        try:
            await arun(self._rtr.delete_session, session_id=self.session_id)
        except Exception as e:
            logger.warning(f"RTR close session warning (non-fatal): {e}")

    async def run_command(self, base_command: str,
                          command_string: str = "",
                          poll_interval: float = 2.0,
                          max_polls: int = 15) -> str:
        """
        Execute an RTR read-only command and poll for result.
        Uses RealTimeResponse.execute_command (read-only analyst role).
        """
        if not self.session_id:
            raise RuntimeError("RTR session not open — call open_session() first")

        cmd_resp = await arun(
            self._rtr.execute_command,
            base_command=base_command,
            command_string=command_string or base_command,
            session_id=self.session_id,
            persist_id=0,
        )
        rsrc = resources(cmd_resp)
        if not rsrc:
            return f"[Command '{base_command}' returned no response: {errors(cmd_resp)}]"

        cloud_request_id = rsrc[0].get("cloud_request_id")
        if not cloud_request_id:
            return "[No cloud_request_id in response]"

        # Poll for completion
        for _ in range(max_polls):
            await asyncio.sleep(poll_interval)
            poll = await arun(
                self._rtr.check_command_status,
                cloud_request_id=cloud_request_id,
                sequence_id=0,
            )
            pr = resources(poll)
            if pr and pr[0].get("complete"):
                stdout = pr[0].get("stdout", "")
                stderr = pr[0].get("stderr", "")
                if stderr:
                    logger.warning(f"RTR stderr [{base_command}]: {stderr[:200]}")
                return stdout or stderr or "[empty output]"

            poll_errs = errors(poll)
            if poll_errs:
                return f"[Poll error: {poll_errs}]"

        return f"[Timeout: '{base_command}' did not complete in {max_polls} polls]"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close_session()
