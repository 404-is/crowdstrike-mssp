"""
services/rtr.py — Real Time Response (RTR) Host Investigation

Connects to live hosts via CrowdStrike RTR to pull:
  - Running processes (ps)
  - Active network connections (netstat)
  - Recent event log entries
  - Scheduled tasks
  - Auto-run entries

Flow per CrowdStrike docs:
  1. POST /real-time-response/entities/sessions/v1       → open session
  2. POST /real-time-response/entities/command/v1        → issue command
  3. GET  /real-time-response/entities/command/v1        → poll result (cloud_request_id)
  4. DELETE /real-time-response/entities/sessions/v1     → close session (always)
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any

from services.crowdstrike import CrowdStrikeClient
from config import ClientConfig

logger = logging.getLogger("falconguard.rtr")

POLL_INTERVAL = 2       # seconds between result polls
MAX_POLLS     = 15      # max attempts before timeout
SESSION_TIMEOUT = 30    # seconds


class RTRSession:
    """Manages a single RTR session lifecycle for one host."""

    def __init__(self, cs: CrowdStrikeClient, device_id: str):
        self.cs        = cs
        self.device_id = device_id
        self.session_id: Optional[str] = None

    async def __aenter__(self):
        await self._open()
        return self

    async def __aexit__(self, *args):
        await self._close()

    async def _open(self):
        """Opens an RTR session to the host."""
        resp = await self.cs.post(
            "/real-time-response/entities/sessions/v1",
            json={
                "device_id": self.device_id,
                "origin":    "falconguard-mssp",
                "queue_offline": False,
            }
        )
        errors = resp.get("errors", [])
        if errors:
            raise RuntimeError(f"RTR session open failed: {errors}")

        resources = resp.get("resources", [])
        if not resources:
            raise RuntimeError("RTR session open returned no session ID")

        self.session_id = resources[0].get("session_id")
        logger.info(f"RTR session opened: {self.session_id} → {self.device_id}")

    async def _close(self):
        """Always close the RTR session to free the host connection."""
        if not self.session_id:
            return
        try:
            await self.cs.delete(
                "/real-time-response/entities/sessions/v1",
                params={"session_id": self.session_id}
            )
            logger.info(f"RTR session closed: {self.session_id}")
        except Exception as e:
            logger.warning(f"RTR session close failed (non-critical): {e}")

    async def run_command(self, base_command: str, command_string: str = "") -> str:
        """
        Issues an RTR read-only command and polls for the result.
        base_command: e.g. 'ps', 'netstat', 'ls', 'reg query'
        command_string: optional arguments
        Returns the command output as a string.
        """
        if not self.session_id:
            raise RuntimeError("RTR session not open")

        # Issue command
        cmd_resp = await self.cs.post(
            "/real-time-response/entities/command/v1",
            json={
                "base_command":    base_command,
                "command_string":  command_string or base_command,
                "session_id":      self.session_id,
                "persist":         False,
            }
        )
        errors = cmd_resp.get("errors", [])
        if errors:
            logger.warning(f"RTR command '{base_command}' error: {errors}")
            return f"[Command error: {errors}]"

        resources = cmd_resp.get("resources", [])
        if not resources:
            return "[No response resources]"

        cloud_request_id = resources[0].get("cloud_request_id")
        if not cloud_request_id:
            return "[No cloud_request_id]"

        # Poll for result
        for attempt in range(MAX_POLLS):
            await asyncio.sleep(POLL_INTERVAL)
            result_resp = await self.cs.get(
                "/real-time-response/entities/command/v1",
                params={
                    "cloud_request_id": cloud_request_id,
                    "sequence_id":      0,
                }
            )
            result_resources = result_resp.get("resources", [])
            if result_resources:
                r = result_resources[0]
                if r.get("complete"):
                    stdout = r.get("stdout", "")
                    stderr = r.get("stderr", "")
                    if stderr:
                        logger.warning(f"RTR stderr for '{base_command}': {stderr}")
                    return stdout or stderr or "[empty output]"

            errors = result_resp.get("errors", [])
            if errors:
                return f"[Poll error: {errors}]"

        return f"[Timeout waiting for '{base_command}' result after {MAX_POLLS} polls]"


async def investigate_host(cfg: ClientConfig, device_id: str) -> Dict[str, Any]:
    """
    Opens an RTR session and runs a standard investigation playbook:
      - Process list
      - Network connections
      - Scheduled tasks (Windows)
      - Auto-run registry keys (Windows)

    Returns a dict of {command: output} for each command.
    Safe — uses read-only RTR commands only.
    """
    results: Dict[str, str] = {}
    cs = CrowdStrikeClient(cfg)

    try:
        async with RTRSession(cs, device_id) as session:
            # Run all investigation commands
            commands = [
                ("ps",      "ps"),
                ("netstat", "netstat"),
                ("ls",      "ls C:\\Windows\\Temp"),
                ("reg",     "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
                ("schtasks","schtasks /query /fo LIST /v"),
            ]

            for base_cmd, full_cmd in commands:
                try:
                    output = await session.run_command(base_cmd, full_cmd)
                    results[base_cmd] = output[:4000]  # truncate for LLM context
                except Exception as e:
                    logger.error(f"RTR command '{base_cmd}' failed: {e}")
                    results[base_cmd] = f"[Failed: {e}]"

    except Exception as e:
        logger.error(f"RTR investigation failed for {device_id}: {e}")
        results["error"] = str(e)
    finally:
        await cs.close()

    return results


async def get_host_processes(cfg: ClientConfig, device_id: str) -> str:
    """Lightweight — just pulls running processes."""
    cs = CrowdStrikeClient(cfg)
    try:
        async with RTRSession(cs, device_id) as session:
            return await session.run_command("ps", "ps")
    finally:
        await cs.close()
