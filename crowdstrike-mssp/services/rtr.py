"""
services/rtr.py — RTR Host Investigation via FalconPy

Uses FalconPy RealTimeResponse service class.
All blocking SDK calls are wrapped in asyncio.run_in_executor via arun().
"""

import logging
from typing import Dict, Any

from config import ClientConfig
from services.falcon_client import FalconRTR

logger = logging.getLogger("falconguard.rtr")

READ_COMMANDS = [
    ("ps",       "ps"),
    ("netstat",  "netstat"),
    ("ls",       "ls C:\\Windows\\Temp"),
    ("reg",      "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ("schtasks", "schtasks /query /fo LIST /v"),
]


async def investigate_host(cfg: ClientConfig, device_id: str) -> Dict[str, Any]:
    """
    Opens an RTR session to device_id and runs the standard read-only
    investigation playbook: ps, netstat, ls, reg query, schtasks.

    Returns dict of {command_name: output_string}.
    """
    results: Dict[str, str] = {}
    rtr = FalconRTR(cfg)

    try:
        await rtr.open_session(device_id)
        logger.info(f"RTR session {rtr.session_id} opened on {device_id}")

        for base_cmd, full_cmd in READ_COMMANDS:
            try:
                output = await rtr.run_command(base_cmd, full_cmd)
                results[base_cmd] = output[:4000]
                logger.debug(f"RTR {base_cmd}: {len(output)} chars")
            except Exception as e:
                logger.error(f"RTR command '{base_cmd}' failed: {e}")
                results[base_cmd] = f"[Failed: {e}]"

    except Exception as e:
        logger.error(f"RTR investigation failed for {device_id}: {e}")
        results["error"] = str(e)
    finally:
        await rtr.close_session()

    return results


async def get_host_processes(cfg: ClientConfig, device_id: str) -> str:
    """Lightweight single-command: just running processes."""
    rtr = FalconRTR(cfg)
    try:
        await rtr.open_session(device_id)
        return await rtr.run_command("ps", "ps")
    except Exception as e:
        return f"[RTR error: {e}]"
    finally:
        await rtr.close_session()
