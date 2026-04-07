import os
import subprocess
import tempfile

import requests
from typing import List

from api.config import config
from api.logger import logger
from .schemas import MinerOutput


def sync_device_with_proxy(
    request_id: str, proxy_base_url: str, browser_devices: List[dict]
):
    for device_info in browser_devices:
        device_cfg = device_info["device_cfg"]
        order_id = device_info["order_id"]
        try:
            requests.post(
                f"{proxy_base_url}/set_device_session",
                json={"device_id": device_cfg.id, "order_id": order_id},
                headers={"X-API-Key": config.challenge.api_key.get_secret_value()},
                timeout=10,
            ).raise_for_status()
        except Exception as e:
            logger.warning(
                f"[{request_id}] - Failed to set proxy session for order {order_id}: {e}"
            )

def get_total_file_size(miner_output: MinerOutput) -> int:
    total_size = 0
    with tempfile.TemporaryDirectory() as tmp_dir:
        file_path = os.path.join(tmp_dir, "fingerprinter.js")
        with open(file_path, "w") as f:
            f.write(miner_output.fingerprinter_js)
        total_size += os.path.getsize(file_path)
    return total_size


def get_network_stats() -> dict:
    result = subprocess.run(
        ["sudo", "nsenter", "-t", "1", "-n", "cat", "/proc/net/dev"],
        capture_output=True,
        text=True,
    )
    logger.info(result.stdout)
    for line in result.stdout.splitlines():
        if "eth0" in line:
            parts = line.split()
            return {
                "interface": "eth0",
                "network_rx_bytes": int(parts[1]),
                "network_tx_bytes": int(parts[9]),
                "unit": "bytes",
            }
    return {"interface": "eth0", "network_rx_bytes": 0, "network_tx_bytes": 0, "unit": "bytes"}
