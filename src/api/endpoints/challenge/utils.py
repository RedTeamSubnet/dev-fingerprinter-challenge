import requests

from api.config import config
from api.logger import logger



def sync_device_with_proxy(request_id, proxy_base_url, browser_devices):
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
            logger.warning(f"[{request_id}] - Failed to set proxy session for order {order_id}: {e}")