# -*- coding: utf-8 -*-

import os
import time
import random
from typing import Optional, List
from collections import defaultdict

from pydantic import validate_call
from api.core.configs.challenge import DeviceStateEnum
from api.core.services import utils as utils_services
from api.config import config
from api.helpers.tailscale import Tailscale
from api.helpers.email import EmailHelper
from api.logger import logger

from .schemas import MinerInput, MinerOutput
from .dfp import DFPManager
from .payload import PayloadManager, Payload


tailscale = Tailscale(
    api_token=config.challenge.ts_api_token, tailnet=config.challenge.ts_tailnet
)

email_helper = EmailHelper(
    smtp_host=config.challenge.smtp_host,
    smtp_port=config.challenge.smtp_port,
    smtp_user=config.challenge.smtp_user,
    smtp_password=config.challenge.smtp_password,
    email_sender=config.challenge.email_sender,
)

dfp_manager: DFPManager
payload_manager = PayloadManager()

# Path to persist the global order offset
OFFSET_FILE = os.path.join("/var/lib/rest.dfp-challenger", "order_offset.txt")

def _get_global_offset() -> int:
    try:
        if os.path.exists(OFFSET_FILE):
            with open(OFFSET_FILE, "r") as f:
                return int(f.read().strip())
    except Exception as e:
        logger.error(f"Failed to read offset file: {e}")
    return 0

def _set_global_offset(val: int):
    try:
        os.makedirs(os.path.dirname(OFFSET_FILE), exist_ok=True)
        with open(OFFSET_FILE, "w") as f:
            f.write(str(val))
    except Exception as e:
        logger.error(f"Failed to write offset file: {e}")


def get_task() -> MinerInput:
    """Return a new challenge task."""
    return MinerInput()


@validate_call
def score(request_id: str, miner_output: MinerOutput) -> float:

    global dfp_manager, payload_manager
    _score = 0.0

    # Load current offset
    start_id = _get_global_offset()

    # Removed ESLint check here
    dfp_manager = DFPManager(fp_js=miner_output.fingerprinter_js)
    payload_manager.clear()
    
    # Store starting ID in manager for session mapping
    dfp_manager.start_id = start_id
    # Initialize dynamic session map
    dfp_manager.session_map = {}
    
    try:
        dfp_manager.send_fp_js(
            request_id=request_id,
            base_url=config.challenge.proxy_inter_base_url,
            api_key=config.challenge.api_key,
        )
    except Exception as e:
        logger.warning(f"[{request_id}] - Failed to send fingerprinter.js to proxy (ignoring): {e}")

    dfp_manager.generate_targets(
        devices=config.challenge.devices,
        n_repeat=1,
        random_seed=config.challenge.random_seed,
    )

    # 1. Group targets by email and prepare URLs
    targets_by_email = defaultdict(list)
    all_active_devices = []
    
    # Available browsers to randomize
    BROWSERS = ["chrome", "brave", "firefox-focus", "duckduckgo", "safari"]

    # Consistency map: device_id -> assigned_browser
    device_browser_map = {}

    for _i, _target_device in enumerate(dfp_manager.target_devices):
        # Ensure consistent browser per device ID for this run
        dev_id = _target_device.id
        if dev_id not in device_browser_map:
            device_browser_map[dev_id] = random.choice(BROWSERS)
            
        _target_device.browser = device_browser_map[dev_id]

        _web_endpoint = "/_web"
        _web_base_url = str(config.challenge.proxy_exter_base_url).rstrip("/")
        
        # Calculate dynamic sequential ID
        _dynamic_id = start_id + _i
        _web_url = f"{_web_base_url}{_web_endpoint}?order_id={_dynamic_id}"
        
        # Save mapping: Dynamic ID -> Index in target list
        dfp_manager.session_map[_dynamic_id] = _i

        # Create Payload in PayloadManager
        payload_manager.create_payload(
            order_id=_dynamic_id,
            device_id=dev_id,
            device_name=_target_device.device_model or "Unknown"
        )

        # Set session in proxy
        try:
            import requests
            proxy_url = str(config.challenge.proxy_inter_base_url).rstrip("/")
            requests.post(
                f"{proxy_url}/set_device_session",
                json={"device_id": dev_id, "order_id": _dynamic_id},
                headers={"X-API-Key": config.challenge.api_key.get_secret_value()},
                timeout=5
            )
        except Exception as e:
            logger.warning(f"[{request_id}] - Failed to set session in proxy for device {dev_id}: {e}")

        # Prepare item for batching
        targets_by_email[_target_device.email].append({
            "device": _target_device,
            "url": _web_url,
            "index": _dynamic_id
        })
        all_active_devices.append(_target_device)

    # 2. Send batched emails
    for email, items in targets_by_email.items():
        # Shuffle items to ensure random order in email
        random.shuffle(items)
        
        # Format: device_model-with-hyphens browser UNIQUE_ID
        # Example: "iphone-se.1 chrome 122"
        subjects = [f"{item['device'].device_model.replace(' ', '-')} {item['device'].browser} {item['index']}" for item in items]
        combined_subject = ", ".join(subjects)
        
        # Body is now just a single space to avoid spam filters but keep content hidden
        combined_body = " "

        logger.info(f"[{request_id}] - Sending batched email with subject: '{combined_subject}'")
        
        success = email_helper.send(
            to=email,
            subject=combined_subject,
            body=combined_body
        )

        if success:
            for item in items:
                item['device'].state = DeviceStateEnum.RUNNING
                logger.info(
                    f"[{request_id}] - Triggered device {{'id': {item['device'].id}}} (Order: {item['index']}) via email batch."
                )
        else:
            for item in items:
                item['device'].state = DeviceStateEnum.ERROR
                logger.error(
                     f"[{request_id}] - Could not send email batch for device {{'id': {item['device'].id}}}."
                )

    # Increment global offset by number of devices used and save to file
    _set_global_offset(start_id + len(dfp_manager.target_devices))

    # 3. Wait for all devices to complete or timeout
    _t = 0
    while True:
        pending_devices = [d for d in all_active_devices if d.state == DeviceStateEnum.RUNNING]
        
        if not pending_devices:
            logger.info(f"[{request_id}] - All devices finished processing (Completed, Timeout, or Error).")
            break

        if config.challenge.fp_timeout <= _t:
            logger.warning(
                f"[{request_id}] - Timeout reached ({config.challenge.fp_timeout}s). Marking {len(pending_devices)} pending devices as TIMEOUT."
            )
            for d in pending_devices:
                d.state = DeviceStateEnum.TIMEOUT
            break

        _t += 1
        time.sleep(1)

    _score = dfp_manager.score(payloads=payload_manager.get_all_payloads())
    return _score


def get_results() -> List[Payload]:
    """Returns the results (payloads) of the last run."""
    global payload_manager
    return payload_manager.get_all_payloads()


@validate_call
def set_fingerprint(order_id: int, fingerprint: str, device_name: Optional[str] = None) -> None:

    global dfp_manager, payload_manager

    if not dfp_manager:
        raise RuntimeError(
            "'dfp_manager' is not initialized, please run '/score' endpoint first!"
        )

    # Update payload in PayloadManager
    payload_manager.update_fingerprint(order_id, fingerprint.strip(), device_name)

    # Map the dynamic ID back to the local index using the session map
    if order_id not in dfp_manager.session_map:
        logger.warning(f"Received fingerprint for old or invalid Order ID {order_id}. Ignoring.")
        return

    _local_index = dfp_manager.session_map[order_id]
    _target_device = dfp_manager.target_devices[_local_index]

    if _target_device.state == DeviceStateEnum.COMPLETED:
        return

    # We only update state to signal completion to the wait loop
    _target_device.state = DeviceStateEnum.COMPLETED

    return


__all__ = [
    "get_task",
    "score",
    "set_fingerprint",
]