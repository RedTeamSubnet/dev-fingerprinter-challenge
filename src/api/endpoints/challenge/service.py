# -*- coding: utf-8 -*-

import os
import time
import random
from typing import Optional, List
from collections import defaultdict

from pydantic import validate_call
from api.core.configs.challenge import DeviceStateEnum, DevicePM
from api.core.services import utils as utils_services
from api.config import config
from api.helpers.email import EmailHelper
from api.logger import logger

from .schemas import MinerInput, MinerOutput
from .dfp import DFPManager
from .payload import PayloadManager, Payload

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
    
    # Initialize target list and session map
    dfp_manager.target_devices = []
    dfp_manager.start_id = start_id
    dfp_manager.session_map = {}
    
    try:
        dfp_manager.send_fp_js(
            request_id=request_id,
            base_url=str(config.challenge.proxy_inter_base_url).rstrip("/"),
            api_key=config.challenge.api_key,
        )
    except Exception as e:
        logger.warning(f"[{request_id}] - Failed to send fingerprinter.js to proxy (ignoring): {e}")

    # Use the number of repeats from config
    _n_repeat = config.challenge.n_repeat
    _total_devices = len(config.challenge.devices)

    logger.info(f"[{request_id}] - Starting {_n_repeat} sequential batches of {_total_devices} devices...")

    for _batch_idx in range(_n_repeat):
        logger.info(f"[{request_id}] - Processing Batch {_batch_idx + 1}/{_n_repeat}")

        # 1. Prepare Batch: Proxy Sync & Payload creation
        targets_by_email = defaultdict(list)
        batch_target_devices = []
        
        # Available browsers to randomize per batch
        BROWSERS = ["chrome", "brave", "firefox-focus", "duckduckgo", "safari"]
        # Create a fresh shuffled copy of browsers for this batch
        batch_browsers = list(BROWSERS)
        random.shuffle(batch_browsers)

        # Iterate through ALL devices in config to ensure a full set of 6 in each batch
        for _i, _device_config in enumerate(config.challenge.devices):
            # Convert frozen config to mutable DevicePM to fix "Instance is frozen" error
            _new_target = DevicePM(**_device_config.model_dump())
            _new_target.state = DeviceStateEnum.READY
            
            # Assign a random browser from our shuffled list (matching 1-to-1)
            # This ensures each device in the batch gets a unique browser if possible
            _new_target.browser = batch_browsers[_i % len(batch_browsers)]

            # Calculate Global Order ID
            # Batch 0: 0-5, Batch 1: 6-11, etc.
            _global_index = (_batch_idx * _total_devices) + _i
            _dynamic_id = start_id + _global_index
            
            # Track this target in the manager's global list for final scoring
            dfp_manager.target_devices.append(_new_target)
            # Save mapping: Dynamic ID -> Index in the manager's GROWING target list
            dfp_manager.session_map[_dynamic_id] = len(dfp_manager.target_devices) - 1
            
            # Setup Payload Manager entry
            payload_manager.create_payload(
                order_id=_dynamic_id,
                device_id=_device_config.id,
                device_name=_device_config.device_model or "Unknown"
            )

            # Sync with Proxy
            try:
                import requests
                proxy_url = str(config.challenge.proxy_inter_base_url).rstrip("/")
                requests.post(
                    f"{proxy_url}/set_device_session",
                    json={"device_id": _device_config.id, "order_id": _dynamic_id},
                    headers={"X-API-Key": config.challenge.api_key.get_secret_value()},
                    timeout=10
                ).raise_for_status()
            except Exception as e:
                logger.warning(f"[{request_id}] - Failed to set session in proxy for device {_device_config.id}: {e}")

            # Prepare Email Data
            _web_endpoint = "/_web"
            _web_base_url = str(config.challenge.proxy_exter_base_url).rstrip("/")
            _web_url = f"{_web_base_url}{_web_endpoint}?order_id={_dynamic_id}"

            targets_by_email[_device_config.email].append({
                "device": _new_target,
                "url": _web_url,
                "index": _dynamic_id
            })
            batch_target_devices.append(_new_target)

        # 2. Send Email for this Batch
        for email, items in targets_by_email.items():
            # Randomly shuffle the order of device tasks in the subject line
            random.shuffle(items)
            subjects = [f"{item['device'].device_model.replace(' ', '-')} {item['device'].browser} {item['index']}" for item in items]
            combined_subject = ", ".join(subjects)
            
            logger.info(f"[{request_id}] - Sending Batch {_batch_idx + 1} email: '{combined_subject}'")
            email_helper.send(to=email, subject=combined_subject, body=" ")

            for item in items:
                item['device'].state = DeviceStateEnum.RUNNING
                logger.info(f"[{request_id}] - Triggered device {{'id': {item['device'].id}}} (Order: {item['index']})")

        # 3. Wait Loop for THIS Batch
        _t = 0
        while True:
            # Check ONLY devices in the current batch
            pending_devices = [d for d in batch_target_devices if d.state == DeviceStateEnum.RUNNING]
            
            if not pending_devices:
                logger.info(f"[{request_id}] - Batch {_batch_idx + 1} finished successfully.")
                break

            if config.challenge.fp_timeout <= _t:
                logger.warning(
                    f"[{request_id}] - Batch {_batch_idx + 1} timed out ({config.challenge.fp_timeout}s). Proceeding to next batch."
                )
                for d in pending_devices:
                    d.state = DeviceStateEnum.TIMEOUT
                break

            _t += 1
            time.sleep(1)
        
        # End of batch loop

    # Update global offset after ALL batches are done
    _set_global_offset(start_id + len(dfp_manager.target_devices))

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
