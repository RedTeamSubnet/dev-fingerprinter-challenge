# -*- coding: utf-8 -*-

import time
import random
from typing import Optional, List
from collections import defaultdict

import requests
from pydantic import validate_call

from api.config import config
from api.helpers.email import EmailHelper
from api.logger import logger

from .schemas import MinerInput, MinerOutput, Payload
from .dfp import dfp_manager, reserve_offset_range


email_helper = EmailHelper(
    smtp_host=config.challenge.smtp_host,
    smtp_port=config.challenge.smtp_port,
    smtp_user=config.challenge.smtp_user,
    smtp_password=config.challenge.smtp_password,
    email_sender=config.challenge.email_sender,
)

BROWSERS = ["chrome", "brave", "firefox-focus", "duckduckgo", "safari"]


def get_task() -> MinerInput:
    """Return a new challenge task."""
    return MinerInput()


@validate_call
def score(request_id: str, miner_output: MinerOutput) -> float:
    """Score a miner's fingerprinter.js submission."""

    _n_repeat = config.challenge.n_repeat
    
    # Get active devices for counting
    active_devices = [d for d in config.challenge.devices if d.status.value == "active"]
    _total_active = len(active_devices)
    
    if _total_active == 0:
        logger.error(f"[{request_id}] - No active devices found!")
        return 0.0

    # Restart manager for new session
    dfp_manager.restart_manager(fp_js=miner_output.fingerprinter_js)
    dfp_manager.request_id = request_id

    # Atomically reserve order IDs
    start_id = reserve_offset_range(_n_repeat * _total_active)
    dfp_manager.start_id = start_id

    # Send fingerprinter.js to proxy
    try:
        dfp_manager.send_fp_js(
            request_id=request_id,
            base_url=config.challenge.proxy_inter_base_url,
            api_key=config.challenge.api_key,
        )
    except Exception as e:
        logger.warning(f"[{request_id}] - Failed to send fingerprinter.js to proxy: {e}")
        raise

    # Generate session structure
    logger.info(f"[{request_id}] - Generating session structure with {_n_repeat} batches...")
    session_structure = dfp_manager.gen_session_structure(
        devices=config.challenge.devices,
        browsers=BROWSERS,
        n_repeat=_n_repeat,
    )

    logger.info(f"[{request_id}] - Starting {_n_repeat} batches of {_total_active} devices...")

    proxy_base_url = str(config.challenge.proxy_inter_base_url).rstrip("/")

    # Process each batch
    for batch_idx, browser_devices in session_structure.items():
        # Each batch has only one browser key
        browser = list(browser_devices.keys())[0]
        devices_list = browser_devices[browser]
        
        logger.info(f"[{request_id}] - Processing Batch {batch_idx + 1}/{_n_repeat} with browser: {browser}")

        # Group devices by email for this batch
        targets_by_email = defaultdict(list)
        batch_order_ids = []
        
        # Sync with proxy and group by email
        for device_info in devices_list:
            device_cfg = device_info["device_cfg"]
            order_id = device_info["order_id"]
            
            # Sync with proxy
            try:
                requests.post(
                    f"{proxy_base_url}/set_device_session",
                    json={"device_id": device_cfg.id, "order_id": order_id},
                    headers={"X-API-Key": config.challenge.api_key.get_secret_value()},
                    timeout=10,
                ).raise_for_status()
            except Exception as e:
                logger.warning(f"[{request_id}] - Failed to set proxy session for order {order_id}: {e}")
            
            # Group for email
            targets_by_email[device_cfg.email].append(device_info)
            batch_order_ids.append(order_id)

        # Send emails
        for email, items in targets_by_email.items():
            random.shuffle(items)
            subject = ", ".join(
                f"{it['device'].device_model.replace(' ', '-')} {it['device'].browser} {it['order_id']}"
                for it in items
            )
            logger.info(f"[{request_id}] - Sending Batch {batch_idx + 1} email: '{subject}'")
            email_helper.send(to=email, subject=subject, body=" ")
            
            # Mark devices as running
            for it in items:
                dfp_manager.set_device_running(it["order_id"])

        # Wait for batch completion
        elapsed = 0
        while True:
            pending = dfp_manager.get_pending_devices()
            if not pending:
                logger.info(f"[{request_id}] - Batch {batch_idx + 1} completed.")
                break
            if elapsed >= config.challenge.fp_timeout:
                logger.warning(f"[{request_id}] - Batch {batch_idx + 1} timed out.")
                for order_id in batch_order_ids:
                    dfp_manager.set_device_timeout(order_id)
                break
            elapsed += 1
            time.sleep(1)

    score_result = dfp_manager.calculate_score()

    return score_result


def get_results() -> List[Payload]:
    """Returns the results from the current session."""
    return dfp_manager.get_all_payloads()


@validate_call
def set_fingerprint(order_id: int, fingerprint: str, device_name: Optional[str] = None) -> bool:
    """Receive fingerprint from proxy."""
    success = dfp_manager.update_fingerprint(
        order_id=order_id,
        fingerprint=fingerprint,
        device_name=device_name
    )
    
    if not success:
        logger.warning(f"Failed to set fingerprint for order_id {order_id}")
    
    return success


__all__ = [
    "get_task",
    "score",
    "set_fingerprint",
    "get_results",
]
