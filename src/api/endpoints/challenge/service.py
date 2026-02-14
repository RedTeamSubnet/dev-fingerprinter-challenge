# -*- coding: utf-8 -*-

import time
import random
from typing import Optional, List
from collections import defaultdict

import requests
from pydantic import validate_call

from api.core.configs.challenge import DeviceStateEnum, DevicePM
from api.config import config
from api.helpers.email import EmailHelper
from api.logger import logger

from .schemas import MinerInput, MinerOutput, Payload
from .dfp import (
    DFPManager,
    reserve_offset_range,
    start_new_session,
    get_active_manager,
    complete_session,
    get_last_results,
    update_fingerprint as dfp_update_fingerprint,
)


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
    _total_devices = len(config.challenge.devices)

    # Start new session (clears any previous state)
    manager = start_new_session(
        fp_js=miner_output.fingerprinter_js,
        request_id=request_id
    )

    # Atomically reserve order IDs
    start_id = reserve_offset_range(_n_repeat * _total_devices)
    manager.start_id = start_id

    # Send fingerprinter.js to proxy
    try:
        manager.send_fp_js(
            request_id=request_id,
            base_url=config.challenge.proxy_inter_base_url,
            api_key=config.challenge.api_key,
        )
    except Exception as e:
        logger.warning(f"[{request_id}] - Failed to send fingerprinter.js to proxy: {e}")
        raise

    logger.info(f"[{request_id}] - Starting {_n_repeat} batches of {_total_devices} devices...")

    for batch_idx in range(_n_repeat):
        logger.info(f"[{request_id}] - Processing Batch {batch_idx + 1}/{_n_repeat}")

        targets_by_email = defaultdict(list)
        batch_devices = []
        batch_browsers = random.sample(BROWSERS, len(BROWSERS))

        for i, device_cfg in enumerate(config.challenge.devices):
            order_id = start_id + (batch_idx * _total_devices) + i
            browser = batch_browsers[i % len(batch_browsers)]

            manager.add_device(
                order_id=order_id,
                device_cfg=device_cfg,
                browser=browser
            )

            # Sync with proxy
            try:
                proxy_url = str(config.challenge.proxy_inter_base_url).rstrip("/")
                requests.post(
                    f"{proxy_url}/set_device_session",
                    json={"device_id": device_cfg.id, "order_id": order_id},
                    headers={"X-API-Key": config.challenge.api_key.get_secret_value()},
                    timeout=10,
                ).raise_for_status()
            except Exception as e:
                logger.warning(f"[{request_id}] - Failed to set proxy session: {e}")

            web_url = f"{str(config.challenge.proxy_exter_base_url).rstrip('/')}/_web?order_id={order_id}"
            targets_by_email[device_cfg.email].append({
                "device": manager.target_devices[-1],
                "url": web_url,
                "index": order_id,
            })
            batch_devices.append(order_id)

        # Send emails
        for email, items in targets_by_email.items():
            random.shuffle(items)
            subject = ", ".join(
                f"{it['device'].device_model.replace(' ', '-')} {it['device'].browser} {it['index']}"
                for it in items
            )
            logger.info(f"[{request_id}] - Sending Batch {batch_idx + 1} email: '{subject}'")
            email_helper.send(to=email, subject=subject, body=" ")

            for it in items:
                order_id = it["index"]
                manager.set_device_running(order_id)

        # Wait for batch completion
        elapsed = 0
        while True:
            pending = manager.get_pending_devices()
            if not pending:
                logger.info(f"[{request_id}] - Batch {batch_idx + 1} completed.")
                break
            if elapsed >= config.challenge.fp_timeout:
                logger.warning(f"[{request_id}] - Batch {batch_idx + 1} timed out.")
                for order_id in batch_devices:
                    manager.set_device_timeout(order_id)
                break
            elapsed += 1
            time.sleep(1)

    score_result = manager.calculate_score()

    # Complete session and save results
    complete_session()

    return score_result


def get_results() -> List[Payload]:
    """Returns the results from the last completed session."""
    return get_last_results()


@validate_call
def set_fingerprint(order_id: int, fingerprint: str, device_name: Optional[str] = None) -> bool:
    """Receive fingerprint from proxy."""
    success = dfp_update_fingerprint(
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
