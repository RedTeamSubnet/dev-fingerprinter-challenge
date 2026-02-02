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

from .schemas import MinerInput, MinerOutput
from .dfp import DFPManager
from .payload import PayloadManager, Payload
from .job import Job, job_registry, reserve_offset_range


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
    """Score a miner's fingerprinter.js submission (thread-safe)."""

    _n_repeat = config.challenge.n_repeat
    _total_devices = len(config.challenge.devices)

    # Atomically reserve order IDs
    start_id = reserve_offset_range(_n_repeat * _total_devices)

    # Create isolated state for this request
    manager = DFPManager(fp_js=miner_output.fingerprinter_js)
    manager.target_devices = []
    payload_mgr = PayloadManager()

    job = Job(
        request_id=request_id,
        manager=manager,
        payload_mgr=payload_mgr,
        start_id=start_id,
    )

    # Send fingerprinter.js to proxy
    try:
        manager.send_fp_js(
            request_id=request_id,
            base_url=str(config.challenge.proxy_inter_base_url).rstrip("/"),
            api_key=config.challenge.api_key,
        )
    except Exception as e:
        logger.warning(f"[{request_id}] - Failed to send fingerprinter.js to proxy: {e}")

    logger.info(f"[{request_id}] - Starting {_n_repeat} batches of {_total_devices} devices...")

    for batch_idx in range(_n_repeat):
        logger.info(f"[{request_id}] - Processing Batch {batch_idx + 1}/{_n_repeat}")

        targets_by_email = defaultdict(list)
        batch_devices = []
        batch_browsers = random.sample(BROWSERS, len(BROWSERS))

        for i, device_cfg in enumerate(config.challenge.devices):
            target = DevicePM(**device_cfg.model_dump())
            target.state = DeviceStateEnum.READY
            target.browser = batch_browsers[i % len(batch_browsers)]

            order_id = start_id + (batch_idx * _total_devices) + i

            manager.target_devices.append(target)
            job.session_map[order_id] = len(manager.target_devices) - 1

            payload_mgr.create_payload(
                order_id=order_id,
                device_id=device_cfg.id,
                device_name=device_cfg.device_model or "Unknown",
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
                "device": target,
                "url": web_url,
                "index": order_id,
            })
            batch_devices.append(target)

        # Register job so fingerprints can be received
        job_registry.register(job)

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
                it["device"].state = DeviceStateEnum.RUNNING

        # Wait for batch completion
        elapsed = 0
        while True:
            pending = [d for d in batch_devices if d.state == DeviceStateEnum.RUNNING]
            if not pending:
                logger.info(f"[{request_id}] - Batch {batch_idx + 1} completed.")
                break
            if elapsed >= config.challenge.fp_timeout:
                logger.warning(f"[{request_id}] - Batch {batch_idx + 1} timed out.")
                for d in pending:
                    d.state = DeviceStateEnum.TIMEOUT
                break
            elapsed += 1
            time.sleep(1)

    score_result = manager.score(payloads=payload_mgr.get_all_payloads())

    # Optional: cleanup (comment out if you need /results after scoring)
    # job_registry.unregister(request_id)

    return score_result


def get_results(request_id: str) -> List[Payload]:
    """Returns the results for a specific request."""
    job = job_registry.get_by_request(request_id)
    return job.payload_mgr.get_all_payloads() if job else []


@validate_call
def set_fingerprint(order_id: int, fingerprint: str, device_name: Optional[str] = None) -> None:
    """Receive fingerprint from proxy."""
    job = job_registry.get_by_order(order_id)
    if not job:
        logger.warning(f"Unknown order_id {order_id}. Ignoring.")
        return

    if order_id not in job.session_map:
        logger.warning(f"Order ID {order_id} not in session_map. Ignoring.")
        return

    idx = job.session_map[order_id]
    target = job.manager.target_devices[idx]

    if target.state == DeviceStateEnum.COMPLETED:
        return

    job.payload_mgr.update_fingerprint(order_id, fingerprint.strip(), device_name)
    target.state = DeviceStateEnum.COMPLETED


__all__ = [
    "get_task",
    "score",
    "set_fingerprint",
    "get_results",
]
