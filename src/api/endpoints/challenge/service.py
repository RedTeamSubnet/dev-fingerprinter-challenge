# -*- coding: utf-8 -*-

import time
import random
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


def get_task() -> MinerInput:
    """Return a new challenge task."""
    return MinerInput()


@validate_call
def score(request_id: str, miner_output: MinerOutput) -> float:

    global dfp_manager
    _score = 0.0

    # Removed ESLint check here
    dfp_manager = DFPManager(fp_js=miner_output.fingerprinter_js)
    dfp_manager.send_fp_js(
        request_id=request_id,
        base_url=config.challenge.proxy_inter_base_url,
        api_key=config.challenge.api_key,
    )
    utils_services.check_health(request_id=request_id)
    dfp_manager.generate_targets(
        devices=config.challenge.devices,
        n_repeat=1,
        random_seed=config.challenge.random_seed,
    )

    # 1. Group targets by email and prepare URLs
    targets_by_email = defaultdict(list)
    all_active_devices = []
    
    # Available browsers to randomize
    BROWSERS = ["chrome", "brave", "firefox"]
    
    # Consistency map: device_id -> assigned_browser
    # This ensures that each physical device (by ID) gets exactly one browser choice.
    device_browser_map = {}

    for _i, _target_device in enumerate(dfp_manager.target_devices):
        # Ensure consistent browser per device ID for this run
        dev_id = _target_device.id
        if dev_id not in device_browser_map:
            device_browser_map[dev_id] = random.choice(BROWSERS)
            
        _target_device.browser = device_browser_map[dev_id]

        _web_endpoint = "/_web"
        _web_base_url = str(config.challenge.proxy_exter_base_url).rstrip("/")
        _web_url = f"{_web_base_url}{_web_endpoint}?order_id={_i}"
        
        # Prepare item for batching
        targets_by_email[_target_device.email].append({
            "device": _target_device,
            "url": _web_url,
            "index": _i
        })
        all_active_devices.append(_target_device)

    # 2. Send batched emails
    for email, items in targets_by_email.items():
        # Shuffle items to ensure random order in email
        random.shuffle(items)
        
        # Format: device_model-with-hyphens browser
        subjects = [f"{item['device'].device_model.replace(' ', '-')} {item['device'].browser}" for item in items]
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
                    f"[{request_id}] - Triggered device {{'order_id': {item['index']}, 'id': {item['device'].id}}} via email batch."
                )
        else:
            for item in items:
                item['device'].state = DeviceStateEnum.ERROR
                logger.error(
                     f"[{request_id}] - Could not send email batch for device {{'order_id': {item['index']}, 'id': {item['device'].id}}}."
                )

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

    _score = dfp_manager.score()
    return _score


@validate_call
def set_fingerprint(order_id: int, fingerprint: str) -> None:

    global dfp_manager

    if not dfp_manager:
        raise RuntimeError(
            "'dfp_manager' is not initialized, please run '/score' endpoint first!"
        )

    if len(dfp_manager.target_devices) <= order_id:
        raise IndexError(f"Order ID {order_id} is out of range!")

    _target_device = dfp_manager.target_devices[order_id]
    if _target_device.state == DeviceStateEnum.COMPLETED:
        raise ValueError(
            f"Device with {{'id': {_target_device.id}, 'order_id': {order_id}}} already completed fingerprinting!"
        )

    _target_device.fingerprint = fingerprint.strip()
    _target_device.state = DeviceStateEnum.COMPLETED

    return


__all__ = [
    "get_task",
    "score",
    "set_fingerprint",
]
