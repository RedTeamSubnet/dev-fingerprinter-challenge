# -*- coding: utf-8 -*-

from typing import List

from pydantic import validate_call

from api.config import config
from api.helpers.email import EmailHelper
from api.logger import logger

from .schemas import MinerInput, MinerOutput, Payload
from .dfp import dfp_manager
from .utils import sync_device_with_proxy

email_helper = EmailHelper(
    smtp_host=config.challenge.smtp_host,
    smtp_port=config.challenge.smtp_port,
    smtp_user=config.challenge.smtp_user,
    smtp_password=config.challenge.smtp_password,
    email_sender=config.challenge.email_sender,
)


def get_task() -> MinerInput:
    """Return a new challenge task."""
    return MinerInput()


@validate_call
def score(request_id: str, miner_output: MinerOutput) -> float:
    """Score a miner's fingerprinter.js submission."""

    _n_repeat = config.challenge.n_repeat

    # Get active devices for counting
    active_devices = [d for d in config.challenge.devices if d.status.value == "ACTIVE"]
    _total_active = len(active_devices)

    if _total_active == 0:
        logger.error(f"[{request_id}] - No active devices found!")
        return 0.0

    # Restart manager for new session
    dfp_manager.restart_manager(fp_js=miner_output.fingerprinter_js)
    dfp_manager.request_id = request_id

    dfp_manager.start_id = 0

    # Send fingerprinter.js to proxy
    try:
        dfp_manager.send_fp_js(
            request_id=request_id,
            base_url=config.challenge.proxy_inter_base_url,
            api_key=config.challenge.api_key,
        )
    except Exception as e:
        logger.warning(
            f"[{request_id}] - Failed to send fingerprinter.js to proxy: {e}"
        )
        raise

    # Generate session structure
    logger.info(
        f"[{request_id}] - Generating session structure with {_n_repeat} batches..."
    )
    session_structure = dfp_manager.gen_session_structure(
        devices=config.challenge.devices,
        browsers=config.challenge.browser_names,
        n_repeat=_n_repeat,
    )

    logger.info(
        f"[{request_id}] - Starting {_n_repeat} batches of {_total_active} devices..."
    )

    proxy_base_url = str(config.challenge.proxy_inter_base_url).rstrip("/")

    for browser, browser_devices in session_structure.items():

        logger.info(
            f"[{request_id}] - Processing Batch {browser} {len(session_structure)} with browser: {browser}"
        )

        batch_order_ids = []
        dfp_manager.current_browser = browser
        sync_device_with_proxy(request_id, proxy_base_url, browser_devices)

        subject = f"Running browser: {browser}"
        logger.info(f"[{request_id}] - Sending email: '{subject}'")
        email_helper.send(to=config.challenge.email_sender, subject=subject, body=" ")

        for _device in browser_devices:
            dfp_manager.set_device_running(_device["order_id"])
            batch_order_ids.append(_device["order_id"])

        dfp_manager.wait_for_batch_completion(
            browser=browser,
            batch_order_ids=batch_order_ids,
            fp_timeout=config.challenge.fp_timeout,
        )
        if dfp_manager.failed_device_count > 10:
            logger.warning(
                f"[{request_id}] - Too many failed devices:({dfp_manager.failed_device_count}). Score: 0.0"
            )
            return 0.0

    score_result = dfp_manager.calculate_score()

    return score_result


def get_results() -> List[dict]:
    """Returns the results from the current session."""
    return dfp_manager.get_all_payloads()


@validate_call
def set_fingerprint(order_id: int, fingerprint: str) -> bool:
    """Receive fingerprint from proxy."""
    success = dfp_manager.update_fingerprint(order_id=order_id, fingerprint=fingerprint)

    if not success:
        logger.warning(f"Failed to set fingerprint for order_id {order_id}")

    return success


__all__ = [
    "get_task",
    "score",
    "set_fingerprint",
    "get_results",
]
