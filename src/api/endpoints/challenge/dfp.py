# -*- coding: utf-8 -*-
import random
import time
from typing import Optional, List, Dict
from collections import defaultdict

import requests
from pydantic import validate_call, AnyHttpUrl, SecretStr

from api.config import config
from api.core.configs.challenge import DevicePM, DeviceStateEnum, DeviceStatusEnum
from api.logger import logger

from .schemas import Payload


class DFPManager:
    """Manages device fingerprinting sessions and scoring."""

    @validate_call
    def __init__(self, fp_js: str = ""):
        if fp_js:
            self.fp_js = fp_js
        self.restart_manager()

    def restart_manager(self, fp_js: str = "") -> None:
        """Reset the manager state for a new session."""
        if fp_js:
            self.fp_js = fp_js
        self.target_devices: List[DevicePM] = []
        self.payloads: Dict[int, Payload] = {}
        self.session_map: Dict[int, int] = {}
        self.score_value: float = 0.0
        self.start_id: int = 0
        self.current_browser: Optional[str] = None
        self.request_id: Optional[str] = None
        self.session_structure: Dict[str, List[dict]] = {}

    @validate_call
    def add_device(self, order_id: int, device_cfg: DevicePM, browser: str) -> None:
        """Add a device to the session."""
        target = DevicePM(**device_cfg.model_dump())
        target.state = DeviceStateEnum.READY
        target.browser = browser

        self.target_devices.append(target)
        self.session_map[order_id] = len(self.target_devices) - 1

        self.payloads[order_id] = Payload(
            order_id=order_id,
            device_id=device_cfg.id,
            device_name=device_cfg.device_model or "Unknown",
            browser=browser,
        )

    def update_fingerprint(self, order_id: int, fingerprint: str) -> bool:
        """Update fingerprint for a device."""
        if order_id not in self.payloads:
            return False

        if order_id not in self.session_map:
            return False

        idx = self.session_map[order_id]
        target = self.target_devices[idx]

        if target.state == DeviceStateEnum.COMPLETED:
            return False

        payload = self.payloads[order_id]
        payload.fingerprint = fingerprint.strip()
        logger.success(
            f"Received fingerprint for device: {target.device_model} (order_id: {order_id})"
        )
        target.state = DeviceStateEnum.COMPLETED
        return True

    def get_pending_devices(self) -> List[DevicePM]:
        """Get devices that are still waiting for fingerprints."""
        return [d for d in self.target_devices if d.state == DeviceStateEnum.RUNNING]

    def set_device_running(self, order_id: int) -> None:
        """Mark a device as running."""
        if order_id in self.session_map:
            idx = self.session_map[order_id]
            if self.target_devices[idx].state == DeviceStateEnum.READY:
                self.target_devices[idx].state = DeviceStateEnum.RUNNING

    def set_device_timeout(self, order_id: int) -> None:
        """Mark a device as timed out."""
        if order_id in self.session_map:
            idx = self.session_map[order_id]
            if self.target_devices[idx].state == DeviceStateEnum.RUNNING:
                self.target_devices[idx].state = DeviceStateEnum.TIMEOUT

    def gen_session_structure(
        self,
        devices: List[DevicePM],
        browsers: List[str],
        n_repeat: int,
    ) -> Dict[str, List[dict]]:
        """Generate session structure with shuffled browsers and devices per batch.

        Structure: dict[browser: list_of_device_info]
        Each batch uses one browser for all devices.
        Devices are shuffled and assigned order_ids in shuffled order.
        """
        # Get only active devices
        active_devices = [d for d in devices if d.status == DeviceStatusEnum.ACTIVE]

        if not active_devices:
            raise ValueError("No active devices found to generate session structure!")

        shuffled_browsers = []
        for n in range(1, n_repeat + 1):
            shuffled = browsers.copy()
            shuffled = [f"{b}_{n}" for b in shuffled]
            random.shuffle(shuffled)
            shuffled_browsers.extend(shuffled)

        structure: Dict[str, List[dict]] = defaultdict(list)
        current_order_id = self.start_id

        for browser in shuffled_browsers:
            batch_devices = active_devices.copy()
            random.shuffle(batch_devices)

            for device_cfg in batch_devices:
                self.add_device(
                    order_id=current_order_id, device_cfg=device_cfg, browser=browser
                )

                structure[browser].append(
                    {
                        "device_cfg": device_cfg,
                        "order_id": current_order_id,
                        "device": self.target_devices[-1],
                        "email": device_cfg.email,
                        "browser": browser,
                    }
                )

                current_order_id += 1

        self.session_structure = structure
        return structure

    @validate_call
    def send_fp_js(
        self, request_id: str, base_url: AnyHttpUrl, api_key: SecretStr
    ) -> None:
        """Send fingerprinter.js to the proxy server."""
        _endpoint = "/_fp-js"
        _base_url = str(base_url).rstrip("/")
        _url = f"{_base_url}{_endpoint}?order_id=0"

        logger.info(
            f"[{request_id}] - Sending fingerprinter.js file to '{_url}' DFP proxy server ..."
        )
        try:
            _headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-API-Key": api_key.get_secret_value(),
            }
            _payload = {"fingerprinter_js": self.fp_js}
            _response = requests.post(_url, headers=_headers, json=_payload)
            _response.raise_for_status()

            logger.info(
                f"[{request_id}] - Successfully sent fingerprinter.js file to '{_url}' DFP proxy server."
            )
        except Exception:
            logger.error(
                f"[{request_id}] - Failed to send fingerprinter.js file to '{_url}' DFP proxy server!"
            )
            raise

    def calculate_score(self) -> float:
        """
        Calculates final score by aggregating all batches
        into physical device identities and applying the 'Two-Strike' collision rule.
        """
        scoring_cfg = config.challenge.scoring

        # Result: { physical_id: [Payload1, Payload2, ...] }
        payloads_by_device = defaultdict(list)
        for payload in self.payloads.values():
            if payload.fingerprint:
                payloads_by_device[payload.device_id].append(payload)

        # Must have at least 2 unique physical phones reporting
        active_device_ids = list(payloads_by_device.keys())
        if len(active_device_ids) < scoring_cfg.min_devices:
            logger.warning(
                f"Scoring: Only {len(active_device_ids)} physical devices reported. Min {scoring_cfg.min_devices} required."
            )
            return 0.0

        # Which physical devices share which strings across ALL batches
        # Result: { "FP_STRING_A": {device_1, device_2} }
        devices_sharing_fingerprint = defaultdict(set)
        for device_id, payloads in payloads_by_device.items():
            for p in payloads:
                devices_sharing_fingerprint[p.fingerprint].add(device_id)

        # Calculate Points for each Target Physical Device
        total_session_points = 0.0
        target_physical_ids = {d.id for d in self.target_devices}

        for device_id in target_physical_ids:
            device_payloads = payloads_by_device.get(device_id, [])

            # If a device never reported, it contributes 0.0 to the average
            if not device_payloads:
                continue

            device_points = 1.0
            unique_fps = {payload.fingerprint for payload in device_payloads}
            unique_fps_count = len(unique_fps)

            # Rule 1 Fragmentation (Internal Consistency)
            if unique_fps_count >= scoring_cfg.max_fragmentation:
                logger.warning(
                    f"Scoring: Device {device_id} reached fragmentation limit ({unique_fps_count} unique IDs)."
                )
                device_points = 0.0
            elif unique_fps_count > 1:
                penalty = scoring_cfg.fragmentation_penalty * (unique_fps_count - 1)
                device_points -= penalty
                logger.info(
                    f"Scoring: Device {device_id} fragmented. Penalty: -{penalty:.2f}"
                )

            # Rule 2 Two-Strike Collision (External Uniqueness)
            if device_points > 0:
                collision_batches_count = 0
                for p in device_payloads:
                    # Does this specific payload's fingerprint match ANY other physical device in the entire session?
                    if len(devices_sharing_fingerprint[p.fingerprint]) > 1:
                        collision_batches_count += 1

                # Strike 1: 1 batch with collision (-0.25 Penalty)
                # Strike 2: 2+ batches with collision (0.0 Score)
                if collision_batches_count >= 2:
                    logger.warning(
                        f"Scoring: Device {device_id} failed uniqueness in {collision_batches_count} batches. Score: 0.0"
                    )
                    device_points = 0.0
                elif collision_batches_count == 1:
                    device_points -= scoring_cfg.collision_penalty
                    logger.info(
                        f"Scoring: Device {device_id} collided in 1 batch. Penalty: -{scoring_cfg.collision_penalty:.2f}"
                    )

            total_session_points += max(0.0, device_points)

        # Final Normalization (Average across all expected physical phones)
        final_score = total_session_points / len(target_physical_ids)
        logger.info(
            f"Final Session Score: {total_session_points:.2f} / {len(target_physical_ids)} devices = {final_score:.3f}"
        )

        return round(min(1.0, max(0.0, final_score)), 3)

    def get_all_payloads(self) -> List[dict]:
        """Return all collected payloads."""
        return list([p.model_dump_json() for p in self.payloads.values()])

    def wait_for_batch_completion(
        self, browser: str, batch_order_ids: list, fp_timeout: int
    ):
        elapsed = 0
        logger.info(
            f"Waiting for batch {browser} to complete with timeout of {fp_timeout} seconds..."
        )
        while True:
            pending = self.get_pending_devices()
            if not pending:
                logger.info(f"Batch {browser} completed.")
                break
            if elapsed >= fp_timeout:
                logger.warning(f"Batch {browser} timed out.")
                for order_id in batch_order_ids:
                    self.set_device_timeout(order_id)
                break
            elapsed += 1
            time.sleep(1)

    ### ATTRIBUTES ###
    @property
    def fp_js(self) -> str:
        try:
            return self.__fp_js
        except AttributeError:
            raise AttributeError("`fp_js` attribute is not set!")

    @fp_js.setter
    def fp_js(self, fp_js: str):
        if not isinstance(fp_js, str):
            raise TypeError(
                f"`fp_js` attribute type {type(fp_js)} is invalid, must be a <str>!"
            )

        fp_js = fp_js.strip()
        if not fp_js:
            raise ValueError("`fp_js` attribute value is empty!")

        self.__fp_js = fp_js

    ### ATTRIBUTES ###


# Global state management - similar to PayloadManager pattern
dfp_manager = DFPManager()


__all__ = ["DFPManager", "dfp_manager"]
