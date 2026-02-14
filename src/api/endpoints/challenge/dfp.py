# -*- coding: utf-8 -*-

import os
import random
import fcntl
from typing import Optional, List, Dict, Set
from collections import defaultdict

import requests
from pydantic import validate_call, AnyHttpUrl, SecretStr

from api.core.configs.challenge import DevicePM, DeviceStateEnum, DeviceStatusEnum
from api.logger import logger

from .schemas import Payload


OFFSET_FILE = os.path.join("/var/lib/rest.dfp-challenger", "order_offset.txt")


def reserve_offset_range(count: int) -> int:
    """Atomically reserve a range of order IDs and return the start ID."""
    try:
        os.makedirs(os.path.dirname(OFFSET_FILE), exist_ok=True)
        with open(OFFSET_FILE, "a+") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.seek(0)
                content = f.read().strip()
                start_id = int(content) if content else 0
                f.seek(0)
                f.truncate()
                f.write(str(start_id + count))
                return start_id
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        logger.error(f"Failed to reserve offset range: {e}")
        return 0


class DFPManager:
    """Manages device fingerprinting sessions and scoring."""

    @validate_call
    def __init__(self, fp_js: str = ""):
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
        self.request_id: Optional[str] = None
        self.session_structure: Dict[int, Dict[str, List[dict]]] = {}

    @validate_call
    def add_device(
        self, order_id: int, device_cfg: DevicePM, browser: str
    ) -> None:
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
        )

    def update_fingerprint(
        self, order_id: int, fingerprint: str, device_name: Optional[str] = None
    ) -> bool:
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
        if device_name:
            payload.reported_device_name = device_name

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
    ) -> Dict[int, Dict[str, List[dict]]]:
        """Generate session structure with shuffled browsers and devices per batch.
        
        Structure: dict[batch_number: dict[browser: list_of_device_info]]
        Each batch uses one browser for all devices.
        Devices are shuffled and assigned order_ids in shuffled order.
        """
        # Get only active devices
        active_devices = [d for d in devices if d.status == DeviceStatusEnum.ACTIVE]
        
        if not active_devices:
            raise ValueError("No active devices found to generate session structure!")
        
        # Shuffle browsers once for all batches
        shuffled_browsers = browsers.copy()
        random.shuffle(shuffled_browsers)
        
        structure: Dict[int, Dict[str, List[dict]]] = {}
        current_order_id = self.start_id
        
        for batch_idx in range(n_repeat):
            # Select browser for this batch (cycle through shuffled browsers if needed)
            browser = shuffled_browsers[batch_idx % len(shuffled_browsers)]
            
            # Shuffle devices for this batch
            batch_devices = active_devices.copy()
            random.shuffle(batch_devices)
            
            # Create device info list with order_ids
            device_infos = []
            for device_cfg in batch_devices:
                self.add_device(
                    order_id=current_order_id,
                    device_cfg=device_cfg,
                    browser=browser
                )
                
                device_infos.append({
                    "device_cfg": device_cfg,
                    "order_id": current_order_id,
                    "device": self.target_devices[-1],
                    "email": device_cfg.email,
                })
                
                current_order_id += 1
            
            # Store in structure: batch_idx -> browser -> list of device infos
            structure[batch_idx] = {browser: device_infos}
        
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
        Calculate the scoring based on strict fingerprint uniqueness (Hard Collisions Only).
        
        Logic:
        1. Numerator: Count of devices that provided a UNIQUE fingerprint.
        2. Denominator: Total number of expected devices.
        3. Result: Numerator / Denominator.
        """
        _unique_ids = {d.id for d in self.target_devices}
        total_expected = len(_unique_ids)

        valid_payloads = [p for p in self.payloads.values() if p.fingerprint]

        logger.info(f"Scoring: Total unique physical devices: {total_expected}")
        logger.info(f"Scoring: Total fingerprints received: {len(valid_payloads)}")

        if not valid_payloads:
            logger.warning("No valid payloads to score (no fingerprints received).")
            self.score_value = 0.0
            return self.score_value

        fingerprint_to_devices: Dict[str, Set[int]] = defaultdict(set)
        for p in valid_payloads:
            if p.fingerprint:
                fingerprint_to_devices[p.fingerprint].add(p.device_id)

        collision_devices = set()
        for fp, dev_ids in fingerprint_to_devices.items():
            if len(dev_ids) > 1:
                for dev_id in dev_ids:
                    collision_devices.add(dev_id)
                    logger.debug(f"Device {dev_id} has collision with fingerprint {fp[:10]}...")

        total_points = 0.0
        participating_devices = {p.device_id for p in valid_payloads}

        for dev_id in participating_devices:
            if dev_id not in collision_devices:
                total_points += 1.0

        self.score_value = total_points / total_expected

        logger.info(f"Scoring Breakdown: {len(participating_devices)}/{total_expected} physical devices responded, {len(collision_devices)} collisions, {total_points} unique.")
        logger.info(f"Final Score Calculation: {total_points} / {total_expected} = {self.score_value:.3f}")

        return round(self.score_value, 3)

    def get_all_payloads(self) -> List[Payload]:
        """Return all collected payloads."""
        return list(self.payloads.values())

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


__all__ = [
    "DFPManager",
    "dfp_manager",
    "reserve_offset_range",
]
