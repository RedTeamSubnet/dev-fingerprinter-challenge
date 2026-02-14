# -*- coding: utf-8 -*-
import random
import time
from typing import Optional, List, Dict, Set
from collections import defaultdict

import requests
from pydantic import validate_call, AnyHttpUrl, SecretStr

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
        self, order_id: int, fingerprint: str
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
        for n in range(1, n_repeat+1):
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
                    order_id=current_order_id,
                    device_cfg=device_cfg,
                    browser=browser
                )
                
                structure[browser].append({
                    "device_cfg": device_cfg,
                    "order_id": current_order_id,
                    "device": self.target_devices[-1],
                    "email": device_cfg.email,
                    "browser": browser,
                })
                
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
        Calculate score based on strict consistency and uniqueness rules.
        """
        # Using a set ensures that identical fingerprints for one device are collapsed into one.
        fingerprints_by_device = defaultdict(set)
        for payload in self.payloads.values():
            if payload.fingerprint:
                fingerprints_by_device[payload.device_id].add(payload.fingerprint)

        # A device is ONLY consistent if it has exactly 1 unique fingerprint string across all browsers.
        consistent_identities = {}
        for device_id, fingerprints in fingerprints_by_device.items():
            if len(fingerprints) == 1:
                # Phone passed the 'Internal Consistency' check
                consistent_identities[device_id] = list(fingerprints)[0]
            else:
                logger.warning(f"Scoring: Device {device_id} failed Consistency Check (Browsers do not match).")

        all_consistent_fingerprints = list(consistent_identities.values())
        perfect_device_count = 0
        
        for device_id, identity in consistent_identities.items():
            if all_consistent_fingerprints.count(identity) == 1:
                perfect_device_count += 1
                logger.success(f"Scoring: Device {device_id} passed both Consistency and Uniqueness checks.")
            else:
                logger.warning(f"Scoring: Device {device_id} failed Uniqueness Check (Collision with other phone).")

        total_expected_devices = len({device.id for device in self.target_devices})
        self.score_value = perfect_device_count / total_expected_devices if total_expected_devices > 0 else 0.0
        
        logger.info(f"Final Score: {perfect_device_count} / {total_expected_devices} = {self.score_value:.3f}")
        return round(self.score_value, 3)

    def get_all_payloads(self) -> List[Payload]:
        """Return all collected payloads."""
        return list(self.payloads.values())
    
    def wait_for_batch_completion(self, browser, batch_order_ids, fp_timeout):
        elapsed = 0
        logger.info(f"Waiting for batch {browser} to complete with timeout of {fp_timeout} seconds...")
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


__all__ = [
    "DFPManager",
    "dfp_manager"
]
