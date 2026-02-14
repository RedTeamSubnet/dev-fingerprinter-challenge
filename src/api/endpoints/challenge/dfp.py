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
from api.config import config

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
    def __init__(self, fp_js: str):
        self.fp_js = fp_js
        self.restart_manager()

    def restart_manager(self) -> None:
        """Reset the manager state for a new session."""
        self.target_devices: List[DevicePM] = []
        self.payloads: Dict[int, Payload] = {}
        self.session_map: Dict[int, int] = {}
        self.score_value: float = 0.0
        self.start_id: int = 0
        self.request_id: Optional[str] = None

    def generate_targets(
        self, devices: list[DevicePM], n_repeat: int, random_seed: Optional[int] = None
    ) -> None:
        """Generate target devices with multiple repeats and shuffling."""
        _target_devices = []
        for _device in devices:
            if _device.status == DeviceStatusEnum.ACTIVE:
                for _ in range(n_repeat):
                    _target_devices.append(
                        DevicePM(
                            **_device.model_dump(exclude={"state"}),
                            state=DeviceStateEnum.READY,
                        )
                    )

        if not _target_devices:
            raise ValueError(
                "Not found any active or connected devices to generate targets!"
            )

        if random_seed is not None:
            random.seed(random_seed)

        random.shuffle(_target_devices)

        if random_seed is not None:
            random.seed(None)

        self.target_devices = _target_devices

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


# Global state management
_active_manager: Optional[DFPManager] = None
_last_results: List[Payload] = []


def start_new_session(fp_js: str, request_id: str) -> DFPManager:
    """Start a new DFP session, clearing any existing state."""
    global _active_manager, _last_results
    
    # Save current results before clearing (if any)
    if _active_manager is not None:
        _last_results = _active_manager.get_all_payloads()
    
    _active_manager = DFPManager(fp_js=fp_js)
    _active_manager.request_id = request_id
    return _active_manager


def get_active_manager() -> Optional[DFPManager]:
    """Get the currently active DFP manager."""
    return _active_manager


def complete_session() -> List[Payload]:
    """Complete the current session and save results."""
    global _active_manager, _last_results
    
    if _active_manager is not None:
        _last_results = _active_manager.get_all_payloads()
        _active_manager = None
    
    return _last_results


def get_last_results() -> List[Payload]:
    """Get the results from the last completed session."""
    return _last_results


def update_fingerprint(
    order_id: int, fingerprint: str, device_name: Optional[str] = None
) -> bool:
    """Update fingerprint in the active session."""
    manager = get_active_manager()
    if manager is None:
        return False
    return manager.update_fingerprint(order_id, fingerprint, device_name)


__all__ = [
    "DFPManager",
    "reserve_offset_range",
    "start_new_session",
    "get_active_manager",
    "complete_session",
    "get_last_results",
    "update_fingerprint",
]
