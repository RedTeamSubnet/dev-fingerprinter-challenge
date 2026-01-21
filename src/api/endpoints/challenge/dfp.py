# -*- coding: utf-8 -*-

import random
from typing import Optional, List, Dict, Set
from collections import Counter, defaultdict

import requests
from pydantic import validate_call, AnyHttpUrl, SecretStr

from api.core.configs.challenge import DevicePM, DeviceStatusEnum, DeviceStateEnum
from api.logger import logger
from api.config import config


from .payload import Payload


class DFPManager:

    @validate_call
    def __init__(self, fp_js: str):
        self.fp_js = fp_js
        self.start_id = 0

    @validate_call
    def send_fp_js(
        self, request_id: str, base_url: AnyHttpUrl, api_key: SecretStr
    ) -> None:

        _endpoint = "/_fp-js"
        _base_url = str(base_url).rstrip("/")
        # Append dummy order_id to satisfy proxy schema
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

        return

    @validate_call
    def generate_targets(
        self, devices: list[DevicePM], n_repeat: int, random_seed: Optional[int] = None
    ) -> None:

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
        return

    def score(self, payloads: List[Payload]) -> float:
        """
        Calculate the scoring based on strict fingerprint uniqueness (Hard Collisions Only).
        
        Logic:
        1. Numerator: Count of devices that provided a UNIQUE fingerprint (not shared by any other device).
        2. Denominator: Total number of expected devices (len(self.target_devices)).
        3. Result: Numerator / Denominator.
        
        Note: Devices that collide or fail to respond (timeout) receive 0 points.
        """
        total_expected = len(self.target_devices)
        valid_payloads = [p for p in payloads if p.fingerprint]

        logger.info(f"Scoring: Total expected devices: {total_expected}")
        logger.info(f"Scoring: Valid fingerprints received: {len(valid_payloads)}")

        if not valid_payloads:
            logger.warning("No valid payloads to score (no fingerprints received).")
            return 0.0

        # Map Fingerprint -> Set of Device IDs that produced it
        fingerprint_to_devices: Dict[str, Set[int]] = defaultdict(set)
        for p in valid_payloads:
            if p.fingerprint:
                fingerprint_to_devices[p.fingerprint].add(p.device_id)

        # Identify which physical devices are in a collision group
        collision_devices = set()
        for fp, dev_ids in fingerprint_to_devices.items():
            if len(dev_ids) > 1:
                # Collision detected! All devices in this group are marked.
                for dev_id in dev_ids:
                    collision_devices.add(dev_id)
                    logger.debug(f"Device {dev_id} has collision with fingerprint {fp[:10]}...")

        # Calculate total earned points
        # A device earns 1 point ONLY if it responded AND its fingerprint was unique.
        total_points = 0.0
        participating_devices = {p.device_id for p in valid_payloads}
        
        for dev_id in participating_devices:
            if dev_id not in collision_devices:
                total_points += 1.0

        # Final Calculation normalized by ALL expected devices
        final_score = total_points / total_expected
        
        logger.info(f"Scoring Breakdown: {len(participating_devices)} responded, {len(collision_devices)} collisions, {total_points} unique.")
        logger.info(f"Final Score Calculation: {total_points} / {total_expected} = {final_score:.3f}")

        return round(final_score, 3)

    ### ATTRIBUTES ###
    ## fp_js ##
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

    ## fp_js ##

    ## target_devices ##
    @property
    def target_devices(self) -> list[DevicePM]:
        try:
            return self.__target_devices
        except AttributeError:
            raise AttributeError("`target_devices` attribute is not set!")

    @target_devices.setter
    def target_devices(self, target_devices: list[DevicePM]):
        if not isinstance(target_devices, list):
            raise TypeError(
                f"`target_devices` attribute type {type(target_devices)} is invalid, must be a <list>!"
            )

        if not target_devices:
            raise ValueError("`target_devices` attribute value is empty!")

        for _task_device in target_devices:
            if not isinstance(_task_device, DevicePM):
                raise TypeError(
                    f"`target_devices` list attribute's item type {_task_device} is invalid, must be a <DevicePM>!"
                )

        self.__target_devices = target_devices

    ## target_devices ##
    ### ATTRIBUTES ###


__all__ = [
    "DFPManager",
]
