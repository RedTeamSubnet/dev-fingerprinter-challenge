# -*- coding: utf-8 -*-

from typing import Dict, Optional, List
from pydantic import BaseModel, Field

class Payload(BaseModel):
    order_id: int = Field(..., description="The dynamic order ID of the device request")
    device_id: int = Field(..., description="The static ID of the device")
    device_name: str = Field(..., description="The model name of the device")
    reported_device_name: Optional[str] = Field(default=None, description="The device name reported by the proxy")
    fingerprint: Optional[str] = Field(default=None, description="The collected fingerprint")

class PayloadManager:
    """
    Manages payloads containing device order, name, and fingerprint.
    """
    def __init__(self):
        self._payloads: Dict[int, Payload] = {}

    def create_payload(self, order_id: int, device_id: int, device_name: str) -> Payload:
        """Creates and registers a new payload."""
        payload = Payload(order_id=order_id, device_id=device_id, device_name=device_name)
        self._payloads[order_id] = payload
        return payload

    def get_payload(self, order_id: int) -> Optional[Payload]:
        """Retrieves a payload by its order ID."""
        return self._payloads.get(order_id)

    def update_fingerprint(self, order_id: int, fingerprint: str, device_name: Optional[str] = None) -> bool:
        """Updates the fingerprint for a specific order ID."""
        payload = self.get_payload(order_id)
        if payload:
            payload.fingerprint = fingerprint
            if device_name:
                payload.reported_device_name = device_name
            return True
        return False

    def get_all_payloads(self) -> List[Payload]:
        """Returns all registered payloads."""
        return list(self._payloads.values())

    def clear(self):
        """Clears all payloads."""
        self._payloads.clear()
