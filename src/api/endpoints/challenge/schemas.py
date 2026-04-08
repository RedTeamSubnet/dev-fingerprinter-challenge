# -*- coding: utf-8 -*-

import os
import pathlib
from typing import Optional, Annotated

from pydantic import BaseModel, Field, field_validator
from pydantic.types import StringConstraints

from api.core.constants import ALPHANUM_REGEX
from api.logger import logger
from api.core import utils


_app_dir = pathlib.Path(__file__).parent.parent.parent.parent.resolve()
_dfp_template_dir = _app_dir / "templates" / "js"

_dfp_js_path = str(_dfp_template_dir / "fingerprinter.js")
_dfp_js_content = ""

try:
    if os.path.exists(_dfp_js_path):
        with open(_dfp_js_path, "r") as _dfp_js_file:
            _dfp_js_content = _dfp_js_file.read()

except Exception:
    logger.exception(f"Failed to read fingerprinter.js file!")


class MinerInput(BaseModel):
    random_val: Optional[
        Annotated[
            str,
            StringConstraints(
                strip_whitespace=True,
                min_length=4,
                max_length=64,
                pattern=ALPHANUM_REGEX,
            ),
        ]
    ] = Field(
        default_factory=utils.gen_random_string,
        title="Random Value",
        description="Random value to prevent caching.",
        examples=["a1b2c3d4e5f6g7h8"],
    )


class MinerOutput(BaseModel):
    fingerprinter_js: str = Field(
        default=_dfp_js_content,
        title="fingerprinter.js",
        min_length=2,
        description="System-provided fingerprinter.js script for fingerprint detection.",
        examples=[_dfp_js_content],
    )

    @field_validator("fingerprinter_js", mode="after")
    @classmethod
    def _check_fingerprinter_js_lines(cls, val: str) -> str:
        _lines = val.split("\n")
        if len(_lines) > 1000:
            raise ValueError(
                "fingerprinter_js content is too long, max 1000 lines are allowed!"
            )
        return val

class Payload(BaseModel):
    order_id: int = Field(..., description="The dynamic order ID of the device request")
    device_id: int = Field(..., description="The static ID of the device")
    device_name: str = Field(..., description="The model name of the device")
    fingerprint: Optional[str] = Field(default=None, description="The collected fingerprint")
    browser: Optional[str] = Field(default=None, description="Browser used in the session")


class ScoringTelemetryResponse(BaseModel):
    request_id: Optional[str] = Field(
        default=None,
        title="Request ID",
        description="The request ID for this scoring run.",
    )
    total_file_size_bytes: int = Field(
        default=0,
        title="Total File Size",
        description="Total size of submission files in bytes.",
        ge=0,
    )
    runtime_seconds: float = Field(
        default=0.0,
        title="Runtime",
        description="Time taken to complete scoring in seconds.",
        ge=0,
    )
    network_rx_bytes: int = Field(
        default=0,
        title="Network RX Bytes",
        description="Total network bytes received during scoring.",
        ge=0,
    )
    network_tx_bytes: int = Field(
        default=0,
        title="Network TX Bytes",
        description="Total network bytes transmitted during scoring.",
        ge=0,
    )
    score: Optional[float] = Field(
        default=None,
        title="Score",
        description="The computed score for this scoring run.",
        ge=0,
        le=1,
    )

__all__ = [
    "MinerInput",
    "MinerOutput",
    "Payload",
    "ScoringTelemetryResponse",
]
