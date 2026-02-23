# -*- coding: utf-8 -*-

from enum import Enum
from typing import Optional

from pydantic import (
    BaseModel,
    Field,
    SecretStr,
    IPvAnyAddress,
    AnyHttpUrl,
    EmailStr,
)
from pydantic_settings import SettingsConfigDict

from api.core.constants import ENV_PREFIX
from ._base import FrozenBaseConfig


class DeviceStatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class DeviceStateEnum(str, Enum):
    NOT_SET = "NOT_SET"
    READY = "READY"
    RUNNING = "RUNNING"
    TIMEOUT = "TIMEOUT"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"
    ERROR = "ERROR"


class DevicePM(BaseModel):
    id: int = Field(..., gt=0)
    ts_node_id: str = Field(..., strip_whitespace=True, min_length=2, max_length=64)
    ts_name: str = Field(..., strip_whitespace=True, min_length=2, max_length=64)
    ts_ip: IPvAnyAddress = Field(...)
    device_model: Optional[str] = Field(
        default=None, strip_whitespace=True, min_length=2, max_length=64
    )
    email: EmailStr = Field(...)
    browser: str = Field(..., strip_whitespace=True, min_length=2, max_length=64)
    fingerprint: Optional[str] = Field(
        default=None, strip_whitespace=True, min_length=2, max_length=256
    )
    state: DeviceStateEnum = Field(default=DeviceStateEnum.NOT_SET)
    status: DeviceStatusEnum = Field(default=DeviceStatusEnum.ACTIVE)


class DeviceConfig(DevicePM, FrozenBaseConfig):
    pass


class ScoringConfig(FrozenBaseConfig):
    min_devices: int = Field(default=2, ge=1)
    fragmentation_penalty: float = Field(default=0.3)
    collision_penalty: float = Field(default=0.25)
    max_fragmentation: int = Field(default=3, ge=1)
    max_collision: int = Field(default=3, ge=1)

    model_config = SettingsConfigDict(env_prefix=f"{ENV_PREFIX}SCORING_")


class ChallengeConfig(FrozenBaseConfig):
    api_key: SecretStr = Field(..., min_length=8, max_length=128)
    ts_api_token: SecretStr = Field(..., min_length=8, max_length=128)
    ts_tailnet: str = Field(..., strip_whitespace=True, min_length=2, max_length=256)
    smtp_host: str = Field(..., strip_whitespace=True, min_length=2, max_length=256)
    smtp_port: int = Field(..., ge=1, le=65535)
    smtp_user: str = Field(..., strip_whitespace=True, min_length=2, max_length=256)
    smtp_password: SecretStr = Field(..., min_length=8, max_length=128)
    email_sender: EmailStr = Field(...)
    n_repeat: int = Field(..., ge=1)
    fp_timeout: int = Field(..., ge=1)
    proxy_inter_base_url: AnyHttpUrl = Field(...)
    devices_fname: str = Field(..., strip_whitespace=True, min_length=2, max_length=256)
    devices: list[DeviceConfig] = Field(default_factory=list)
    scoring: ScoringConfig = Field(...)
    browser_names: list[str] = Field(
        default_factory=list, strip_whitespace=True, min_length=2, max_length=64
    )
    model_config = SettingsConfigDict(env_prefix=f"{ENV_PREFIX}CHALLENGE_")


__all__ = [
    "ChallengeConfig",
    "DeviceConfig",
    "DevicePM",
    "DeviceStatusEnum",
    "DeviceStateEnum",
]
