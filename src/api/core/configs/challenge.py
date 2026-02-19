# -*- coding: utf-8 -*-

from enum import Enum
from typing import Optional

from pydantic import (
    BaseModel,
    Field,
    constr,
    conint,
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
    id: int = Field(..., gt=0)  # type: ignore
    ts_node_id: str = Field(..., strip_whitespace=True, min_length=2, max_length=64)  # type: ignore
    ts_name: str = Field(..., strip_whitespace=True, min_length=2, max_length=64)  # type: ignore
    ts_ip: IPvAnyAddress = Field(...)
    device_model: Optional[str] = Field(default=None, strip_whitespace=True, min_length=2, max_length=64)  # type: ignore
    email: EmailStr = Field(...)
    browser: str = Field(..., strip_whitespace=True, min_length=2, max_length=64)  # type: ignore
    fingerprint: Optional[str] = Field(default=None, strip_whitespace=True, min_length=2, max_length=256)  # type: ignore
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
    fp_js_fname: str = Field(  # type: ignore
        ..., strip_whitespace=True, min_length=2, max_length=256
    )
    ts_api_token: SecretStr = Field(..., min_length=8, max_length=128)
    ts_tailnet: str = Field(..., strip_whitespace=True, min_length=2, max_length=256)  # type: ignore
    ts_device_tag: str = Field(  # type: ignore
        ..., strip_whitespace=True, min_length=2, max_length=64
    )
    ts_static_ip: IPvAnyAddress = Field(...)
    change_ts_ip: bool = Field(...)
    smtp_host: str = Field(..., strip_whitespace=True, min_length=2, max_length=256)  # type: ignore
    smtp_port: int = Field(..., ge=1, le=65535)  # type: ignore
    smtp_user: str = Field(..., strip_whitespace=True, min_length=2, max_length=256)  # type: ignore
    smtp_password: SecretStr = Field(..., min_length=8, max_length=128)
    email_sender: EmailStr = Field(...)
    n_repeat: int = Field(..., ge=1)  # type: ignore
    random_seed: Optional[int] = Field(default=None)
    fp_timeout: int = Field(..., ge=1)  # type: ignore
    proxy_inter_base_url: AnyHttpUrl = Field(...)
    proxy_exter_base_url: AnyHttpUrl = Field(...)
    devices_fname: str = Field(  # type: ignore
        ..., strip_whitespace=True, min_length=2, max_length=256
    )
    devices: list[DeviceConfig] = Field(default_factory=list)
    scoring: ScoringConfig = Field(...)

    model_config = SettingsConfigDict(env_prefix=f"{ENV_PREFIX}CHALLENGE_")


__all__ = [
    "ChallengeConfig",
    "DeviceConfig",
    "DevicePM",
    "DeviceStatusEnum",
    "DeviceStateEnum",
]
