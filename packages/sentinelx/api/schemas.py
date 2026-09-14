"""Request and response schemas.

Inputs are strict: unknown fields are rejected, strings have length bounds, and
enumerations are real enums, so malformed input fails at the edge with a 422
instead of reaching a service.  Response shapes for large domain objects are left
as dictionaries produced by the shared serialisers (see
:mod:`sentinelx.events.serialize`), so the REST payload, the WebSocket payload and
the CLI's ``--json`` output are identical by construction.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sentinelx.common.enums import IncidentStatus, UserRole

__all__ = [
    "BlockRequest",
    "ChangePasswordRequest",
    "ConfigUpdateRequest",
    "DetectionStatusRequest",
    "IncidentUpdateRequest",
    "LoginRequest",
    "Message",
    "RejectRequest",
    "ReplayRequest",
    "RuleDefinitionRequest",
    "RuleEnabledRequest",
    "RuleTestRequest",
    "SafetyCheckRequest",
    "SensorStartRequest",
    "TokenResponse",
    "UnblockRequest",
    "UserCreateRequest",
    "UserResponse",
    "UserUpdateRequest",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Message(BaseModel):
    message: str


class LoginRequest(StrictModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserResponse(BaseModel):
    id: int
    username: str
    role: UserRole
    is_active: bool = True
    must_change_password: bool = False
    last_login_at: str | None = None
    created_at: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str | None = Field(
        default=None, description="Returned only to non-browser clients; browsers receive an httpOnly cookie."
    )
    token_type: Literal["bearer"] = "bearer"
    expires_at: str
    user: UserResponse
    csrf_token: str | None = None


class ChangePasswordRequest(StrictModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class UserCreateRequest(StrictModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=1, max_length=256)
    role: UserRole = UserRole.VIEWER


class UserUpdateRequest(StrictModel):
    role: UserRole | None = None
    is_active: bool | None = None


class PasswordResetRequest(StrictModel):
    new_password: str = Field(min_length=1, max_length=256)


class DetectionStatusRequest(StrictModel):
    status: Literal["new", "acknowledged", "false_positive", "resolved"]


class IncidentUpdateRequest(StrictModel):
    status: IncidentStatus | None = None
    assigned_to: str | None = Field(default=None, max_length=64)
    notes: str | None = Field(default=None, max_length=10_000)


class BlockRequest(StrictModel):
    target: str = Field(min_length=2, max_length=64, description="IP address or CIDR prefix.")
    reason: str = Field(min_length=3, max_length=500)
    duration_seconds: int | None = Field(default=None, ge=30, le=604_800, description="Omit for a permanent block.")
    rate_limit: bool = False


class UnblockRequest(StrictModel):
    target: str = Field(min_length=2, max_length=64)
    reason: str = Field(min_length=3, max_length=500)


class SafetyCheckRequest(StrictModel):
    target: str = Field(min_length=1, max_length=64)


class RejectRequest(StrictModel):
    reason: str = Field(default="", max_length=500)


class AllowlistRequest(StrictModel):
    networks: list[str] = Field(max_length=1000)


class RuleDefinitionRequest(StrictModel):
    definition: str = Field(min_length=10, max_length=20_000, description="The rule in YAML.")


class RuleEnabledRequest(StrictModel):
    enabled: bool


class RuleTestRequest(StrictModel):
    definition: str = Field(min_length=10, max_length=20_000)
    scenario: str | None = Field(default=None, max_length=64)
    pcap_path: str | None = Field(default=None, max_length=512)


class ConfigUpdateRequest(StrictModel):
    changes: dict[str, Any] = Field(min_length=1)
    confirmation: str | None = Field(default=None, max_length=64)


class SensorStartRequest(StrictModel):
    interface: str | None = Field(default=None, max_length=32, pattern=r"^[A-Za-z0-9_.:@-]+$")
    bpf_filter: str | None = Field(default=None, max_length=512)

    @field_validator("bpf_filter")
    @classmethod
    def _bpf(cls, value: str | None) -> str | None:
        if value and set(";|`$\n\r\\") & set(value):
            raise ValueError("BPF filter contains forbidden characters")
        return value


class ReplayRequest(StrictModel):
    path: str = Field(min_length=1, max_length=512)
    speed: float = Field(default=0.0, ge=0, le=100)
    limit: int | None = Field(default=None, ge=1, le=100_000_000)


class ScenarioRequest(StrictModel):
    params: dict[str, int | float | str] = Field(default_factory=dict, max_length=10)
