from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class RoleName(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    OPERATOR = "operator"
    AUDITOR = "auditor"
    READONLY = "readonly"


class SecretType(str, Enum):
    GENERIC = "generic"
    API_KEY = "api_key"
    DB_CREDENTIAL = "db_credential"
    CERTIFICATE = "certificate"
    SSH_KEY = "ssh_key"


class EnvironmentKind(str, Enum):
    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"
    CUSTOM = "custom"


class AuditSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AuditAction(str, Enum):
    SECRET_READ = "secret.read"
    SECRET_WRITE = "secret.write"
    SECRET_DELETE = "secret.delete"
    SECRET_ROLLBACK = "secret.rollback"
    POLICY_CHANGE = "policy.change"
    LOGIN = "auth.login"
    LOGOUT = "auth.logout"
    TOKEN_CREATE = "token.create"
    TOKEN_REVOKE = "token.revoke"
    BREAK_GLASS_GRANT = "break_glass.grant"
    BREAK_GLASS_USE = "break_glass.use"


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    slug: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9-]+$")


class OrganizationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str
    created_at: datetime


class WorkspaceCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    slug: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9-]+$")


class WorkspaceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    name: str
    slug: str
    created_at: datetime


class EnvironmentCreate(BaseModel):
    name: str = Field(min_length=2, max_length=64)
    kind: EnvironmentKind = EnvironmentKind.CUSTOM


class EnvironmentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    workspace_id: UUID
    name: str
    kind: EnvironmentKind
    created_at: datetime


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    full_name: str = Field(min_length=1, max_length=120)


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    full_name: str
    is_active: bool
    created_at: datetime


class RoleAssignment(BaseModel):
    user_id: UUID
    role: RoleName
    workspace_id: UUID | None = None


class SecretCreate(BaseModel):
    path: str = Field(min_length=1, max_length=512)
    secret_type: SecretType = SecretType.GENERIC
    payload: str = Field(min_length=1)
    metadata: dict[str, str] = Field(default_factory=dict)


class SecretMetadataRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    path: str
    secret_type: SecretType
    environment_id: UUID
    current_version: int
    created_at: datetime
    updated_at: datetime
    metadata: dict[str, str]


class SecretVersionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    secret_id: UUID
    version: int
    created_at: datetime
    created_by: UUID
    metadata: dict[str, str]


class ApiTokenCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    scopes: list[str] = Field(min_length=1)
    expires_at: datetime | None = None


class ApiTokenRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    scopes: list[str]
    prefix: str
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None


class RotationPolicyCreate(BaseModel):
    secret_id: UUID
    interval_days: int = Field(ge=1, le=3650)
    notify_before_days: int = Field(ge=1, le=90)


class RotationPolicyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    secret_id: UUID
    interval_days: int
    notify_before_days: int
    last_rotated_at: datetime | None
    next_due_at: datetime | None


class BreakGlassRequestCreate(BaseModel):
    secret_path: str = Field(min_length=1, max_length=512)
    reason: str = Field(min_length=10, max_length=2000)
    ttl_minutes: int = Field(default=60, ge=5, le=480)


class BreakGlassRequestRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    requester_id: UUID
    secret_path: str
    reason: str
    status: str
    approved_by: UUID | None
    expires_at: datetime | None
    created_at: datetime


class AccessPolicyCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    path_prefix: str = Field(min_length=1, max_length=512)
    role: RoleName
    can_read: bool = True
    can_write: bool = False


class AccessPolicyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    workspace_id: UUID
    name: str
    path_prefix: str
    role: RoleName
    can_read: bool
    can_write: bool


class AuditLogEntryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    actor_id: UUID | None
    action: AuditAction
    severity: AuditSeverity
    resource_path: str | None
    details: dict[str, str]
    entry_hash: str
    previous_hash: str | None
    created_at: datetime
