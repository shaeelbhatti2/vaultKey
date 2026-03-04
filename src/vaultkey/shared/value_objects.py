from dataclasses import dataclass
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class SecretPath(BaseModel):
    value: str = Field(min_length=1, max_length=512)

    @field_validator("value")
    @classmethod
    def validate_path(cls, raw: str) -> str:
        normalized = raw.strip().strip("/")
        if not normalized:
            raise ValueError("path cannot be empty")
        if ".." in normalized.split("/"):
            raise ValueError("path traversal not allowed")
        if any(part.startswith(".") for part in normalized.split("/")):
            raise ValueError("hidden path segments not allowed")
        return normalized

    def join(self, suffix: str) -> "SecretPath":
        return SecretPath(value=f"{self.value}/{suffix.strip('/')}")

    def parent(self) -> "SecretPath | None":
        parts = self.value.split("/")
        if len(parts) <= 1:
            return None
        return SecretPath(value="/".join(parts[:-1]))

    def matches_prefix(self, prefix: str) -> bool:
        clean = prefix.strip("/")
        return self.value == clean or self.value.startswith(f"{clean}/")


class SecretRef(BaseModel):
    organization_id: UUID
    workspace_id: UUID
    environment_id: UUID
    path: SecretPath
    version: int | None = None

    @property
    def qualified(self) -> str:
        version_part = f"@v{self.version}" if self.version else ""
        return f"{self.organization_id}/{self.workspace_id}/{self.environment_id}/{self.path.value}{version_part}"


@dataclass(frozen=True)
class EncryptedBlob:
    ciphertext: bytes
    nonce: bytes
    wrapped_dek: bytes
    algorithm: str = "aes-256-gcm"
    key_version: int = 1

    def as_dict(self) -> dict[str, str | int]:
        import base64

        return {
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "wrapped_dek": base64.b64encode(self.wrapped_dek).decode("ascii"),
            "algorithm": self.algorithm,
            "key_version": self.key_version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str | int]) -> "EncryptedBlob":
        import base64

        return cls(
            ciphertext=base64.b64decode(str(data["ciphertext"])),
            nonce=base64.b64decode(str(data["nonce"])),
            wrapped_dek=base64.b64decode(str(data["wrapped_dek"])),
            algorithm=str(data.get("algorithm", "aes-256-gcm")),
            key_version=int(data.get("key_version", 1)),
        )
