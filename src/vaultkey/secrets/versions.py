from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.secrets.service import SecretService
from vaultkey.shared.db_models import SecretModel, SecretVersionModel
from vaultkey.shared.domain import SecretCreate, SecretMetadataRead, SecretVersionRead
from vaultkey.shared.value_objects import EncryptedBlob, SecretPath


class SecretVersionService:
    def __init__(self, base: SecretService | None = None) -> None:
        self._base = base or SecretService()

    async def update_secret(
        self,
        session: AsyncSession,
        environment_id: UUID,
        actor_id: UUID,
        path: str,
        payload: str,
        metadata: dict[str, str] | None = None,
    ) -> SecretMetadataRead:
        secret = await self._require_secret(session, environment_id, path)
        new_version = secret.current_version + 1
        blob = self._base._crypto.encrypt_payload(payload.encode("utf-8"), secret.id.bytes)
        version = SecretVersionModel(
            secret_id=secret.id,
            version=new_version,
            ciphertext=blob.ciphertext,
            nonce=blob.nonce,
            wrapped_dek=blob.wrapped_dek,
            key_version=blob.key_version,
            metadata_json=metadata or secret.metadata_json,
            created_by=actor_id,
        )
        secret.current_version = new_version
        secret.updated_at = datetime.now(UTC)
        if metadata:
            secret.metadata_json = metadata
        session.add(version)
        await session.flush()
        return self._base._to_metadata(secret)

    async def soft_delete(
        self,
        session: AsyncSession,
        environment_id: UUID,
        path: str,
    ) -> None:
        secret = await self._require_secret(session, environment_id, path)
        secret.deleted_at = datetime.now(UTC)

    async def restore(
        self,
        session: AsyncSession,
        environment_id: UUID,
        path: str,
    ) -> SecretMetadataRead:
        normalized = SecretPath(value=path).value
        result = await session.execute(
            select(SecretModel).where(
                SecretModel.environment_id == environment_id,
                SecretModel.path == normalized,
            )
        )
        secret = result.scalar_one_or_none()
        if secret is None:
            raise LookupError("secret not found")
        secret.deleted_at = None
        return self._base._to_metadata(secret)

    async def rollback(
        self,
        session: AsyncSession,
        environment_id: UUID,
        path: str,
        target_version: int,
    ) -> SecretMetadataRead:
        secret = await self._require_secret(session, environment_id, path)
        if target_version >= secret.current_version:
            raise ValueError("cannot rollback to current or future version")
        version = await self._get_version(session, secret.id, target_version)
        if version is None:
            raise LookupError("version not found")
        secret.current_version = target_version
        secret.metadata_json = version.metadata_json
        secret.updated_at = datetime.now(UTC)
        return self._base._to_metadata(secret)

    async def list_versions(
        self,
        session: AsyncSession,
        environment_id: UUID,
        path: str,
    ) -> list[SecretVersionRead]:
        secret = await self._require_secret(session, environment_id, path)
        result = await session.execute(
            select(SecretVersionModel)
            .where(SecretVersionModel.secret_id == secret.id)
            .order_by(SecretVersionModel.version.desc())
        )
        return [
            SecretVersionRead(
                id=v.id,
                secret_id=v.secret_id,
                version=v.version,
                created_at=v.created_at,
                created_by=v.created_by,
                metadata=v.metadata_json,
            )
            for v in result.scalars()
        ]

    async def decrypt_version(
        self,
        session: AsyncSession,
        environment_id: UUID,
        path: str,
        version_num: int | None = None,
    ) -> str:
        secret = await self._require_secret(session, environment_id, path)
        version_number = version_num or secret.current_version
        version = await self._get_version(session, secret.id, version_number)
        if version is None:
            raise LookupError("version not found")
        blob = EncryptedBlob(
            ciphertext=version.ciphertext,
            nonce=version.nonce,
            wrapped_dek=version.wrapped_dek,
            key_version=version.key_version,
        )
        plaintext = self._base._crypto.decrypt_payload(blob, secret.id.bytes)
        return plaintext.decode("utf-8")

    async def _require_secret(
        self,
        session: AsyncSession,
        environment_id: UUID,
        path: str,
    ) -> SecretModel:
        normalized = SecretPath(value=path).value
        result = await session.execute(
            select(SecretModel).where(
                SecretModel.environment_id == environment_id,
                SecretModel.path == normalized,
                SecretModel.deleted_at.is_(None),
            )
        )
        secret = result.scalar_one_or_none()
        if secret is None:
            raise LookupError("secret not found")
        return secret

    async def _get_version(
        self,
        session: AsyncSession,
        secret_id: UUID,
        version: int,
    ) -> SecretVersionModel | None:
        result = await session.execute(
            select(SecretVersionModel).where(
                SecretVersionModel.secret_id == secret_id,
                SecretVersionModel.version == version,
            )
        )
        return result.scalar_one_or_none()
