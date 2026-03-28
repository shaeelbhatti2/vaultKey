from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.crypto.envelope import EnvelopeCrypto
from vaultkey.shared.db_models import SecretModel, SecretVersionModel
from vaultkey.shared.domain import SecretCreate, SecretMetadataRead, SecretType
from vaultkey.shared.settings import get_settings
from vaultkey.shared.value_objects import SecretPath


class SecretService:
    def __init__(self, crypto: EnvelopeCrypto | None = None) -> None:
        settings = get_settings()
        self._crypto = crypto or EnvelopeCrypto(settings.master_key)
        self._max_bytes = settings.max_secret_bytes

    async def create_secret(
        self,
        session: AsyncSession,
        environment_id: UUID,
        actor_id: UUID,
        data: SecretCreate,
    ) -> SecretMetadataRead:
        path = SecretPath(value=data.path)
        payload = data.payload.encode("utf-8")
        if len(payload) > self._max_bytes:
            raise ValueError("payload too large")

        existing = await session.execute(
            select(SecretModel).where(
                SecretModel.environment_id == environment_id,
                SecretModel.path == path.value,
                SecretModel.deleted_at.is_(None),
            )
        )
        if existing.scalar_one_or_none() is not None:
            raise ValueError("secret already exists")

        secret = SecretModel(
            environment_id=environment_id,
            path=path.value,
            secret_type=data.secret_type.value,
            current_version=1,
            metadata_json=data.metadata,
        )
        session.add(secret)
        await session.flush()

        blob = self._crypto.encrypt_payload(payload, secret.id.bytes)
        version = SecretVersionModel(
            secret_id=secret.id,
            version=1,
            ciphertext=blob.ciphertext,
            nonce=blob.nonce,
            wrapped_dek=blob.wrapped_dek,
            key_version=blob.key_version,
            metadata_json=data.metadata,
            created_by=actor_id,
        )
        session.add(version)
        await session.flush()
        return self._to_metadata(secret)

    async def get_metadata(
        self,
        session: AsyncSession,
        environment_id: UUID,
        path: str,
    ) -> SecretMetadataRead | None:
        secret = await self._find_secret(session, environment_id, path)
        if secret is None:
            return None
        return self._to_metadata(secret)

    async def _find_secret(
        self,
        session: AsyncSession,
        environment_id: UUID,
        path: str,
    ) -> SecretModel | None:
        normalized = SecretPath(value=path).value
        result = await session.execute(
            select(SecretModel).where(
                SecretModel.environment_id == environment_id,
                SecretModel.path == normalized,
                SecretModel.deleted_at.is_(None),
            )
        )
        return result.scalar_one_or_none()

    def _to_metadata(self, secret: SecretModel) -> SecretMetadataRead:
        return SecretMetadataRead(
            id=secret.id,
            path=secret.path,
            secret_type=SecretType(secret.secret_type),
            environment_id=secret.environment_id,
            current_version=secret.current_version,
            created_at=secret.created_at,
            updated_at=secret.updated_at,
            metadata=secret.metadata_json,
        )
