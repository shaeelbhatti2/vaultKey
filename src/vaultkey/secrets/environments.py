from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.secrets.service import SecretService
from vaultkey.shared.db_models import EnvironmentModel, SecretModel
from vaultkey.shared.domain import SecretCreate, SecretMetadataRead
from vaultkey.shared.value_objects import SecretPath


class EnvironmentSecretService:
    def __init__(self) -> None:
        self._secrets = SecretService()

    async def list_by_prefix(
        self,
        session: AsyncSession,
        environment_id: UUID,
        prefix: str = "",
    ) -> list[SecretMetadataRead]:
        query = select(SecretModel).where(
            SecretModel.environment_id == environment_id,
            SecretModel.deleted_at.is_(None),
        )
        if prefix:
            normalized = SecretPath(value=prefix).value
            query = query.where(SecretModel.path.startswith(normalized))
        result = await session.execute(query.order_by(SecretModel.path))
        return [self._secrets._to_metadata(s) for s in result.scalars()]

    async def clone_to_environment(
        self,
        session: AsyncSession,
        source_env_id: UUID,
        target_env_id: UUID,
        path: str,
        actor_id: UUID,
        new_path: str | None = None,
    ) -> SecretMetadataRead:
        from vaultkey.secrets.versions import SecretVersionService

        versions = SecretVersionService(self._secrets)
        payload = await versions.decrypt_version(session, source_env_id, path)
        meta = await self._secrets.get_metadata(session, source_env_id, path)
        if meta is None:
            raise LookupError("source secret not found")
        target_path = new_path or path
        return await self._secrets.create_secret(
            session,
            target_env_id,
            actor_id,
            SecretCreate(path=target_path, secret_type=meta.secret_type, payload=payload, metadata=meta.metadata),
        )

    async def get_environment_chain(
        self,
        session: AsyncSession,
        environment_id: UUID,
    ) -> tuple[UUID, UUID, UUID]:
        result = await session.execute(
            select(EnvironmentModel).where(EnvironmentModel.id == environment_id)
        )
        env = result.scalar_one_or_none()
        if env is None:
            raise LookupError("environment not found")
        return env.id, env.workspace_id, env.workspace_id
