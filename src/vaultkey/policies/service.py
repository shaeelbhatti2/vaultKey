from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.shared.db_models import AccessPolicyModel
from vaultkey.shared.domain import AccessPolicyCreate, AccessPolicyRead, RoleName


class AccessPolicyService:
    async def create(
        self,
        session: AsyncSession,
        workspace_id: UUID,
        data: AccessPolicyCreate,
    ) -> AccessPolicyRead:
        model = AccessPolicyModel(
            workspace_id=workspace_id,
            name=data.name,
            path_prefix=data.path_prefix.strip("/"),
            role=data.role.value,
            can_read=data.can_read,
            can_write=data.can_write,
        )
        session.add(model)
        await session.flush()
        return self._to_read(model)

    async def list_for_workspace(
        self,
        session: AsyncSession,
        workspace_id: UUID,
    ) -> list[AccessPolicyRead]:
        result = await session.execute(
            select(AccessPolicyModel).where(AccessPolicyModel.workspace_id == workspace_id)
        )
        return [self._to_read(p) for p in result.scalars()]

    async def delete(self, session: AsyncSession, policy_id: UUID) -> None:
        result = await session.execute(select(AccessPolicyModel).where(AccessPolicyModel.id == policy_id))
        model = result.scalar_one_or_none()
        if model is not None:
            await session.delete(model)

    def _to_read(self, model: AccessPolicyModel) -> AccessPolicyRead:
        return AccessPolicyRead(
            id=model.id,
            workspace_id=model.workspace_id,
            name=model.name,
            path_prefix=model.path_prefix,
            role=RoleName(model.role),
            can_read=model.can_read,
            can_write=model.can_write,
        )
