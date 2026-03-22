from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.auth.rbac import PermissionChecker
from vaultkey.shared.db_models import AccessPolicyModel, MembershipModel
from vaultkey.shared.domain import RoleName
from vaultkey.shared.value_objects import SecretPath


class PolicyEvaluator:
    def __init__(self) -> None:
        self._checker = PermissionChecker()

    async def resolve_role(
        self,
        session: AsyncSession,
        user_id: UUID,
        organization_id: UUID,
    ) -> RoleName:
        result = await session.execute(
            select(MembershipModel).where(
                MembershipModel.user_id == user_id,
                MembershipModel.organization_id == organization_id,
            )
        )
        membership = result.scalar_one_or_none()
        if membership is None:
            raise PermissionError("not a member of organization")
        return RoleName(membership.role)

    async def evaluate_read(
        self,
        session: AsyncSession,
        workspace_id: UUID,
        role: RoleName,
        secret_path: SecretPath,
    ) -> bool:
        policies = await self._load_policies(session, workspace_id)
        if not policies:
            return self._checker.can_read_path(role, "", secret_path.value)
        return any(
            self._checker.can_read_path(role, policy.path_prefix, secret_path.value)
            for policy in policies
            if RoleName(policy.role) == role or role_at_least(role, RoleName(policy.role))
        )

    async def evaluate_write(
        self,
        session: AsyncSession,
        workspace_id: UUID,
        role: RoleName,
        secret_path: SecretPath,
    ) -> bool:
        policies = await self._load_policies(session, workspace_id)
        if not policies:
            return role_at_least(role, RoleName.OPERATOR)
        return any(
            self._checker.can_write_path(role, policy.path_prefix, secret_path.value, policy.can_write)
            for policy in policies
        )

    async def _load_policies(self, session: AsyncSession, workspace_id: UUID) -> list[AccessPolicyModel]:
        result = await session.execute(
            select(AccessPolicyModel).where(AccessPolicyModel.workspace_id == workspace_id)
        )
        return list(result.scalars())


def role_at_least(actual: RoleName, required: RoleName) -> bool:
    from vaultkey.auth.rbac import role_at_least as _role_at_least

    return _role_at_least(actual, required)
