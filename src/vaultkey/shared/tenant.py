from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.shared.db_models import EnvironmentModel, OrganizationModel, WorkspaceModel


class TenantContext:
    def __init__(
        self,
        organization_id: UUID,
        workspace_id: UUID,
        environment_id: UUID,
    ) -> None:
        self.organization_id = organization_id
        self.workspace_id = workspace_id
        self.environment_id = environment_id


class TenantService:
    async def resolve_context(
        self,
        session: AsyncSession,
        org_slug: str,
        workspace_slug: str,
        environment_name: str,
    ) -> TenantContext:
        org_result = await session.execute(
            select(OrganizationModel).where(OrganizationModel.slug == org_slug)
        )
        org = org_result.scalar_one_or_none()
        if org is None:
            raise LookupError("organization not found")

        ws_result = await session.execute(
            select(WorkspaceModel).where(
                WorkspaceModel.organization_id == org.id,
                WorkspaceModel.slug == workspace_slug,
            )
        )
        workspace = ws_result.scalar_one_or_none()
        if workspace is None:
            raise LookupError("workspace not found")

        env_result = await session.execute(
            select(EnvironmentModel).where(
                EnvironmentModel.workspace_id == workspace.id,
                EnvironmentModel.name == environment_name,
            )
        )
        environment = env_result.scalar_one_or_none()
        if environment is None:
            raise LookupError("environment not found")

        return TenantContext(org.id, workspace.id, environment.id)

    async def assert_org_access(
        self,
        session: AsyncSession,
        user_org_id: UUID,
        target_org_id: UUID,
    ) -> None:
        if user_org_id != target_org_id:
            raise PermissionError("cross-tenant access denied")
