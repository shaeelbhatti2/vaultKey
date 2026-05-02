from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.admin.app import get_templates
from vaultkey.admin.auth import get_db, require_admin_session
from vaultkey.policies.service import AccessPolicyService
from vaultkey.shared.db_models import MembershipModel, UserModel


router = APIRouter(prefix="/admin/users", tags=["admin-users"])


@router.get("", response_class=HTMLResponse)
async def users_page(
    request: Request,
    workspace_id: UUID,
    session: AsyncSession = Depends(get_db),
    _: object = Depends(require_admin_session),
) -> HTMLResponse:
    templates = get_templates(request)
    users = await session.execute(select(UserModel).order_by(UserModel.email))
    memberships = await session.execute(
        select(MembershipModel).where(MembershipModel.organization_id == workspace_id)
    )
    policies = await AccessPolicyService().list_for_workspace(session, workspace_id)
    return templates.TemplateResponse(
        "users.html",
        {
            "request": request,
            "users": users.scalars().all(),
            "memberships": memberships.scalars().all(),
            "policies": policies,
        },
    )
