from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.admin.app import get_templates
from vaultkey.admin.auth import get_db, require_admin_session
from vaultkey.shared.db_models import AuditLogEntryModel, RotationPolicyModel, SecretModel

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    session: AsyncSession = Depends(get_db),
    _: object = Depends(require_admin_session),
) -> HTMLResponse:
    templates = get_templates(request)
    since = datetime.now(UTC) - timedelta(days=7)
    recent_count = await session.scalar(
        select(func.count()).select_from(AuditLogEntryModel).where(AuditLogEntryModel.created_at >= since)
    )
    expiring = await session.scalar(
        select(func.count()).select_from(RotationPolicyModel).where(
            RotationPolicyModel.next_due_at.is_not(None),
            RotationPolicyModel.next_due_at <= datetime.now(UTC) + timedelta(days=30),
        )
    )
    secret_count = await session.scalar(
        select(func.count()).select_from(SecretModel).where(SecretModel.deleted_at.is_(None))
    )
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "recent_access": recent_count or 0,
            "expiring_secrets": expiring or 0,
            "secret_count": secret_count or 0,
        },
    )
