from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.admin.app import get_templates
from vaultkey.admin.auth import get_db, require_admin_session
from vaultkey.shared.db_models import SecretModel


router = APIRouter(prefix="/admin/secrets", tags=["admin-secrets"])


def build_tree(paths: list[str]) -> dict:
    root: dict = {}
    for path in sorted(paths):
        node = root
        for part in path.split("/"):
            node = node.setdefault(part, {})
    return root


@router.get("", response_class=HTMLResponse)
async def secrets_browser(
    request: Request,
    environment_id: UUID = Query(...),
    session: AsyncSession = Depends(get_db),
    _: object = Depends(require_admin_session),
) -> HTMLResponse:
    templates = get_templates(request)
    result = await session.execute(
        select(SecretModel.path).where(
            SecretModel.environment_id == environment_id,
            SecretModel.deleted_at.is_(None),
        )
    )
    paths = [row[0] for row in result.all()]
    return templates.TemplateResponse(
        "secrets.html",
        {"request": request, "tree": build_tree(paths), "environment_id": str(environment_id)},
    )
