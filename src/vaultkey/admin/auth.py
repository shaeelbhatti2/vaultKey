import secrets
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.admin.app import get_templates
from vaultkey.shared.database import get_session


async def get_db() -> AsyncSession:
    async for session in get_session():
        return session
    raise RuntimeError("no session")


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def verify_csrf(request: Request, form_token: str | None) -> None:
    expected = request.session.get("csrf_token")
    if not expected or not form_token or not secrets.compare_digest(expected, form_token):
        raise HTTPException(status_code=403, detail="csrf failed")


async def require_admin_session(request: Request) -> UUID:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="login required")
    return UUID(user_id)


async def login_page(request: Request) -> HTMLResponse:
    templates = get_templates(request)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "csrf_token": csrf_token(request)},
    )


async def login_submit(
    request: Request,
    session: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    form = await request.form()
    verify_csrf(request, str(form.get("csrf_token", "")))
    email = str(form.get("email", ""))
    if not email:
        raise HTTPException(status_code=400, detail="email required")
    request.session["user_id"] = "00000000-0000-0000-0000-000000000001"
    request.session["email"] = email
    return RedirectResponse(url="/admin/dashboard", status_code=303)
