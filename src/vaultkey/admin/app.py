from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from vaultkey.shared.settings import get_settings

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


def mount_admin(app: FastAPI) -> None:
    settings = get_settings()
    app.add_middleware(SessionMiddleware, secret_key=settings.jwt_secret)
    if STATIC_DIR.exists():
        app.mount("/admin/static", StaticFiles(directory=STATIC_DIR), name="admin-static")
    app.state.admin_templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def get_templates(request: Request) -> Jinja2Templates:
    return request.app.state.admin_templates
