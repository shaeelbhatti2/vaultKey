from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.auth.jwt import JwtService
from vaultkey.auth.passwords import PasswordService
from vaultkey.auth.tokens import ApiTokenService
from vaultkey.crypto.envelope import EnvelopeCrypto
from vaultkey.secrets.service import SecretService
from vaultkey.secrets.versions import SecretVersionService
from vaultkey.shared.database import get_session
from vaultkey.shared.logging import setup_logging
from vaultkey.shared.settings import Settings, get_settings


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    setup_logging()
    yield


def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    return get_session()


class AppContainer:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.crypto = EnvelopeCrypto(self.settings.master_key)
        self.passwords = PasswordService()
        self.jwt = JwtService()
        self.api_tokens = ApiTokenService()
        self.secrets = SecretService(self.crypto)
        self.secret_versions = SecretVersionService(self.secrets)


_container: AppContainer | None = None


def get_container() -> AppContainer:
    global _container
    if _container is None:
        _container = AppContainer()
    return _container


def create_app() -> FastAPI:
    from vaultkey.api.etag import ETagMiddleware
    from vaultkey.api.routes.secrets import router as secrets_router

    app = FastAPI(title="VaultKey", version="0.1.0", lifespan=lifespan)
    app.state.container = get_container()
    app.add_middleware(ETagMiddleware)
    app.include_router(secrets_router)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
