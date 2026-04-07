import hashlib
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.api.app import AppContainer, get_container
from vaultkey.shared.database import get_session


async def get_db() -> AsyncSession:
    async for session in get_session():
        return session
    raise RuntimeError("no session")


async def get_actor_id(
    authorization: str | None = Header(default=None),
    container: AppContainer = Depends(get_container),
    session: AsyncSession = Depends(get_db),
) -> UUID:
    if not authorization:
        raise HTTPException(status_code=401, detail="missing authorization")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="invalid authorization")
    try:
        payload = container.jwt.decode_token(token)
        return UUID(payload.sub)
    except ValueError:
        api_token = await container.api_tokens.verify_token(session, token)
        if api_token is None:
            raise HTTPException(status_code=401, detail="invalid token") from None
        return api_token.user_id


def require_scope(scope: str):
    async def _checker(
        authorization: str | None = Header(default=None),
        container: AppContainer = Depends(get_container),
        session: AsyncSession = Depends(get_db),
    ) -> None:
        if not authorization:
            raise HTTPException(status_code=401, detail="missing authorization")
        _, _, token = authorization.partition(" ")
        try:
            payload = container.jwt.decode_token(token)
            from vaultkey.auth.rbac import scopes_allow

            if not scopes_allow(payload.scopes, scope):
                raise HTTPException(status_code=403, detail="forbidden")
            return
        except ValueError:
            api_token = await container.api_tokens.verify_token(session, token)
            if api_token is None:
                raise HTTPException(status_code=401, detail="invalid token")
            from vaultkey.auth.rbac import scopes_allow

            if not scopes_allow(api_token.scopes, scope):
                raise HTTPException(status_code=403, detail="forbidden")

    return _checker


def compute_etag(secret_id: UUID, version: int) -> str:
    return hashlib.sha256(f"{secret_id}:{version}".encode()).hexdigest()
