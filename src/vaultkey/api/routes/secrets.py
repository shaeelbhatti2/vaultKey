import hashlib
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.api.deps import get_actor_id, get_container, get_db, require_scope
from vaultkey.api.app import AppContainer
from vaultkey.shared.domain import SecretCreate, SecretMetadataRead, SecretVersionRead


router = APIRouter(prefix="/v1/secrets", tags=["secrets"])


class SecretWriteBody(BaseModel):
    payload: str = Field(min_length=1)
    secret_type: str = "generic"
    metadata: dict[str, str] = Field(default_factory=dict)


class SecretListResponse(BaseModel):
    items: list[SecretMetadataRead]
    next_cursor: str | None = None


@router.get("")
async def list_secrets(
    prefix: str = Query(default=""),
    environment_id: UUID = Query(...),
    container: AppContainer = Depends(get_container),
    session: AsyncSession = Depends(get_db),
    _: None = Depends(require_scope("read:secrets")),
) -> SecretListResponse:
    from vaultkey.secrets.environments import EnvironmentSecretService

    svc = EnvironmentSecretService()
    items = await svc.list_by_prefix(session, environment_id, prefix)
    return SecretListResponse(items=items)


@router.get("/{path:path}")
async def get_secret(
    path: str,
    environment_id: UUID = Query(...),
    version: int | None = Query(default=None),
    container: AppContainer = Depends(get_container),
    session: AsyncSession = Depends(get_db),
    _: None = Depends(require_scope("read:secrets")),
) -> dict[str, str | int]:
    plaintext = await container.secret_versions.decrypt_version(session, environment_id, path, version)
    meta = await container.secrets.get_metadata(session, environment_id, path)
    if meta is None:
        raise HTTPException(status_code=404, detail="not found")
    etag = hashlib.sha256(f"{meta.id}:{meta.current_version}".encode()).hexdigest()
    return {"path": meta.path, "version": meta.current_version, "payload": plaintext, "etag": etag}


@router.post("/{path:path}")
async def upsert_secret(
    path: str,
    body: SecretWriteBody,
    environment_id: UUID = Query(...),
    actor_id: UUID = Depends(get_actor_id),
    container: AppContainer = Depends(get_container),
    session: AsyncSession = Depends(get_db),
    _: None = Depends(require_scope("write:secrets")),
) -> SecretMetadataRead:
    existing = await container.secrets.get_metadata(session, environment_id, path)
    if existing is None:
        data = SecretCreate(path=path, payload=body.payload, metadata=body.metadata)
        from vaultkey.shared.domain import SecretType

        data.secret_type = SecretType(body.secret_type)
        return await container.secrets.create_secret(session, environment_id, actor_id, data)
    return await container.secret_versions.update_secret(
        session, environment_id, actor_id, path, body.payload, body.metadata
    )


@router.delete("/{path:path}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_secret(
    path: str,
    environment_id: UUID = Query(...),
    container: AppContainer = Depends(get_container),
    session: AsyncSession = Depends(get_db),
    _: None = Depends(require_scope("write:secrets")),
) -> Response:
    await container.secret_versions.soft_delete(session, environment_id, path)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{path:path}/versions")
async def list_versions(
    path: str,
    environment_id: UUID = Query(...),
    container: AppContainer = Depends(get_container),
    session: AsyncSession = Depends(get_db),
    _: None = Depends(require_scope("read:secrets")),
) -> list[SecretVersionRead]:
    return await container.secret_versions.list_versions(session, environment_id, path)
