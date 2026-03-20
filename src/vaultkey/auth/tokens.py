import hashlib
import hmac
import secrets
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.shared.db_models import ApiTokenModel


class ApiTokenService:
    PREFIX_LEN = 8

    def generate_token(self) -> tuple[str, str, str]:
        raw = secrets.token_urlsafe(32)
        prefix = raw[: self.PREFIX_LEN]
        token_hash = hashlib.sha256(raw.encode()).hexdigest()
        return raw, prefix, token_hash

    async def create_token(
        self,
        session: AsyncSession,
        user_id: UUID,
        org_id: UUID,
        name: str,
        scopes: list[str],
        expires_at: datetime | None = None,
    ) -> tuple[ApiTokenModel, str]:
        raw, prefix, token_hash = self.generate_token()
        model = ApiTokenModel(
            user_id=user_id,
            organization_id=org_id,
            name=name,
            prefix=prefix,
            token_hash=token_hash,
            scopes=scopes,
            expires_at=expires_at,
        )
        session.add(model)
        await session.flush()
        return model, raw

    async def verify_token(self, session: AsyncSession, raw_token: str) -> ApiTokenModel | None:
        if len(raw_token) < self.PREFIX_LEN:
            return None
        prefix = raw_token[: self.PREFIX_LEN]
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        result = await session.execute(
            select(ApiTokenModel).where(
                ApiTokenModel.prefix == prefix,
                ApiTokenModel.revoked_at.is_(None),
            )
        )
        for candidate in result.scalars():
            if hmac.compare_digest(candidate.token_hash, token_hash):
                if candidate.expires_at and candidate.expires_at < datetime.now(UTC):
                    return None
                return candidate
        return None

    async def revoke_token(self, session: AsyncSession, token_id: UUID) -> None:
        result = await session.execute(select(ApiTokenModel).where(ApiTokenModel.id == token_id))
        model = result.scalar_one_or_none()
        if model is not None:
            model.revoked_at = datetime.now(UTC)
