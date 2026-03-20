from datetime import UTC, datetime, timedelta
from uuid import UUID

from jose import JWTError, jwt
from pydantic import BaseModel

from vaultkey.shared.settings import get_settings


class TokenPayload(BaseModel):
    sub: str
    org_id: str
    scopes: list[str] = []
    exp: int
    typ: str = "access"


class JwtService:
    def __init__(self) -> None:
        settings = get_settings()
        self._secret = settings.jwt_secret
        self._algorithm = "HS256"
        self._expire_minutes = settings.token_expire_minutes

    def create_access_token(
        self,
        user_id: UUID,
        org_id: UUID,
        scopes: list[str] | None = None,
        expires_delta: timedelta | None = None,
    ) -> str:
        delta = expires_delta or timedelta(minutes=self._expire_minutes)
        expire = datetime.now(UTC) + delta
        payload = {
            "sub": str(user_id),
            "org_id": str(org_id),
            "scopes": scopes or [],
            "exp": int(expire.timestamp()),
            "typ": "access",
        }
        return jwt.encode(payload, self._secret, algorithm=self._algorithm)

    def decode_token(self, token: str) -> TokenPayload:
        try:
            data = jwt.decode(token, self._secret, algorithms=[self._algorithm])
            return TokenPayload.model_validate(data)
        except JWTError as exc:
            raise ValueError("invalid token") from exc
