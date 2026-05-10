import hashlib
import hmac
import json
from datetime import UTC, datetime
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.shared.db_models import WebhookEndpointModel


class WebhookDelivery:
    def sign_payload(self, secret: str, body: bytes) -> str:
        digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return f"sha256={digest}"

    async def deliver(
        self,
        endpoint: WebhookEndpointModel,
        event: str,
        payload: dict[str, str],
    ) -> bool:
        if event not in endpoint.events:
            return False
        body = json.dumps({"event": event, "payload": payload, "ts": datetime.now(UTC).isoformat()}).encode()
        signature = self.sign_payload(endpoint.secret, body)
        headers = {"X-VaultKey-Signature": signature, "Content-Type": "application/json"}
        delay = 1.0
        for attempt in range(5):
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.post(endpoint.url, content=body, headers=headers)
                    if response.status_code < 500:
                        return response.is_success
            except httpx.HTTPError:
                pass
            delay *= 2
        return False

    async def emit(
        self,
        session: AsyncSession,
        organization_id: UUID,
        event: str,
        payload: dict[str, str],
    ) -> int:
        result = await session.execute(
            select(WebhookEndpointModel).where(
                WebhookEndpointModel.organization_id == organization_id,
                WebhookEndpointModel.is_active.is_(True),
            )
        )
        delivered = 0
        for endpoint in result.scalars():
            if await self.deliver(endpoint, event, payload):
                delivered += 1
        return delivered
