import base64
import json
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.crypto.envelope import EnvelopeCrypto
from vaultkey.secrets.service import SecretService
from vaultkey.shared.domain import SecretCreate, SecretType
from vaultkey.shared.settings import get_settings


class BundleService:
    VERSION = 1

    def __init__(self) -> None:
        settings = get_settings()
        self._crypto = EnvelopeCrypto(settings.master_key)
        self._secrets = SecretService(self._crypto)

    async def export_bundle(
        self,
        session: AsyncSession,
        environment_id: UUID,
        actor_id: UUID,
        paths: list[str],
    ) -> bytes:
        from vaultkey.secrets.versions import SecretVersionService

        reader = SecretVersionService(self._secrets)
        entries: list[dict[str, str | int]] = []
        for path in paths:
            payload = await reader.decrypt_version(session, environment_id, path)
            meta = await self._secrets.get_metadata(session, environment_id, path)
            if meta is None:
                continue
            entries.append(
                {
                    "path": path,
                    "secret_type": meta.secret_type.value,
                    "payload": payload,
                    "version": meta.current_version,
                }
            )
        bundle = {"version": self.VERSION, "environment_id": str(environment_id), "secrets": entries}
        raw = json.dumps(bundle).encode()
        blob = self._crypto.encrypt_payload(raw, environment_id.bytes)
        return base64.b64encode(json.dumps(blob.as_dict()).encode())

    async def import_bundle(
        self,
        session: AsyncSession,
        environment_id: UUID,
        actor_id: UUID,
        encoded: bytes,
    ) -> int:
        wrapper = json.loads(base64.b64decode(encoded).decode())
        from vaultkey.shared.value_objects import EncryptedBlob

        blob = EncryptedBlob.from_dict(wrapper)
        raw = self._crypto.decrypt_payload(blob, environment_id.bytes)
        bundle = json.loads(raw.decode())
        imported = 0
        for entry in bundle.get("secrets", []):
            await self._secrets.create_secret(
                session,
                environment_id,
                actor_id,
                SecretCreate(
                    path=str(entry["path"]),
                    secret_type=SecretType(str(entry.get("secret_type", "generic"))),
                    payload=str(entry["payload"]),
                ),
            )
            imported += 1
        return imported
